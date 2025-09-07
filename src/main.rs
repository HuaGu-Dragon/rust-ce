use anyhow::Context;
use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};

use crate::{debug::DebugToken, memory::CandidateLocations, progress::Process};

pub mod debug;
pub mod memory;
pub mod progress;
pub mod scan;
pub mod thread;

fn main() -> anyhow::Result<()> {
    enum_proc()?.into_iter().for_each(|pid| {
        let process = match Process::open(pid) {
            Ok(process) => process,
            Err(e) => {
                println!("{e}");
                return;
            }
        };
        let name = match process.name() {
            Ok(name) => name,
            Err(e) => {
                println!("Failed to get process name: {e}");
                return;
            }
        };
        println!("{}: {}", process.pid, name);
    });

    let mut input = String::new();
    let process = loop {
        print!("Enter a pid: ");
        std::io::Write::flush(&mut std::io::stdout())?;
        std::io::stdin().read_line(&mut input)?;
        let pid: u32 = input.trim().parse()?;
        match Process::open(pid) {
            Ok(process) => break process,
            Err(e) => {
                println!("{e}");
                input.clear();
                continue;
            }
        };
    };

    let mask = winapi::um::winnt::PAGE_EXECUTE_READWRITE
        | winapi::um::winnt::PAGE_EXECUTE_WRITECOPY
        | winapi::um::winnt::PAGE_READWRITE
        | winapi::um::winnt::PAGE_WRITECOPY;
    loop {
        let regions: Vec<_> = process
            .memory_region()
            .into_iter()
            .filter(|region| region.Protect & mask != 0)
            .collect();
        println!("  Memory Regions: {}", regions.len());

        // let address: usize = 0x100325AD0;
        // let pointer = process.read_memory(address, 8)?;
        // let pointer = usize::from_le_bytes(pointer.try_into().unwrap());
        // println!("  Pointer at {address:x}: {pointer:x}");
        // let value = process.read_memory(pointer, 4)?;
        // let value = u32::from_le_bytes(value.try_into().unwrap());
        // println!("  Value at {pointer:x}: {value}");

        let scan = scan::build()?;

        let mut locations = process.scan_regions(regions, scan);

        while locations.iter().map(|r| r.locations.len()).sum::<usize>() != 1 {
            println!(
                "  Candidate Locations: {}",
                locations.iter().map(|r| r.locations.len()).sum::<usize>()
            );
            let scan = scan::build()?;
            process.re_scan_regions(&mut locations, scan);
        }

        let address = match locations[0].locations {
            CandidateLocations::Discrete { ref locations } => locations[0],
            _ => anyhow::bail!("Unexpected candidate locations"),
        };

        println!("Target Address: {address:x}");

        input.clear();
        print!("Write a hardware breakpoint? (y/n) > ");
        std::io::Write::flush(&mut std::io::stdout())?;
        std::io::stdin().read_line(&mut input)?;
        let s = input.trim();
        if s == "y" {
            write_nop(&process, address)?;
        }

        input.clear();
        print!("Rewrite the value? (y/n) > ");
        std::io::Write::flush(&mut std::io::stdout())?;
        std::io::stdin().read_line(&mut input)?;
        let s = input.trim();
        if s == "y" {
            let target = loop {
                match scan::write()? {
                    scan::Scan::Exact(v) => break v,
                    _ => {
                        println!("Please enter an exact value to write.");
                        continue;
                    }
                }
            };
            let n = process.write_memory(address, target.mem_view())?;
            println!("Written {n} bytes to address: [{address:x}]");
        }

        input.clear();
        print!("Do you want to write again? (y/n): ");
        std::io::Write::flush(&mut std::io::stdout())?;
        std::io::stdin().read_line(&mut input)?;
        if input.trim().to_lowercase() != "y" {
            break;
        }
    }
    Ok(())
}

//TODO: change the buffer to user given, like the Read trait
//TODO: change vector to a more abstract type, like a slice or other type like HashMap
pub fn enum_proc() -> anyhow::Result<Vec<u32>> {
    let mut pid = Vec::with_capacity(1024);
    let mut size = 0;
    if unsafe {
        winapi::um::psapi::EnumProcesses(
            pid.as_mut_ptr(),
            (pid.capacity() * size_of::<u32>()) as u32,
            &raw mut size,
        ) == winapi::shared::minwindef::FALSE
    } {
        return Err(std::io::Error::last_os_error().into());
    }
    unsafe {
        pid.set_len(size as usize / size_of::<u32>());
    }
    Ok(pid)
}

pub fn write_nop(process: &Process, address: usize) -> anyhow::Result<()> {
    let threads: anyhow::Result<Vec<thread::ProcessThread>> = process
        .enum_threads()
        .context("iter threads")?
        .into_iter()
        .map(thread::ProcessThread::open)
        .collect();

    let threads = threads?;

    // for thread in threads.iter_mut() {
    //     thread.suspend()?;
    //     thread.watch_memory_write(address)?;
    //     thread.resume()?;
    // }

    let _breakpoints = threads
        .iter()
        .map(|t| {
            let did_suspend = t.suspend().is_ok();
            let breakpoint =
                t.add_breakpoint(address, thread::Condition::Write, thread::Size::Dword);
            if did_suspend {
                drop(t.resume());
            }
            breakpoint
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let debugger = DebugToken::debug(process.pid).context("debug token")?;
    loop {
        let event = debugger.wait_event(None).context("wait event")?;
        if event.dwDebugEventCode == winapi::um::minwinbase::EXCEPTION_DEBUG_EVENT {
            let info = unsafe { event.u.Exception() };
            if info.ExceptionRecord.ExceptionCode == winapi::um::minwinbase::EXCEPTION_SINGLE_STEP {
                let region = process
                    .memory_region()
                    .into_iter()
                    .find(|region| {
                        let base = region.BaseAddress as usize;
                        let target = info.ExceptionRecord.ExceptionAddress as usize;
                        base <= target && target < base + region.RegionSize
                    })
                    .ok_or_else(|| anyhow::anyhow!("not matching region found!"))?;

                println!(
                    "ExceptionAddress: {:x}",
                    info.ExceptionRecord.ExceptionAddress as usize
                );

                let bytes = process.read_memory(region.BaseAddress as usize, region.RegionSize)?;

                let decoder =
                    Decoder::with_ip(64, &bytes, region.BaseAddress as u64, DecoderOptions::NONE);
                let mut formatter = NasmFormatter::new();
                let mut output = String::new();

                let instruction = decoder.into_iter().collect::<Vec<_>>();
                for (i, inst) in instruction.iter().enumerate() {
                    if inst.next_ip() == info.ExceptionRecord.ExceptionAddress as u64 {
                        let low = i.saturating_sub(5);
                        let high = (i + 5).min(instruction.len());
                        for (l, inst) in instruction[low..high].iter().enumerate() {
                            print!(
                                "{} {:016X} ",
                                if l == i.saturating_sub(low) {
                                    ">>>"
                                } else {
                                    "   "
                                },
                                inst.ip()
                            );
                            let k = (inst.ip() - region.BaseAddress as u64) as usize;
                            let inst_bytes = &bytes[k..k + inst.len()];
                            for b in inst_bytes {
                                print!("{b:02X} ");
                            }
                            if inst_bytes.len() < 8 {
                                for _ in 0..8usize.saturating_sub(inst_bytes.len()) {
                                    print!("   ");
                                }
                            }
                            output.clear();
                            formatter.format(inst, &mut output);
                            println!("{output}");
                        }

                        let value = vec![0x90; inst.len()];
                        process.write_memory(inst.ip() as usize, &value)?;

                        break;
                    }
                }

                process.flush_cache()?;
                debugger.continue_event(event)?;
                break;
            }
        }
        debugger.continue_event(event).context("continue event")?;
    }

    Ok(())
}
