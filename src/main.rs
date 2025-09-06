use anyhow::Context;
use iced_x86::{Decoder, DecoderOptions};

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

    let mut threads = threads?;

    for thread in threads.iter_mut() {
        thread.suspend()?;
        thread.watch_memory_write(address)?;
        thread.resume()?;
    }
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
                println!(
                    "Region: 0x{:x}-0x{:x}",
                    region.BaseAddress as usize,
                    region.BaseAddress as usize + region.RegionSize
                );

                let bytes = process.read_memory(region.BaseAddress as usize, region.RegionSize)?;

                let mut decoder =
                    Decoder::with_ip(64, &bytes, region.BaseAddress as u64, DecoderOptions::NONE);

                let mut instruction = iced_x86::Instruction::default();
                while decoder.can_decode() {
                    decoder.decode_out(&mut instruction);
                    if instruction.next_ip() == info.ExceptionRecord.ExceptionAddress as u64 {
                        println!("Instruction: {instruction}");
                        let value = vec![0x90; instruction.len()];
                        process.write_memory(instruction.ip() as usize, &value)?;
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

    for thread in threads.iter_mut() {
        thread.suspend()?;
        thread.cancel()?;
        thread.resume()?;
    }

    Ok(())
}
