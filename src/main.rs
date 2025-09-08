use anyhow::Context;
use iced_x86::{Decoder, DecoderOptions, Formatter, NasmFormatter};

use crate::{debug::DebugToken, memory::CandidateLocations, progress::Process, thread::Condition};

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

    loop {
        input.clear();
        println!("1. Find Address");
        println!("2. Write Address");
        println!("3. Exit");
        print!("> ");
        std::io::Write::flush(&mut std::io::stdout())?;
        std::io::stdin().read_line(&mut input)?;
        let s = input.trim();

        match s.as_bytes()[0] {
            b'1' => find_address(&process)?,
            b'2' => write_address(&process)?,
            _ => break,
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

pub fn find_address(process: &Process) -> anyhow::Result<()> {
    let mask = winapi::um::winnt::PAGE_EXECUTE_READWRITE
        | winapi::um::winnt::PAGE_EXECUTE_WRITECOPY
        | winapi::um::winnt::PAGE_READWRITE
        | winapi::um::winnt::PAGE_WRITECOPY;

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

    let mut input = String::new();
    print!("Write a hardware breakpoint? (y/n) > ");
    std::io::Write::flush(&mut std::io::stdout())?;
    std::io::stdin().read_line(&mut input)?;
    let s = input.trim();
    if s == "y" {
        write_breakpoint(process, address)?;
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

    Ok(())
}

pub fn write_address(process: &Process) -> anyhow::Result<()> {
    let mut input = String::new();
    print!("Is the address a pointer? (y/n) > ");
    std::io::Write::flush(&mut std::io::stdout())?;
    std::io::stdin().read_line(&mut input)?;
    let s = input.trim();

    let address = if s == "y" {
        print!("The base address of pointer? (hex) > ");
        std::io::Write::flush(&mut std::io::stdout())?;
        input.clear();
        std::io::stdin().read_line(&mut input)?;

        let base_address = usize::from_str_radix(input.trim().trim_start_matches("0x"), 16)?;

        print!("The offsets? (hex, split by space) > ");
        std::io::Write::flush(&mut std::io::stdout())?;
        input.clear();
        std::io::stdin().read_line(&mut input)?;

        let offsets: Vec<isize> = input
            .split_whitespace()
            .map(|s| isize::from_str_radix(s.trim_start_matches("0x"), 16).unwrap())
            .collect();

        let mut current_address = base_address;
        println!("Base Address: {base_address:x}");
        for (i, &offset) in offsets
            .iter()
            .enumerate()
            .take(offsets.len().saturating_sub(1))
        {
            current_address = (current_address as isize + offset) as usize;
            let pointer_bytes =
                process.read_memory(current_address, std::mem::size_of::<usize>())?;
            let pointer_value = usize::from_ne_bytes(
                pointer_bytes
                    .try_into()
                    .expect("Failed to convert bytes to usize"),
            );
            println!("Level {i}: Offset 0x{offset:x} -> Address 0x{pointer_value:x}");
            current_address = pointer_value;
        }

        if let Some(&last_offset) = offsets.last() {
            current_address = (current_address as isize + last_offset) as usize;
            println!("Final Offset: 0x{last_offset:x} -> Address 0x{current_address:x}");
        }

        current_address
    } else {
        input.clear();
        print!("The address? (hex) > ");
        std::io::Write::flush(&mut std::io::stdout())?;
        std::io::stdin().read_line(&mut input)?;
        usize::from_str_radix(input.trim().trim_start_matches("0x"), 16)?
    };

    input.clear();
    print!("Hardware breakpoint on write? (y/n) > ");
    std::io::Write::flush(&mut std::io::stdout())?;
    std::io::stdin().read_line(&mut input)?;
    let s = input.trim();

    if s == "y" {
        write_breakpoint(process, address)?;
    } else {
        let scan = loop {
            match scan::write()? {
                scan::Scan::Exact(v) => break v,
                _ => {
                    println!("Please enter an exact value to write.");
                    continue;
                }
            }
        };

        let bytes = process.write_memory(address, scan.mem_view())?;
        println!("  Write {bytes} bytes to address: [{address:x}]");
    }
    Ok(())
}

pub fn write_breakpoint(process: &Process, address: usize) -> anyhow::Result<()> {
    let threads: anyhow::Result<Vec<thread::ProcessThread>> = process
        .enum_threads()
        .context("iter threads")?
        .into_iter()
        .map(thread::ProcessThread::open)
        .collect();

    let threads = threads?;

    let mut input = String::new();
    print!("Condition (a=access, e=execute, w=write) > ");
    std::io::Write::flush(&mut std::io::stdout())?;
    std::io::stdin().read_line(&mut input)?;
    let s = input.trim();
    let cond = match s.as_bytes()[0] {
        b'a' => Condition::Access,
        b'e' => Condition::Execute,
        b'w' => Condition::Write,
        _ => {
            println!("Invalid condition, default to Execute");
            Condition::Write
        }
    };

    let _breakpoints = threads
        .iter()
        .map(|t| {
            let did_suspend = t.suspend().is_ok();
            let breakpoint = t.add_breakpoint(address, cond, thread::Size::Dword);
            if did_suspend {
                drop(t.resume());
            }
            breakpoint
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let debugger = DebugToken::debug(process.pid).context("debug token")?;
    'breakpoint: loop {
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
                        let thread = threads
                            .iter()
                            .find(|t| t.id() == event.dwThreadId)
                            .ok_or_else(|| anyhow::anyhow!("not matching thread found!"))?;
                        let context = thread.get_context()?;
                        println!(
                            "RAX={:016X} RBX={:016X} RCX={:016X} RDX={:016X}",
                            context.Rax, context.Rbx, context.Rcx, context.Rdx
                        );
                        println!("RDI={:016X} RSI={:016X}", context.Rdi, context.Rsi);

                        input.clear();
                        print!("Is this the instruction to modify? (y/n) > ");
                        std::io::Write::flush(&mut std::io::stdout()).unwrap();
                        std::io::stdin().read_line(&mut input).unwrap();
                        let s = input.trim();
                        if s != "y" {
                            debugger.continue_event(event)?;
                            continue 'breakpoint;
                        }

                        input.clear();
                        print!("Write NOPs to this instruction? (y/n) > ");
                        std::io::Write::flush(&mut std::io::stdout()).unwrap();
                        std::io::stdin().read_line(&mut input).unwrap();
                        let s = input.trim();
                        if s == "y" {
                            let value = vec![0x90; inst.len()];
                            process.write_memory(inst.ip() as usize, &value)?;
                        }

                        input.clear();
                        print!("Inject code to change the write value? (y/n) > ");
                        std::io::Write::flush(&mut std::io::stdout()).unwrap();
                        std::io::stdin().read_line(&mut input).unwrap();
                        let s = input.trim();
                        if s == "y" {
                            let region = process
                                .memory_region()
                                .into_iter()
                                .rev()
                                .find(|region| {
                                    (region.State & winapi::um::winnt::MEM_FREE) != 0
                                        && (region.BaseAddress as usize)
                                            < info.ExceptionRecord.ExceptionAddress as usize
                                })
                                .unwrap();

                            let address = region.BaseAddress as usize + region.RegionSize - 2048;
                            let alloc_address = process.alloc(address, 2048)?;

                            // jmp target_address
                            // nop 2
                            let mut jmp = [0xE9, 0, 0, 0, 0, 0x66, 0x90];
                            jmp[1..5].copy_from_slice(
                                &((alloc_address as isize
                                    - (info.ExceptionRecord.ExceptionAddress as usize - 2) as isize)
                                    as i32)
                                    .to_ne_bytes(),
                            );
                            process.write_memory(
                                info.ExceptionRecord.ExceptionAddress as usize - jmp.len(),
                                &jmp,
                            )?;

                            // add dword ptr [rsi + 7E0h], 2
                            // jmp back
                            let mut injection =
                                [0x83, 0x86, 0xE0, 0x07, 0x00, 0x00, 0x02, 0xE9, 0, 0, 0, 0];
                            let inj_len = injection.len();
                            injection[8..12].copy_from_slice(
                                &((info.ExceptionRecord.ExceptionAddress as isize
                                    - (alloc_address + inj_len) as isize)
                                    as i32)
                                    .to_ne_bytes(),
                            );
                            process.write_memory(alloc_address, &injection)?;
                        }

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

// 100325AD0h + 0 + 0

// [rel 100325AD0h]

//    000000010002DB51 8B 9E E0 07 00 00       mov ebx,[rsi+7E0h]
// >>> 000000010002DB57 83 AE E0 07 00 00 01    sub dword [rsi+7E0h],1

// To:
//>>> 00000000FFFF0000 83 86 E0 07 00 00 02    add dword [rsi+7E0h],2
// 00000000FFFF0007 E9 52 DB 03 00          jmp 000000010002DB5Eh

// Multilevel pointers:
// RSI=00000000015B3C60 + 18h
// RSI=00000000015B3BE0 + 0h
// RSI=00000000015B3B60 + 18h
// RSI=0000000001536790 + 10h
// 100325B00h + 0
