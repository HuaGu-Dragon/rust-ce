use anyhow::Context;

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

    dbg!(debug::enum_threads(process.pid).context("dbg enum threads")?);

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

        let target = loop {
            match scan::write()? {
                scan::Scan::Exact(v) => break v,
                _ => {
                    println!("Please enter an exact value to write.");
                    continue;
                }
            }
        };

        let address = match locations[0].locations {
            CandidateLocations::Discrete { ref locations } => locations[0],
            _ => anyhow::bail!("Unexpected candidate locations"),
        };

        println!("Target Address: {:x}", address);

        let threads: anyhow::Result<Vec<thread::ProcessThread>> = debug::enum_threads(process.pid)
            .context("iter threads")?
            .into_iter()
            .map(thread::ProcessThread::open)
            .collect();

        threads
            .context("collect threads")?
            .iter_mut()
            .for_each(|t| {
                match t.suspend() {
                    Ok(count) => println!("Suspended thread {}: suspend count {}", t.id(), count),
                    Err(e) => println!("Failed to suspend thread {}: {}", t.id(), e),
                }
                match t.get_context() {
                    Ok(context) => {
                        println!("Dr0: {:016x}", context.Dr0);
                        println!("Dr7: {:016x}", context.Dr7);
                        println!("Dr6: {:016x}", context.Dr6);
                        println!("Rax: {:016x}", context.Rax);
                        println!("Rbx: {:016x}", context.Rbx);
                        println!("Rcx: {:016x}", context.Rcx);
                        println!("Rip: {:016x}", context.Rip);
                    }
                    Err(e) => eprintln!("Failed to get context of thread {}: {}", t.id(), e),
                }
                t.watch_memory_write(address).expect("watch memory write");

                match t.resume() {
                    Ok(count) => println!("Resumed thread {}: suspend count {}", t.id(), count),
                    Err(e) => println!("Failed to resume thread {}: {}", t.id(), e),
                }
            });
        let debugger = DebugToken::debug(process.pid).context("debug token")?;
        for _ in 0..100 {
            let event = debugger.wait_event(None).context("wait event")?;
            println!("Debug Event: {:?}", event.dwDebugEventCode);
            if event.dwDebugEventCode == winapi::um::minwinbase::EXCEPTION_DEBUG_EVENT {
                let info = unsafe { event.u.Exception() };
                println!("First Chance: {}", info.dwFirstChance);
                println!("Exception Code: {:x}", info.ExceptionRecord.ExceptionCode);
                println!("Exception Flags: {:x}", info.ExceptionRecord.ExceptionFlags);
                println!(
                    "Exception Record: {:x}",
                    info.ExceptionRecord.ExceptionRecord as usize
                );
                println!(
                    "Exception Address: {:x}",
                    info.ExceptionRecord.ExceptionAddress as usize
                );
                println!(
                    "Number Parameters: {}",
                    info.ExceptionRecord.NumberParameters
                );
                println!(
                    "Exception Information: {:?}",
                    info.ExceptionRecord.ExceptionInformation
                );
            }
            debugger.continue_event(event).context("continue event")?;
        }

        match locations[0].locations {
            CandidateLocations::Discrete { ref locations } => {
                let n = process.write_memory(locations[0], target.mem_view())?;
                println!("Written {} bytes to address: [{:x}]", n, locations[0]);
            }
            _ => anyhow::bail!("Unexpected candidate locations"),
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
