use crate::{memory::CandidateLocations, progress::Process};

pub mod debug;
pub mod memory;
pub mod progress;
pub mod scan;

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

    dbg!(debug::enum_threads(process.pid)?);

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
