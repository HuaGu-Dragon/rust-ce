use std::{mem::MaybeUninit, ops::Range, ptr::NonNull};

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
    let regions: Vec<_> = process
        .memory_region()
        .into_iter()
        .filter(|region| region.Protect & mask != 0)
        .collect();
    println!("  Memory Regions: {}", regions.len());

    let scan = process.scan_regions(&regions, Scan::Unknown);
    println!("  Scanned Regions: {}", scan.len());
    println!(
        "  Found {} locations",
        scan.iter().map(|r| r.locations.len()).sum::<usize>()
    );
    std::thread::sleep(std::time::Duration::from_secs(10));
    let last_scan = process.re_scan_regions(&scan, Scan::Decreased);
    println!(
        "Found {} locations",
        last_scan.iter().map(|r| r.locations.len()).sum::<usize>()
    );

    let mut location = Vec::with_capacity(regions.len());

    let mut target = String::new();
    std::io::stdin().read_line(&mut target)?;
    let first = target.trim().parse::<i32>()?.to_ne_bytes();

    regions.into_iter().for_each(|region| {
        match process.read_memory(region.BaseAddress as _, region.RegionSize) {
            Ok(memory) => {
                memory
                    .chunks_exact(first.len())
                    .enumerate()
                    .for_each(|(offset, chunk)| {
                        if chunk == first {
                            location.push(
                                region.BaseAddress as usize
                                    + offset * std::mem::size_of_val(&first),
                            );
                        }
                    })
            }
            Err(e) => eprintln!(
                "    Failed to read {} bytes at {:?}: {e}",
                region.RegionSize, region.BaseAddress
            ),
        }
    });

    loop {
        println!("Found {} locations", location.len());
        target.clear();
        std::io::stdin().read_line(&mut target)?;
        let target = target.trim().parse::<i32>()?.to_ne_bytes();
        location.retain(|&addr| match process.read_memory(addr, target.len()) {
            Ok(memory) => {
                if memory == target {
                    true
                } else {
                    false
                }
            }
            Err(_) => false,
        });
        if location.len() == 1 {
            println!("    Found unique value at [{:x}]", location[0]);
            break;
        }
    }

    let mut target = String::new();
    print!("Write new value: ");
    std::io::Write::flush(&mut std::io::stdout())?;
    std::io::stdin().read_line(&mut target)?;
    let target = target.trim().parse::<i32>()?.to_ne_bytes();
    process.write_memory(location[0], &target)?;
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

pub struct Process {
    pid: u32,
    handle: NonNull<winapi::ctypes::c_void>,
}

impl Process {
    pub fn open(pid: u32) -> anyhow::Result<Self> {
        let handle = unsafe {
            winapi::um::processthreadsapi::OpenProcess(
                winapi::um::winnt::PROCESS_QUERY_INFORMATION
                    | winapi::um::winnt::PROCESS_VM_READ
                    | winapi::um::winnt::PROCESS_VM_WRITE
                    | winapi::um::winnt::PROCESS_VM_OPERATION,
                winapi::shared::minwindef::FALSE,
                pid,
            )
        };
        let handle = NonNull::new(handle)
            .ok_or_else(|| anyhow::anyhow!("Failed to open process: {}", pid))?;
        Ok(Process { pid, handle })
    }

    pub fn name(&self) -> anyhow::Result<String> {
        let mut module = MaybeUninit::uninit();
        let mut size = 0;
        if unsafe {
            winapi::um::psapi::EnumProcessModules(
                self.handle.as_ptr(),
                module.as_mut_ptr(),
                size_of::<winapi::shared::minwindef::HMODULE>() as u32,
                &raw mut size,
            ) == winapi::shared::minwindef::FALSE
        } {
            return Err(std::io::Error::last_os_error().into());
        }

        let module = unsafe { module.assume_init() };
        let mut buffer = MaybeUninit::<[u16; 64]>::uninit();
        let length = unsafe {
            winapi::um::psapi::GetModuleBaseNameW(
                self.handle.as_ptr(),
                module,
                buffer.as_mut_ptr().cast(),
                64,
            )
        };
        if length == 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        let buffer = unsafe { buffer.assume_init() };
        Ok(String::from_utf16_lossy(&buffer[..length as usize]))
    }

    pub fn memory_region(&self) -> Vec<winapi::um::winnt::MEMORY_BASIC_INFORMATION> {
        let mut base = 0;
        let mut region = Vec::new();
        let mut info = MaybeUninit::uninit();

        loop {
            let written = unsafe {
                winapi::um::memoryapi::VirtualQueryEx(
                    self.handle.as_ptr(),
                    base as _,
                    info.as_mut_ptr(),
                    size_of::<winapi::um::winnt::MEMORY_BASIC_INFORMATION>(),
                )
            };
            if written == 0 {
                break region;
            }
            let info = unsafe { info.assume_init() };
            base = info.BaseAddress as usize + info.RegionSize;
            region.push(info);
        }
    }

    pub fn read_memory(&self, addr: usize, n: usize) -> anyhow::Result<Vec<u8>> {
        let mut buffer: Vec<u8> = Vec::with_capacity(n);
        let mut read = 0;
        if unsafe {
            winapi::um::memoryapi::ReadProcessMemory(
                self.handle.as_ptr(),
                addr as _,
                buffer.as_mut_ptr().cast(),
                buffer.capacity(),
                &mut read,
            ) == winapi::shared::minwindef::FALSE
        } {
            Err(std::io::Error::last_os_error().into())
        } else {
            unsafe {
                buffer.set_len(read);
            }
            Ok(buffer)
        }
    }

    pub fn write_memory(&self, addr: usize, value: &[u8]) -> anyhow::Result<usize> {
        let mut written = 0;
        if unsafe {
            winapi::um::memoryapi::WriteProcessMemory(
                self.handle.as_ptr(),
                addr as _,
                value.as_ptr().cast(),
                value.len(),
                &raw mut written,
            )
        } == winapi::shared::minwindef::FALSE
        {
            Err(std::io::Error::last_os_error().into())
        } else {
            Ok(written)
        }
    }

    pub fn scan_regions(
        &self,
        regions: &[winapi::um::winnt::MEMORY_BASIC_INFORMATION],
        scan: Scan,
    ) -> Vec<Region> {
        regions
            .iter()
            .filter_map(|region| match scan {
                Scan::Exact(_) => todo!(),
                Scan::Unknown => {
                    let base = region.BaseAddress as usize;
                    match self.read_memory(base, region.RegionSize) {
                        Ok(memory) => Some(Region {
                            info: *region,
                            locations: CandidateLocations::Dense {
                                range: base..base + region.RegionSize,
                            },
                            value: Value::Any(memory),
                        }),
                        Err(_) => None,
                    }
                }
                Scan::Decreased => todo!(),
            })
            .collect()
    }

    pub fn re_scan_regions(&self, regions: &[Region], scan: Scan) -> Vec<Region> {
        regions
            .iter()
            .filter_map(|region| match scan {
                Scan::Exact(_) => todo!(),
                Scan::Unknown => todo!(),
                Scan::Decreased => {
                    let mut locations = Vec::new();
                    match &region.locations {
                        CandidateLocations::Discrete { locations } => todo!(),
                        CandidateLocations::Dense { range } => {
                            match self.read_memory(range.start, range.len()) {
                                Ok(memory) => match &region.value {
                                    Value::Exact(_) => todo!(),
                                    Value::Any(items) => {
                                        memory
                                            .chunks_exact(4)
                                            .zip(items.chunks_exact(4))
                                            .enumerate()
                                            .for_each(|(offset, (chunk, prev))| {
                                                let old = i32::from_ne_bytes([
                                                    prev[0], prev[1], prev[2], prev[3],
                                                ]);
                                                let new = i32::from_ne_bytes([
                                                    chunk[0], chunk[1], chunk[2], chunk[3],
                                                ]);

                                                if new < old {
                                                    locations.push(
                                                        range.start
                                                            + offset
                                                                * std::mem::size_of_val(&chunk),
                                                    );
                                                }
                                            });
                                        Some(Region {
                                            info: region.info,
                                            locations: CandidateLocations::Discrete { locations },
                                            value: Value::Any(memory),
                                        })
                                    }
                                },
                                Err(e) => {
                                    println!("Error reading memory: {e}");
                                    None
                                }
                            }
                        }
                    }
                }
            })
            .collect()
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            winapi::um::handleapi::CloseHandle(self.handle.as_ptr());
        }
    }
}
pub enum CandidateLocations {
    Discrete { locations: Vec<usize> },
    Dense { range: Range<usize> },
}

impl CandidateLocations {
    pub fn len(&self) -> usize {
        match self {
            CandidateLocations::Discrete { locations } => locations.len(),
            CandidateLocations::Dense { range } => range.len(),
        }
    }
}
pub enum Scan {
    Exact(i32),
    Unknown,
    Decreased,
}
pub enum Value {
    Exact(i32),
    Any(Vec<u8>),
}

pub struct Region {
    pub info: winapi::um::winnt::MEMORY_BASIC_INFORMATION,
    pub locations: CandidateLocations,
    pub value: Value,
}
