use std::{io::Write, mem::MaybeUninit, ops::Range, ptr::NonNull, str::FromStr};

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

    let scan = Scan::new()?;

    let mut locations = process.scan_regions(&regions, scan);

    while locations.iter().map(|r| r.locations.len()).sum::<usize>() != 1 {
        println!(
            "  Candidate Locations: {}",
            locations.iter().map(|r| r.locations.len()).sum::<usize>()
        );
        let scan = Scan::new()?;
        locations = process.re_scan_regions(locations, scan);
    }

    let mut target = String::new();
    print!("Write new value: ");
    std::io::Write::flush(&mut std::io::stdout())?;
    std::io::stdin().read_line(&mut target)?;
    let target = target.trim().parse::<i32>()?.to_ne_bytes();
    match locations[0].locations {
        CandidateLocations::Discrete { ref locations } => {
            process.write_memory(locations[0], &target)?;
        }
        _ => anyhow::bail!("Unexpected candidate locations"),
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
            .filter_map(|region| {
                match self.read_memory(region.BaseAddress as _, region.RegionSize) {
                    Ok(memory) => scan.run(*region, memory),
                    Err(e) => {
                        eprintln!(
                            "    Failed to read {} bytes at {:?}: {e}",
                            region.RegionSize, region.BaseAddress
                        );
                        None
                    }
                }
            })
            .collect()
    }

    pub fn re_scan_regions(&self, regions: Vec<Region>, scan: Scan) -> Vec<Region> {
        regions
            .into_iter()
            .filter_map(|region| {
                match self.read_memory(region.info.BaseAddress as _, region.info.RegionSize) {
                    Ok(memory) => scan.rerun(region, memory),
                    Err(e) => {
                        eprintln!(
                            "    Failed to read {} bytes at {:?}: {e}",
                            region.info.RegionSize, region.info.BaseAddress
                        );
                        None
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

#[derive(Clone, Copy)]
pub enum Scan {
    Exact(i32),
    Unknown,
    Unchanged,
    Changed,
    Decreased,
    Increased,
    DecreasedBy(i32),
    IncreasedBy(i32),
    Range(i32, i32),
}

impl FromStr for Scan {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.as_bytes()[0] {
            b'u' => Ok(Scan::Unknown),
            b'd' => {
                let n = s[1..].trim();
                if n.is_empty() {
                    Ok(Scan::Decreased)
                } else {
                    Ok(Scan::DecreasedBy(n.parse()?))
                }
            }
            b'i' => {
                let n = s[1..].trim();
                if n.is_empty() {
                    Ok(Scan::Increased)
                } else {
                    Ok(Scan::IncreasedBy(n.parse()?))
                }
            }
            b'=' => Ok(Scan::Unchanged),
            b'~' => Ok(Scan::Changed),
            _ => {
                if let Some((low, high)) = s.split_once("..=") {
                    Ok(Scan::Range(low.parse()?, high.parse()?))
                } else {
                    Ok(Scan::Exact(s.parse::<i32>()?))
                }
            }
        }
    }
}

impl Scan {
    pub fn new() -> anyhow::Result<Self> {
        write!(std::io::stdout(), "scan (? for help) >")?;
        std::io::Write::flush(&mut std::io::stdout())?;

        let mut input = String::new();
        let scan = loop {
            write!(std::io::stdout(), "scan (? for help) >")?;
            std::io::Write::flush(&mut std::io::stdout())?;
            input.clear();
            std::io::stdin().read_line(&mut input)?;
            let trimmed = input.trim();
            if trimmed.is_empty() {
                writeln!(std::io::stdout(), "Please enter a value")?;
            } else if trimmed == "?" {
                let mut stdout = std::io::stdout().lock();
                writeln!(stdout, "Help:")?;
                writeln!(stdout, "(empty): exact value scan")?;
                writeln!(stdout, "u: unknown value")?;
                writeln!(stdout, "=: unchanged value")?;
                writeln!(stdout, "~: changed value")?;
                writeln!(stdout, "d: decreased value")?;
                writeln!(stdout, "i: increased value")?;
                writeln!(stdout, "low..=high: range scan")?;
            } else {
                match trimmed.parse() {
                    Ok(value) => break value,
                    Err(e) => writeln!(std::io::stdout(), "Invalid input: {e}")?,
                }
            }
        };
        Ok(scan)
    }

    pub fn run(
        self,
        info: winapi::um::winnt::MEMORY_BASIC_INFORMATION,
        memory: Vec<u8>,
    ) -> Option<Region> {
        let base = info.BaseAddress as usize;
        match self {
            Scan::Exact(n) => {
                let target = n.to_ne_bytes();
                let locations = memory
                    .chunks_exact(4)
                    .enumerate()
                    .filter_map(|(offset, chunk)| {
                        if chunk == target {
                            Some(base + offset * 4)
                        } else {
                            None
                        }
                    })
                    .collect();
                Some(Region {
                    info,
                    locations: CandidateLocations::Discrete { locations },
                    value: Value::Exact(n),
                })
            }
            Scan::Range(low, high) => {
                let locations = memory
                    .chunks_exact(4)
                    .enumerate()
                    .filter_map(|(offset, chunk)| {
                        let value = i32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                        if value >= low && value <= high {
                            Some(base + offset * 4)
                        } else {
                            None
                        }
                    })
                    .collect();
                Some(Region {
                    info,
                    locations: CandidateLocations::Discrete { locations },
                    value: Value::Any(memory),
                })
            }
            Scan::Unknown => Some(Region {
                info,
                locations: CandidateLocations::Dense {
                    range: base..base + info.RegionSize,
                },
                value: Value::Any(memory),
            }),
            Scan::DecreasedBy(_)
            | Scan::IncreasedBy(_)
            | Scan::Decreased
            | Scan::Increased
            | Scan::Unchanged
            | Scan::Changed => None,
        }
    }
    pub fn rerun(self, region: Region, memory: Vec<u8>) -> Option<Region> {
        match self {
            Scan::Unknown => Some(region),
            _ => {
                let region = Region {
                    info: region.info,
                    locations: CandidateLocations::Discrete {
                        locations: {
                            region
                                .iter_location(&memory)
                                .filter_map(|(addr, old, new)| {
                                    if self.acceptable(old, new) {
                                        Some(addr)
                                    } else {
                                        None
                                    }
                                })
                                .collect()
                        },
                    },
                    value: Value::Any(memory),
                };

                if region.locations.len() == 0 {
                    None
                } else {
                    Some(region)
                }
            }
        }
    }

    pub fn acceptable(&self, old: i32, new: i32) -> bool {
        match self {
            Scan::Exact(n) => *n == new,
            Scan::Unknown => true,
            Scan::Decreased => new < old,
            Scan::Increased => new > old,
            Scan::Unchanged => old == new,
            Scan::Changed => old != new,
            Scan::Range(low, high) => new >= *low && new <= *high,
            Scan::DecreasedBy(amount) => new == old.wrapping_sub(*amount),
            Scan::IncreasedBy(amount) => new == old.wrapping_add(*amount),
        }
    }
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

impl Region {
    fn iter_location<'a>(
        &'a self,
        memory: &'a [u8],
    ) -> Box<dyn Iterator<Item = (usize, i32, i32)> + 'a> {
        match &self.locations {
            CandidateLocations::Discrete { locations } => {
                Box::new(locations.iter().map(move |&addr| {
                    let old = self.value_at(addr);
                    let base = addr - self.info.BaseAddress as usize;
                    let bytes = &memory[base..base + 4];
                    (
                        addr,
                        old,
                        i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
                    )
                }))
            }
            CandidateLocations::Dense { range } => {
                Box::new(range.clone().step_by(4).map(move |addr| {
                    let old = self.value_at(addr);

                    let base = addr - self.info.BaseAddress as usize;
                    let bytes = &memory[base..base + 4];

                    let new = i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

                    (addr, old, new)
                }))
            }
        }
    }

    fn value_at(&self, addr: usize) -> i32 {
        match self.value {
            Value::Exact(v) => v,
            Value::Any(ref chunk) => {
                let base = addr - self.info.BaseAddress as usize;
                let bytes = &chunk[base..base + 4];
                i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            }
        }
    }
}
