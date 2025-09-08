use std::{mem::MaybeUninit, ptr::NonNull};

use crate::{
    debug::Debugger,
    memory::Region,
    scan::{Scan, Scannable},
};

pub struct Process {
    pub pid: u32,
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

    pub fn scan_regions<T: Scannable>(
        &self,
        regions: Vec<winapi::um::winnt::MEMORY_BASIC_INFORMATION>,
        scan: Scan<T>,
    ) -> Vec<Region> {
        regions
            .into_iter()
            .filter_map(|region| {
                match self.read_memory(region.BaseAddress as _, region.RegionSize) {
                    Ok(memory) => scan.run(region, memory),
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

    pub fn re_scan_regions<T: Scannable>(&self, regions: &mut Vec<Region>, scan: Scan<T>) {
        regions.retain_mut(|region| {
            match self.read_memory(region.info.BaseAddress as _, region.info.RegionSize) {
                Ok(memory) => scan.rerun(region, memory),
                Err(e) => {
                    eprintln!(
                        "    Failed to read {} bytes at {:?}: {e}",
                        region.info.RegionSize, region.info.BaseAddress
                    );
                    false
                }
            }
        })
    }

    pub fn flush_cache(&self) -> anyhow::Result<()> {
        if unsafe {
            winapi::um::processthreadsapi::FlushInstructionCache(
                self.handle.as_ptr(),
                std::ptr::null(),
                0,
            )
        } == winapi::shared::minwindef::FALSE
        {
            Err(std::io::Error::last_os_error().into())
        } else {
            Ok(())
        }
    }

    pub fn enum_threads(&self) -> anyhow::Result<Vec<u32>> {
        const ENTRY_SIZE: u32 = std::mem::size_of::<winapi::um::tlhelp32::THREADENTRY32>() as u32;
        const NEEDED_ENTRY_SIZE: u32 =
            4 * std::mem::size_of::<winapi::shared::minwindef::DWORD>() as u32;

        let handle = unsafe {
            winapi::um::tlhelp32::CreateToolhelp32Snapshot(
                winapi::um::tlhelp32::TH32CS_SNAPTHREAD,
                0,
            )
        };
        if handle == winapi::um::handleapi::INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error().into());
        }

        let mut entry: MaybeUninit<winapi::um::tlhelp32::THREADENTRY32> = MaybeUninit::uninit();
        unsafe {
            (*entry.as_mut_ptr()).dwSize = ENTRY_SIZE;
        }
        let tool = Debugger::new(handle);
        if unsafe {
            winapi::um::tlhelp32::Thread32First(tool.handle(), entry.as_mut_ptr())
                == winapi::shared::minwindef::FALSE
        } {
            return Err(std::io::Error::last_os_error().into());
        }

        let mut threads = Vec::new();
        let mut entry = unsafe { entry.assume_init() };
        loop {
            if entry.th32OwnerProcessID == self.pid && entry.dwSize >= NEEDED_ENTRY_SIZE {
                threads.push(entry.th32ThreadID);
            }
            if unsafe { winapi::um::tlhelp32::Thread32Next(tool.handle(), &raw mut entry) }
                == winapi::shared::minwindef::FALSE
            {
                break;
            }
        }

        Ok(threads)
    }

    pub fn alloc(&self, addr: usize, size: usize) -> anyhow::Result<usize> {
        let addr = unsafe {
            winapi::um::memoryapi::VirtualAllocEx(
                self.handle.as_ptr(),
                addr as _,
                size,
                winapi::um::winnt::MEM_COMMIT | winapi::um::winnt::MEM_RESERVE,
                winapi::um::winnt::PAGE_EXECUTE_READWRITE,
            )
        };

        if addr.is_null() {
            Err(std::io::Error::last_os_error().into())
        } else {
            Ok(addr as usize)
        }
    }

    pub fn dealloc(&self, addr: usize) -> anyhow::Result<()> {
        if unsafe {
            winapi::um::memoryapi::VirtualFreeEx(
                self.handle.as_ptr(),
                addr as _,
                0,
                winapi::um::winnt::MEM_RELEASE,
            )
        } == winapi::shared::minwindef::FALSE
        {
            Err(std::io::Error::last_os_error().into())
        } else {
            Ok(())
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        unsafe {
            winapi::um::handleapi::CloseHandle(self.handle.as_ptr());
        }
    }
}
