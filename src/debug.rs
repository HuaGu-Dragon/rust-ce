use std::{mem::MaybeUninit, ptr::NonNull};

pub struct Debugger {
    handle: winapi::um::winnt::HANDLE,
}

impl Drop for Debugger {
    fn drop(&mut self) {
        unsafe {
            winapi::um::handleapi::CloseHandle(self.handle);
        }
    }
}

pub fn enum_threads(pid: u32) -> anyhow::Result<Vec<u32>> {
    const ENTRY_SIZE: u32 = std::mem::size_of::<winapi::um::tlhelp32::THREADENTRY32>() as u32;
    const NEEDED_ENTRY_SIZE: u32 =
        4 * std::mem::size_of::<winapi::shared::minwindef::DWORD>() as u32;

    let handle = unsafe {
        winapi::um::tlhelp32::CreateToolhelp32Snapshot(winapi::um::tlhelp32::TH32CS_SNAPTHREAD, 0)
    };
    if handle == winapi::um::handleapi::INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error().into());
    }

    let mut entry: MaybeUninit<winapi::um::tlhelp32::THREADENTRY32> = MaybeUninit::uninit();
    unsafe {
        (*entry.as_mut_ptr()).dwSize = ENTRY_SIZE;
    }
    let tool = Debugger { handle };
    if unsafe {
        winapi::um::tlhelp32::Thread32First(tool.handle, entry.as_mut_ptr())
            == winapi::shared::minwindef::FALSE
    } {
        return Err(std::io::Error::last_os_error().into());
    }

    let mut threads = Vec::new();
    let mut entry = unsafe { entry.assume_init() };
    loop {
        if entry.th32OwnerProcessID == pid && entry.dwSize >= NEEDED_ENTRY_SIZE {
            threads.push(entry.th32ThreadID);
        }
        if unsafe { winapi::um::tlhelp32::Thread32Next(tool.handle, &raw mut entry) }
            == winapi::shared::minwindef::FALSE
        {
            break;
        }
    }

    Ok(threads)
}

pub struct ProcessThread {
    tid: u32,
    handle: NonNull<winapi::ctypes::c_void>,
}

impl ProcessThread {
    pub fn open(tid: u32) -> anyhow::Result<Self> {
        match NonNull::new(unsafe {
            winapi::um::processthreadsapi::OpenProcess(
                winapi::um::winnt::THREAD_SUSPEND_RESUME,
                winapi::shared::minwindef::FALSE,
                tid,
            )
        }) {
            Some(handle) => Ok(ProcessThread { tid, handle }),
            None => Err(std::io::Error::last_os_error().into()),
        }
    }

    pub fn suspend(&mut self) -> anyhow::Result<usize> {
        let ret = unsafe { winapi::um::processthreadsapi::SuspendThread(self.handle.as_ptr()) };
        if ret == -1i32 as u32 {
            Err(std::io::Error::last_os_error().into())
        } else {
            Ok(ret as usize)
        }
    }

    pub fn resume(&mut self) -> anyhow::Result<usize> {
        let ret = unsafe { winapi::um::processthreadsapi::ResumeThread(self.handle.as_ptr()) };
        if ret == -1i32 as u32 {
            Err(std::io::Error::last_os_error().into())
        } else {
            Ok(ret as usize)
        }
    }
}

impl Drop for ProcessThread {
    fn drop(&mut self) {
        unsafe {
            winapi::um::handleapi::CloseHandle(self.handle.as_mut());
        }
    }
}

impl ProcessThread {}
