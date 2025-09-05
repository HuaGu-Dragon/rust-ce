use std::{mem::MaybeUninit, time::Duration};

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

pub struct DebugToken {
    pid: u32,
}

impl DebugToken {
    pub fn debug(pid: u32) -> anyhow::Result<Self> {
        if unsafe { winapi::um::debugapi::DebugActiveProcess(pid) }
            == winapi::shared::minwindef::FALSE
        {
            return Err(std::io::Error::last_os_error().into());
        }

        let token = DebugToken { pid };
        if unsafe {
            winapi::um::winbase::DebugSetProcessKillOnExit(winapi::shared::minwindef::FALSE)
        } == winapi::shared::minwindef::FALSE
        {
            Err(std::io::Error::last_os_error().into())
        } else {
            Ok(token)
        }
    }

    pub fn wait_event(
        &self,
        timeout: Option<Duration>,
    ) -> anyhow::Result<winapi::um::minwinbase::DEBUG_EVENT> {
        let mut event = MaybeUninit::uninit();
        let timeout = timeout
            .map(|d| d.as_millis().try_into().ok())
            .flatten()
            .unwrap_or(winapi::um::winbase::INFINITE);

        if unsafe { winapi::um::debugapi::WaitForDebugEvent(event.as_mut_ptr(), timeout) }
            == winapi::shared::minwindef::FALSE
        {
            Err(std::io::Error::last_os_error().into())
        } else {
            Ok(unsafe { event.assume_init() })
        }
    }

    pub fn continue_event(&self, event: winapi::um::minwinbase::DEBUG_EVENT) -> anyhow::Result<()> {
        if unsafe {
            winapi::um::debugapi::ContinueDebugEvent(
                event.dwProcessId,
                event.dwThreadId,
                winapi::um::winnt::DBG_CONTINUE,
            )
        } == winapi::shared::minwindef::FALSE
        {
            Err(std::io::Error::last_os_error().into())
        } else {
            Ok(())
        }
    }
}

impl Drop for DebugToken {
    fn drop(&mut self) {
        unsafe {
            winapi::um::debugapi::DebugActiveProcessStop(self.pid);
        }
    }
}
