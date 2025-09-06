use std::{mem::MaybeUninit, time::Duration};

pub struct Debugger {
    handle: winapi::um::winnt::HANDLE,
}

impl Debugger {
    pub fn new(handle: winapi::um::winnt::HANDLE) -> Self {
        Self { handle }
    }

    pub fn handle(&self) -> winapi::um::winnt::HANDLE {
        self.handle
    }
}

impl Drop for Debugger {
    fn drop(&mut self) {
        unsafe {
            winapi::um::handleapi::CloseHandle(self.handle);
        }
    }
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
            .and_then(|d| d.as_millis().try_into().ok())
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
