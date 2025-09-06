use std::{mem::MaybeUninit, ptr::NonNull};

use anyhow::Context;

pub struct ProcessThread {
    tid: u32,
    handle: NonNull<winapi::ctypes::c_void>,
}

impl ProcessThread {
    pub fn open(tid: u32) -> anyhow::Result<Self> {
        match NonNull::new(unsafe {
            winapi::um::processthreadsapi::OpenThread(
                winapi::um::winnt::THREAD_SUSPEND_RESUME
                    | winapi::um::winnt::THREAD_GET_CONTEXT
                    | winapi::um::winnt::THREAD_SET_CONTEXT
                    | winapi::um::winnt::THREAD_QUERY_INFORMATION,
                winapi::shared::minwindef::FALSE,
                tid,
            )
        }) {
            Some(handle) => Ok(ProcessThread { tid, handle }),
            None => Err(std::io::Error::last_os_error().into()),
        }
    }

    pub fn id(&self) -> u32 {
        self.tid
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

    pub fn get_context(&self) -> anyhow::Result<winapi::um::winnt::CONTEXT> {
        // In order to ensure the CONTEXT structure is aligned properly
        // we create a new struct with an alignment attribute.
        #[repr(align(16))]
        struct AlignedContext(winapi::um::winnt::CONTEXT);
        let context: MaybeUninit<AlignedContext> = MaybeUninit::uninit();
        let mut context = unsafe { context.assume_init() };
        context.0.ContextFlags = winapi::um::winnt::CONTEXT_ALL;
        if unsafe {
            winapi::um::processthreadsapi::GetThreadContext(
                self.handle.as_ptr(),
                &raw mut context.0,
            )
        } == winapi::shared::minwindef::FALSE
        {
            Err(std::io::Error::last_os_error().into())
        } else {
            Ok(context.0)
        }
    }

    pub fn set_context(&self, context: winapi::um::winnt::CONTEXT) -> anyhow::Result<()> {
        #[repr(align(16))]
        struct AlignedContext(winapi::um::winnt::CONTEXT);
        let context = AlignedContext(context);
        if unsafe {
            winapi::um::processthreadsapi::SetThreadContext(
                self.handle.as_ptr(),
                &raw const context.0,
            )
        } == winapi::shared::minwindef::FALSE
        {
            Err(std::io::Error::last_os_error().into())
        } else {
            Ok(())
        }
    }

    //TODO: Create a Struct then when drop call the cancel automatically
    pub fn watch_memory_write(&self, address: usize) -> anyhow::Result<()> {
        let mut context = self.get_context()?;
        context.Dr0 = address as u64;
        context.Dr7 = 0x00000000000d0001;
        self.set_context(context)
    }

    pub fn cancel(&self) -> anyhow::Result<()> {
        let mut context = self.get_context().context("get thread context")?;
        context.Dr0 = 0;
        context.Dr7 = 0;
        self.set_context(context).context("set thread context")
    }
}

impl Drop for ProcessThread {
    fn drop(&mut self) {
        unsafe {
            winapi::um::handleapi::CloseHandle(self.handle.as_ptr());
        }
    }
}
