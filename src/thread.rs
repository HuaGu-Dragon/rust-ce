use std::{mem::MaybeUninit, ptr::NonNull};

use anyhow::Context;

pub struct ProcessThread {
    tid: u32,
    handle: NonNull<winapi::ctypes::c_void>,
}

#[repr(u8)]
pub enum Condition {
    Execute = 0b00,
    Write = 0b01,
    Access = 0b11,
}

#[repr(u8)]
pub enum Size {
    Byte = 0b00,
    Word = 0b01,
    Dword = 0b11,
    Qword = 0b10,
}

pub struct Breakpoint<'a> {
    thread: &'a ProcessThread,
    index: u8,
    clear_mask: u64,
}

#[repr(align(16))]
struct AlignedContext(winapi::um::winnt::CONTEXT);

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

    pub fn suspend(&self) -> anyhow::Result<usize> {
        let ret = unsafe { winapi::um::processthreadsapi::SuspendThread(self.handle.as_ptr()) };
        if ret == -1i32 as u32 {
            Err(std::io::Error::last_os_error().into())
        } else {
            Ok(ret as usize)
        }
    }

    pub fn resume(&self) -> anyhow::Result<usize> {
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

    pub fn add_breakpoint(
        &self,
        address: usize,
        condition: Condition,
        size: Size,
    ) -> anyhow::Result<Breakpoint> {
        let mut context = self.get_context()?;
        let index = (0..4)
            .find(|&i| (context.Dr7 & (0b11 << (i * 2))) == 0)
            .ok_or_else(|| {
                anyhow::anyhow!("no available hardware breakpoint, max 4 breakpoints")
            })?;
        let address = address as u64;
        match index {
            0 => context.Dr0 = address,
            1 => context.Dr1 = address,
            2 => context.Dr2 = address,
            3 => context.Dr3 = address,
            _ => unreachable!(),
        }
        let clear_mask = !((0b1111 << (16 + index * 4)) | (0b11 << (index * 2)));
        context.Dr7 &= clear_mask;

        context.Dr7 |= 0b1 << (index * 2);

        let sc = (((size as u8) << 2) | (condition as u8)) as u64;
        context.Dr7 |= sc << (16 + index * 4);
        self.set_context(context)?;
        Ok(Breakpoint {
            thread: self,
            index,
            clear_mask,
        })
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

impl Drop for Breakpoint<'_> {
    fn drop(&mut self) {
        let did_suspend = self.thread.suspend().is_ok();
        match self.thread.get_context() {
            Ok(mut context) => {
                match self.index {
                    0 => context.Dr0 = 0,
                    1 => context.Dr1 = 0,
                    2 => context.Dr2 = 0,
                    3 => context.Dr3 = 0,
                    _ => unreachable!(),
                }
                context.Dr7 &= self.clear_mask;
                if let Err(e) = self.thread.set_context(context) {
                    eprintln!("Failed to clear breakpoint: {e}");
                }
            }
            Err(e) => eprintln!("Failed to get context to clear breakpoint: {e}"),
        }
        if did_suspend {
            drop(self.thread.resume());
        }
    }
}
