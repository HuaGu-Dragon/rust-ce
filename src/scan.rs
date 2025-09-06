use std::{
    cmp::Ordering,
    io::{Write, stdout},
    str::FromStr,
};

use crate::memory::{CandidateLocations, Region, Value};

/// # Safety
///
/// The implementer of this trait must ensure that the returned memory slice is valid for the lifetime of use
/// and that any operations performed via the associated scan mode do not violate memory safety.
pub unsafe trait Scannable {
    fn mem_view(&self) -> &[u8];

    fn scan_mode(&self) -> ScanMode;
}

#[derive(Clone, Copy)]
pub struct ScanMode {
    eq: unsafe fn(left: &[u8], right: &[u8]) -> bool,

    cmp: unsafe fn(left: &[u8], right: &[u8]) -> Ordering,

    sub: unsafe fn(left: &mut [u8], right: &[u8]),

    rsub: unsafe fn(left: &mut [u8], right: &[u8]),
}

unsafe impl<T: AsRef<dyn Scannable>> Scannable for T {
    fn mem_view(&self) -> &[u8] {
        self.as_ref().mem_view()
    }

    fn scan_mode(&self) -> ScanMode {
        self.as_ref().scan_mode()
    }
}

#[derive(Clone, Copy)]
pub enum Scan<T: Scannable> {
    Exact(T),
    Unknown(usize, ScanMode),
    Unchanged(usize, ScanMode),
    Changed(usize, ScanMode),
    Decreased(usize, ScanMode),
    Increased(usize, ScanMode),
    DecreasedBy(T),
    IncreasedBy(T),
    Range(T, T),
}

impl FromStr for Scan<Box<dyn Scannable>> {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        enum Ty {
            U8,
            U16,
            U32,
            U64,
            U128,
            I8,
            I16,
            I32,
            I64,
            I128,
            F32,
            F64,
        }

        impl FromStr for Ty {
            type Err = anyhow::Error;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(match s {
                    "u8" | "U8" => Ty::U8,
                    "u16" | "U16" => Ty::U16,
                    "u32" | "U32" => Ty::U32,
                    "u64" | "U64" => Ty::U64,
                    "u128" | "U128" => Ty::U128,
                    "i8" | "I8" => Ty::I8,
                    "i16" | "I16" => Ty::I16,
                    "i32" | "I32" => Ty::I32,
                    "i64" | "I64" => Ty::I64,
                    "i128" | "I128" => Ty::I128,
                    "f32" | "F32" => Ty::F32,
                    "f64" | "F64" => Ty::F64,
                    _ => return Err(anyhow::anyhow!("Unknown type: {}", s)),
                })
            }
        }

        impl Ty {
            fn parse(&self, value: &str) -> anyhow::Result<Box<dyn Scannable>> {
                Ok(match self {
                    Ty::U8 => Box::new(value.parse::<u8>()?),
                    Ty::U16 => Box::new(value.parse::<u16>()?),
                    Ty::U32 => Box::new(value.parse::<u32>()?),
                    Ty::U64 => Box::new(value.parse::<u64>()?),
                    Ty::U128 => Box::new(value.parse::<u128>()?),
                    Ty::I8 => Box::new(value.parse::<i8>()?),
                    Ty::I16 => Box::new(value.parse::<i16>()?),
                    Ty::I32 => Box::new(value.parse::<i32>()?),
                    Ty::I64 => Box::new(value.parse::<i64>()?),
                    Ty::I128 => Box::new(value.parse::<i128>()?),
                    Ty::F32 => Box::new(value.parse::<f32>()?),
                    Ty::F64 => Box::new(value.parse::<f64>()?),
                })
            }

            fn size(&self) -> usize {
                match self {
                    Ty::U8 | Ty::I8 => 1,
                    Ty::U16 | Ty::I16 => 2,
                    Ty::U32 | Ty::I32 | Ty::F32 => 4,
                    Ty::U64 | Ty::I64 | Ty::F64 => 8,
                    Ty::U128 | Ty::I128 => 16,
                }
            }

            fn mode(&self) -> ScanMode {
                match self {
                    Ty::U8 => (0u8).scan_mode(),
                    Ty::U16 => (0u16).scan_mode(),
                    Ty::U32 => (0u32).scan_mode(),
                    Ty::U64 => (0u64).scan_mode(),
                    Ty::U128 => (0u128).scan_mode(),
                    Ty::I8 => (0i8).scan_mode(),
                    Ty::I16 => (0i16).scan_mode(),
                    Ty::I32 => (0i32).scan_mode(),
                    Ty::I64 => (0i64).scan_mode(),
                    Ty::I128 => (0i128).scan_mode(),
                    Ty::F32 => (0f32).scan_mode(),
                    Ty::F64 => (0f64).scan_mode(),
                }
            }
        }

        let (value, ty) = if let Some((value, ty)) = s.split_once(':') {
            let value = value.trim();
            let ty = ty.trim().parse::<Ty>()?;

            (value, ty)
        } else {
            let value = s.trim();
            (value, Ty::I32)
        };

        Ok(match value.as_bytes()[0] {
            b'u' | b'U' => Scan::Unknown(ty.size(), ty.mode()),
            b'd' | b'D' => {
                let n = &value[1..];
                if n.is_empty() {
                    Scan::Decreased(ty.size(), ty.mode())
                } else {
                    let n = ty.parse(n)?;
                    Scan::DecreasedBy(n)
                }
            }
            b'i' | b'I' => {
                let n = &value[1..];
                if n.is_empty() {
                    Scan::Increased(ty.size(), ty.mode())
                } else {
                    let n = ty.parse(n)?;
                    Scan::IncreasedBy(n)
                }
            }
            b'=' => Scan::Unchanged(ty.size(), ty.mode()),
            b'~' => Scan::Changed(ty.size(), ty.mode()),
            _ => {
                if let Some((low, high)) = value.split_once("..=") {
                    let low = ty.parse(low.trim())?;
                    let high = ty.parse(high.trim())?;
                    Scan::Range(low, high)
                } else {
                    let n = ty.parse(value)?;
                    Scan::Exact(n)
                }
            }
        })
    }
}

pub fn build() -> anyhow::Result<Scan<Box<dyn Scannable>>> {
    let mut input = String::new();

    let scan = loop {
        write!(stdout(), "scan (? for help) > ")?;
        std::io::Write::flush(&mut std::io::stdout())?;
        input.clear();

        std::io::stdin().read_line(&mut input)?;
        let trimmed = input.trim();

        if trimmed.is_empty() {
            writeln!(stdout(), "Please enter a value")?;
        } else if trimmed == "?" {
            let mut stdout = stdout().lock();
            writeln!(stdout, "Help:")?;
            writeln!(stdout, "|  (value type): exact value scan")?;
            writeln!(stdout, "|  u: unknown value")?;
            writeln!(stdout, "|  =: unchanged value")?;
            writeln!(stdout, "|  ~: changed value")?;
            writeln!(stdout, "|  d(? value): decreased value")?;
            writeln!(stdout, "|  i(? value): increased value")?;
            writeln!(stdout, "|  low..=high: range scan")?;
        } else {
            match trimmed.parse() {
                Ok(value) => break value,
                Err(e) => writeln!(std::io::stdout(), "Invalid input: {e}")?,
            }
        }
    };
    Ok(scan)
}

pub fn write() -> anyhow::Result<Scan<Box<dyn Scannable>>> {
    let mut input = String::new();

    let scan = loop {
        write!(stdout(), "New Value > ")?;
        std::io::Write::flush(&mut std::io::stdout())?;
        input.clear();

        std::io::stdin().read_line(&mut input)?;
        let trimmed = input.trim();
        if trimmed.is_empty() {
            writeln!(stdout(), "Please enter a value")?;
        } else {
            match trimmed.parse() {
                Ok(value) => break value,
                Err(e) => writeln!(std::io::stdout(), "Invalid input: {e}")?,
            }
        }
    };

    Ok(scan)
}

impl<T: Scannable> Scan<T> {
    pub fn run(
        &self,
        info: winapi::um::winnt::MEMORY_BASIC_INFORMATION,
        memory: Vec<u8>,
    ) -> Option<Region> {
        let base = info.BaseAddress as usize;
        match self {
            scan @ (Scan::Exact(n) | Scan::Range(n, _)) => {
                let target = n.mem_view();
                let locations: Vec<usize> = memory
                    .chunks_exact(target.len())
                    .enumerate()
                    .filter_map(|(offset, chunk)| {
                        if self.acceptable(chunk, chunk) {
                            Some(base + offset * target.len())
                        } else {
                            None
                        }
                    })
                    .collect();
                if locations.is_empty() {
                    return None;
                }
                Some(Region {
                    info,
                    locations: CandidateLocations::Discrete { locations },
                    value: if matches!(scan, Scan::Exact(_)) {
                        Value::Exact(target.to_vec())
                    } else {
                        Value::Any {
                            memory,
                            size: target.len(),
                        }
                    },
                })
            }
            Scan::Unknown(size, _) => Some(Region {
                info,
                locations: CandidateLocations::Dense {
                    range: base..base + info.RegionSize,
                    step: *size,
                },
                value: Value::Any {
                    memory,
                    size: *size,
                },
            }),
            Scan::DecreasedBy(_)
            | Scan::IncreasedBy(_)
            | Scan::Decreased(_, _)
            | Scan::Increased(_, _)
            | Scan::Unchanged(_, _)
            | Scan::Changed(_, _) => None,
        }
    }
    pub fn rerun(&self, region: &mut Region, memory: Vec<u8>) -> bool {
        match self {
            Scan::Unknown(_, _) => true,
            scan => {
                region.locations.retain_mut(|addr| {
                    let offset = addr - region.info.BaseAddress as usize;
                    let bytes = &memory[offset..];
                    let old = Region::value_at(offset, &region.value);
                    let new = &bytes[..scan.size()];
                    self.acceptable(old, new)
                });
                if region.locations.is_empty() {
                    false
                } else {
                    region.value = Value::Any {
                        memory,
                        size: scan.size(),
                    };
                    true
                }
            }
        }
    }

    pub fn size(&self) -> usize {
        match self {
            Scan::Exact(n) | Scan::DecreasedBy(n) | Scan::IncreasedBy(n) | Scan::Range(n, _) => {
                n.mem_view().len()
            }
            Scan::Unknown(size, _)
            | Scan::Changed(size, _)
            | Scan::Unchanged(size, _)
            | Scan::Decreased(size, _)
            | Scan::Increased(size, _) => *size,
        }
    }

    pub fn acceptable(&self, old: &[u8], new: &[u8]) -> bool {
        unsafe {
            match self {
                Scan::Exact(n) => (n.scan_mode().eq)(n.mem_view(), new),
                Scan::Unknown(_, _) => true,
                Scan::Decreased(_, mode) => (mode.cmp)(old, new) == Ordering::Greater,
                Scan::Increased(_, mode) => (mode.cmp)(old, new) == Ordering::Less,
                Scan::Unchanged(_, mode) => (mode.eq)(old, new),
                Scan::Changed(_, mode) => !(mode.eq)(old, new),
                Scan::Range(low, high) => {
                    let mode = low.scan_mode();
                    let (low, high) = (low.mem_view(), high.mem_view());
                    (mode.cmp)(low, new) != Ordering::Greater
                        && (mode.cmp)(high, new) != Ordering::Less
                }
                Scan::DecreasedBy(amount) => {
                    let mode = amount.scan_mode();
                    let mut delta = old.to_vec();
                    (mode.sub)(delta.as_mut(), new);
                    (mode.eq)(amount.mem_view(), delta.as_ref())
                }
                Scan::IncreasedBy(amount) => {
                    let mode = amount.scan_mode();
                    let mut delta = old.to_vec();
                    (mode.rsub)(delta.as_mut(), new);
                    (mode.eq)(amount.mem_view(), delta.as_ref())
                }
            }
        }
    }
}

macro_rules! impl_scan_for_int {
    ( $( $ty:ty ),* ) => {
        $(
            unsafe impl Scannable for $ty {
                fn mem_view(&self) -> &[u8] {
                    unsafe {
                        std::slice::from_raw_parts(
                            self as *const _ as *const u8,
                            std::mem::size_of::<$ty>(),
                        )
                    }
                }

                fn scan_mode(&self) -> ScanMode {
                    unsafe fn eq(left: &[u8], right: &[u8]) -> bool {
                        let lhs = unsafe { left.as_ptr().cast::<$ty>().read_unaligned() };
                        let rhs = unsafe { right.as_ptr().cast::<$ty>().read_unaligned() };
                        lhs == rhs
                    }

                    unsafe fn cmp(left: &[u8], right: &[u8]) -> Ordering {
                        let lhs = unsafe { left.as_ptr().cast::<$ty>().read_unaligned() };
                        let rhs = unsafe { right.as_ptr().cast::<$ty>().read_unaligned() };
                        Ord::cmp(&lhs, &rhs)
                    }

                    unsafe fn sub(left: &mut [u8], right: &[u8]) {
                        let left = left.as_mut_ptr().cast::<$ty>();
                        let lhs = unsafe { left.read_unaligned() };
                        let rhs = unsafe { right.as_ptr().cast::<$ty>().read_unaligned() };
                        unsafe { left.write_unaligned(lhs.wrapping_sub(rhs)) }
                    }

                    unsafe fn rsub(left: &mut [u8], right: &[u8]) {
                        let left = left.as_mut_ptr().cast::<$ty>();
                        let lhs = unsafe { left.read_unaligned() };
                        let rhs = unsafe { right.as_ptr().cast::<$ty>().read_unaligned() };
                        unsafe { left.write_unaligned(rhs.wrapping_sub(lhs)) }
                    }

                    ScanMode { eq, cmp, sub, rsub }
                }
            }
        )*
    };
}

macro_rules! impl_scan_for_float {
    ( $( $ty:ty : $int_ty:ty ),* ) => {
        $(
            unsafe impl Scannable for $ty {
                fn mem_view(&self) -> &[u8] {
                    unsafe { std::slice::from_raw_parts(self as *const _ as *const u8, std::mem::size_of::<$ty>()) }
                }

                fn scan_mode(&self) -> ScanMode {
                    unsafe fn eq(left: &[u8], right: &[u8]) -> bool {
                        const MASK: $int_ty = !((1 << (<$ty>::MANTISSA_DIGITS / 2)) - 1);

                        let lhs = unsafe { left.as_ptr().cast::<$ty>().read_unaligned() };
                        let rhs = unsafe { right.as_ptr().cast::<$ty>().read_unaligned() };
                        let lhs = <$ty>::from_bits(lhs.to_bits() & MASK);
                        let rhs = <$ty>::from_bits(rhs.to_bits() & MASK);
                        lhs == rhs
                    }

                    unsafe fn cmp(left: &[u8], right: &[u8]) -> Ordering {
                        let lhs = unsafe { left.as_ptr().cast::<$ty>().read_unaligned() };
                        let rhs = unsafe { right.as_ptr().cast::<$ty>().read_unaligned() };
                        lhs.partial_cmp(&rhs).unwrap_or(Ordering::Less)
                    }

                    unsafe fn sub(left: &mut [u8], right: &[u8]) {
                        let left = left.as_mut_ptr().cast::<$ty>();
                        let lhs = unsafe { left.read_unaligned() };
                        let rhs = unsafe { right.as_ptr().cast::<$ty>().read_unaligned() };
                        unsafe { left.write_unaligned(lhs - rhs) }
                    }

                    unsafe fn rsub(left: &mut [u8], right: &[u8]) {
                        let left = left.as_mut_ptr().cast::<$ty>();
                        let lhs = unsafe { left.read_unaligned() };
                        let rhs = unsafe { right.as_ptr().cast::<$ty>().read_unaligned() };
                        unsafe { left.write_unaligned(rhs - lhs) }
                    }

                    ScanMode { eq, cmp, sub, rsub }
                }
            }
        )*
    };
}

impl_scan_for_int!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128);
impl_scan_for_float!(f32: u32, f64: u64);
