use std::{
    io::{Write, stdout},
    str::FromStr,
};

use crate::memory::{CandidateLocations, Region, Value};

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
                writeln!(stdout, "|  (empty): exact value scan")?;
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

    pub fn run(
        self,
        info: winapi::um::winnt::MEMORY_BASIC_INFORMATION,
        memory: Vec<u8>,
    ) -> Option<Region> {
        let base = info.BaseAddress as usize;
        match self {
            scan @ (Scan::Exact(_) | Scan::Range(_, _)) => {
                let locations = memory
                    .chunks_exact(4)
                    .enumerate()
                    .filter_map(|(offset, chunk)| {
                        let value = i32::from_ne_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
                        if self.acceptable(value, value) {
                            Some(base + offset * 4)
                        } else {
                            None
                        }
                    })
                    .collect();
                Some(Region {
                    info,
                    locations: CandidateLocations::Discrete { locations },
                    value: if let Scan::Exact(v) = scan {
                        Value::Exact(v)
                    } else {
                        Value::Any(memory)
                    },
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
    pub fn rerun(self, region: &mut Region, memory: Vec<u8>) -> bool {
        match self {
            Scan::Unknown => true,
            _ => {
                region.locations.retain_mut(|addr| {
                    let offset = addr - region.info.BaseAddress as usize;
                    let bytes = &memory[offset..offset + 4];
                    let old = Region::value_at(offset, &region.value);
                    let new = i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                    self.acceptable(old, new)
                });
                if region.locations.len() == 0 {
                    false
                } else {
                    region.value = Value::Any(memory);
                    true
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
