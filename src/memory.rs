use std::ops::Range;

pub enum Value {
    Exact(i32),
    Any(Vec<u8>),
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

pub struct Region {
    pub info: winapi::um::winnt::MEMORY_BASIC_INFORMATION,
    pub locations: CandidateLocations,
    pub value: Value,
}

impl Region {
    pub fn iter_location<'a>(
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
