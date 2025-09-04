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

    pub fn iter(&self) -> LocationIter {
        self.into_iter()
    }
}

impl<'a> IntoIterator for &'a CandidateLocations {
    type Item = usize;

    type IntoIter = LocationIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            CandidateLocations::Discrete { locations } => LocationIter {
                iter: Box::new(locations.iter().map(|&x| x)),
            },
            CandidateLocations::Dense { range } => LocationIter {
                iter: Box::new(range.clone().step_by(4)),
            },
        }
    }
}

impl IntoIterator for CandidateLocations {
    type Item = usize;

    type IntoIter = LocationIter<'static>;

    fn into_iter(self) -> Self::IntoIter {
        match self {
            CandidateLocations::Discrete { locations } => LocationIter {
                iter: Box::new(locations.into_iter()),
            },
            CandidateLocations::Dense { range } => LocationIter {
                iter: Box::new(range.into_iter().step_by(4)),
            },
        }
    }
}
pub struct LocationIter<'a> {
    iter: Box<dyn Iterator<Item = usize> + 'a>,
}

impl<'a> Iterator for LocationIter<'a> {
    type Item = usize;

    fn next(&mut self) -> Option<Self::Item> {
        self.iter.next()
    }
}

pub struct Region {
    pub info: winapi::um::winnt::MEMORY_BASIC_INFORMATION,
    pub locations: CandidateLocations,
    pub value: Value,
}

impl Region {
    // pub fn iter_location<'a>(
    //     &'a self,
    //     memory: &'a [u8],
    // ) -> Box<dyn Iterator<Item = (usize, i32, i32)> + 'a> {
    //     match &self.locations {
    //         CandidateLocations::Discrete { locations } => Box::new(locations.iter().map(|&addr| {
    //             let old = self.value_at(addr);
    //             let base = addr - self.info.BaseAddress as usize;
    //             let bytes = &memory[base..base + 4];
    //             (
    //                 addr,
    //                 old,
    //                 i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
    //             )
    //         })),
    //         CandidateLocations::Dense { range } => Box::new(range.clone().step_by(4).map(|addr| {
    //             let old = self.value_at(addr);

    //             let base = addr - self.info.BaseAddress as usize;
    //             let bytes = &memory[base..base + 4];

    //             let new = i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);

    //             (addr, old, new)
    //         })),
    //     }
    // }

    pub fn value_at(addr: usize, value: &Value) -> i32 {
        match value {
            Value::Exact(v) => *v,
            Value::Any(chunk) => {
                let bytes = &chunk[addr..addr + 4];
                i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            }
        }
    }
}
