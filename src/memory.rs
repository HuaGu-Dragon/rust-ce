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

    pub fn retain_mut<F>(&mut self, mut f: F)
    where
        F: FnMut(&usize) -> bool,
    {
        match self {
            CandidateLocations::Discrete { locations } => locations.retain_mut(|addr| f(addr)),
            CandidateLocations::Dense { range } => {
                let locations = range.step_by(4).filter(|addr| f(addr)).collect::<Vec<_>>();
                *self = CandidateLocations::Discrete { locations };
            }
        }
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
    pub fn value_at(offset: usize, value: &Value) -> i32 {
        match value {
            Value::Exact(v) => *v,
            Value::Any(chunk) => {
                let bytes = &chunk[offset..offset + 4];
                i32::from_ne_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
            }
        }
    }
}
