use std::ops::Range;

pub enum Value {
    Exact(Vec<u8>),
    Any { memory: Vec<u8>, size: usize },
}
pub enum CandidateLocations {
    Discrete { locations: Vec<usize> },
    Dense { range: Range<usize>, step: usize },
}

impl CandidateLocations {
    pub fn len(&self) -> usize {
        match self {
            CandidateLocations::Discrete { locations } => locations.len(),
            CandidateLocations::Dense { range, .. } => range.len(),
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
            CandidateLocations::Dense { range, step } => {
                let locations = range
                    .step_by(*step)
                    .filter(|addr| f(addr))
                    .collect::<Vec<_>>();
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
            CandidateLocations::Dense { range, step } => LocationIter {
                iter: Box::new(range.clone().step_by(*step)),
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
    pub fn value_at(offset: usize, value: &Value) -> &[u8] {
        match value {
            Value::Exact(v) => v,
            Value::Any { memory, size } => &memory[offset..offset + size],
        }
    }
}
