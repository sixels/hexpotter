use std::fmt::Display;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PatternId(pub usize);

impl PatternId {
    pub fn new(id: usize) -> Self {
        PatternId(id)
    }

    pub fn usize(&self) -> usize {
        self.0 as usize
    }
}

impl Display for PatternId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "#{}", self.0)
    }
}
