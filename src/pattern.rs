use std::borrow::Cow;

pub struct HexPattern<'p>(pub Cow<'p, str>);

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
