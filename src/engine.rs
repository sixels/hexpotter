mod common;

pub(crate) mod anchor;
pub(crate) mod teddy;

use crate::pattern::PatternId;

pub(crate) trait LookupEngine {
    fn new<'s, I>(patterns: I) -> Self
    where
        Self: Sized,
        I: IntoIterator<Item = &'s str>;

    fn scan(&self, data: &[u8], on_match: &mut dyn FnMut(MatchedPattern) -> Scan);
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Scan {
    Continue,
    Stop,
}

#[derive(Clone, Copy)]
pub struct MatchedPattern {
    pub(crate) start: usize,
    pub(crate) end: usize,
    pub(crate) pattern_id: PatternId,
}

impl MatchedPattern {
    #[inline(always)]
    pub fn start(&self) -> usize {
        self.start
    }

    #[inline(always)]
    pub fn end(&self) -> usize {
        self.end
    }

    #[inline(always)]
    pub fn id(&self) -> PatternId {
        self.pattern_id
    }
}
