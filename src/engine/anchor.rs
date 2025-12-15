use aho_corasick::{AhoCorasick, AhoCorasickKind, Match};
use std::collections::HashMap;

use crate::{
    engine::{
        LookupEngine, MatchedPattern, Scan,
        common::{self, PatternInfo},
    },
    pattern::PatternId,
};

pub struct Anchor {
    ac: AhoCorasick,
    pattern_map: HashMap<usize, Vec<PatternInfo>>,
    all_values: Vec<u8>,
    all_masks: Vec<u8>,
}

impl LookupEngine for Anchor {
    fn new<'s, I>(patterns: I) -> Self
    where
        Self: Sized,
        I: IntoIterator<Item = &'s str>,
    {
        let mut anchors = Vec::new();
        let mut pattern_map: HashMap<usize, Vec<PatternInfo>> = HashMap::new();

        let mut all_values = Vec::new();
        let mut all_masks = Vec::new();

        for (index, pattern_str) in patterns.into_iter().enumerate() {
            let (p_values, p_masks) = common::parse_hex_pattern(pattern_str);
            let (anchor, offset) = common::find_best_anchor(&p_values, &p_masks);

            // Deduplicate Anchors
            let ac_id = anchors
                .iter()
                .position(|x| x == &anchor)
                .unwrap_or_else(|| {
                    anchors.push(anchor.clone());
                    anchors.len() - 1
                });

            let data_offset = all_values.len();
            let len = p_values.len();
            all_values.extend_from_slice(&p_values);
            all_masks.extend_from_slice(&p_masks);

            let pat = PatternInfo {
                id: index,
                data_offset,
                len,
                anchor_offset: offset,
            };

            pattern_map.entry(ac_id).or_default().push(pat);
        }

        let ac = AhoCorasick::builder()
            .kind(Some(AhoCorasickKind::DFA))
            .build(&anchors)
            .expect("Failed to build Aho-Corasick");

        Anchor {
            ac,
            pattern_map,
            all_values,
            all_masks,
        }
    }

    fn scan(&self, data: &[u8], on_match: &mut dyn FnMut(MatchedPattern) -> Scan) {
        for mat in self.ac.find_overlapping_iter(data) {
            let ac_id = mat.pattern().as_usize();

            if let Some(candidates) = self.pattern_map.get(&ac_id) {
                for pat in candidates {
                    if self.verify_match(data, &mat, pat, on_match) == Scan::Stop {
                        return;
                    }
                }
            }
        }
    }
}

impl Anchor {
    #[inline(always)]
    fn verify_match<F>(
        &self,
        data: &[u8],
        anchor_match: &Match,
        pat: &PatternInfo,
        on_match: &mut F,
    ) -> Scan
    where
        F: FnMut(MatchedPattern) -> Scan + ?Sized,
    {
        let match_start = anchor_match.start();

        // bounds Checks
        if match_start < pat.anchor_offset {
            return Scan::Continue;
        }
        let start_index = match_start - pat.anchor_offset;
        let end_index = start_index + pat.len;
        if end_index > data.len() {
            return Scan::Continue;
        }

        let data_slice = &data[start_index..end_index];
        let pat_vals = &self.all_values[pat.data_offset..pat.data_offset + pat.len];
        let pat_masks = &self.all_masks[pat.data_offset..pat.data_offset + pat.len];

        let mut is_match = true;

        for i in 0..pat.len {
            if (data_slice[i] & pat_masks[i]) != pat_vals[i] {
                is_match = false;
                break;
            }
        }

        if is_match {
            return on_match(MatchedPattern {
                start: start_index,
                end: end_index,
                pattern_id: PatternId(pat.id),
            });
        }

        Scan::Continue
    }
}
