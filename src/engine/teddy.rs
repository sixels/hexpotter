#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::*;

#[cfg(target_arch = "aarch64")]
use std::arch::aarch64::*;

#[cfg(target_arch = "arm")]
use std::arch::arm::*;

use std::collections::HashMap;

use crate::{
    engine::{
        LookupEngine, MatchedPattern, Scan,
        common::{self, PatternInfo},
    },
    pattern::PatternId,
};

pub struct Teddy {
    buckets: Vec<Bucket>,
    all_values: Vec<u8>,
    all_masks: Vec<u8>,
}

impl LookupEngine for Teddy {
    fn new<'s, I>(patterns: I) -> Self
    where
        Self: Sized,
        I: IntoIterator<Item = &'s str>,
    {
        let mut all_values = Vec::new();
        let mut all_masks = Vec::new();
        let mut groups: HashMap<Vec<u8>, Vec<PatternInfo>> = HashMap::new();

        for (id, pat_str) in patterns.into_iter().enumerate() {
            let (values, masks) = common::parse_hex_pattern(pat_str);
            let (anchor, anchor_off) = common::find_best_anchor(&values, &masks);

            let key_len = anchor.len().min(3);
            let key = anchor[0..key_len].to_vec();

            let data_offset = all_values.len();
            let len = values.len();
            all_values.extend_from_slice(&values);
            all_masks.extend_from_slice(&masks);

            groups.entry(key).or_default().push(PatternInfo {
                id,
                len,
                data_offset,
                anchor_offset: anchor_off,
            });
        }

        let mut buckets = Vec::new();
        for (key, patterns) in groups {
            buckets.push(Teddy::build_bucket(key, patterns));
        }

        Teddy {
            buckets,
            all_values,
            all_masks,
        }
    }

    fn scan(&self, data: &[u8], on_match: &mut dyn FnMut(MatchedPattern) -> Scan) {
        #[cfg(target_arch = "x86_64")]
        {
            if is_x86_feature_detected!("avx2") {
                unsafe {
                    self.scan_avx2(data, on_match);
                    return;
                }
            }
        }

        #[cfg(target_arch = "aarch64")]
        unsafe {
            self.scan_neon(data, on_match);
            return;
        }

        #[cfg(target_arch = "arm")]
        unsafe {
            self.scan_neon_arm32(data, &mut on_match);
            return;
        }

        self.scan_slow(data, 0, on_match);
    }
}

impl Teddy {
    #[cfg(target_arch = "x86_64")]
    fn build_bucket(key: Vec<u8>, patterns: Vec<PatternInfo>) -> Bucket {
        unsafe {
            let f0 = Some(_mm256_set1_epi8(key[0] as i8));
            let f1 = (key.len() >= 2).then(|| _mm256_set1_epi8(key[1] as i8));
            let f2 = (key.len() >= 3).then(|| _mm256_set1_epi8(key[2] as i8));

            Bucket {
                fingerprint_avx: [f0, f1, f2],
                fingerprint_bytes: key,
                patterns,
            }
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn build_bucket(key: Vec<u8>, patterns: Vec<PatternInfo>) -> Bucket {
        unsafe {
            let f0 = Some(vdupq_n_u8(key[0]));
            let f1 = if key.len() >= 2 {
                Some(vdupq_n_u8(key[1]))
            } else {
                None
            };
            let f2 = if key.len() >= 3 {
                Some(vdupq_n_u8(key[2]))
            } else {
                None
            };

            Bucket {
                fingerprint_neon: [f0, f1, f2],
                fingerprint_bytes: key,
                patterns,
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    #[target_feature(enable = "avx2")]
    unsafe fn scan_avx2<F>(&self, data: &[u8], on_match: &mut F)
    where
        F: FnMut(MatchedPattern) -> Scan + ?Sized,
    {
        let len = data.len();
        // limit: 32 bytes (vector) + 2 bytes
        if len < 34 {
            self.scan_slow(data, 0, on_match);
            return;
        }

        // align the limit to 32-byte boundaries to keep SIMD and scalar synchronized
        // we stop SIMD 34 bytes before end to be safe.
        let safe_limit = len - 34;
        let aligned_limit = safe_limit & !0x1F; // floor to multiple of 32

        for bucket in &self.buckets {
            let fp = bucket.fingerprint_avx;
            let mut i = 0;
            while i <= aligned_limit {
                unsafe {
                    let ptr = data.as_ptr().add(i);

                    let block_0 = _mm256_loadu_si256(ptr as *const _);
                    let mut candidates = _mm256_cmpeq_epi8(block_0, fp[0].unwrap());

                    if let Some(reg_b1) = fp[1] {
                        let block_1 = _mm256_loadu_si256(ptr.add(1) as *const _);
                        let cmp = _mm256_cmpeq_epi8(block_1, reg_b1);
                        candidates = _mm256_and_si256(candidates, cmp);
                    }

                    if let Some(reg_b2) = fp[2] {
                        let block_2 = _mm256_loadu_si256(ptr.add(2) as *const _);
                        let cmp = _mm256_cmpeq_epi8(block_2, reg_b2);
                        candidates = _mm256_and_si256(candidates, cmp);
                    }

                    let mask = _mm256_movemask_epi8(candidates) as u32;

                    if mask != 0 {
                        let mut bits = mask;
                        while bits != 0 {
                            let bit_idx = bits.trailing_zeros() as usize;
                            let match_pos = i + bit_idx;
                            if !self.verify_bucket_patterns(data, match_pos, bucket, on_match) {
                                return;
                            }
                            bits &= bits - 1;
                        }
                    }
                    i += 32;
                }
            }
        }

        self.scan_slow(data, aligned_limit + 32, on_match);
    }

    #[cfg(any(target_arch = "aarch64"))]
    unsafe fn scan_neon(&self, data: &[u8], on_match: &mut impl FnMut((usize, usize)) -> bool) {
        let len = data.len();
        // limit: 16 bytes (vector) + 2 bytes
        if len < 18 {
            self.scan_slow(data, 0, on_match);
            return;
        }

        // align to 16-byte boundary
        let safe_limit = len - 18;
        let aligned_limit = safe_limit & !0xF;

        for bucket in &self.buckets {
            let fp = bucket.fingerprint_neon;
            let mut i = 0;
            while i <= aligned_limit {
                unsafe {
                    let ptr = data.as_ptr().add(i);

                    let block_0 = vld1q_u8(ptr);
                    let mut candidates = vceqq_u8(block_0, fp[0].unwrap());

                    if let Some(reg_b1) = fp[1] {
                        let block_1 = vld1q_u8(ptr.add(1));
                        let cmp = vceqq_u8(block_1, reg_b1);
                        candidates = vandq_u8(candidates, cmp);
                    }

                    if let Some(reg_b2) = fp[2] {
                        let block_2 = vld1q_u8(ptr.add(2));
                        let cmp = vceqq_u8(block_2, reg_b2);
                        candidates = vandq_u8(candidates, cmp);
                    }

                    if vmaxvq_u8(candidates) != 0 {
                        let mut res_arr = [0u8; 16];
                        vst1q_u8(res_arr.as_mut_ptr(), candidates);
                        for k in 0..16 {
                            if res_arr[k] == 0xFF {
                                let match_pos = i + k;
                                if !self.verify_bucket_patterns(data, match_pos, bucket, on_match) {
                                    return;
                                }
                            }
                        }
                    }
                    i += 16;
                }
            }
        }

        self.scan_slow(data, aligned_limit + 16, on_match);
    }

    #[cfg(target_arch = "arm")]
    #[target_feature(enable = "neon")]
    unsafe fn scan_neon_arm32(
        &self,
        data: &[u8],
        on_match: &mut impl FnMut((usize, usize)) -> bool,
    ) {
        let len = data.len();
        if len < 18 {
            self.scan_slow(data, 0, on_match);
            return;
        }

        let safe_limit = len - 18;
        let aligned_limit = safe_limit & !0xF;

        for bucket in &self.buckets {
            let fp = bucket.fingerprint_neon;
            let mut i = 0;
            while i <= aligned_limit {
                unsafe {
                    let ptr = data.as_ptr().add(i);

                    let block_0 = vld1q_u8(ptr);
                    let mut candidates = vceqq_u8(block_0, fp[0].unwrap());

                    if let Some(reg_b1) = fp[1] {
                        let block_1 = vld1q_u8(ptr.add(1));
                        let cmp = vceqq_u8(block_1, reg_b1);
                        candidates = vandq_u8(candidates, cmp);
                    }

                    if let Some(reg_b2) = fp[2] {
                        let block_2 = vld1q_u8(ptr.add(2));
                        let cmp = vceqq_u8(block_2, reg_b2);
                        candidates = vandq_u8(candidates, cmp);
                    }

                    if self.neon_has_match_arm32(candidates) {
                        let mut res_arr = [0u8; 16];
                        vst1q_u8(res_arr.as_mut_ptr(), candidates);
                        for k in 0..16 {
                            if res_arr[k] == 0xFF {
                                let match_pos = i + k;
                                if !self.verify_bucket_patterns(data, match_pos, bucket, on_match) {
                                    return;
                                }
                            }
                        }
                    }
                    i += 16;
                }
            }
        }
        self.scan_slow(data, aligned_limit + 16, on_match);
    }

    #[cfg(target_arch = "arm")]
    #[inline(always)]
    unsafe fn neon_has_match_arm32(&self, v: uint8x16_t) -> bool {
        unsafe {
            let u32s: uint32x4_t = std::mem::transmute(v);
            let t1 = vgetq_lane_u32(u32s, 0);
            let t2 = vgetq_lane_u32(u32s, 1);
            let t3 = vgetq_lane_u32(u32s, 2);
            let t4 = vgetq_lane_u32(u32s, 3);
            (t1 | t2 | t3 | t4) != 0
        }
    }

    fn scan_slow<F>(&self, data: &[u8], start_offset: usize, on_match: &mut F)
    where
        F: FnMut(MatchedPattern) -> Scan + ?Sized,
    {
        let len = data.len();
        if start_offset >= len {
            return;
        }

        for i in start_offset..len {
            for bucket in &self.buckets {
                let fp = &bucket.fingerprint_bytes;
                if i + fp.len() > len {
                    continue;
                }

                if &data[i..i + fp.len()] == fp.as_slice() {
                    if !self.verify_bucket_patterns(data, i, bucket, on_match) {
                        return;
                    }
                }
            }
        }
    }

    #[inline(always)]
    fn verify_bucket_patterns<F>(
        &self,
        data: &[u8],
        anchor_pos: usize,
        bucket: &Bucket,
        on_match: &mut F,
    ) -> bool
    where
        F: FnMut(MatchedPattern) -> Scan + ?Sized,
    {
        for pat in &bucket.patterns {
            if anchor_pos < pat.anchor_offset {
                continue;
            }
            let start = anchor_pos - pat.anchor_offset;
            let end = start + pat.len;
            if end > data.len() {
                continue;
            }

            let mut is_match = true;
            for k in 0..pat.len {
                let val = self.all_values[pat.data_offset + k];
                let mask = self.all_masks[pat.data_offset + k];
                if (data[start + k] & mask) != val {
                    is_match = false;
                    break;
                }
            }

            if is_match {
                if on_match(MatchedPattern {
                    pattern_id: PatternId(pat.id),
                    start: start,
                    end: end,
                }) == Scan::Stop
                {
                    return false;
                }
            }
        }
        true
    }
}

struct Bucket {
    #[cfg(target_arch = "x86_64")]
    fingerprint_avx: [Option<__m256i>; 3],
    #[cfg(any(target_arch = "aarch64", target_arch = "arm"))]
    fingerprint_neon: [Option<uint8x16_t>; 3],
    fingerprint_bytes: Vec<u8>,

    patterns: Vec<common::PatternInfo>,
}
