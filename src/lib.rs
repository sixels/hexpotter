use crate::engine::{LookupEngine, MatchedPattern, Scan, anchor::Anchor};

pub mod engine;
pub mod pattern;

/// A high-performance, multi-pattern binary scanner that automatically selects
/// the optimal search algorithm based on available CPU features.
pub struct Hexpotter {
    engine: Box<dyn engine::LookupEngine>,
}

impl Hexpotter {
    /// Creates a new `Hexpotter` instance optimized for the current CPU architecture.
    ///
    /// This constructor performs runtime feature detection to choose the fastest
    /// available engine:
    ///
    /// * **x86_64**: Uses **AVX2** SIMD engine if available.
    /// * **AArch64 / ARM**: Uses **NEON** SIMD engine if available.
    /// * **Fallback**: Defaults to an Aho-Corasick + Anchors based engine if no SIMD
    ///  features are detected.
    ///
    /// # Arguments
    ///
    /// * `patterns` - An iterator of string slices representing the hex patterns
    ///   to compile (e.g., `vec!["FF ?? AA", "E8 ?? ?? ?? ??"]`).
    ///
    /// # Example
    ///
    /// ```rust
    /// let scanner = Hexpotter::new([
    ///     "48 89 5C 24 08",
    ///     "E8 ?? ?? ?? ?? 48 89 44 24",
    /// ]);
    /// ```
    pub fn new<'s, I>(patterns: I) -> Self
    where
        I: IntoIterator<Item = &'s str>,
    {
        // choose the best engine based on the current architecture and features.
        #[cfg(target_arch = "x86_64")]
        if is_x86_feature_detected!("avx2") {
            use crate::engine::teddy::Teddy;

            return Self {
                engine: Box::new(Teddy::new(patterns)),
            };
        }

        #[cfg(target_arch = "aarch64")]
        {
            use crate::engine::teddy::Teddy;

            return Self {
                engine: Box::new(Teddy::new(patterns)),
            };
        }

        #[cfg(target_arch = "arm")]
        {
            use crate::engine::teddy::Teddy;

            return Self {
                engine: Box::new(Teddy::new(patterns)),
            };
        }

        #[allow(unreachable_code)]
        Self {
            engine: Box::new(Anchor::new(patterns)),
        }
    }

    /// Scans the provided byte slice for occurrences of the compiled patterns.
    ///
    /// When a match is found, the provided closure `on_match` is called with details
    /// about the match (Pattern ID and offset). The closure must return a `Scan` enum
    /// to control the scanning process (e.g., continue searching or stop).
    ///
    /// # Arguments
    ///
    /// * `data` - The binary data to scan.
    /// * `on_match` - A closure that receives a `MatchedPattern`. Returning
    ///   `Scan::Continue` will resume scanning; returning `Scan::Stop` will stop immediately.
    ///
    /// # Example
    ///
    /// ```rust
    /// scanner.scan(&binary_data, |match_ctx| {
    ///     println!("Found pattern {} at offset 0x{:X}", match_ctx.id, match_ctx.offset);
    ///     Scan::Continue
    /// });
    /// ```
    pub fn scan<F>(&self, data: &[u8], mut on_match: F)
    where
        F: FnMut(MatchedPattern) -> Scan,
    {
        self.engine.scan(data, &mut on_match);
    }
}
