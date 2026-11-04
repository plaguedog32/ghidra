//! Inclusive bit ranges, used for token fields and context fields.

use crate::Size;
use serde::{Deserialize, Serialize};
use std::{cmp, ops::RangeInclusive};

/// An inclusive range of bits
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BitRange {
    start: Size,
    end: Size,
}

impl BitRange {
    /// The start bit of this range
    pub fn start(&self) -> usize {
        self.start as usize
    }

    /// The end bit of this range (inclusive)
    pub fn end(&self) -> usize {
        self.end as usize
    }
}

impl IntoIterator for &BitRange {
    type Item = usize;

    type IntoIter = RangeInclusive<usize>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl BitRange {
    /// Creates a new bitrange spanning `start..=end`.
    ///
    /// # Panics
    ///
    /// `start` must not exceed `end`. A reversed range is not rejected here,
    /// but [`Self::size`] will then panic; callers building a range from a
    /// specification should validate it first and report a diagnostic.
    pub fn new(start: usize, end: usize) -> Self {
        Self {
            start: start as Size,
            end: end as Size,
        }
    }

    /// Creates a new bitrange from a single value
    pub fn singleton(start: usize) -> Self {
        Self {
            start: start as Size,
            end: start as Size,
        }
    }

    /// The number of bits contained in this range.
    ///
    /// # Panics
    ///
    /// Panics if the range was built reversed (`start > end`); see
    /// [`Self::new`].
    pub fn size(&self) -> usize {
        (self.end - self.start + 1) as usize
    }

    /// The mask this range contributes, expressed relative to `range`.
    ///
    /// # Panics
    ///
    /// Panics if `range` is wider than 64 bits, or if the two ranges do not
    /// overlap.
    pub fn mask(&self, range: &BitRange) -> u64 {
        assert!(range.size() <= 64);

        let start = cmp::max(self.start, range.start);
        let end = cmp::min(self.end, range.end);

        let size = end - start + 1;
        let offset = start - range.start;

        let base = if size == 64 {
            u64::MAX
        } else {
            (1u64 << size) - 1
        };

        base << offset
    }

    /// Returns an identical offset that has been shifted by `bit_offset` bits
    pub fn shifted(&self, bit_offset: usize) -> Self {
        Self {
            start: self.start + bit_offset as Size,
            end: self.end + bit_offset as Size,
        }
    }

    /// Iterates the bit indices this range covers, `start` through `end`
    /// inclusive.
    pub fn iter(&self) -> RangeInclusive<usize> {
        self.start()..=self.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_singleton() {
        let range = BitRange::singleton(10);
        assert_eq!(range.start(), 10);
        assert_eq!(range.end(), 10);
    }

    #[test]
    fn test_size() {
        assert_eq!(BitRange::new(10, 15).size(), 6);
    }

    #[test]
    fn test_mask() {
        //   .........111111..
        let r1 = BitRange::new(10, 15);
        // .............1111
        let r2 = BitRange::new(14, 17);

        assert_eq!(r1.mask(&r2), 0b0011);
    }

    #[test]
    fn test_shifted() {
        let range = BitRange::new(10, 15);
        let shifted = range.shifted(6);

        assert_eq!(range.size(), shifted.size());
        assert_eq!(shifted.start(), 16);
        assert_eq!(shifted.end(), 21);
    }
}
