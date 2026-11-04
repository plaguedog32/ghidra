use std::{
    cmp,
    fmt::{self, Display, Write},
};

use crate::bitrange::BitRange;
use crate::builder::Endian;
use crate::token::token_stream_bit;
use serde::{Deserialize, Serialize};

#[derive(Default, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BitPreference {
    #[default]
    Any,
    Zero,
    One,
}

impl Display for BitPreference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let c = match self {
            BitPreference::Any => '.',
            BitPreference::Zero => '0',
            BitPreference::One => '1',
        };
        f.write_char(c)
    }
}

impl fmt::Debug for BitPreference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(self, f)
    }
}

/// A mask value pair.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum PatternBlock {
    /// LSB ordered bit preference.
    Pattern(Vec<BitPreference>),
    /// An always false pattern.
    False,
    /// An always true pattern.
    True,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum CompiledPatternBlock {
    AlwaysTrue,
    AlwaysFalse,
    Masked { masks: Box<[u8]>, values: Box<[u8]> },
}

impl CompiledPatternBlock {
    /// The per-byte mask of a `Masked` block.
    pub(crate) fn mask(&self) -> Option<&[u8]> {
        match self {
            Self::Masked { masks, .. } => Some(masks),
            _ => None,
        }
    }

    /// The masks and values of a `Masked` block.
    pub(crate) fn test_bytes(&self) -> Option<(&[u8], &[u8])> {
        match self {
            Self::Masked { masks, values } => Some((masks, values)),
            _ => None,
        }
    }

    /// Why `data` does not match, when it does not: the first byte that
    /// disagrees, or that `data` is too short to test.
    pub(crate) fn test(&self, data: &[u8]) -> Result<(), Option<usize>> {
        match self {
            Self::AlwaysTrue => Ok(()),
            Self::AlwaysFalse => Err(None),
            Self::Masked { masks, values } => {
                if data.len() < masks.len() {
                    return Err(None);
                }
                data.iter()
                    .zip(masks.iter().zip(values.iter()))
                    .position(|(byte, (mask, value))| byte & mask != *value)
                    .map_or(Ok(()), |byte| Err(Some(byte)))
            }
        }
    }

    pub(crate) fn matches(&self, data: &[u8]) -> bool {
        match self {
            Self::AlwaysTrue => true,
            Self::AlwaysFalse => false,
            Self::Masked { masks, values } => {
                data.len() >= masks.len()
                    && data
                        .iter()
                        .zip(masks.iter().zip(values.iter()))
                        .all(|(byte, (mask, value))| byte & mask == *value)
            }
        }
    }
}

impl<'a> IntoIterator for &'a PatternBlock {
    type Item = BitPreference;
    type IntoIter = std::iter::Copied<std::slice::Iter<'a, BitPreference>>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl FromIterator<BitPreference> for PatternBlock {
    fn from_iter<T: IntoIterator<Item = BitPreference>>(iter: T) -> Self {
        Self::Pattern(iter.into_iter().collect::<Vec<_>>()).normalized()
    }
}

impl From<Vec<BitPreference>> for PatternBlock {
    fn from(value: Vec<BitPreference>) -> Self {
        Self::Pattern(value).normalized()
    }
}

impl From<bool> for PatternBlock {
    fn from(value: bool) -> Self {
        if value { Self::True } else { Self::False }
    }
}

impl Display for PatternBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pattern(pattern) => pattern.iter().try_for_each(|p| write!(f, "{p}")),
            Self::False => write!(f, "False"),
            Self::True => write!(f, "True"),
        }
    }
}

impl fmt::Debug for PatternBlock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        Display::fmt(&self, f)
    }
}

impl PatternBlock {
    pub fn get(&self, idx: usize) -> BitPreference {
        match self {
            Self::False | Self::True => BitPreference::Any,
            Self::Pattern(preferences) if idx >= preferences.len() => BitPreference::Any,
            Self::Pattern(bit_preferences) => bit_preferences[idx],
        }
    }

    pub fn iter(&self) -> std::iter::Copied<std::slice::Iter<'_, BitPreference>> {
        match self {
            PatternBlock::Pattern(bit_preferences) => bit_preferences.iter(),
            PatternBlock::False | PatternBlock::True => [].iter(),
        }
        .copied()
    }

    pub fn len(&self) -> usize {
        match self {
            PatternBlock::Pattern(bit_preferences) => bit_preferences.len(),
            PatternBlock::False | PatternBlock::True => 0,
        }
    }

    pub fn from_masked_value(mask: u64, value: u64) -> Self {
        use BitPreference::*;
        let width = 64 - mask.leading_zeros() as usize;

        (0..width)
            .map(|i| {
                let cursor = 1u64 << i;
                if mask & cursor != 0 {
                    if value & cursor != 0 { One } else { Zero }
                } else {
                    Any
                }
            })
            .collect()
    }

    pub fn from_le_value(range: &BitRange, value: u64) -> Self {
        use BitPreference::*;
        let mut values = vec![Any; range.start()];
        let size = range.size();
        debug_assert!(size < u64::BITS as usize);
        for i in 0..size {
            let v = if value & (1 << i) != 0 { One } else { Zero };
            values.push(v);
        }
        Self::Pattern(values)
    }

    /// Builds a pattern over a **context** field.
    ///
    /// Context fields number their bits most-significant first across the
    /// context buffer, matching how `read_context` reads them back. This is a
    /// bit reversal within the field, and is unrelated to the byte permutation
    /// a big-endian *token* needs — see [`Self::from_be_token_value`].
    pub fn from_be_value(range: &BitRange, value: u64) -> Self {
        use BitPreference::*;
        let mut values = vec![Any; range.start()];
        let size = range.size();
        debug_assert!(size < u64::BITS as usize);
        for i in 1..=size {
            let v = if value & (1 << (size - i)) != 0 {
                One
            } else {
                Zero
            };
            values.push(v);
        }
        Self::Pattern(values)
    }

    /// Builds a pattern over a field of a **big-endian token**.
    ///
    /// The token's value is a big-endian read of its bytes, so a value bit
    /// lands in a different stream byte than it would little-endian, keeping
    /// its position within that byte. Bits are scattered through
    /// [`token_stream_bit`] rather than written consecutively.
    pub fn from_be_token_value(range: &BitRange, value: u64, token_bits: usize) -> Self {
        use BitPreference::*;
        let size = range.size();
        debug_assert!(size < u64::BITS as usize);

        // The permutation can move bits into any byte of the token, so the
        // pattern spans the whole token rather than stopping at the field.
        let mut values = vec![Any; token_bits.max(range.end() + 1)];
        for i in 0..size {
            let pos = token_stream_bit(token_bits, Endian::Big, range.start() + i);
            if let Some(slot) = values.get_mut(pos) {
                *slot = if value & (1 << i) != 0 { One } else { Zero };
            }
        }
        Self::Pattern(values)
    }

    pub fn intersect(&self, other: &Self, shift_amount: usize) -> Self {
        if self == &Self::False || other == &Self::False {
            return Self::False;
        }

        let max_len = cmp::max(self.len(), shift_amount + other.len());
        let mut values = Vec::with_capacity(max_len);

        for i in 0..max_len {
            let v1 = self.get(i);
            let v2 = if i < shift_amount {
                BitPreference::Any
            } else {
                other.get(i - shift_amount)
            };

            use BitPreference::*;
            let v = match (v1, v2) {
                (Any, _) => v2,
                (_, Any) => v1,
                (Zero, Zero) => Zero,
                (One, One) => One,
                (Zero, One) | (One, Zero) => return Self::False,
            };

            values.push(v);
        }

        PatternBlock::Pattern(values).normalized()
    }

    pub fn includes(&self, other: &Self) -> bool {
        if self == &Self::True || other == &Self::False {
            return true;
        }

        if self.len() > other.len() {
            return false;
        }

        self.iter()
            .zip(other.iter())
            .all(|(p1, p2)| (p1 == BitPreference::Any) || p1 == p2)
    }

    pub fn common_sub_pattern(&self, other: &Self) -> Self {
        match (self, other) {
            (Self::False, _) => other.clone(),
            (_, Self::False) => self.clone(),
            (_, Self::True) | (Self::True, _) => Self::True,
            (Self::Pattern(p1), Self::Pattern(p2)) => p1
                .iter()
                .zip(p2.iter())
                .map(|(&p1, &p2)| if p1 == p2 { p1 } else { BitPreference::Any })
                .collect::<Self>(),
        }
    }

    pub fn normalize(&mut self) {
        if let PatternBlock::Pattern(pattern) = self {
            while matches!(pattern.last(), Some(BitPreference::Any)) {
                pattern.pop();
            }
            if pattern.is_empty() {
                *self = Self::True;
            }
        }
    }

    pub fn normalized(mut self) -> Self {
        self.normalize();
        self
    }

    pub fn get_mask(&self, range: &BitRange) -> u64 {
        match self {
            PatternBlock::False | PatternBlock::True => 0,
            PatternBlock::Pattern(pattern) => {
                let mut res = 0;
                for i in range.iter().rev() {
                    res <<= 1;
                    if pattern
                        .get(i)
                        .is_some_and(|&p| p == BitPreference::Zero || p == BitPreference::One)
                    {
                        res |= 1;
                    }
                }
                res
            }
        }
    }

    pub fn get_value(&self, range: &BitRange) -> u64 {
        match self {
            PatternBlock::False | PatternBlock::True => 0,
            PatternBlock::Pattern(pattern) => {
                let mut res = 0;
                for i in range.iter().rev() {
                    res <<= 1;
                    if pattern.get(i).is_some_and(|&p| p == BitPreference::One) {
                        res |= 1;
                    }
                }
                res
            }
        }
    }

    pub fn values_over(&self, range: &BitRange) -> Vec<u64> {
        fn values_over(
            pattern: &PatternBlock,
            mut range: BitRange,
            mut base: u64,
            res: &mut Vec<u64>,
        ) {
            base <<= 1;
            let idx = range.end();

            if range.start() == range.end() {
                match pattern.get(idx) {
                    BitPreference::Any => {
                        res.push(base);
                        res.push(base | 1);
                    }
                    BitPreference::Zero => res.push(base),
                    BitPreference::One => res.push(base | 1),
                }
                return;
            }

            range = BitRange::new(range.start(), idx - 1);

            match pattern.get(idx) {
                BitPreference::Any => {
                    values_over(pattern, range.clone(), base | 1, res);
                    values_over(pattern, range, base, res);
                }
                BitPreference::Zero => values_over(pattern, range, base, res),
                BitPreference::One => values_over(pattern, range, base | 1, res),
            }
        }

        let mut res = Vec::new();
        values_over(self, range.clone(), 0, &mut res);
        res
    }

    pub fn specifies_range(&self, range: &BitRange) -> bool {
        range
            .into_iter()
            .all(|idx| self.get(idx) != BitPreference::Any)
    }

    pub fn and(&self, other: &Self, shift_amount: i64) -> Self {
        if shift_amount < 0 {
            other.and(self, -shift_amount)
        } else {
            self.intersect(other, shift_amount as usize)
        }
    }

    pub fn shifted(&self, amount: usize) -> Self {
        match self {
            Self::Pattern(pattern) => std::iter::repeat_n(BitPreference::Any, amount)
                .chain(pattern.iter().copied())
                .collect::<Self>(),
            Self::False => Self::False,
            Self::True => Self::True,
        }
    }

    pub fn specificity(&self) -> usize {
        match self {
            PatternBlock::Pattern(bit_preferences) => bit_preferences
                .iter()
                .filter(|&&p| p != BitPreference::Any)
                .count(),
            PatternBlock::False | PatternBlock::True => 0,
        }
    }

    pub fn matches(&self, data: &[u8]) -> bool {
        let len = self.len().div_ceil(8);
        (0..len).all(|idx| {
            let range = BitRange::new(idx * 8, idx * 8 + 7);
            let mask = self.get_mask(&range);
            let value = self.get_value(&range);
            (data[idx] as u64) & mask == value
        })
    }

    pub fn is_always_true(&self) -> bool {
        self == &Self::True
    }

    pub fn is_always_false(&self) -> bool {
        self == &Self::False
    }

    pub(crate) fn compile_matcher(&self) -> CompiledPatternBlock {
        match self {
            Self::True => CompiledPatternBlock::AlwaysTrue,
            Self::False => CompiledPatternBlock::AlwaysFalse,
            Self::Pattern(_) => {
                let len = self.len().div_ceil(8);
                let mut masks = Vec::with_capacity(len);
                let mut values = Vec::with_capacity(len);
                for idx in 0..len {
                    let range = BitRange::new(idx * 8, idx * 8 + 7);
                    masks.push(self.get_mask(&range) as u8);
                    values.push(self.get_value(&range) as u8);
                }
                CompiledPatternBlock::Masked {
                    masks: masks.into_boxed_slice(),
                    values: values.into_boxed_slice(),
                }
            }
        }
    }
}
