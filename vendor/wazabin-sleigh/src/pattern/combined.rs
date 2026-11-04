use std::{
    cmp,
    ops::{Deref, DerefMut},
};

use crate::bitrange::BitRange;
use serde::{Deserialize, Serialize};

use super::block::{CompiledPatternBlock, PatternBlock};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum CombinedRange {
    Context(BitRange),
    Instruction(BitRange),
}

impl Deref for CombinedRange {
    type Target = BitRange;

    fn deref(&self) -> &Self::Target {
        self.bitrange()
    }
}

impl DerefMut for CombinedRange {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.bitrange_mut()
    }
}

impl CombinedRange {
    pub fn bitrange(&self) -> &BitRange {
        match self {
            CombinedRange::Context(bit_range) | CombinedRange::Instruction(bit_range) => bit_range,
        }
    }

    pub fn bitrange_mut(&mut self) -> &mut BitRange {
        match self {
            CombinedRange::Context(bit_range) | CombinedRange::Instruction(bit_range) => bit_range,
        }
    }

    pub fn shifted(&self, bit_offset: usize) -> Self {
        match self {
            CombinedRange::Context(bit_range) => {
                CombinedRange::Context(bit_range.shifted(bit_offset))
            }
            CombinedRange::Instruction(bit_range) => {
                CombinedRange::Instruction(bit_range.shifted(bit_offset))
            }
        }
    }
}

/// A pattern on context and one on an instruction.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CombinedPattern {
    pub context: PatternBlock,
    pub instruction: PatternBlock,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct CompiledCombinedPattern {
    context: CompiledPatternBlock,
    instruction: CompiledPatternBlock,
}

impl CompiledCombinedPattern {
    /// The compiled context-register half of this pattern.
    #[cfg(feature = "unstable-introspect")]
    pub(crate) fn context_block(&self) -> &CompiledPatternBlock {
        &self.context
    }

    /// The compiled instruction-stream half of this pattern.
    #[cfg(feature = "unstable-introspect")]
    pub(crate) fn instruction_block(&self) -> &CompiledPatternBlock {
        &self.instruction
    }

    pub(crate) fn matches(&self, bytes: &[u8], context: &[u8]) -> bool {
        self.instruction.matches(bytes) && self.context.matches(context)
    }

    /// The per-byte mask of the instruction half, when it tests anything.
    pub(crate) fn instruction_mask(&self) -> Option<&[u8]> {
        self.instruction.mask()
    }

    /// Whether the context half matches `context`.
    pub(crate) fn context_matches(&self, context: &[u8]) -> bool {
        self.context.matches(context)
    }

    /// The instruction half's masks and values, when it tests anything.
    pub(crate) fn instruction_test(&self) -> Option<(&[u8], &[u8])> {
        self.instruction.test_bytes()
    }

    /// [`matches`](Self::matches), saying why not.
    pub(crate) fn test(&self, bytes: &[u8], context: &[u8]) -> PatternOutcome {
        if !self.context.matches(context) {
            return PatternOutcome::FailedContext;
        }
        match self.instruction.test(bytes) {
            Ok(()) => PatternOutcome::Matched,
            Err(Some(byte)) => PatternOutcome::FailedByte(byte),
            // Too short, or a pattern that never matches — which the tree
            // would not have offered.
            Err(None) => PatternOutcome::FailedShort,
        }
    }
}

/// How a [`CompiledCombinedPattern`] fared against an instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PatternOutcome {
    Matched,
    /// The context half failed; the instruction half was not consulted.
    FailedContext,
    /// The instruction half first disagreed at this byte.
    FailedByte(usize),
    /// The instruction bytes ran out before the pattern did.
    FailedShort,
}

impl CombinedPattern {
    pub fn impossible() -> Self {
        Self {
            context: PatternBlock::False,
            instruction: PatternBlock::False,
        }
    }

    pub fn from_insn(block: PatternBlock) -> Self {
        Self {
            context: PatternBlock::True,
            instruction: block,
        }
    }

    pub fn from_ctx(block: PatternBlock) -> Self {
        Self {
            context: block,
            instruction: PatternBlock::True,
        }
    }

    pub fn and(&self, other: &Self, shift_amount: i64) -> Self {
        Self {
            context: self.context.and(&other.context, 0),
            instruction: self.instruction.and(&other.instruction, shift_amount),
        }
    }

    pub fn shifted(&mut self, amount: usize) -> Self {
        Self {
            context: self.context.clone(),
            instruction: self.instruction.shifted(amount),
        }
    }

    pub fn common_sub_pattern(&self, other: &Self) -> Self {
        Self {
            context: self.context.common_sub_pattern(&other.context),
            instruction: self.instruction.common_sub_pattern(&other.instruction),
        }
    }

    pub fn includes(&self, other: &Self) -> bool {
        self.context.includes(&other.context) && self.instruction.includes(&other.instruction)
    }

    pub fn is_less_specific(&self, other: &Self) -> bool {
        self != other && self.includes(other)
    }

    pub fn map_range<F, T>(&self, range: &CombinedRange, f: F) -> T
    where
        F: FnOnce(&PatternBlock, &BitRange) -> T,
    {
        match range {
            CombinedRange::Context(range) => f(&self.context, range),
            CombinedRange::Instruction(range) => f(&self.instruction, range),
        }
    }

    pub fn get_mask(&self, range: &CombinedRange) -> u64 {
        self.map_range(range, PatternBlock::get_mask)
    }

    pub fn get_value(&self, range: &CombinedRange) -> u64 {
        self.map_range(range, PatternBlock::get_value)
    }

    pub fn specifies_range(&self, range: &CombinedRange) -> bool {
        self.map_range(range, PatternBlock::specifies_range)
    }

    pub fn values_over(&self, range: &CombinedRange) -> Vec<u64> {
        self.map_range(range, PatternBlock::values_over)
    }

    pub fn specificity(&self) -> usize {
        self.context.specificity() + self.instruction.specificity()
    }

    pub fn max_len(&self) -> usize {
        cmp::max(self.context.len(), self.instruction.len())
    }

    pub fn is_always_true(&self) -> bool {
        self.context.is_always_true() && self.instruction.is_always_true()
    }

    pub fn is_always_false(&self) -> bool {
        self.context.is_always_false() || self.instruction.is_always_false()
    }

    pub(crate) fn compile_matcher(&self) -> CompiledCombinedPattern {
        CompiledCombinedPattern {
            context: self.context.compile_matcher(),
            instruction: self.instruction.compile_matcher(),
        }
    }
}

/// An OR of multiple patterns.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatternDisjunction {
    pub disjunctions: Vec<CombinedPattern>,
}

impl<'a> IntoIterator for &'a PatternDisjunction {
    type Item = &'a CombinedPattern;
    type IntoIter = std::slice::Iter<'a, CombinedPattern>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a> IntoIterator for &'a mut PatternDisjunction {
    type Item = &'a mut CombinedPattern;
    type IntoIter = std::slice::IterMut<'a, CombinedPattern>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

impl FromIterator<CombinedPattern> for PatternDisjunction {
    fn from_iter<T: IntoIterator<Item = CombinedPattern>>(iter: T) -> Self {
        Self::new(iter.into_iter().collect::<Vec<_>>()).normalized()
    }
}

impl From<CombinedPattern> for PatternDisjunction {
    fn from(value: CombinedPattern) -> Self {
        Self::new(vec![value])
    }
}

impl PatternDisjunction {
    pub fn new(disjunctions: Vec<CombinedPattern>) -> Self {
        Self { disjunctions }
    }

    pub fn normalize(&mut self) {
        self.disjunctions.retain(|atom| !atom.is_always_false());

        let mut patterns = Vec::with_capacity(self.disjunctions.len());
        let disjunctions = std::mem::take(&mut self.disjunctions);
        for p1 in disjunctions {
            if !self
                .disjunctions
                .iter()
                .any(|p2| &p1 != p2 && p2.includes(&p1))
            {
                patterns.push(p1);
            }
        }

        self.disjunctions = patterns;
    }

    pub fn normalized(mut self) -> Self {
        self.normalize();
        self
    }

    pub fn iter(&self) -> std::slice::Iter<'_, CombinedPattern> {
        self.disjunctions.iter()
    }

    pub fn iter_mut(&mut self) -> std::slice::IterMut<'_, CombinedPattern> {
        self.disjunctions.iter_mut()
    }

    pub fn or(&self, other: &Self, shift_amount: i64) -> Self {
        if shift_amount < 0 {
            other.or(self, -shift_amount)
        } else {
            self.disjunctions
                .iter()
                .cloned()
                .chain(
                    other
                        .iter()
                        .map(|c| c.clone().shifted(shift_amount as usize)),
                )
                .collect::<Self>()
        }
    }

    pub fn common_pattern(&self) -> CombinedPattern {
        self.disjunctions
            .iter()
            .fold(CombinedPattern::impossible(), |c1, c2| {
                c1.common_sub_pattern(c2)
            })
    }

    pub fn common_sub_pattern(&self, other: &Self) -> Self {
        self.common_pattern()
            .common_sub_pattern(&other.common_pattern())
            .into()
    }

    pub fn and(&self, other: &Self, shift_amount: i64) -> Self {
        if shift_amount < 0 {
            // A negative shift means `other` is the one to shift, so the
            // operands swap: `other` becomes the left-hand side.
            other.and(self, -shift_amount)
        } else {
            self.iter()
                .flat_map(|lhs| other.iter().map(move |rhs| lhs.and(rhs, shift_amount)))
                .collect::<Self>()
        }
    }

    pub fn is_always_true(&self) -> bool {
        self.iter().any(|e| e.is_always_true())
    }

    pub fn is_always_false(&self) -> bool {
        self.iter().all(|e| e.is_always_false())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pattern::block::BitPreference::{One, Zero};

    fn disj(bits: &[super::super::block::BitPreference]) -> PatternDisjunction {
        CombinedPattern::from_insn(bits.iter().copied().collect()).into()
    }

    /// A negative shift means the *other* operand is the one to shift, so the
    /// two sides swap. Both `PatternBlock::and` and `PatternDisjunction::or`
    /// spell this `other.op(self, -n)`; `and` used to spell it
    /// `other.and(other, -n)`, silently dropping `self` from the conjunction.
    #[test]
    fn negative_shift_and_swaps_operands_rather_than_dropping_self() {
        let lhs = disj(&[One, Zero, One, Zero]);
        let rhs = disj(&[Zero, Zero]);

        assert_eq!(lhs.and(&rhs, -2), rhs.and(&lhs, 2));
    }

    /// The self-AND bug is only observable when the operands differ, which is
    /// why it survived: it produces `rhs ∧ shift(rhs)` instead of the real
    /// conjunction.
    #[test]
    fn negative_shift_and_is_not_the_rhs_conjoined_with_itself() {
        let lhs = disj(&[One, One, One, One]);
        let rhs = disj(&[Zero, Zero]);

        assert_ne!(lhs.and(&rhs, -2), rhs.and(&rhs, 2));
    }
}
