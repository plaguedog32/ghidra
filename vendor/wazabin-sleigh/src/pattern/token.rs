use std::cmp;

use crate::bitrange::BitRange;
use crate::{
    builder::Endian,
    objects::{field::FieldId, table::TableId},
    token::{TokenContext, TokenId},
};
use pcode_types::RegisterId;
use serde::{Deserialize, Serialize};

use super::{
    Error, Result,
    block::PatternBlock,
    combined::{CombinedPattern, PatternDisjunction},
};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum Alignment {
    #[default]
    Fixed,
    Left,
    Right,
}

/// The type of the operand in question.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum OperandType {
    Field(FieldId),
    Table(TableId),
    // TODO: I don't know why we need this ?
    Register(RegisterId),
}

pub(crate) type OperandId = u32;

/// An operand in an instruction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Operand {
    pub ty: OperandType,
    relative: Option<(OperandId, crate::Size)>,
    offset: crate::Size,
}

impl Operand {
    pub(crate) fn new(ty: OperandType) -> Self {
        Self {
            ty,
            relative: None,
            offset: 0,
        }
    }

    pub(crate) fn offset(&self) -> usize {
        self.offset as usize
    }

    pub(crate) fn relative(&self) -> Option<(usize, usize)> {
        self.relative.map(|(rel, min)| (rel as usize, min as usize))
    }
}

/// A pattern disjunction with the list of built tokens.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TokenPattern {
    pub(super) pattern: PatternDisjunction,
    pub tokens: Vec<TokenId>,
    pub alignment: Alignment,
    pub operands: Vec<Operand>,
}

/// Merges the operand lists of the two branches of a `|`.
///
/// `lhs` keeps its positions; an operand of `rhs` naming something `lhs`
/// already has is dropped in favour of it, and anything else is appended. A
/// `relative` operand refers to another operand by index, so those are remapped
/// onto the merged list as they move.
fn merge_operands(lhs: &[Operand], rhs: &[Operand]) -> Vec<Operand> {
    let mut merged = lhs.to_vec();
    let mut remap = Vec::with_capacity(rhs.len());

    for operand in rhs {
        match merged.iter().position(|existing| existing.ty == operand.ty) {
            Some(index) => remap.push(index as OperandId),
            None => {
                remap.push(merged.len() as OperandId);
                merged.push(operand.clone());
            }
        }
    }

    // Second pass: the appended operands' `relative` indices still point into
    // `rhs`, and the operand they point at may itself have moved.
    for (source, operand) in rhs.iter().enumerate() {
        let Some((rel, _)) = operand.relative else {
            continue;
        };
        let target = remap[source] as usize;
        if target < lhs.len() {
            // Kept `lhs`'s copy, which already has its own `relative`.
            continue;
        }
        if let Some(&mapped) = remap.get(rel as usize) {
            if let Some(slot) = merged[target].relative.as_mut() {
                slot.0 = mapped;
            }
        }
    }

    merged
}

fn check_alignment(lhs: &TokenPattern, rhs: &TokenPattern) -> Result<()> {
    let lhs_size = lhs.tokens.len();
    let rhs_size = rhs.tokens.len();
    let min_size = cmp::min(lhs_size, rhs_size);

    use Alignment::*;
    use Error::*;

    match (lhs.alignment, rhs.alignment) {
        (Left, Right) => Err(RLellipsis),
        (Right, Left) => Err(LRellipsis),
        (Left, Fixed) if lhs_size != min_size => Err(MismatchedSizes(lhs_size, min_size)),
        (Right, Fixed) if lhs_size != min_size => Err(MismatchedSizes(lhs_size, min_size)),
        (Fixed, Left) if rhs_size != min_size => Err(MismatchedSizes(rhs_size, min_size)),
        (Fixed, Right) if rhs_size != min_size => Err(MismatchedSizes(rhs_size, min_size)),
        (Fixed, Fixed) if lhs_size != rhs_size => Err(MismatchedSizes(lhs_size, rhs_size)),

        // An ellipsis that happens not to extend anything is not an error. The
        // arms above already reject the case that *is* broken — an unanchored
        // side longer than the fixed one — and `A ... & B` at equal length is
        // an ordinary fixed pattern, which `resolve_tokens` builds correctly.
        // HCS08 writes `(op=0xDC | op=0xEC | op=0xFC) ... & ADDRI` and M16C
        // `(...) & $(DST5AX) ...`; Ghidra accepts both.
        _ => Ok(()),
    }
}

fn check_tokens_match(
    lhs: impl Iterator<Item = TokenId>,
    rhs: impl Iterator<Item = TokenId>,
) -> Result<()> {
    lhs.zip(rhs).try_for_each(|(l, r)| {
        if l != r {
            Err(Error::MismatchedTokens(l, r))
        } else {
            Ok(())
        }
    })
}

fn shared_prefix<T>(it1: impl Iterator<Item = T>, it2: impl Iterator<Item = T>) -> Vec<T>
where
    T: Copy + Eq,
{
    it1.zip(it2)
        .take_while(|(t1, t2)| t1 == t2)
        .map(|(t, _)| t)
        .collect()
}

impl Default for TokenPattern {
    fn default() -> Self {
        Self {
            pattern: CombinedPattern::from_ctx(PatternBlock::True).into(),
            tokens: vec![],
            alignment: Alignment::Fixed,
            operands: vec![],
        }
    }
}

impl TokenPattern {
    pub(crate) fn impossible() -> Self {
        Self {
            pattern: CombinedPattern::from_ctx(PatternBlock::False).into(),
            ..Default::default()
        }
    }

    pub(crate) fn from_iter<I>(ctx: &dyn TokenContext, iter: I) -> Result<Self>
    where
        I: IntoIterator<Item = Self>,
    {
        let mut res = TokenPattern::impossible();
        for pattern in iter {
            res = res.or(ctx, &pattern)?;
        }
        Ok(res)
    }

    pub(crate) fn from_insn(tok: TokenId) -> Self {
        Self {
            pattern: CombinedPattern::from_insn(PatternBlock::True).into(),
            tokens: vec![tok],
            ..Default::default()
        }
    }

    pub(crate) fn from_insn_value(
        ctx: &dyn TokenContext,
        tok: TokenId,
        range: &BitRange,
        value: u64,
    ) -> Self {
        Self::from_insn_pattern(
            tok,
            match ctx.token_endian(tok) {
                Endian::Little => PatternBlock::from_le_value(range, value),
                Endian::Big => PatternBlock::from_be_token_value(range, value, ctx.token_size(tok)),
            },
        )
    }

    pub(crate) fn from_insn_pattern(tok: TokenId, block: PatternBlock) -> Self {
        Self {
            pattern: CombinedPattern::from_insn(block).into(),
            tokens: vec![tok],
            ..Default::default()
        }
    }

    pub(crate) fn from_ctx_value(range: &BitRange, value: u64) -> Self {
        let block = PatternBlock::from_be_value(range, value);
        Self {
            pattern: CombinedPattern::from_ctx(block).into(),
            ..Default::default()
        }
    }

    pub(crate) fn with_operand(mut self, ty: OperandType) -> Self {
        self.operands.push(Operand::new(ty));
        self
    }

    pub(crate) fn min_size(&self, ctx: &dyn TokenContext) -> usize {
        self.tokens.iter().map(|&id| ctx.token_size(id)).sum()
    }

    /// Renders the pattern as a table: one column per token, a header row of
    /// token names, then one row of bit strings per disjunction.
    ///
    /// Debug aid only — reached through the walker's `DEBUG_LOG` tracing,
    /// which compiles out entirely without `debug_assertions`, hence the
    /// allow.
    #[allow(dead_code)]
    pub(crate) fn to_string(&self, ctx: &dyn TokenContext) -> String {
        let mut rows = vec![
            self.tokens
                .iter()
                .map(|&tok| ctx.token_name(tok).to_string())
                .collect::<Vec<_>>(),
        ];

        for pat in &self.pattern.disjunctions {
            let mut row = Vec::with_capacity(self.tokens.len());
            let mut i = 0;
            for &tok in &self.tokens {
                let end = i + ctx.token_size(tok);
                row.push(
                    (i..end)
                        .map(|j| pat.instruction.get(j).to_string())
                        .collect(),
                );
                i = end;
            }
            rows.push(row);
        }

        let mut widths = vec![0; self.tokens.len()];
        for row in &rows {
            for (w, cell) in widths.iter_mut().zip(row) {
                *w = cmp::max(*w, cell.chars().count());
            }
        }

        let mut out = format!("aligned: ({:?})\n", self.alignment);
        for row in &rows {
            for (cell, &w) in row.iter().zip(&widths) {
                out.push_str("| ");
                out.push_str(cell);
                out.extend(std::iter::repeat_n(' ', w - cell.chars().count()));
                out.push(' ');
            }
            out.push_str("|\n");
        }
        out
    }

    fn always_instruction_true(&self) -> bool {
        self.pattern
            .iter()
            .any(|cp| cp.instruction.is_always_true())
    }

    pub(crate) fn and(&self, ctx: &dyn TokenContext, other: &Self) -> Result<Self> {
        let mut res = Self::default();
        let amount = res.resolve_tokens(ctx, self, other)?;
        res.pattern = self.pattern.and(&other.pattern, amount);

        res.operands.extend(self.operands.iter().cloned());
        let base = res.operands.len();
        res.operands.extend(other.operands.iter().map(|op| {
            let mut op = op.clone();
            if let Some((rel, _min_size)) = &mut op.relative {
                *rel += base as OperandId;
            }
            op
        }));

        Ok(res)
    }

    /// Unions two patterns.
    ///
    /// The branches need not name the same operands. SLEIGH lets one branch of
    /// a `|` mention an operand the other does not — ARM's NEON `vdup` is
    /// `( <arm-encoding> & vdupSize & ... ) | ( <thumb-encoding> ... )`, and
    /// `vdupSize` appears only on the ARM side. Operands belong to the
    /// *constructor*, not to the branch that matched: a token field is read out
    /// of the instruction bytes either way, so the merged list is the union.
    ///
    /// Operands already present keep their position, because display elements
    /// and `field_map` address operands by index.
    pub(crate) fn or(&self, ctx: &dyn TokenContext, other: &Self) -> Result<Self> {
        let mut res = Self::default();
        let amount = res.resolve_tokens(ctx, self, other)?;
        res.pattern = self.pattern.or(&other.pattern, amount);

        res.operands = if self.operands == other.operands {
            self.operands.clone()
        } else {
            merge_operands(&self.operands, &other.operands)
        };

        Ok(res)
    }

    pub(crate) fn cat(&self, ctx: &dyn TokenContext, other: &Self) -> Result<Self> {
        let mut res = TokenPattern {
            alignment: self.alignment,
            tokens: self.tokens.clone(),
            ..Self::default()
        };

        let shift_amount = match (self.alignment, other.alignment) {
            (Alignment::Left, _) if !other.always_instruction_true() => {
                return Err(Error::InteriorEllipsis);
            }
            (_, Alignment::Right) if !self.always_instruction_true() => {
                return Err(Error::InteriorEllipsis);
            }
            (Alignment::Left, Alignment::Right) => return Err(Error::LRellipsis),
            (Alignment::Right, Alignment::Left) => return Err(Error::RLellipsis),
            (Alignment::Left, _) => 0,
            (_, Alignment::Right) => {
                res.alignment = Alignment::Right;
                0
            }
            _ => {
                let mut shift_amount = 0;
                for &tok in &self.tokens {
                    shift_amount += ctx.token_size(tok) as i64;
                }
                for &tok in &other.tokens {
                    res.tokens.push(tok);
                }
                if other.alignment == Alignment::Left {
                    res.alignment = Alignment::Left;
                }
                shift_amount
            }
        };

        res.pattern = self.pattern.and(&other.pattern, shift_amount);

        let lhs_size = self.min_size(ctx);
        res.operands = self.operands.clone();
        res.operands.extend(other.operands.iter().map(|op| {
            if self.alignment == Alignment::Fixed {
                let mut op = op.clone();
                if let Some((rel, min_size)) = op.relative {
                    op.relative = Some((
                        rel + self.operands.len() as OperandId,
                        min_size + lhs_size as crate::Size,
                    ))
                } else {
                    op.offset += lhs_size as crate::Size;
                }
                op
            } else {
                debug_assert!(!self.operands.is_empty());
                let base = self.operands.len();
                Operand {
                    relative: Some(op.relative.map_or(
                        ((base - 1) as OperandId, lhs_size as crate::Size),
                        |(rel, min_size)| {
                            (base as OperandId + rel, min_size + lhs_size as crate::Size)
                        },
                    )),
                    ..op.clone()
                }
            }
        }));

        Ok(res)
    }

    pub(crate) fn common_sub_pattern(&self, other: &Self) -> Result<Self> {
        let mut res = Self::default();

        if self == &Self::impossible() {
            return Ok(other.clone());
        }

        if other == &Self::impossible() {
            return Ok(self.clone());
        }

        if (self.alignment == Alignment::Right && other.alignment == Alignment::Left)
            || (self.alignment == Alignment::Left && other.alignment == Alignment::Right)
        {
            return Err(Error::CommonSubPattern);
        }

        let mut reversed = false;

        if self.alignment == Alignment::Right || other.alignment == Alignment::Right {
            reversed = true;
            res.alignment = Alignment::Right;
        }

        if self.alignment == Alignment::Left || other.alignment == Alignment::Left {
            res.alignment = Alignment::Left;
        }

        let max_len = cmp::max(self.tokens.len(), other.tokens.len());

        if reversed {
            res.tokens = shared_prefix(
                self.tokens.iter().copied().rev(),
                other.tokens.iter().copied().rev(),
            );
            res.tokens.reverse();
        } else {
            res.tokens = shared_prefix(self.tokens.iter().copied(), other.tokens.iter().copied());
            if res.tokens.len() < max_len {
                res.alignment = Alignment::Left;
            }
        };

        res.pattern = self.pattern.common_sub_pattern(&other.pattern);

        Ok(res)
    }

    fn resolve_tokens(
        &mut self,
        ctx: &dyn TokenContext,
        lhs: &TokenPattern,
        rhs: &TokenPattern,
    ) -> Result<i64> {
        let lhs_size = lhs.tokens.len();
        let rhs_size = rhs.tokens.len();
        let min_size = cmp::min(lhs_size, rhs_size);

        if lhs.always_instruction_true() && lhs.alignment == Alignment::Fixed {
            self.tokens = rhs.tokens.clone();
            self.alignment = rhs.alignment;
            return Ok(0);
        }

        if rhs.always_instruction_true() && rhs.alignment == Alignment::Fixed {
            self.tokens = lhs.tokens.clone();
            self.alignment = lhs.alignment;
            return Ok(0);
        }

        check_alignment(lhs, rhs)?;

        self.alignment = match (lhs.alignment, rhs.alignment) {
            (Alignment::Left, Alignment::Left) => Alignment::Left,
            (Alignment::Right, Alignment::Right) => Alignment::Right,
            _ => Alignment::Fixed,
        };

        let largest = if lhs_size <= rhs_size { rhs } else { lhs };
        self.tokens = largest.tokens.clone();

        let right_aligned = lhs.alignment == Alignment::Right || rhs.alignment == Alignment::Right;

        let lhs_iter = lhs.tokens.iter().copied();
        let rhs_iter = rhs.tokens.iter().copied();

        if right_aligned {
            check_tokens_match(lhs_iter.rev(), rhs_iter.rev())?;
        } else {
            check_tokens_match(lhs_iter, rhs_iter)?;
        }

        if right_aligned {
            Ok((if lhs_size > rhs_size { 1i64 } else { -1i64 })
                * largest
                    .tokens
                    .iter()
                    .take(self.tokens.len() - min_size)
                    .map(|&t| ctx.token_size(t) as i64)
                    .sum::<i64>())
        } else {
            Ok(0)
        }
    }

    pub(crate) fn combined_patterns(&self) -> impl Iterator<Item = &CombinedPattern> {
        self.pattern.disjunctions.iter()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use crate::bitrange::BitRange;
    use crate::builder::SpecBuilder;

    use super::super::block::{BitPreference, PatternBlock};
    use super::*;

    #[test]
    fn test_block_pattern_fmt() {
        use BitPreference::*;
        assert_eq!(
            format!("{}", PatternBlock::from(vec![Any, Zero, One])),
            ".01"
        )
    }

    #[test]
    fn test_get() {
        use BitPreference::*;
        let block: PatternBlock = vec![Zero, Any, Zero, Zero, One, One, Any, One].into();
        assert_eq!(block.get(0), Zero);
        assert_eq!(block.get(1), Any);
        assert_eq!(block.get(7), One);
        assert_eq!(PatternBlock::True.get(255), Any);
        assert_eq!(PatternBlock::False.get(255), Any);
    }

    #[test]
    fn test_len() {
        use BitPreference::*;
        let block: PatternBlock = vec![Zero, Any, Zero, Zero, One, One, Any, One].into();
        assert_eq!(block.len(), 8);
        assert_eq!(PatternBlock::True.len(), 0);
        assert_eq!(PatternBlock::False.len(), 0);
    }

    #[test]
    fn combined_pattern_specificity_requires_full_pattern_inclusion() {
        use BitPreference::{One, Zero};
        let epsilon = CombinedPattern::from_ctx(PatternBlock::True);
        let specific = CombinedPattern::from_insn(vec![One, Zero, One].into());
        assert!(epsilon.is_less_specific(&specific));
        assert!(!specific.is_less_specific(&epsilon));
    }

    #[test]
    fn test_intersect() {
        use BitPreference::*;
        let block = PatternBlock::intersect(
            &vec![Any, Any, Zero, Zero, One, One, Any, Any].into(),
            &vec![One, Any, Zero, Any, Any, One, Any, Zero].into(),
            0,
        );
        assert_eq!(
            block,
            vec![One, Any, Zero, Zero, One, One, Any, Zero].into()
        );
    }

    #[test]
    fn test_intersect_false() {
        use BitPreference::*;
        let block = PatternBlock::intersect(
            &vec![Any, Any, Zero, Zero, One, One, Any, Any].into(),
            &PatternBlock::False,
            0,
        );
        assert_eq!(block, PatternBlock::False);
    }

    #[test]
    fn test_intersect_true() {
        use BitPreference::*;
        let block = PatternBlock::intersect(
            &vec![Any, Any, Zero, Zero, One, One, Any, Any].into(),
            &PatternBlock::True,
            0,
        );
        assert_eq!(block, vec![Any, Any, Zero, Zero, One, One].into());
    }

    #[test]
    fn test_intersect_incompatible() {
        use BitPreference::*;
        let block = PatternBlock::intersect(
            &vec![Any, Any, Zero, Zero, One, One, Any, Any].into(),
            &vec![One, Any, Zero, One, Any, One, Any, Zero].into(),
            0,
        );
        assert_eq!(block, PatternBlock::False);
    }

    #[test]
    fn test_from_masked_value_basic() {
        use BitPreference::*;
        let mask = 0b0010110;
        let value = 0b000100;
        let block = PatternBlock::from_masked_value(mask, value);
        assert_eq!(block, vec![Any, Zero, One, Any, Zero].into());
    }

    #[test]
    fn test_from_le_value() {
        use BitPreference::*;
        assert_eq!(
            PatternBlock::from_le_value(&BitRange::new(3, 5), 6),
            vec![Any, Any, Any, Zero, One, One].into()
        );
    }

    #[test]
    fn test_from_be_value() {
        use BitPreference::*;
        assert_eq!(
            PatternBlock::from_be_value(&BitRange::new(3, 5), 6),
            vec![Any, Any, Any, One, One, Zero].into()
        );
    }

    #[test]
    fn test_values_over() {
        use BitPreference::*;
        let pattern: PatternBlock = vec![Any, Any, Any, One, One, Zero].into();
        let values: HashSet<_> = pattern
            .values_over(&BitRange::new(1, 5))
            .iter()
            .copied()
            .collect();
        let mut expected = HashSet::new();
        expected.insert(0b01100);
        expected.insert(0b01101);
        expected.insert(0b01110);
        expected.insert(0b01111);
        assert_eq!(values, expected);
    }

    #[test]
    fn test_intersect_includes() {
        use BitPreference::*;
        assert!(PatternBlock::includes(
            &vec![Any, Any, Zero, Zero, Any, One, Any, Any].into(),
            &vec![Any, One, Zero, Zero, Any, One, Any, Zero].into()
        ));
        assert!(!PatternBlock::includes(
            &vec![Any, Any, Zero, One, Any, One, Any, Any].into(),
            &vec![Any, One, Zero, Zero, Any, One, Any, Zero].into()
        ));
        assert!(PatternBlock::includes(
            &PatternBlock::True,
            &vec![Any, One, Zero, Zero, Any, One, Any, Zero].into()
        ));
        assert!(PatternBlock::includes(
            &vec![Any, One, Zero, Zero, Any, One, Any, Zero].into(),
            &PatternBlock::False,
        ));
    }

    #[test]
    fn test_combined_pattern_and() {
        use BitPreference::*;
        let p1 = CombinedPattern::from_insn(PatternBlock::from_le_value(&BitRange::new(0, 2), 3));
        // CombinedPattern::new(instruction, context) in the original API
        let p2 = CombinedPattern {
            instruction: PatternBlock::from_le_value(&BitRange::new(3, 5), 2),
            context: PatternBlock::from_le_value(&BitRange::new(0, 8), 7),
        };
        assert_eq!(
            p1.and(&p2, 1),
            CombinedPattern {
                instruction: vec![One, One, Zero, Any, Zero, One, Zero].into(),
                context: PatternBlock::from_le_value(&BitRange::new(0, 8), 7),
            }
        )
    }

    #[test]
    fn test_tok_pattern_and_operands() {
        let mut ctx = SpecBuilder::new();
        let token = ctx.register_token("token1", 8).unwrap().id;
        let field1: FieldId = 1.into();
        let field2: FieldId = 2.into();
        let p1 = TokenPattern::from_insn(token).with_operand(OperandType::Field(field1));
        let p2 = TokenPattern::from_insn(token).with_operand(OperandType::Field(field2));
        assert_eq!(
            p1.and(&ctx, &p2).unwrap(),
            TokenPattern::from_insn(token)
                .with_operand(OperandType::Field(field1))
                .with_operand(OperandType::Field(field2))
        )
    }

    #[test]
    fn test_get_mask() {
        use BitPreference::*;
        let pattern: PatternBlock = vec![Zero, One, Any, Any, Zero, One, One, One].into();
        assert_eq!(pattern.get_mask(&BitRange::new(0, 7)), 0b11110011)
    }

    #[test]
    fn test_get_value() {
        use BitPreference::*;
        let pattern: PatternBlock = vec![Zero, One, Any, Any, Zero, One, One, One].into();
        assert_eq!(pattern.get_value(&BitRange::new(0, 7)), 0b11100010)
    }

    #[test]
    fn test_matches() {
        use BitPreference::*;
        let pattern: PatternBlock = vec![
            Zero, One, Any, Any, Zero, One, One, Any, Any, Any, Any, Any, One, One, One, One,
        ]
        .into();
        let data = vec![0b11100010, 0b11110000];
        assert!(pattern.matches(&data))
    }
}
