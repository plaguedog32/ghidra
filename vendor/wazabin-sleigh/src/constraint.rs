//! Compilation of SLEIGH pattern constraints into [`TokenPattern`]s.
//!
//! In SLEIGH, a constructor's bit-pattern is described by a set of *constraints* — predicates on
//! token fields that must all hold for the constructor to match a given encoding.  A constraint has
//! the form `<field> <op> <expr>`, where `<op>` is `=`, `!=`, or `<` and `<expr>` is either an
//! integer literal or another field name.  Constraints can be combined with `&` (AND) and `|`
//! (OR), and fields may be prefixed with an ellipsis to denote a sub-range match.
//!
//! This module walks the [`ConstraintAst`] produced by the parser and resolves each node against
//! the symbol table in [`SpecBuilder`], producing a flat [`TokenPattern`] that encodes exactly
//! which bit combinations satisfy the constraint:
//!
//! 1. **Leaf constraints** (`field = k`, `field != k`, `field < k`) are expanded into the
//!    exhaustive set of bit-mask/bit-value pairs that satisfy the operator, one per token word.
//! 2. **Identifier leaves** (bare names) are looked up as fields, tables, or registers and turned
//!    into operand patterns.
//! 3. **Binary `&` / `|` / `cat` operators** merge two child [`TokenPattern`]s by intersecting or
//!    unioning their bit constraints.
//! 4. **Ellipsis nodes** adjust the alignment of a child pattern so that it can be matched at a
//!    variable offset within the token stream.
//!
//! Errors are returned as [`Diagnostic`](crate::diagnostic::Diagnostic) values with physical source spans.

// These types are part of the source AST that `unstable-syntax` exposes; without
// that feature nothing outside the crate can reach them.
#![cfg_attr(not(feature = "unstable-syntax"), allow(unreachable_pub))]

use crate::{
    bitrange::BitRange,
    builder::{SpecBuilder, Symbol},
    diagnostic::{BuildResult, Diagnostic, DiagnosticCode},
    objects::field::{Field, FieldId, FieldParent, field_pattern},
    pattern::{Alignment, OperandType, PatternBlock, TokenPattern},
    source::Span,
    token::{TokenContext, token_stream_bit},
};
use jstd::registry::Identified;
use std::collections::BTreeMap;

/// Ceiling on how many field-value combinations a constraint may be expanded
/// into.
///
/// Several constraint forms are compiled by enumerating the values their fields
/// can take. That is exponential in the total field width, so a spec pairing two
/// 16-bit fields would otherwise ask for four billion patterns. Specs that need
/// more than this are rejected with a diagnostic rather than left to run out of
/// memory.
const MAX_EXPANDED_VALUES: u64 = 1 << 20;

type ValueAssignment = BTreeMap<Box<str>, u64>;
type ValueAssignmentVisitor<'a> = dyn FnMut(&ValueAssignment) -> BuildResult<()> + 'a;

/// The type of the constraint
/// This is the operator that sits between the field and the expression
/// <field> <ConstraintVerb> <expression>
#[derive(Debug, Clone, Copy)]
pub enum ConstraintVerb {
    /// Equal
    Eq,

    /// Not equal
    Ne,

    /// Lesser than
    Lt,

    /// Lesser than or equal
    Le,

    /// Greater than
    Gt,

    /// Greater than or equal
    Ge,
}

impl ConstraintVerb {
    /// The operator as it is spelled in SLEIGH source.
    pub fn symbol(self) -> &'static str {
        match self {
            Self::Eq => "=",
            Self::Ne => "!=",
            Self::Lt => "<",
            Self::Le => "<=",
            Self::Gt => ">",
            Self::Ge => ">=",
        }
    }

    fn is_ne(self) -> bool {
        matches!(self, Self::Ne)
    }

    /// Is this one of the four ordering verbs, as opposed to `=` / `!=`?
    fn is_ordered(self) -> bool {
        matches!(self, Self::Lt | Self::Le | Self::Gt | Self::Ge)
    }
}

/// An operator in the expression
#[derive(Debug, Clone, Copy)]
pub enum BitVerb {
    /// Bitwise and
    And,

    /// Bitwise or
    Or,

    /// Concatenation of two ?
    Cat,
}

/// An arithmetic operator in a constraint value expression.
#[derive(Debug, Clone, Copy)]
pub enum ValueVerb {
    /// Addition.
    Add,

    /// Subtraction.
    Sub,

    /// Multiplication.
    Mul,

    /// Division.
    Div,

    /// Left shift.
    Shl,

    /// Right shift.
    Shr,
}

/// A node of a constructor's bit-pattern expression, before it is compiled
/// into the bit-level [`TokenPattern`].
#[derive(Debug, Clone)]
pub enum BitPatternAstNode {
    /// A bare name: a field, a sub-table operand, or a register.
    Ident(Box<str>),

    /// `field <op> expr` — a comparison the encoding must satisfy.
    Constraint {
        lhs: Box<str>,
        op: ConstraintVerb,
        rhs: Box<ConstraintAst>,
    },

    ValueBinOp {
        lhs: Box<ConstraintAst>,
        op: ValueVerb,
        rhs: Box<ConstraintAst>,
    },

    /// A trailing `...`: the term is matched at a variable offset from the
    /// left, so the pattern is left-aligned.
    RElipsis(Box<ConstraintAst>),

    /// A leading `...`: the term is matched at a variable offset from the
    /// right. Parsed but not yet compiled, so the inner pattern is carried
    /// and never read.
    LElipsis(#[allow(dead_code)] Box<ConstraintAst>),

    /// Two patterns combined with `&`, `|` or `;`.
    BinOp {
        /// Left-hand pattern.
        lhs: Box<ConstraintAst>,
        op: BitVerb,
        rhs: Box<ConstraintAst>,
    },

    Int(u64),
}

#[derive(Debug, Clone)]
pub struct ConstraintAst {
    /// The ast of this constraint
    pub value: BitPatternAstNode,

    /// Physical source span for error reporting.
    pub span: Span,
}

impl ConstraintAst {
    /// Creates the resulting constraint after "anding" two constraints
    pub fn and(self, other: Self, span: Span) -> Self {
        Self {
            value: BitPatternAstNode::BinOp {
                lhs: Box::new(self),
                op: BitVerb::And,
                rhs: Box::new(other),
            },

            span,
        }
    }

    /// Tries to get a field by name, otherwise returns an error
    fn try_get_field<'b>(
        &self,
        ctx: &'b SpecBuilder,
        name: &str,
    ) -> BuildResult<Identified<FieldId, &'b Field>> {
        ctx.try_get_field(name).ok_or_else(|| {
            Box::new(Diagnostic::error(
                DiagnosticCode::Compile,
                format!("\"{name}\" is not a field"),
                self.span,
            ))
        })
    }

    /// Builds [`TokenPattern`] with an operand
    fn build_operand(&self, ctx: &mut SpecBuilder, name: &str) -> BuildResult<TokenPattern> {
        match ctx.get_symbol(name) {
            Symbol::Field(field) => Ok(field_pattern(field)),

            Symbol::Table(table) => {
                let id = table.id;

                if let Some(pat) = &table.pattern {
                    Ok(pat.clone().with_operand(OperandType::Table(id)))
                } else {
                    ctx.concretize_table(id)
                        .map(|pattern| pattern.with_operand(OperandType::Table(id)))
                }
            }

            Symbol::Register(reg) => {
                Ok(TokenPattern::default().with_operand(OperandType::Register(reg.id)))
            }

            _ => Err(Box::new(Diagnostic::error(
                DiagnosticCode::Compile,
                format!("Unrecognized name \"{name}\""),
                self.span,
            ))),
        }
    }

    /// Creates a [`TokenPattern`] from a `<field> <op> <int>` constraint
    fn constraint_int_to_pattern(
        &self,
        ctx: &SpecBuilder,
        name: &str,
        op: ConstraintVerb,
        value: u64,
    ) -> BuildResult<TokenPattern> {
        let field = self.try_get_field(ctx, name)?;
        let width = field.width();

        // `!=` and `<` are encoded bit-wise below, against a `u64` value.
        if width >= u64::BITS as usize {
            return Err(Box::new(Diagnostic::error(
                DiagnosticCode::Compile,
                format!(
                    "Field \"{name}\" is {width} bits wide; constraints are limited to {} bits",
                    u64::BITS - 1
                ),
                self.span,
            )));
        }
        // The number of distinct values the field can hold.
        let field_size = 1u64 << width;

        // The ordering verbs describe sets that are exponentially large in the
        // field width, so they are decomposed into a linear number of bit
        // patterns rather than enumerated value by value: a 32-bit `!=` would
        // otherwise materialize four billion patterns.
        //
        // `<=`, `>` and `>=` are first rewritten in terms of `<` and `>`, which
        // is exact on the field's own value range — the endpoints that would
        // overflow the rewrite are the ones that make the constraint constant.
        let max = field_size - 1;
        match op {
            ConstraintVerb::Eq => {}

            ConstraintVerb::Ne if value < field_size => {
                // x != K  ⟺  ∃i. bit i of x differs from bit i of K.
                // One disjunct per bit, versus 2^width - 1 values.
                return self.any_bit_differs(ctx, &field, name, value, width);
            }

            ConstraintVerb::Lt if value < field_size => {
                // x < K  ⟺  ∃i where K has a 1 bit: x agrees with K above bit
                // i and has 0 at bit i. One disjunct per set bit of K, and the
                // disjuncts are pairwise disjoint.
                return self.less_than(ctx, &field, name, value, width);
            }

            // x <= K  ⟺  x < K+1, and every value is <= the field's maximum.
            ConstraintVerb::Le if value < max => {
                return self.less_than(ctx, &field, name, value + 1, width);
            }
            ConstraintVerb::Le => return Ok(TokenPattern::default()),

            // x > K  ⟺  ∃i where K has a 0 bit: x agrees with K above bit i
            // and has 1 at bit i. Nothing exceeds the field's maximum.
            ConstraintVerb::Gt if value < max => {
                return self.greater_than(ctx, &field, name, value, width);
            }
            ConstraintVerb::Gt => return Ok(TokenPattern::impossible()),

            // x >= K  ⟺  x > K-1, and every value is >= 0.
            ConstraintVerb::Ge if value == 0 => return Ok(TokenPattern::default()),
            ConstraintVerb::Ge if value <= max => {
                return self.greater_than(ctx, &field, name, value - 1, width);
            }
            ConstraintVerb::Ge => return Ok(TokenPattern::impossible()),

            // A comparison against a value too large for the field is constant:
            // every encoding is `!=` it and `<` it. `Eq` falls through and
            // builds the (unsatisfiable) pattern, matching the previous
            // behaviour.
            ConstraintVerb::Ne | ConstraintVerb::Lt => {
                return Ok(TokenPattern::default());
            }
        }

        let values = [value];

        let patterns: Vec<_> = match field.parent {
            FieldParent::Token(tok) => values
                .iter()
                .map(|&v| TokenPattern::from_insn_value(ctx, tok, &field.range, v))
                .collect(),

            FieldParent::Context => values
                .iter()
                .map(|&v| TokenPattern::from_ctx_value(&field.range, v))
                .collect(),

            FieldParent::Global => {
                return Err(Box::new(Diagnostic::error(
                    DiagnosticCode::Compile,
                    "Found a global in a pattern",
                    self.span,
                )));
            }
        };

        let span = self.span;
        TokenPattern::from_iter(ctx, patterns).map_err(|err| {
            Box::new(Diagnostic::error(
                DiagnosticCode::Compile,
                err.to_string(),
                span,
            ))
        })
    }

    /// A pattern constraining bit `i` (LSB-first within the field's value) to
    /// `bit`.
    ///
    /// The field's value bits are laid out across the token in an order that
    /// depends on the parent token's endianness, so the token bit position is
    /// resolved here rather than by handing a whole-field value to
    /// [`TokenPattern::from_insn_value`].
    ///
    /// Token bits go through [`token_stream_bit`], the one mapping field
    /// extraction also uses. A big-endian token is a **byte permutation**: it
    /// changes which stream byte a value bit lands in and leaves its position
    /// within that byte alone. Reversing the bits within the field instead —
    /// which is the *context* convention, and what this did — happens to be
    /// harmless for a whole-field equality (the same bijection applies to both
    /// sides) and is wrong for anything that reads individual bits, which is
    /// every decomposition here.
    fn field_bit_pattern(
        ctx: &SpecBuilder,
        field: &Field,
        width: usize,
        i: usize,
        bit: u64,
    ) -> TokenPattern {
        match field.parent {
            FieldParent::Token(tok) => {
                let pos = BitRange::singleton(token_stream_bit(
                    ctx.token_size(tok),
                    ctx.token_endian(tok),
                    field.range.start() + i,
                ));
                TokenPattern::from_insn_pattern(tok, PatternBlock::from_le_value(&pos, bit))
            }

            // Context fields number their bits most-significant first, matching
            // `read_context`. That really is a bit reversal within the field.
            FieldParent::Context => {
                let pos = BitRange::singleton(field.range.start() + width - 1 - i);
                TokenPattern::from_ctx_value(&pos, bit)
            }

            FieldParent::Global => TokenPattern::impossible(),
        }
    }

    /// Builds `field != value` as one disjunct per bit, rather than one per
    /// non-matching value.
    fn any_bit_differs(
        &self,
        ctx: &SpecBuilder,
        field: &Field,
        name: &str,
        value: u64,
        width: usize,
    ) -> BuildResult<TokenPattern> {
        if field.parent == FieldParent::Global {
            return Err(self.global_in_pattern());
        }

        let disjuncts = (0..width).map(|i| {
            let differing = (value >> i) & 1 ^ 1;
            Self::field_bit_pattern(ctx, field, width, i, differing)
        });

        self.union(ctx, disjuncts, name)
    }

    /// Builds `field < value` as one disjunct per set bit of `value`.
    ///
    /// Each disjunct pins the bits above some set bit of `value` to `value`'s
    /// own bits and forces that bit to zero, leaving the rest free; the
    /// disjuncts partition `0..value`.
    fn less_than(
        &self,
        ctx: &SpecBuilder,
        field: &Field,
        name: &str,
        value: u64,
        width: usize,
    ) -> BuildResult<TokenPattern> {
        if field.parent == FieldParent::Global {
            return Err(self.global_in_pattern());
        }

        let mut disjuncts = Vec::new();
        for i in (0..width).filter(|&i| (value >> i) & 1 == 1) {
            // bits above i must equal value's, and bit i must be 0
            let mut conjunct = Self::field_bit_pattern(ctx, field, width, i, 0);
            for hi in i + 1..width {
                let bit = (value >> hi) & 1;
                let clause = Self::field_bit_pattern(ctx, field, width, hi, bit);
                conjunct = conjunct.and(ctx, &clause).map_err(|err| {
                    Box::new(Diagnostic::error(
                        DiagnosticCode::Compile,
                        err.to_string(),
                        self.span,
                    ))
                })?;
            }
            disjuncts.push(conjunct);
        }

        self.union(ctx, disjuncts, name)
    }

    /// Intersects two patterns, turning the pattern error into a diagnostic.
    fn conjoin(
        &self,
        ctx: &SpecBuilder,
        lhs: &TokenPattern,
        rhs: &TokenPattern,
    ) -> BuildResult<TokenPattern> {
        lhs.and(ctx, rhs).map_err(|err| {
            Box::new(Diagnostic::error(
                DiagnosticCode::Compile,
                err.to_string(),
                self.span,
            ))
        })
    }

    /// Builds `lhs = rhs` between two fields, one disjunct per shared value.
    ///
    /// The bits are placed through [`Self::field_bit_pattern`] rather than by
    /// masking a whole value into the token. Those are the same thing for a
    /// little-endian token and not for a big-endian one, where a value bit
    /// lands in a different stream byte: masking wrote the constraint onto
    /// entirely the wrong bits, so `rs=rt` on MIPS accepted encodings with
    /// `rs != rt`.
    fn fields_equal(
        &self,
        ctx: &SpecBuilder,
        lhs: &Field,
        rhs: &Field,
        name: &str,
        width: usize,
        field_size: u64,
    ) -> BuildResult<TokenPattern> {
        let mut disjuncts = Vec::with_capacity(field_size as usize);

        for value in 0..field_size {
            let mut conjunct = TokenPattern::default();
            for i in 0..width {
                let bit = (value >> i) & 1;
                let lhs_clause = Self::field_bit_pattern(ctx, lhs, width, i, bit);
                let rhs_clause = Self::field_bit_pattern(ctx, rhs, width, i, bit);
                conjunct = self.conjoin(ctx, &conjunct, &lhs_clause)?;
                conjunct = self.conjoin(ctx, &conjunct, &rhs_clause)?;
            }
            disjuncts.push(conjunct);
        }

        self.union(ctx, disjuncts, name)
    }

    /// Builds `lhs != rhs` between two fields, as two disjuncts per bit.
    ///
    /// `a != b` holds exactly when some bit differs, and a bit differs in one
    /// of two ways — so each bit position contributes `{a[i]=0, b[i]=1}` and
    /// `{a[i]=1, b[i]=0}`. That is `2·width` disjuncts, against the `2^width -
    /// 1` value pairs an enumeration would need.
    ///
    /// The disjuncts overlap (two values may differ in several bits), which is
    /// fine: matching takes any disjunct, not exactly one.
    ///
    /// Signedness does not matter here. Two's-complement equality is bit
    /// equality, so the same decomposition is correct for signed fields.
    fn fields_differ(
        &self,
        ctx: &SpecBuilder,
        lhs: &Field,
        rhs: &Field,
        name: &str,
        width: usize,
    ) -> BuildResult<TokenPattern> {
        let mut disjuncts = Vec::with_capacity(2 * width);

        for i in 0..width {
            for (lhs_bit, rhs_bit) in [(0u64, 1u64), (1, 0)] {
                let lhs_clause = Self::field_bit_pattern(ctx, lhs, width, i, lhs_bit);
                let rhs_clause = Self::field_bit_pattern(ctx, rhs, width, i, rhs_bit);
                disjuncts.push(self.conjoin(ctx, &lhs_clause, &rhs_clause)?);
            }
        }

        self.union(ctx, disjuncts, name)
    }

    /// Builds `lhs < rhs` between two fields, unsigned, by first differing bit.
    ///
    /// `a < b` holds exactly when there is a bit `i` where `a` has 0 and `b`
    /// has 1 and the two agree above it. The agreeing high bits have to be
    /// enumerated — there are `2^(width-1-i)` ways for them to agree — so the
    /// whole expansion is `2^width - 1` disjuncts, no worse than the `=` form
    /// next door, and the disjuncts partition the satisfying pairs.
    ///
    /// Bits are addressed through [`Self::field_bit_pattern`], which resolves a
    /// value bit to a token bit under the parent token's endianness. Going
    /// through whole masked values instead — the way the `=` expansion does —
    /// would be wrong here: a big-endian token reverses the bits within a
    /// field, which equality survives (it is the same bijection on both sides)
    /// and ordering does not.
    fn fields_less_than(
        &self,
        ctx: &SpecBuilder,
        lhs: &Field,
        rhs: &Field,
        name: &str,
        width: usize,
    ) -> BuildResult<TokenPattern> {
        let mut disjuncts = Vec::new();

        for i in 0..width {
            let lhs_low = Self::field_bit_pattern(ctx, lhs, width, i, 0);
            let rhs_low = Self::field_bit_pattern(ctx, rhs, width, i, 1);
            let first_difference = self.conjoin(ctx, &lhs_low, &rhs_low)?;

            let high_bits = width - 1 - i;
            for combination in 0..(1u64 << high_bits) {
                let mut conjunct = first_difference.clone();
                for j in 0..high_bits {
                    let bit = (combination >> j) & 1;
                    let lhs_clause = Self::field_bit_pattern(ctx, lhs, width, i + 1 + j, bit);
                    let rhs_clause = Self::field_bit_pattern(ctx, rhs, width, i + 1 + j, bit);
                    conjunct = self.conjoin(ctx, &conjunct, &lhs_clause)?;
                    conjunct = self.conjoin(ctx, &conjunct, &rhs_clause)?;
                }
                disjuncts.push(conjunct);
            }
        }

        self.union(ctx, disjuncts, name)
    }

    /// Builds `field > value` as one disjunct per clear bit of `value`.
    ///
    /// The mirror of [`Self::less_than`]: each disjunct pins the bits above
    /// some clear bit of `value` to `value`'s own bits and forces that bit to
    /// one, leaving the rest free. The disjuncts partition `value+1 ..= max`.
    fn greater_than(
        &self,
        ctx: &SpecBuilder,
        field: &Field,
        name: &str,
        value: u64,
        width: usize,
    ) -> BuildResult<TokenPattern> {
        if field.parent == FieldParent::Global {
            return Err(self.global_in_pattern());
        }

        let mut disjuncts = Vec::new();
        for i in (0..width).filter(|&i| (value >> i) & 1 == 0) {
            // bits above i must equal value's, and bit i must be 1
            let mut conjunct = Self::field_bit_pattern(ctx, field, width, i, 1);
            for hi in i + 1..width {
                let bit = (value >> hi) & 1;
                let clause = Self::field_bit_pattern(ctx, field, width, hi, bit);
                conjunct = self.conjoin(ctx, &conjunct, &clause)?;
            }
            disjuncts.push(conjunct);
        }

        self.union(ctx, disjuncts, name)
    }

    fn union(
        &self,
        ctx: &SpecBuilder,
        patterns: impl IntoIterator<Item = TokenPattern>,
        name: &str,
    ) -> BuildResult<TokenPattern> {
        TokenPattern::from_iter(ctx, patterns).map_err(|err| {
            Box::new(Diagnostic::error(
                DiagnosticCode::Compile,
                format!("Constraint on \"{name}\": {err}"),
                self.span,
            ))
        })
    }

    fn global_in_pattern(&self) -> Box<Diagnostic> {
        Box::new(Diagnostic::error(
            DiagnosticCode::Compile,
            "Found a global in a pattern",
            self.span,
        ))
    }

    fn constraint_ident_to_pattern(
        &self,
        ctx: &SpecBuilder,
        lhs_name: &str,
        op: ConstraintVerb,
        rhs_name: &str,
    ) -> BuildResult<TokenPattern> {
        if lhs_name == rhs_name {
            return Ok(match op {
                // `a = a`, `a <= a` and `a >= a` hold for every encoding:
                // constrain nothing.
                ConstraintVerb::Eq | ConstraintVerb::Le | ConstraintVerb::Ge => {
                    TokenPattern::default()
                }

                // `a != a`, `a < a` and `a > a` hold for none. An empty pattern
                // would say the opposite — it matches everything.
                ConstraintVerb::Ne | ConstraintVerb::Lt | ConstraintVerb::Gt => {
                    TokenPattern::impossible()
                }
            });
        }

        let lhs = self.try_get_field(ctx, lhs_name)?;
        let rhs = self.try_get_field(ctx, rhs_name)?;

        if lhs.width() != rhs.width() {
            return Err(Box::new(Diagnostic::error(
                DiagnosticCode::Compile,
                format!("Incompatible field sizes for \"{lhs_name}\" and \"{rhs_name}\""),
                self.span,
            )));
        }

        if lhs.overlaps(*rhs) {
            return Err(Box::new(Diagnostic::error(
                DiagnosticCode::Compile,
                format!("Fields {lhs_name} and {rhs_name} overlap"),
                self.span,
            )));
        }

        if lhs.parent != rhs.parent {
            return Err(Box::new(Diagnostic::error(
                DiagnosticCode::Compile,
                format!(
                    "Fields \"{lhs_name}\" and \"{rhs_name}\" belong to different tokens; \
                     comparing fields across tokens is not supported"
                ),
                self.span,
            )));
        }

        // Both decompositions address individual token bits, which only makes
        // sense for a token field.
        match lhs.parent {
            FieldParent::Token(_) => {}

            FieldParent::Context => {
                return Err(Box::new(Diagnostic::error(
                    DiagnosticCode::Compile,
                    format!(
                        "Comparing two context fields (\"{lhs_name}\" and \"{rhs_name}\") \
                         is not supported"
                    ),
                    self.span,
                )));
            }

            FieldParent::Global => return Err(self.global_in_pattern()),
        }

        let width = lhs.width();

        // `!=` decomposes bit by bit, so it costs two disjuncts per bit and
        // needs only enough room to shift within a `u64`.
        if op.is_ne() {
            if width >= u64::BITS as usize {
                return Err(Box::new(Diagnostic::error(
                    DiagnosticCode::Compile,
                    format!(
                        "Fields \"{lhs_name}\" and \"{rhs_name}\" are {width} bits wide; \
                         comparison is limited to {} bits",
                        u64::BITS - 1
                    ),
                    self.span,
                )));
            }
            return self.fields_differ(ctx, *lhs, *rhs, lhs_name, width);
        }

        // `=` and `<` both enumerate: one pattern per shared value, and one per
        // way the high bits can agree. Bound them rather than hang.
        let field_size = lhs
            .size()
            .filter(|&n| n <= MAX_EXPANDED_VALUES)
            .ok_or_else(|| {
                Box::new(Diagnostic::error(
                    DiagnosticCode::Compile,
                    format!(
                        "Comparing \"{lhs_name}\" and \"{rhs_name}\" would expand to {} patterns; \
                     field-to-field comparison is limited to {} bits",
                        lhs.size()
                            .map_or_else(|| ">= 2^64".to_string(), |n| n.to_string()),
                        MAX_EXPANDED_VALUES.trailing_zeros()
                    ),
                    self.span,
                ))
            })?;

        if op.is_ordered() {
            // The decomposition orders by raw bit weight. A signed field's
            // sign bit inverts that, so accepting one here would silently
            // compile the wrong set of encodings.
            if lhs.signed || rhs.signed {
                return Err(Box::new(Diagnostic::error(
                    DiagnosticCode::Compile,
                    format!(
                        "Comparing signed fields with \"{}\" (\"{lhs_name}\" {} \"{rhs_name}\") \
                         is not supported; the expansion is unsigned",
                        op.symbol(),
                        op.symbol()
                    ),
                    self.span,
                )));
            }

            // `a > b` is `b < a` with the operands swapped, and the inclusive
            // forms add the equal case — `a <= b` is `a < b` or `a = b`.
            let (strict_lhs, strict_rhs) = match op {
                ConstraintVerb::Lt | ConstraintVerb::Le => (*lhs, *rhs),
                _ => (*rhs, *lhs),
            };
            let strict = self.fields_less_than(ctx, strict_lhs, strict_rhs, lhs_name, width)?;

            return match op {
                ConstraintVerb::Lt | ConstraintVerb::Gt => Ok(strict),
                _ => {
                    let equal = self.fields_equal(ctx, *lhs, *rhs, lhs_name, width, field_size)?;
                    self.union(ctx, [strict, equal], lhs_name)
                }
            };
        }

        self.fields_equal(ctx, *lhs, *rhs, lhs_name, width, field_size)
    }

    fn constraint_expr_to_pattern(
        &self,
        ctx: &SpecBuilder,
        lhs_name: &str,
        op: ConstraintVerb,
        rhs: &ConstraintAst,
    ) -> BuildResult<TokenPattern> {
        match &rhs.value {
            BitPatternAstNode::Int(value) => {
                return self.constraint_int_to_pattern(ctx, lhs_name, op, *value);
            }
            BitPatternAstNode::Ident(rhs_name) => {
                return self.constraint_ident_to_pattern(ctx, lhs_name, op, rhs_name);
            }
            _ => {}
        }

        let lhs = self.try_get_field(ctx, lhs_name)?;
        if lhs.parent == FieldParent::Global {
            return Err(Box::new(Diagnostic::error(
                DiagnosticCode::Compile,
                "Found a global in a pattern",
                self.span,
            )));
        }

        let parent = lhs.parent;
        let mut fields = vec![lhs];
        rhs.collect_value_fields(ctx, &mut fields)?;

        if parent == FieldParent::Context {
            return Err(Box::new(Diagnostic::error(
                DiagnosticCode::Compile,
                "Unsupported constraint expression",
                self.span,
            )));
        }

        let FieldParent::Token(token) = parent else {
            return Err(Box::new(Diagnostic::error(
                DiagnosticCode::Compile,
                "Found a global in a pattern",
                self.span,
            )));
        };

        for field in &fields {
            if field.parent != parent {
                return Err(Box::new(Diagnostic::error(
                    DiagnosticCode::Compile,
                    "Unsupported constraint expression",
                    self.span,
                )));
            }
        }

        for (index, field) in fields.iter().enumerate() {
            if fields[..index]
                .iter()
                .any(|previous| previous.id != field.id && previous.overlaps(**field))
            {
                return Err(Box::new(Diagnostic::error(
                    DiagnosticCode::Compile,
                    format!("Fields {lhs_name} and {} overlap", field.name),
                    self.span,
                )));
            }
        }

        let span = self.span;
        let mut patterns = Vec::new();
        let mut values: BTreeMap<Box<str>, u64> = BTreeMap::new();
        self.enumerate_constraint_values(&fields, 0, &mut values, &mut |values| {
            let lhs_value = values[lhs_name];
            let rhs_value = rhs.eval_value_expr(values)?;
            let matches = match op {
                ConstraintVerb::Eq => lhs_value == rhs_value,
                ConstraintVerb::Ne => lhs_value != rhs_value,
                ConstraintVerb::Lt => lhs_value < rhs_value,
                ConstraintVerb::Le => lhs_value <= rhs_value,
                ConstraintVerb::Gt => lhs_value > rhs_value,
                ConstraintVerb::Ge => lhs_value >= rhs_value,
            };

            if matches {
                let mut mask = 0;
                let mut value = 0;
                for field in &fields {
                    let field_value = values[&field.name] << field.range.start();
                    mask |= field.mask();
                    value |= field_value;
                }

                patterns.push(TokenPattern::from_insn_pattern(
                    token,
                    PatternBlock::from_masked_value(mask, value),
                ));
            }

            Ok(())
        })?;

        let mut pattern = TokenPattern::from_iter(ctx, patterns)
            .map_err(|err| Diagnostic::error(DiagnosticCode::Compile, err.to_string(), span))?;
        for field in fields {
            pattern = pattern.with_operand(OperandType::Field(field.id));
        }
        Ok(pattern)
    }

    fn collect_value_fields<'b>(
        &self,
        ctx: &'b SpecBuilder,
        fields: &mut Vec<Identified<FieldId, &'b Field>>,
    ) -> BuildResult<()> {
        match &self.value {
            BitPatternAstNode::Ident(name) => {
                let field = self.try_get_field(ctx, name)?;
                if fields.iter().all(|existing| existing.id != field.id) {
                    fields.push(field);
                }
                Ok(())
            }
            BitPatternAstNode::Int(_) => Ok(()),
            BitPatternAstNode::ValueBinOp { lhs, rhs, .. } => {
                lhs.collect_value_fields(ctx, fields)?;
                rhs.collect_value_fields(ctx, fields)
            }
            _ => Err(Box::new(Diagnostic::error(
                DiagnosticCode::Compile,
                "Unsupported constraint expression",
                self.span,
            ))),
        }
    }

    /// The number of assignments [`Self::enumerate_constraint_values`] would
    /// visit, or `None` if that exceeds [`MAX_EXPANDED_VALUES`].
    fn expansion_size(fields: &[Identified<FieldId, &Field>]) -> Option<u64> {
        fields.iter().try_fold(1u64, |acc, field| {
            acc.checked_mul(field.size()?)
                .filter(|&n| n <= MAX_EXPANDED_VALUES)
        })
    }

    fn enumerate_constraint_values(
        &self,
        fields: &[Identified<FieldId, &Field>],
        index: usize,
        values: &mut ValueAssignment,
        visit: &mut ValueAssignmentVisitor<'_>,
    ) -> BuildResult<()> {
        // The walk is a cartesian product over every field's value range, so
        // check the total up front instead of discovering it 2^48 iterations in.
        if index == 0 && Self::expansion_size(fields).is_none() {
            let widths = fields
                .iter()
                .map(|f| format!("\"{}\" ({} bits)", f.name, f.width()))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(Box::new(Diagnostic::error(
                DiagnosticCode::Compile,
                format!(
                    "Constraint expression over {widths} expands to more than {} combinations",
                    MAX_EXPANDED_VALUES
                ),
                self.span,
            )));
        }

        if index == fields.len() {
            return visit(values);
        }

        let field = &fields[index];
        // `expansion_size` above proved every field's size is representable.
        for value in 0..field.size().unwrap_or(0) {
            values.insert(field.name.clone(), value);
            self.enumerate_constraint_values(fields, index + 1, values, visit)?;
        }
        values.remove(&field.name);
        Ok(())
    }

    fn eval_value_expr(&self, values: &BTreeMap<Box<str>, u64>) -> BuildResult<u64> {
        match &self.value {
            BitPatternAstNode::Int(value) => Ok(*value),
            BitPatternAstNode::Ident(name) => values.get(name.as_ref()).copied().ok_or_else(|| {
                Box::new(Diagnostic::error(
                    DiagnosticCode::Compile,
                    format!("\"{name}\" is not a field"),
                    self.span,
                ))
            }),
            BitPatternAstNode::ValueBinOp { lhs, op, rhs } => {
                let lhs = lhs.eval_value_expr(values)?;
                let rhs = rhs.eval_value_expr(values)?;
                // These are compile-time constants from the specification, so
                // a bad one is a spec error rather than something to wrap or
                // panic on.
                let bad = |what: &str| {
                    Box::new(Diagnostic::error(
                        DiagnosticCode::Compile,
                        format!("Invalid constraint expression: {what}"),
                        self.span,
                    ))
                };
                match op {
                    ValueVerb::Add => Ok(lhs.wrapping_add(rhs)),
                    ValueVerb::Sub => Ok(lhs.wrapping_sub(rhs)),
                    ValueVerb::Mul => Ok(lhs.wrapping_mul(rhs)),
                    ValueVerb::Div => lhs.checked_div(rhs).ok_or_else(|| bad("division by zero")),
                    ValueVerb::Shl => u32::try_from(rhs)
                        .ok()
                        .and_then(|n| lhs.checked_shl(n))
                        .ok_or_else(|| bad("shift distance out of range")),
                    ValueVerb::Shr => u32::try_from(rhs)
                        .ok()
                        .and_then(|n| lhs.checked_shr(n))
                        .ok_or_else(|| bad("shift distance out of range")),
                }
            }
            _ => Err(Box::new(Diagnostic::error(
                DiagnosticCode::Compile,
                "Unsupported constraint expression",
                self.span,
            ))),
        }
    }

    pub(crate) fn to_pattern(&self, ctx: &mut SpecBuilder) -> BuildResult<TokenPattern> {
        match &self.value {
            BitPatternAstNode::Ident(name) if name.as_ref() == "epsilon" => {
                Ok(TokenPattern::default())
            }

            BitPatternAstNode::Ident(name) => self.build_operand(ctx, name),

            BitPatternAstNode::Constraint { lhs, op, rhs } => {
                self.constraint_expr_to_pattern(ctx, lhs, *op, rhs)
            }

            BitPatternAstNode::BinOp { lhs, op, rhs } => {
                let lhs = lhs.to_pattern(ctx)?;
                let rhs = rhs.to_pattern(ctx)?;

                match op {
                    BitVerb::Or => lhs.or(ctx, &rhs),

                    BitVerb::And => lhs.and(ctx, &rhs),

                    BitVerb::Cat => lhs.cat(ctx, &rhs),
                }
                .map_err(|err| {
                    Box::new(Diagnostic::error(
                        DiagnosticCode::Compile,
                        err.to_string(),
                        self.span,
                    ))
                })
            }

            BitPatternAstNode::RElipsis(ast) => ast.to_pattern(ctx).map(|mut tok| {
                tok.alignment = Alignment::Left;
                tok
            }),

            // Right-aligned patterns are not implemented: `TokenPattern`
            // carries the alignment, but nothing builds the shifted match.
            // Reject the spec rather than compile it to the wrong thing.
            BitPatternAstNode::LElipsis(_) => Err(Box::new(Diagnostic::error(
                DiagnosticCode::Compile,
                "A leading \"...\" (right-aligned pattern) is not supported",
                self.span,
            ))),

            BitPatternAstNode::Int(_) | BitPatternAstNode::ValueBinOp { .. } => unreachable!(),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Compiler, Decoder, SourceDb};

    /// A one-token spec whose single constructor carries `constraint` on a
    /// 4-bit field, plus a catch-all so that only the constraint decides which
    /// instruction a byte decodes to.
    fn matching_values(constraint: &str) -> Vec<u8> {
        let src = format!(
            "define endian=little;
             define space ram type=ram_space size=4 default;
             define token instr(8) f=(0,3) g=(4,7);
             :hit is {constraint} & g {{ }}
             :miss is g {{ }}"
        );

        let mut sources = SourceDb::new();
        let root = sources.add_file("constraint.sla", src);
        let spec = Compiler::new(&mut sources)
            .compile(root)
            .expect("spec compiles");
        let context = spec.new_context();
        let decoder = Decoder::new(&spec);

        (0u8..=0xF)
            .filter(|&byte| {
                decoder
                    .decode_one(0x1000, &[byte], &context)
                    .map(|inst| inst.to_string().starts_with("hit"))
                    .unwrap_or(false)
            })
            .collect()
    }

    /// `!=` used to be compiled by enumerating every non-matching value, which
    /// is 2^width patterns. It is now one disjunct per bit; this pins that the
    /// matched set is unchanged.
    #[test]
    fn not_equal_matches_every_value_but_the_excluded_one() {
        for k in 0u8..=0xF {
            let expected: Vec<u8> = (0u8..=0xF).filter(|&v| v != k).collect();
            assert_eq!(
                matching_values(&format!("f!={k}")),
                expected,
                "f!={k} matched the wrong set"
            );
        }
    }

    /// `<` used to enumerate `0..k`; it is now one disjunct per set bit of `k`.
    #[test]
    fn less_than_matches_exactly_the_smaller_values() {
        for k in 0u8..=0xF {
            let expected: Vec<u8> = (0u8..k).collect();
            assert_eq!(
                matching_values(&format!("f<{k}")),
                expected,
                "f<{k} matched the wrong set"
            );
        }
    }

    /// A 32-bit `!=` used to enumerate 2^32 - 1 patterns, which does not
    /// terminate in practice. The bit-wise encoding is linear in the width, so
    /// this compiles.
    #[test]
    fn a_wide_not_equal_constraint_compiles() {
        let src = "define endian=little;
             define space ram type=ram_space size=4 default;
             define token instr(32) wide=(0,31);
             :hit is wide!=0x12345678 { }";

        let mut sources = SourceDb::new();
        let root = sources.add_file("wide.sla", src);
        let spec = Compiler::new(&mut sources).compile(root).expect("compiles");
        let context = spec.new_context();
        let decoder = Decoder::new(&spec);

        // The excluded encoding does not match; a neighbour does.
        assert!(
            decoder
                .decode_one(0x1000, &[0x78, 0x56, 0x34, 0x12], &context)
                .is_err()
        );
        assert!(
            decoder
                .decode_one(0x1000, &[0x79, 0x56, 0x34, 0x12], &context)
                .is_ok()
        );
    }

    /// A field wider than the 64-bit value the encoding works in is rejected
    /// with a diagnostic rather than panicking on the shift.
    #[test]
    fn an_over_wide_field_constraint_is_rejected() {
        let src = "define endian=little;
             define space ram type=ram_space size=4 default;
             define token instr(72) huge=(0,71);
             :hit is huge!=1 { }";

        let mut sources = SourceDb::new();
        let root = sources.add_file("huge.sla", src);
        let Err(err) = Compiler::new(&mut sources).compile(root) else {
            panic!("an over-wide field constraint should not compile");
        };
        assert!(
            err.to_string().contains("bits wide"),
            "unexpected error: {err}"
        );
    }

    /// A constraint expression is expanded as a cartesian product over its
    /// fields' value ranges, which is exponential in their combined width. Two
    /// 16-bit fields would be four billion combinations; the expansion is
    /// bounded instead.
    #[test]
    fn an_oversized_constraint_expression_is_rejected() {
        let src = "define endian=little;
             define space ram type=ram_space size=4 default;
             define token instr(24) a=(0,7) b=(8,15) c=(16,23);
             :hit is c=a+b { }";

        let mut sources = SourceDb::new();
        let root = sources.add_file("expand.sla", src);
        let Err(err) = Compiler::new(&mut sources).compile(root) else {
            panic!("an oversized constraint expression should not compile");
        };
        assert!(
            err.to_string().contains("combinations"),
            "unexpected error: {err}"
        );
    }

    /// The grammar accepts `...` on either side of a term, but the Pratt
    /// parser only knew the trailing form, so a leading `...` panicked inside
    /// pest before any diagnostic could be produced.
    #[test]
    fn a_leading_ellipsis_is_rejected_not_panicked_on() {
        let src = "define endian=little;
             define space ram type=ram_space size=4 default;
             define token instr(8) f=(0,3);
             :hit is ...f=1 { }";

        let mut sources = SourceDb::new();
        let root = sources.add_file("ellipsis.sla", src);
        let Err(err) = Compiler::new(&mut sources).compile(root) else {
            panic!("a leading ellipsis should not compile");
        };
        assert!(
            err.to_string().contains("not supported"),
            "unexpected error: {err}"
        );
    }

    /// The trailing form still compiles.
    #[test]
    fn a_trailing_ellipsis_still_compiles() {
        let src = "define endian=little;
             define space ram type=ram_space size=4 default;
             define token instr(8) f=(0,3);
             sub: is f=1 { }
             :hit sub is sub ... { }";

        let mut sources = SourceDb::new();
        let root = sources.add_file("trailing.sla", src);
        assert!(Compiler::new(&mut sources).compile(root).is_ok());
    }

    /// A constraint's value expression only allowed `+` and `-`. The Atmel
    /// specifications write `ophi9=(0x94<<1)`, which failed to parse.
    #[test]
    fn constraint_values_take_shifts_and_products() {
        // 0x94 << 1 == 0x128, and the field is 9 bits wide.
        assert_eq!(matching_values_wide("f=(0x94<<1)"), vec![0x128]);
        assert_eq!(matching_values_wide("f=(0x128>>1)"), vec![0x94]);
        assert_eq!(matching_values_wide("f=(3*4)"), vec![12]);
        assert_eq!(matching_values_wide("f=(12/4)"), vec![3]);
    }

    /// Every operator sat at one precedence level, so a mixed expression
    /// associated strictly left to right. `1+2*3` has to be 7, not 9.
    #[test]
    fn constraint_value_operators_have_precedence() {
        assert_eq!(matching_values_wide("f=(1+2*3)"), vec![7]);
        assert_eq!(matching_values_wide("f=(2*3+1)"), vec![7]);
        assert_eq!(matching_values_wide("f=(1+2<<3)"), vec![24]);
        // Parentheses still override it.
        assert_eq!(matching_values_wide("f=((1+2)*3)"), vec![9]);
    }

    /// A zero divisor or an out-of-range shift in a specification constant is
    /// a spec error, not something to wrap or panic on.
    #[test]
    fn malformed_constraint_arithmetic_is_rejected() {
        for expr in ["f=(1/0)", "f=(1<<64)", "f=(1>>64)"] {
            let src = format!(
                "define endian=little;
                 define space ram type=ram_space size=4 default;
                 define token instr(16) f=(0,8) g=(9,15);
                 :hit is {expr} & g {{ }}"
            );
            let mut sources = SourceDb::new();
            let root = sources.add_file("bad.sla", src);
            assert!(
                Compiler::new(&mut sources).compile(root).is_err(),
                "{expr} should not compile"
            );
        }
    }

    /// As [`matching_values`], but over a 9-bit field so that values above 255
    /// are representable.
    fn matching_values_wide(constraint: &str) -> Vec<u16> {
        let src = format!(
            "define endian=little;
             define space ram type=ram_space size=4 default;
             define token instr(16) f=(0,8) g=(9,15);
             :hit is {constraint} & g {{ }}
             :miss is g {{ }}"
        );

        let mut sources = SourceDb::new();
        let root = sources.add_file("wide.sla", src);
        let spec = Compiler::new(&mut sources)
            .compile(root)
            .expect("spec compiles");
        let context = spec.new_context();
        let decoder = Decoder::new(&spec);

        (0u16..=0x1FF)
            .filter(|&v| {
                decoder
                    .decode_one(0x1000, &v.to_le_bytes(), &context)
                    .map(|inst| inst.to_string().starts_with("hit"))
                    .unwrap_or(false)
            })
            .collect()
    }

    #[test]
    fn equality_still_matches_exactly_one_value() {
        for k in 0u8..=0xF {
            assert_eq!(matching_values(&format!("f={k}")), vec![k]);
        }
    }
}
