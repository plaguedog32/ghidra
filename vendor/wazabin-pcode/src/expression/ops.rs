//! The operators of SLEIGH's p-code expression language.
//!
//! SLEIGH's operands carry a size but no type, so an operator has to say how
//! its bits are to be read. Where a machine operation differs between signed,
//! unsigned and floating-point interpretations, SLEIGH spells the three
//! differently — `/`, `s/` and `f/` — and each spelling is a separate variant
//! here. A consumer lowering to its own IR reads the variant, not the operand.

use serde::{Deserialize, Serialize};

/// A prefix operator in a p-code expression.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UnaryOperator {
    /// `!x` — boolean negation. Yields 1 when `x` is zero and 0 otherwise, in
    /// one byte, regardless of how wide `x` is.
    LogicalNot,

    /// `~x` — bitwise complement, in the width of `x`.
    BitwiseNot,

    /// `-x` — two's-complement negation, in the width of `x`. Wraps.
    Minus,

    /// `f-x` — floating-point negation, in the width of `x`.
    FloatMinus,

    /// `&x` or `&:n x` — the address of a varnode, as a constant.
    ///
    /// This does not read `x`; it yields where `x` lives. The payload is the
    /// explicit result width from `&:n`, in bytes, or `None` for a bare `&`,
    /// in which case the address is the width of the containing space's
    /// addresses.
    AddressOf(Option<usize>),
}

/// An infix operator in a p-code expression.
///
/// Unless a variant says otherwise, both operands and the result are the same
/// width, and arithmetic wraps rather than trapping. The comparisons are the
/// exception: they yield one byte holding 0 or 1, whatever their operands'
/// width. [`Self::is_comparison`] and its siblings classify a variant without
/// having to match all thirty-six.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum BinaryOperator {
    /// `*` — multiplication. The low half of the product, so the same for
    /// signed and unsigned operands.
    Mul,

    /// `/` — unsigned division.
    Div,

    /// `s/` — signed division, truncating towards zero.
    SignedDiv,

    /// `%` — unsigned remainder.
    Mod,

    /// `s%` — signed remainder, taking its sign from the dividend.
    SignedMod,

    /// `f/` — floating-point division.
    FloatDiv,

    /// `f*` — floating-point multiplication.
    FloatMul,

    /// `+` — addition. Two's-complement, so the same for signed and unsigned
    /// operands; a carry or overflow flag is computed separately, with
    /// [`Builtin::Carry`](super::Builtin::Carry) or
    /// [`Builtin::Sborrow`](super::Builtin::Sborrow).
    Add,

    /// `-` — subtraction, likewise sign-agnostic.
    Sub,

    /// `f+` — floating-point addition.
    FloatAdd,

    /// `f-` — floating-point subtraction.
    FloatSub,

    /// `<<` — left shift. Bits shifted off the top are discarded.
    LeftShift,

    /// `>>` — logical right shift, shifting in zeroes.
    RightShift,

    /// `s>>` — arithmetic right shift, shifting in copies of the sign bit.
    SignedRightShift,

    /// `s<` — signed less-than.
    SignedLessThan,

    /// `s>` — signed greater-than.
    SignedGreaterThan,

    /// `s<=` — signed less-than-or-equal.
    SignedLessEqual,

    /// `s>=` — signed greater-than-or-equal.
    SignedGreaterEqual,

    /// `<=` — unsigned less-than-or-equal.
    LessEqual,

    /// `>=` — unsigned greater-than-or-equal.
    GreaterEqual,

    /// `<` — unsigned less-than.
    LessThan,

    /// `>` — unsigned greater-than.
    GreaterThan,

    /// `f<=` — floating-point less-than-or-equal.
    FloatLessEqual,

    /// `f>=` — floating-point greater-than-or-equal.
    FloatGreaterEqual,

    /// `f<` — floating-point less-than.
    FloatLessThan,

    /// `f>` — floating-point greater-than.
    FloatGreaterThan,

    /// `==` — bitwise equality. Sign-agnostic, since two's-complement
    /// equality is bit equality.
    Equal,

    /// `!=` — bitwise inequality.
    NotEqual,

    /// `f==` — floating-point equality, which is *not* bit equality: `NaN`
    /// compares unequal to itself, and the two zeroes compare equal.
    FloatEqual,

    /// `f!=` — floating-point inequality.
    FloatNotEqual,

    /// `^^` — boolean exclusive-or. Operands are read as false when zero and
    /// true otherwise; the result is one byte.
    LogicalXor,

    /// `&&` — boolean and. One byte, and **not** short-circuiting: p-code has
    /// no control flow inside an expression, so both operands are evaluated.
    LogicalAnd,

    /// `||` — boolean or, likewise one byte and not short-circuiting.
    LogicalOr,

    /// `^` — bitwise exclusive-or, in the width of the operands.
    BitwiseXor,

    /// `|` — bitwise or.
    BitwiseOr,

    /// `&` — bitwise and.
    BitwiseAnd,
}

impl BinaryOperator {
    /// Does this operator yield a one-byte boolean rather than a value in the
    /// width of its operands?
    pub fn is_comparison(self) -> bool {
        matches!(
            self,
            BinaryOperator::LessEqual
                | BinaryOperator::GreaterEqual
                | BinaryOperator::LessThan
                | BinaryOperator::GreaterThan
                | BinaryOperator::SignedLessThan
                | BinaryOperator::SignedGreaterThan
                | BinaryOperator::SignedLessEqual
                | BinaryOperator::SignedGreaterEqual
                | BinaryOperator::Equal
                | BinaryOperator::NotEqual
                | BinaryOperator::FloatLessThan
                | BinaryOperator::FloatLessEqual
                | BinaryOperator::FloatGreaterThan
                | BinaryOperator::FloatGreaterEqual
                | BinaryOperator::FloatEqual
                | BinaryOperator::FloatNotEqual
        )
    }

    /// Is this a shift, whose right operand is a distance rather than a value
    /// of the same width?
    pub fn is_shift(self) -> bool {
        matches!(
            self,
            BinaryOperator::LeftShift
                | BinaryOperator::RightShift
                | BinaryOperator::SignedRightShift
        )
    }

    /// Is this one of the four comparisons that read their operands as
    /// two's-complement signed integers?
    pub fn is_signed_comparison(self) -> bool {
        matches!(
            self,
            BinaryOperator::SignedLessThan
                | BinaryOperator::SignedGreaterThan
                | BinaryOperator::SignedLessEqual
                | BinaryOperator::SignedGreaterEqual
        )
    }

    /// Is this one of the six comparisons that read their operands as
    /// floating-point?
    pub fn is_float_comparison(self) -> bool {
        matches!(
            self,
            BinaryOperator::FloatLessThan
                | BinaryOperator::FloatLessEqual
                | BinaryOperator::FloatGreaterThan
                | BinaryOperator::FloatGreaterEqual
                | BinaryOperator::FloatEqual
                | BinaryOperator::FloatNotEqual
        )
    }

    /// Does this operator read its operands as floating-point, whether it
    /// compares them or computes with them?
    pub fn is_float(self) -> bool {
        matches!(
            self,
            BinaryOperator::FloatDiv
                | BinaryOperator::FloatMul
                | BinaryOperator::FloatAdd
                | BinaryOperator::FloatSub
                | BinaryOperator::FloatLessEqual
                | BinaryOperator::FloatGreaterEqual
                | BinaryOperator::FloatLessThan
                | BinaryOperator::FloatGreaterThan
                | BinaryOperator::FloatEqual
                | BinaryOperator::FloatNotEqual
        )
    }

    /// Is this a boolean connective (`&&`, `||`, `^^`) rather than a bitwise
    /// one? Both operands and the result are truth values, one byte wide.
    pub fn is_logical(self) -> bool {
        matches!(
            self,
            BinaryOperator::LogicalXor | BinaryOperator::LogicalAnd | BinaryOperator::LogicalOr
        )
    }

    /// Does this operator read its operands as two's-complement signed
    /// integers? Covers the signed comparisons plus `s/`, `s%` and `s>>`.
    pub fn is_signed_integer(self) -> bool {
        matches!(
            self,
            BinaryOperator::SignedDiv
                | BinaryOperator::SignedMod
                | BinaryOperator::SignedLessThan
                | BinaryOperator::SignedGreaterThan
                | BinaryOperator::SignedLessEqual
                | BinaryOperator::SignedGreaterEqual
                | BinaryOperator::SignedRightShift
        )
    }

    pub fn pretty_print(self) -> &'static str {
        match self {
            BinaryOperator::Mul => "*",
            BinaryOperator::Div => "/",
            BinaryOperator::SignedDiv => "s/",
            BinaryOperator::Mod => "%",
            BinaryOperator::SignedMod => "s%",
            BinaryOperator::FloatDiv => "f/",
            BinaryOperator::FloatMul => "f*",
            BinaryOperator::Add => "+",
            BinaryOperator::Sub => "-",
            BinaryOperator::FloatAdd => "f+",
            BinaryOperator::FloatSub => "f-",
            BinaryOperator::LeftShift => "<<",
            BinaryOperator::RightShift => ">>",
            BinaryOperator::SignedRightShift => "s>>",
            BinaryOperator::SignedLessThan => "s<",
            BinaryOperator::SignedGreaterThan => "s>",
            BinaryOperator::SignedLessEqual => "s<=",
            BinaryOperator::SignedGreaterEqual => "s>=",
            BinaryOperator::LessEqual => "<=",
            BinaryOperator::GreaterEqual => ">=",
            BinaryOperator::LessThan => "<",
            BinaryOperator::GreaterThan => ">",
            BinaryOperator::FloatLessEqual => "f<=",
            BinaryOperator::FloatGreaterEqual => "f>=",
            BinaryOperator::FloatLessThan => "f<",
            BinaryOperator::FloatGreaterThan => "f>",
            BinaryOperator::Equal => "==",
            BinaryOperator::NotEqual => "!=",
            BinaryOperator::FloatEqual => "f==",
            BinaryOperator::FloatNotEqual => "f!=",
            BinaryOperator::LogicalXor => "^^",
            BinaryOperator::LogicalAnd => "&&",
            BinaryOperator::LogicalOr => "||",
            BinaryOperator::BitwiseXor => "^",
            BinaryOperator::BitwiseOr => "|",
            BinaryOperator::BitwiseAnd => "&",
        }
    }
}
