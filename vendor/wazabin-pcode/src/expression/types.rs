use crate::{BinaryOperator, Expression, PcodeResolver, SpaceId, UnaryOperator};
use serde::{Deserialize, Serialize};

/// A space reference that may be unresolved at Phase 2 parse time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpaceRef {
    /// A space of the compiled specification. Always this variant by the time
    /// a consumer sees an expression.
    Resolved(SpaceId),
    /// Space name absent from the symbol table during Phase 2; resolved in Phase 3.
    Deferred(Box<str>),
}

impl SpaceRef {
    /// The space this refers to.
    ///
    /// # Panics
    ///
    /// Panics on [`SpaceRef::Deferred`], which cannot occur in an expression
    /// handed to a consumer — compilation resolves every space name or fails.
    pub fn resolved(&self) -> SpaceId {
        match self {
            SpaceRef::Resolved(id) => *id,
            SpaceRef::Deferred(name) => panic!("unresolved space `{name}` reached runtime"),
        }
    }
}

/// A bit position or width in a [`Range`], which a macro may parameterise.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RangeParam {
    /// A constant number of bits.
    Literal(usize),

    /// A macro parameter standing in for one. Substituted when the macro is
    /// expanded, so a consumer does not see this variant.
    MacroArg(crate::LocalVarId),
}

/// `x[start, size]` — `size` bits of `x`, counting from bit `start`.
///
/// Bit 0 is the least significant. The result is the smallest whole number of
/// bytes that holds `size` bits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Range<S = ()> {
    /// The value being sliced.
    pub value: Box<Expression<S>>,
    /// Index of the lowest bit taken, counting from the least significant.
    pub start: RangeParam,
    /// How many bits to take.
    pub size: RangeParam,
}

impl<S> Range<S> {
    /// Discards source spans.
    pub fn strip_span(self) -> Range<()> {
        Range {
            value: Box::new(self.value.strip_span()),
            start: self.start,
            size: self.size,
        }
    }
}

impl Range {
    /// Renders this range in a diagnostic-oriented SLEIGH-like syntax.
    pub fn pretty_print(&self, spec: &impl PcodeResolver) -> String {
        format!(
            "range({}, {}, {})",
            self.value.pretty_print(spec),
            pretty_print_range_param(&self.start),
            pretty_print_range_param(&self.size)
        )
    }
}

/// `*[space]:size ptr` — a read from memory.
///
/// A load from the constant space is not a memory access at all: it is the
/// pointer value itself, taken at the declared width.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Load<S = ()> {
    /// Which space to read, or `None` for the producer's default space.
    pub space: Option<SpaceRef>,

    /// How many bytes to read, or `None` when the width is not written and
    /// must come from the context the load appears in.
    pub size: Option<usize>,

    /// The address to read from.
    pub ptr: Box<Expression<S>>,
}

impl<S> Load<S> {
    /// Discards source spans.
    pub fn strip_span(self) -> Load<()> {
        Load {
            space: self.space,
            size: self.size,
            ptr: Box::new(self.ptr.strip_span()),
        }
    }
}

impl Load {
    /// Renders this load in a diagnostic-oriented SLEIGH-like syntax.
    pub fn pretty_print(&self, spec: &impl PcodeResolver) -> String {
        let mut parts = Vec::new();
        if let Some(space) = &self.space {
            let name = match space {
                SpaceRef::Resolved(id) => pretty_print_space(spec, *id),
                SpaceRef::Deferred(name) => format!("?{name}"),
            };
            parts.push(format!("space={name}"));
        }
        if let Some(size) = self.size {
            parts.push(format!("size={size}"));
        }
        parts.push(format!("ptr={}", self.ptr.pretty_print(spec)));
        format!("load({})", parts.join(", "))
    }
}

/// A prefix operator and its operand.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unop<S = ()> {
    /// Which operator.
    pub op: UnaryOperator,
    /// The operand.
    pub e: Box<Expression<S>>,
}

impl<S> Unop<S> {
    /// Discards source spans.
    pub fn strip_span(self) -> Unop<()> {
        Unop {
            op: self.op,
            e: Box::new(self.e.strip_span()),
        }
    }
}

impl Unop {
    /// Renders this unary expression in a diagnostic-oriented SLEIGH-like syntax.
    pub fn pretty_print(&self, spec: &impl PcodeResolver) -> String {
        let expr = self.e.pretty_print(spec);
        match self.op {
            UnaryOperator::LogicalNot => format!("!{expr}"),
            UnaryOperator::BitwiseNot => format!("~{expr}"),
            UnaryOperator::Minus => format!("-{expr}"),
            UnaryOperator::FloatMinus => format!("f-{expr}"),
            UnaryOperator::AddressOf(Some(size)) => format!("&:{size} {expr}"),
            UnaryOperator::AddressOf(None) => format!("&{expr}"),
        }
    }
}

/// An infix operator and its two operands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Binop<S = ()> {
    /// Which operator.
    pub op: BinaryOperator,
    /// Left operand.
    pub lhs: Box<Expression<S>>,
    /// Right operand.
    pub rhs: Box<Expression<S>>,
}

impl<S> Binop<S> {
    /// Discards source spans.
    pub fn strip_span(self) -> Binop<()> {
        Binop {
            op: self.op,
            lhs: Box::new(self.lhs.strip_span()),
            rhs: Box::new(self.rhs.strip_span()),
        }
    }
}

impl Binop {
    /// Renders this binary expression in a diagnostic-oriented SLEIGH-like syntax.
    pub fn pretty_print(&self, spec: &impl PcodeResolver) -> String {
        format!(
            "({} {} {})",
            self.lhs.pretty_print(spec),
            self.op.pretty_print(),
            self.rhs.pretty_print(spec)
        )
    }
}

fn pretty_print_range_param(param: &RangeParam) -> String {
    match param {
        RangeParam::Literal(value) => value.to_string(),
        RangeParam::MacroArg(id) => format!("arg{}", id.0),
    }
}

fn pretty_print_space(spec: &impl PcodeResolver, id: SpaceId) -> String {
    spec.space_name(id)
}
