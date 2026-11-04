mod ids;
mod ops;
mod types;

pub use ids::LocalVarInterner;
pub use ids::{Builtin, LocalVarId};
pub use ops::{BinaryOperator, UnaryOperator};
pub use types::{Binop, Load, Range, RangeParam, SpaceRef, Unop};

use crate::{BitRangeFieldId, FieldId, PCodeOpId, PMacroId, RegisterId, TableId};
use serde::{Deserialize, Serialize};

/// A named thing a p-code expression refers to.
///
/// Everything but [`Ident::Global`] is fully resolved: by the time an
/// instruction's AST reaches a consumer, a name has become an index into the
/// compiled specification. Look identifiers up through the producer's
/// specification table — its register table for a [`RegisterId`], bit-range
/// table for a bit-range field, and so on.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Ident {
    /// A temporary declared inside a constructor or macro body — `local x:4`,
    /// or an assignment to a name that was never declared. Unique within one
    /// decoded instruction; see [`LocalVarId`].
    Named(LocalVarId),

    /// A machine register, as named by `define register`.
    Register(RegisterId),

    /// A named sub-range of a register, as named by `define bitrange`.
    /// The producer's bit-range table gives the parent register and byte
    /// window.
    BitRange(BitRangeFieldId),

    /// A token, context or global field. In an emitted instruction this is
    /// normally already folded to a constant; one surviving here means the
    /// decode could not supply a value for it.
    Field(FieldId),

    /// A sub-table operand. One surviving in an emitted instruction means its
    /// sub-constructor exported nothing.
    Table(TableId),
    /// An identifier absent from the symbol table during Phase 2 parsing.
    /// Resolved to the appropriate variant by the Phase 3 resolve pass.
    Global(Box<str>),
}

/// The shape of a p-code expression node.
///
/// `S` is the span type: `(usize, usize)` at parse time, `()` in the stored/runtime form.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExpressionTy<S = ()> {
    /// An integer literal.
    SizedInt {
        /// The value, zero-extended into a `u64`.
        value: u64,
        /// Explicit width in bytes from a `:n` suffix, or `None` when the
        /// literal takes its width from the context it appears in.
        size: Option<usize>,
    },

    /// `x(n)` — drop the low `n` bytes of `x`, keeping the high end.
    SubPieceMsb {
        /// The value being truncated.
        src: Box<Expression<S>>,
        /// How many bytes to drop from the bottom.
        count: usize,
    },

    /// `x:n` — keep the low `n` bytes of `x`.
    SubPieceLsb {
        /// The value being truncated.
        src: Box<Expression<S>>,
        /// How many low bytes to keep.
        count: usize,
    },

    /// `*[space]:n ptr` — a memory read.
    Load(Load<S>),

    /// `x[start, size]` — a bit range of a value.
    Range(Range<S>),

    /// A call to one of SLEIGH's built-in functions.
    FunctionCall {
        /// Which builtin.
        builtin: Builtin,
        /// Its arguments, in source order.
        args: Vec<Expression<S>>,
    },

    /// A call to a `define pcodeop` — an operation the specification declares
    /// but does not define, so a consumer must give it meaning. The name is
    /// the `id`-th entry of
    /// the producer's user-defined operation table.
    PcodeOp {
        /// Index into the specification's user-defined operation list.
        id: PCodeOpId,
        /// Its arguments, in source order.
        args: Vec<Expression<S>>,
    },

    /// A call to a `macro`. Expanded away before a consumer sees the AST;
    /// one surviving is a bug in this crate.
    MacroCall {
        /// The macro being called.
        id: PMacroId,
        /// Its arguments, in source order.
        args: Vec<Expression<S>>,
    },

    /// A call to a name the symbol table did not hold — necessarily a macro
    /// parameter, substituted when the macro is inlined. A consumer does not
    /// see this variant.
    DeferredCall {
        /// The name being called.
        name: Box<str>,
        /// Its arguments, in source order.
        args: Vec<Expression<S>>,
    },

    /// A reference to a named thing.
    Ident(Ident),

    /// A prefix operator applied to one operand.
    Unop(Unop<S>),

    /// An infix operator applied to two operands.
    Binop(Binop<S>),
}

impl From<ExpressionTy> for Expression {
    fn from(ty: ExpressionTy) -> Self {
        Self {
            ty,
            size: None,
            span: (),
        }
    }
}

impl ExpressionTy {
    /// Wraps this node in an expression with a known byte width.
    pub fn with_size(self, size: usize) -> Expression {
        Expression {
            ty: self,
            size: Some(size),
            span: (),
        }
    }

    pub(crate) fn pretty_print(&self, spec: &impl crate::PcodeResolver) -> String {
        match self {
            ExpressionTy::SizedInt { value, size } => match size {
                Some(size) => format!("{value}:{size}"),
                None => value.to_string(),
            },
            ExpressionTy::SubPieceMsb { src, count } => {
                format!("subpiece_msb({}, {})", src.pretty_print(spec), count)
            }
            ExpressionTy::SubPieceLsb { src, count } => {
                format!("subpiece_lsb({}, {})", src.pretty_print(spec), count)
            }
            ExpressionTy::Load(load) => load.pretty_print(spec),
            ExpressionTy::Range(range) => range.pretty_print(spec),
            ExpressionTy::FunctionCall { builtin, args } => {
                format!("{}({})", builtin.as_str(), pretty_print_args(args, spec))
            }
            ExpressionTy::PcodeOp { id, args } => format!(
                "{}({})",
                spec.pcode_op_name(*id),
                pretty_print_args(args, spec)
            ),
            ExpressionTy::MacroCall { id, args } => format!(
                "{}({})",
                spec.macro_name(*id),
                pretty_print_args(args, spec)
            ),
            ExpressionTy::DeferredCall { name, args } => {
                format!("{}({})", name, pretty_print_args(args, spec))
            }
            ExpressionTy::Ident(ident) => pretty_print_ident(spec, ident),
            ExpressionTy::Unop(unop) => unop.pretty_print(spec),
            ExpressionTy::Binop(binop) => binop.pretty_print(spec),
        }
    }
}

impl<S> ExpressionTy<S> {
    /// Discards source spans.
    pub fn strip_span(self) -> ExpressionTy<()> {
        match self {
            ExpressionTy::SizedInt { value, size } => ExpressionTy::SizedInt { value, size },
            ExpressionTy::SubPieceMsb { src, count } => ExpressionTy::SubPieceMsb {
                src: Box::new(src.strip_span()),
                count,
            },
            ExpressionTy::SubPieceLsb { src, count } => ExpressionTy::SubPieceLsb {
                src: Box::new(src.strip_span()),
                count,
            },
            ExpressionTy::Load(load) => ExpressionTy::Load(load.strip_span()),
            ExpressionTy::Range(range) => ExpressionTy::Range(range.strip_span()),
            ExpressionTy::FunctionCall { builtin, args } => ExpressionTy::FunctionCall {
                builtin,
                args: args.into_iter().map(Expression::strip_span).collect(),
            },
            ExpressionTy::PcodeOp { id, args } => ExpressionTy::PcodeOp {
                id,
                args: args.into_iter().map(Expression::strip_span).collect(),
            },
            ExpressionTy::MacroCall { id, args } => ExpressionTy::MacroCall {
                id,
                args: args.into_iter().map(Expression::strip_span).collect(),
            },
            ExpressionTy::DeferredCall { name, args } => ExpressionTy::DeferredCall {
                name,
                args: args.into_iter().map(Expression::strip_span).collect(),
            },
            ExpressionTy::Ident(ident) => ExpressionTy::Ident(ident),
            ExpressionTy::Unop(unop) => ExpressionTy::Unop(unop.strip_span()),
            ExpressionTy::Binop(binop) => ExpressionTy::Binop(binop.strip_span()),
        }
    }
}

/// A p-code expression: a node kind, plus the width its value has.
///
/// `S` is the span type. It is `(usize, usize)` — a byte range into the
/// preprocessed source — while the compiler is lowering, and `()` in the form
/// a consumer receives, which is the default span parameter.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Expression<S = ()> {
    /// What kind of expression this is, and its operands.
    pub ty: ExpressionTy<S>,

    /// Width of the value in bytes.
    ///
    /// `None` means the width was not written in the source and could not be
    /// inferred — a literal in a position that does not pin one down, most
    /// often. A consumer that needs a width must supply one from context
    /// rather than assume.
    pub size: Option<usize>,

    /// Where this node came from in the preprocessed source, or `()` once the
    /// compiler is done with it.
    pub span: S,
}

impl<S: std::fmt::Debug> std::fmt::Debug for Expression<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(size) = self.size {
            write!(f, "{:?} (size: {:?})", self.ty, size)
        } else {
            self.ty.fmt(f)
        }
    }
}

impl<S> Expression<S> {
    /// Discards source spans, giving the form a consumer receives.
    pub fn strip_span(self) -> Expression<()> {
        Expression {
            ty: self.ty.strip_span(),
            size: self.size,
            span: (),
        }
    }
}

impl Expression {
    /// Renders this expression in a SLEIGH-like syntax, resolving identifiers
    /// against `spec`. For diagnostics and tests; not a stable format.
    pub fn pretty_print(&self, spec: &impl crate::PcodeResolver) -> String {
        self.ty.pretty_print(spec)
    }
}

impl Expression<(usize, usize)> {
    /// Creates an integer literal with its parse-time span and optional width.
    pub fn new_int(value: u64, size: Option<usize>, span: (usize, usize)) -> Self {
        Self {
            ty: ExpressionTy::SizedInt { value, size },
            size,
            span,
        }
    }
}

fn pretty_print_args(args: &[Expression], spec: &impl crate::PcodeResolver) -> String {
    args.iter()
        .map(|arg| arg.pretty_print(spec))
        .collect::<Vec<_>>()
        .join(", ")
}

pub fn pretty_print_ident(spec: &impl crate::PcodeResolver, ident: &Ident) -> String {
    match ident {
        Ident::Named(id) => format!("v{}", id.0),
        Ident::Register(_) => spec.ident_name(ident),
        Ident::BitRange(_) => spec.ident_name(ident),
        Ident::Field(_) => spec.ident_name(ident),
        Ident::Table(id) => format!("table{}", usize::from(*id)),
        Ident::Global(name) => format!("?{name}"),
    }
}
