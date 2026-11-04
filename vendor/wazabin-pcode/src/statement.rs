use std::fmt::{self, Debug};

use crate::{Expression, FieldId, Ident, Load, PcodeResolver, Range, TableId, pretty_print_ident};
use serde::{Deserialize, Serialize};

/// A branch/call target that may be a label, an unresolved name, or an expression.
///
/// `S` is the span type: `(usize, usize)` at parse time, `()` in the stored/runtime form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LabelOrNode<S = ()> {
    /// A label declared elsewhere in the same body: `goto <loopstart>`.
    ///
    /// Control flow *within* one instruction's p-code. The matching
    /// [`AstNode::Label`] carries the same name. Names are scoped per spliced
    /// body, so two macro expansions in one instruction cannot collide.
    Label(Box<str>),

    /// A name the compiler could not resolve to a value. One reaching a
    /// consumer means the destination could not be worked out.
    Node(Box<str>),

    /// A computed destination: an address, or a value to branch through.
    Expr(Expression<S>),
}

impl<S> LabelOrNode<S> {
    /// Discards source spans.
    pub fn strip_span(self) -> LabelOrNode<()> {
        match self {
            LabelOrNode::Label(name) => LabelOrNode::Label(name),
            LabelOrNode::Node(name) => LabelOrNode::Node(name),
            LabelOrNode::Expr(expr) => LabelOrNode::Expr(expr.strip_span()),
        }
    }
}

/// The minimum number of delay-slot bytes a `delayslot(n)` directive asks for.
///
/// SLEIGH counts *bytes*, not instructions: whole instructions are parsed after
/// the current one until at least this many bytes have been consumed.
/// `delayslot(1)` is the idiom for "exactly one following instruction".
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DelaySlotArg {
    /// A literal byte count.
    Bytes(u64),

    /// A field whose decoded value is the byte count — pi32v2's `rep` computes
    /// one in its disassembly action.
    Field(FieldId),

    /// A name that was not a known symbol during Phase 2 parsing. Resolved to
    /// [`DelaySlotArg::Field`] by the Phase 3 resolve pass.
    Deferred(Box<str>),
}

/// A single p-code statement node.
///
/// `S` is the span type: `(usize, usize)` at parse time, `()` in the stored/runtime form.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AstNode<S = ()> {
    /// `x = rhs;` — write to a register, a bit-range field or a temporary.
    Assignment {
        /// What is written.
        lhs: Ident,
        /// Width in bytes from an explicit `:n` on the destination, or `None`
        /// to take it from the destination itself.
        size: Option<usize>,
        /// The value written.
        rhs: Expression<S>,
    },

    /// `*[space]:n ptr = rhs;` — a memory write.
    LoadAssignment {
        /// The destination address, space and width.
        lhs: Load<S>,
        /// Width from a `:n` on the statement rather than on the store; almost
        /// always `None`, since the store carries its own.
        size: Option<usize>,
        /// The value written.
        rhs: Expression<S>,
    },

    /// `x[start, size] = rhs;` — write to a bit range of a varnode, leaving
    /// the surrounding bits alone.
    RangeAssignment {
        /// The destination range.
        lhs: Range<S>,
        /// Explicit statement width, usually `None`.
        size: Option<usize>,
        /// The value written.
        rhs: Expression<S>,
    },

    /// `build X;` — splice in the p-code of the sub-table operand `X`.
    ///
    /// Expanded before a consumer sees the AST; one surviving is a bug in
    /// this crate.
    Build(TableId),

    /// `delayslot(n);` — splice in the p-code of the instruction(s) that follow.
    DelaySlot(DelaySlotArg),

    /// A `build X` where X was not in the symbol table during Phase 2 parsing.
    /// Resolved to `Build(TableId)` by the Phase 3 resolve pass.
    DeferredBuild(Box<str>),

    /// `<name>` — a branch destination within this instruction's own p-code.
    Label(Box<str>),

    /// `goto dest;` — an unconditional branch.
    Branch {
        /// Where to.
        target: LabelOrNode<S>,
    },

    /// `if cond goto dest;` — branch when `cond` is non-zero. Falls through
    /// to the next statement otherwise.
    ConditionalBranch {
        /// The condition, read as false when zero.
        condition: Expression<S>,
        /// Where to when it holds.
        target: LabelOrNode<S>,
    },

    /// `goto [expr];` — branch to a computed address.
    BranchIndirect {
        /// The address to branch to.
        target: Expression<S>,
    },

    /// `call dest;` — a call, which a consumer may treat as a branch that is
    /// expected to return.
    Call {
        /// Where to.
        target: LabelOrNode<S>,
    },

    /// `call [expr];` — a call to a computed address.
    CallIndirect {
        /// The address to call.
        target: Expression<S>,
    },

    /// `return [expr];` — return to a computed address.
    Return {
        /// The address returned to.
        target: Expression<S>,
    },

    /// `export x;` — the value a sub-table constructor hands to its parent.
    ///
    /// Consumed while the parent's body is expanded, so a consumer does not
    /// see this statement.
    Export(Expression<S>),

    /// An expression evaluated for its effect — in practice a call to a
    /// `define pcodeop`, whose result is discarded.
    Expression(Expression<S>),
}

impl AstNode {
    /// Renders this statement in a SLEIGH-like syntax, resolving identifiers
    /// against `spec`. For diagnostics and tests; not a stable format.
    pub fn pretty_print(&self, spec: &impl PcodeResolver) -> String {
        match self {
            AstNode::Assignment { lhs, size, rhs } => format!(
                "{}{} = {};",
                pretty_print_ident(spec, lhs),
                pretty_print_size(*size),
                rhs.pretty_print(spec)
            ),
            AstNode::LoadAssignment { lhs, size, rhs } => format!(
                "{}{} = {};",
                lhs.pretty_print(spec),
                pretty_print_size(*size),
                rhs.pretty_print(spec)
            ),
            AstNode::RangeAssignment { lhs, size, rhs } => format!(
                "{}{} = {};",
                lhs.pretty_print(spec),
                pretty_print_size(*size),
                rhs.pretty_print(spec)
            ),
            AstNode::Build(table_id) => format!("build table{};", usize::from(*table_id)),
            AstNode::DelaySlot(arg) => match arg {
                DelaySlotArg::Bytes(n) => format!("delayslot({n});"),
                DelaySlotArg::Field(id) => {
                    format!("delayslot({});", spec.field_name(*id))
                }
                DelaySlotArg::Deferred(name) => format!("delayslot({name});"),
            },
            AstNode::DeferredBuild(name) => format!("build {name};"),
            AstNode::Label(name) => format!("<{name}>"),
            AstNode::Branch { target } => format!("goto {};", pretty_print_target(spec, target)),
            AstNode::ConditionalBranch { condition, target } => format!(
                "if {} goto {};",
                condition.pretty_print(spec),
                pretty_print_target(spec, target)
            ),
            AstNode::BranchIndirect { target } => {
                format!("goto [{}];", target.pretty_print(spec))
            }
            AstNode::Call { target } => format!("call {};", pretty_print_target(spec, target)),
            AstNode::CallIndirect { target } => {
                format!("call [{}];", target.pretty_print(spec))
            }
            AstNode::Return { target } => format!("return [{}];", target.pretty_print(spec)),
            AstNode::Export(expr) => format!("export {};", expr.pretty_print(spec)),
            AstNode::Expression(expr) => format!("{};", expr.pretty_print(spec)),
        }
    }
}

impl<S> AstNode<S> {
    /// Discards source spans.
    pub fn strip_span(self) -> AstNode<()> {
        match self {
            AstNode::Assignment { lhs, size, rhs } => AstNode::Assignment {
                lhs,
                size,
                rhs: rhs.strip_span(),
            },
            AstNode::LoadAssignment { lhs, size, rhs } => AstNode::LoadAssignment {
                lhs: lhs.strip_span(),
                size,
                rhs: rhs.strip_span(),
            },
            AstNode::RangeAssignment { lhs, size, rhs } => AstNode::RangeAssignment {
                lhs: lhs.strip_span(),
                size,
                rhs: rhs.strip_span(),
            },
            AstNode::Build(table_id) => AstNode::Build(table_id),
            AstNode::DelaySlot(arg) => AstNode::DelaySlot(arg),
            AstNode::DeferredBuild(name) => AstNode::DeferredBuild(name),
            AstNode::Label(name) => AstNode::Label(name),
            AstNode::Branch { target } => AstNode::Branch {
                target: target.strip_span(),
            },
            AstNode::ConditionalBranch { condition, target } => AstNode::ConditionalBranch {
                condition: condition.strip_span(),
                target: target.strip_span(),
            },
            AstNode::BranchIndirect { target } => AstNode::BranchIndirect {
                target: target.strip_span(),
            },
            AstNode::Call { target } => AstNode::Call {
                target: target.strip_span(),
            },
            AstNode::CallIndirect { target } => AstNode::CallIndirect {
                target: target.strip_span(),
            },
            AstNode::Return { target } => AstNode::Return {
                target: target.strip_span(),
            },
            AstNode::Export(expr) => AstNode::Export(expr.strip_span()),
            AstNode::Expression(expr) => AstNode::Expression(expr.strip_span()),
        }
    }
}

/// A p-code statement with a byte-range span.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ast<S = ()> {
    /// What kind of statement this is, and its operands.
    pub ty: AstNode<S>,
    /// Where it came from in the preprocessed source, or `()` once the
    /// compiler is done with it.
    pub span: S,
}

impl<S: Debug> Debug for Ast<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.ty.fmt(f)
    }
}

impl<S> Ast<S> {
    /// Discards source spans.
    pub fn strip_span(self) -> Ast<()> {
        Ast {
            ty: self.ty.strip_span(),
            span: (),
        }
    }
}

impl From<AstNode> for Ast {
    fn from(ty: AstNode) -> Self {
        Self { ty, span: () }
    }
}

impl Ast {
    /// Renders this statement in a SLEIGH-like syntax, resolving identifiers
    /// against `spec`. For diagnostics and tests; not a stable format.
    pub fn pretty_print(&self, spec: &impl PcodeResolver) -> String {
        self.ty.pretty_print(spec)
    }
}

fn pretty_print_target(spec: &impl PcodeResolver, target: &LabelOrNode) -> String {
    match target {
        LabelOrNode::Label(name) => format!("<{name}>"),
        LabelOrNode::Node(name) => (*name).to_string(),
        LabelOrNode::Expr(expr) => expr.pretty_print(spec),
    }
}

fn pretty_print_size(size: Option<usize>) -> String {
    size.map(|size| format!(":{size}")).unwrap_or_default()
}
