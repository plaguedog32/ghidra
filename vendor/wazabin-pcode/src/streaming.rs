//! Feeding the planner and emitter one statement at a time.
//!
//! **For producer implementations.** A consumer of p-code lowers an owned
//! [`PcodeAst`](crate::PcodeAst) with [`plan_instruction`](crate::plan_instruction),
//! [`emit_instruction`](crate::emit_instruction) or
//! [`lower_instruction`](crate::lower_instruction), and never needs this
//! module. It exists for a producer — a SLEIGH decoder, say — that would
//! rather not build that instruction-wide AST only to drop it again: the
//! producer resolves its own source template on the fly and hands each
//! statement to a [`Planner`], then an [`Emitter`], as it goes.
//!
//! The lowering passes in [`crate::instruction`] walk a *shape*: an
//! expression is a literal, an identifier, a load, an operator over
//! sub-expressions, and so on. Nothing in them needs the nodes to be owned
//! [`Expression`] values. Abstracting the shape behind [`ExprNode`] lets a
//! producer hand the passes a view that resolves its template in place — an
//! operand field to the constant this encoding gave it, a sub-table to what
//! it exports — with nothing allocated to say so.
//!
//! [`&Expression`](Expression) is itself an [`ExprNode`], and
//! [`StmtKind`] is built from an [`AstNode`] with [`From`], so an owned AST is
//! one such shape rather than a special case; the AST entry points above are
//! that shape fed through the same passes.

use std::{borrow::Cow, slice};

pub use crate::instruction::{Emitter, Planner, SizeInference};
use crate::{
    AstNode, BinaryOperator, Builtin, Expression, ExpressionTy, Ident, LabelOrNode, Load,
    PCodeOpId, PcodeSpaceRef, RangeParam, SpaceId, UnaryOperator,
};

/// One p-code expression, generic over how it is stored.
///
/// A node is a cheap handle — the passes copy it freely and ask for its
/// [`kind`](Self::kind) and [`size`](Self::size) more than once — so an
/// implementation should be a reference plus whatever context resolves it,
/// never an owned tree.
pub trait ExprNode: Copy {
    /// The arguments of a call node, in order.
    type Args: Iterator<Item = Self> + ExactSizeIterator + Clone;

    /// The width in bytes this node carries, if the producer knows one.
    ///
    /// This is the [`Expression::size`] a materialised AST would have: what
    /// was written, or what the producer inferred while expanding. `None`
    /// leaves the passes to derive one from the node's shape.
    fn size(self) -> Option<usize>;

    /// The shape of this node, with its children as nodes of the same kind.
    ///
    /// `'a` is the life of anything the shape borrows from the node — the
    /// name of a deferred load space — so it is bounded by the node's own.
    fn kind<'a>(self) -> ExprKind<'a, Self>
    where
        Self: 'a;
}

/// The shape of one expression node. See [`ExpressionTy`] for the meaning of
/// each variant; this is the same inventory with the children abstracted.
#[derive(Debug, Clone)]
pub enum ExprKind<'a, E: ExprNode> {
    /// An integer literal.
    SizedInt {
        /// The value.
        value: u64,
        /// The width the literal was written with, if any.
        size: Option<usize>,
    },
    /// A named storage location.
    Ident(Ident),
    /// `*[space]:size ptr`.
    Load(LoadNode<'a, E>),
    /// `value[start, size]`.
    Range(RangeNode<E>),
    /// `src(count)`: drop `count` low bytes.
    SubPieceMsb {
        /// The value truncated.
        src: E,
        /// Bytes dropped.
        count: usize,
    },
    /// `src:count`: keep `count` low bytes.
    SubPieceLsb {
        /// The value truncated.
        src: E,
        /// Bytes kept.
        count: usize,
    },
    /// A built-in function.
    FunctionCall {
        /// Which one.
        builtin: Builtin,
        /// Its arguments.
        args: E::Args,
    },
    /// A `define pcodeop` call.
    PcodeOp {
        /// The operation.
        id: PCodeOpId,
        /// Its arguments.
        args: E::Args,
    },
    /// A unary operator.
    Unop {
        /// The operator.
        op: UnaryOperator,
        /// Its operand.
        e: E,
    },
    /// A binary operator.
    Binop {
        /// The operator.
        op: BinaryOperator,
        /// Left operand.
        lhs: E,
        /// Right operand.
        rhs: E,
    },
    /// A node that has no place in a consumer-form AST: a macro call or a
    /// deferred call. The passes reject it with
    /// [`PcodeLowerError::InternalNode`](crate::PcodeLowerError::InternalNode).
    Internal(&'static str),
}

/// The address space a load or store names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoadSpace<'a> {
    /// No space was written: the specification's default.
    Default,
    /// A resolved space.
    Resolved(SpaceId),
    /// A space name compilation never resolved, borrowed from the producer.
    /// Cannot occur in a consumer-form AST; the passes report it as
    /// unresolved, and an AST built from the node keeps the name.
    Deferred(&'a str),
}

impl<'a> From<&'a Option<PcodeSpaceRef>> for LoadSpace<'a> {
    fn from(space: &'a Option<PcodeSpaceRef>) -> Self {
        match space {
            None => LoadSpace::Default,
            Some(PcodeSpaceRef::Resolved(id)) => LoadSpace::Resolved(*id),
            Some(PcodeSpaceRef::Deferred(name)) => LoadSpace::Deferred(name),
        }
    }
}

impl From<LoadSpace<'_>> for Option<PcodeSpaceRef> {
    /// The owned form, as it reads in an AST.
    fn from(space: LoadSpace<'_>) -> Self {
        match space {
            LoadSpace::Default => None,
            LoadSpace::Resolved(id) => Some(PcodeSpaceRef::Resolved(id)),
            LoadSpace::Deferred(name) => Some(PcodeSpaceRef::Deferred(name.into())),
        }
    }
}

/// `*[space]:size ptr`, with the pointer as a node.
#[derive(Debug, Clone, Copy)]
pub struct LoadNode<'a, E> {
    /// The space read.
    pub space: LoadSpace<'a>,
    /// Bytes read, if written.
    pub size: Option<usize>,
    /// The address.
    pub ptr: E,
}

impl<'a, E> LoadNode<'a, E> {
    fn from_load<S>(load: &'a Load<S>, node: impl FnOnce(&'a Expression<S>) -> E) -> Self {
        Self {
            space: (&load.space).into(),
            size: load.size,
            ptr: node(&load.ptr),
        }
    }
}

/// `value[start, size]`, with the value as a node.
#[derive(Debug, Clone, Copy)]
pub struct RangeNode<E> {
    /// The value sliced.
    pub value: E,
    /// Lowest bit taken.
    pub start: RangeParam,
    /// Bits taken.
    pub size: RangeParam,
}

/// Where a direct branch or call goes.
#[derive(Debug, Clone)]
pub enum TargetNode<'a, E> {
    /// An instruction-local label.
    Label(Cow<'a, str>),
    /// A name the producer never resolved. Cannot occur in a consumer-form
    /// AST; the passes reject it.
    Node(&'a str),
    /// An address.
    Expr(E),
}

impl<'a, S> From<&'a LabelOrNode<S>> for TargetNode<'a, &'a Expression<S>> {
    fn from(target: &'a LabelOrNode<S>) -> Self {
        match target {
            LabelOrNode::Label(name) => TargetNode::Label(Cow::Borrowed(name)),
            LabelOrNode::Node(name) => TargetNode::Node(name),
            LabelOrNode::Expr(expr) => TargetNode::Expr(expr),
        }
    }
}

/// The shape of one statement. See [`AstNode`] for the meaning of each
/// variant.
#[derive(Debug, Clone)]
pub enum StmtKind<'a, E: ExprNode> {
    /// `lhs = rhs`.
    Assignment {
        /// The storage written.
        lhs: Ident,
        /// The width written, if any.
        size: Option<usize>,
        /// The value.
        rhs: E,
    },
    /// `*[space]:size ptr = rhs`.
    LoadAssignment {
        /// Where the value goes.
        load: LoadNode<'a, E>,
        /// The width written, if any.
        size: Option<usize>,
        /// The value.
        rhs: E,
    },
    /// `value[start, size] = rhs`.
    RangeAssignment {
        /// The bits written.
        range: RangeNode<E>,
        /// The width written, if any.
        size: Option<usize>,
        /// The value.
        rhs: E,
    },
    /// `<name>`.
    Label(Cow<'a, str>),
    /// `goto target`.
    Branch {
        /// Where.
        target: TargetNode<'a, E>,
    },
    /// `if condition goto target`.
    ConditionalBranch {
        /// The one-byte condition.
        condition: E,
        /// Where.
        target: TargetNode<'a, E>,
    },
    /// `goto [target]`.
    BranchIndirect {
        /// The address.
        target: E,
    },
    /// `call target`.
    Call {
        /// Where.
        target: TargetNode<'a, E>,
    },
    /// `call [target]`.
    CallIndirect {
        /// The address.
        target: E,
    },
    /// `return [target]`.
    Return {
        /// The address.
        target: E,
    },
    /// An expression evaluated for its effect.
    Expression(E),
    /// A statement that has no place in a consumer-form AST: `build`,
    /// `delayslot`, `export`, or a deferred `build`. The passes reject it
    /// with [`PcodeLowerError::InternalNode`](crate::PcodeLowerError::InternalNode).
    Internal(&'static str),
}

impl<'a, S> From<&'a AstNode<S>> for StmtKind<'a, &'a Expression<S>> {
    fn from(statement: &'a AstNode<S>) -> Self {
        match statement {
            AstNode::Assignment { lhs, size, rhs } => StmtKind::Assignment {
                lhs: lhs.clone(),
                size: *size,
                rhs,
            },
            AstNode::LoadAssignment { lhs, size, rhs } => StmtKind::LoadAssignment {
                load: LoadNode::from_load(lhs, |ptr| ptr),
                size: *size,
                rhs,
            },
            AstNode::RangeAssignment { lhs, size, rhs } => StmtKind::RangeAssignment {
                range: RangeNode {
                    value: &lhs.value,
                    start: lhs.start,
                    size: lhs.size,
                },
                size: *size,
                rhs,
            },
            AstNode::Build(_) => StmtKind::Internal("build statement"),
            AstNode::DelaySlot(_) => StmtKind::Internal("delay-slot directive"),
            AstNode::DeferredBuild(_) => StmtKind::Internal("deferred build statement"),
            AstNode::Label(name) => StmtKind::Label(Cow::Borrowed(name)),
            AstNode::Branch { target } => StmtKind::Branch {
                target: target.into(),
            },
            AstNode::ConditionalBranch { condition, target } => StmtKind::ConditionalBranch {
                condition,
                target: target.into(),
            },
            AstNode::BranchIndirect { target } => StmtKind::BranchIndirect { target },
            AstNode::Call { target } => StmtKind::Call {
                target: target.into(),
            },
            AstNode::CallIndirect { target } => StmtKind::CallIndirect { target },
            AstNode::Return { target } => StmtKind::Return { target },
            AstNode::Export(_) => StmtKind::Internal("export statement"),
            AstNode::Expression(expr) => StmtKind::Expression(expr),
        }
    }
}

impl<'a, S> ExprNode for &'a Expression<S> {
    type Args = slice::Iter<'a, Expression<S>>;

    fn size(self) -> Option<usize> {
        self.size
    }

    fn kind<'b>(self) -> ExprKind<'b, Self>
    where
        Self: 'b,
    {
        match &self.ty {
            ExpressionTy::SizedInt { value, size } => ExprKind::SizedInt {
                value: *value,
                size: *size,
            },
            ExpressionTy::Ident(ident) => ExprKind::Ident(ident.clone()),
            ExpressionTy::Load(load) => ExprKind::Load(LoadNode::from_load(load, |ptr| ptr)),
            ExpressionTy::Range(range) => ExprKind::Range(RangeNode {
                value: &range.value,
                start: range.start,
                size: range.size,
            }),
            ExpressionTy::SubPieceMsb { src, count } => {
                ExprKind::SubPieceMsb { src, count: *count }
            }
            ExpressionTy::SubPieceLsb { src, count } => {
                ExprKind::SubPieceLsb { src, count: *count }
            }
            ExpressionTy::FunctionCall { builtin, args } => ExprKind::FunctionCall {
                builtin: *builtin,
                args: args.iter(),
            },
            ExpressionTy::PcodeOp { id, args } => ExprKind::PcodeOp {
                id: *id,
                args: args.iter(),
            },
            ExpressionTy::MacroCall { .. } => ExprKind::Internal("macro call"),
            ExpressionTy::DeferredCall { .. } => ExprKind::Internal("deferred call"),
            ExpressionTy::Unop(unop) => ExprKind::Unop {
                op: unop.op,
                e: &unop.e,
            },
            ExpressionTy::Binop(binop) => ExprKind::Binop {
                op: binop.op,
                lhs: &binop.lhs,
                rhs: &binop.rhs,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{ExprKind, ExprNode, LoadSpace, StmtKind};
    use crate::{
        AstNode, Expression, ExpressionTy, Ident, Load, PcodeSpaceRef, RegisterId, SpaceId,
    };

    fn load(space: Option<PcodeSpaceRef>) -> Expression {
        Expression {
            ty: ExpressionTy::Load(Load {
                space,
                size: Some(4),
                ptr: Box::new(Expression {
                    ty: ExpressionTy::Ident(Ident::Register(RegisterId::new(0))),
                    size: Some(8),
                    span: (),
                }),
            }),
            size: Some(4),
            span: (),
        }
    }

    /// A deferred space keeps its name through the node and back: an AST
    /// rebuilt from the view reads exactly as the one it was built from.
    #[test]
    fn deferred_load_space_keeps_its_name() {
        let deferred = Some(PcodeSpaceRef::Deferred("segment".into()));
        let expr = load(deferred.clone());
        let ExprKind::Load(node) = (&expr).kind() else {
            panic!("a load");
        };
        assert_eq!(node.space, LoadSpace::Deferred("segment"));
        assert_eq!(Option::<PcodeSpaceRef>::from(node.space), deferred);

        let store = AstNode::LoadAssignment {
            lhs: Load {
                space: deferred.clone(),
                size: Some(4),
                ptr: Box::new(expr.clone()),
            },
            size: None,
            rhs: expr,
        };
        let StmtKind::LoadAssignment { load, .. } = StmtKind::from(&store) else {
            panic!("a store");
        };
        assert_eq!(load.space, LoadSpace::Deferred("segment"));

        assert_eq!(
            LoadSpace::from(&Some(PcodeSpaceRef::Resolved(SpaceId::new(3)))),
            LoadSpace::Resolved(SpaceId::new(3))
        );
        assert_eq!(LoadSpace::from(&None), LoadSpace::Default);
    }
}
