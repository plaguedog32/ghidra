//! Resolved views over a constructor's semantic template.
//!
//! A constructor's p-code body is compiled once and shared by every instance
//! of that constructor. What differs per decoded instruction is small: which
//! constant each operand field became, what each sub-table operand exports,
//! where this body's locals sit in the instruction's id space, and what
//! `inst_next` is. A [`Scope`] holds exactly that, and a [`View`] is a
//! template node paired with the scope that resolves it.
//!
//! The view implements [`ExprNode`], so the p-code planner and emitter can
//! walk it directly: an operand field reads as the literal it decoded to, a
//! table operand as the expression it exports, and nothing is allocated to
//! say so. [`materialize`] turns a view into the owned [`Expression`] that
//! [`Instruction::pcode_ast`](crate::Instruction::pcode_ast) returns — the
//! same tree the eager expander used to build, produced from the same scope.

use std::{borrow::Cow, slice};

use pcode_types::{
    SPACE_CONST, SpaceId,
    streaming::{ExprKind, ExprNode, LoadNode, LoadSpace, RangeNode, StmtKind, TargetNode},
};

use crate::{
    builder::SymbolId,
    instance::ConstructorInstance,
    objects::table::TableId,
    pmacro::{
        expression::{
            Binop, Builtin, Expression, ExpressionTy, Ident, Load, LocalVarId, Range, SpaceRef,
            UnaryOperator, Unop, ident_size, infer_expr_size,
        },
        statement::{Ast, AstNode, LabelOrNode},
        validate,
    },
    runtime::pcode::{
        RuntimeValue,
        collect::{Resolved, resolve_field_ident},
    },
    semantics::EmitError,
    spec::Spec,
};

/// What the sub-table operands of one body export: the body's slice of the
/// traversal's export stack.
pub(super) type BuildExports = [(TableId, RuntimeValue)];

pub(super) fn export(exports: &BuildExports, table: TableId) -> Option<&RuntimeValue> {
    exports
        .iter()
        .find(|(id, _)| *id == table)
        .map(|(_, value)| value)
}

/// Everything that resolves one body's template for one decoded instruction.
pub(super) struct Scope<'a> {
    pub(super) spec: &'a Spec,
    pub(super) instance: &'a ConstructorInstance,
    /// Offset of this body's locals in the instruction's id space.
    pub(super) base: u32,
    /// `inst_next` as the semantic section sees it — past the delay slot.
    pub(super) inst_next: u64,
    pub(super) inst_next2: Option<u64>,
    pub(super) exports: &'a BuildExports,
    /// Label namespace: `0` is the instruction's own, and each delay-slot
    /// instruction spliced into it gets its own.
    pub(super) label_scope: u32,
}

impl<'a> Scope<'a> {
    fn field(&self, id: crate::objects::field::FieldId) -> Resolved {
        resolve_field_ident(
            self.spec,
            id,
            self.instance,
            self.inst_next,
            self.inst_next2,
        )
    }

    /// Qualifies a label with the body it was declared in.
    ///
    /// `#` cannot appear in a SLEIGH identifier, so a scoped name can never
    /// collide with one a specification wrote. The instruction's own labels
    /// are left alone, so an instruction with no delay slot emits exactly
    /// what it emitted before.
    fn label(&self, name: &'a str) -> Cow<'a, str> {
        match self.label_scope {
            0 => Cow::Borrowed(name),
            scope => Cow::Owned(format!("{name}#ds{scope}")),
        }
    }

    /// A node of this body's template.
    ///
    /// An operand field is resolved here, once, rather than on each of the
    /// several queries the passes make of a node: the result is a leaf, and
    /// a leaf costs nothing to carry.
    fn node(&'a self, expr: &'a Expression) -> View<'a> {
        match &expr.ty {
            ExpressionTy::Ident(Ident::Field(id)) => View::Leaf(self.field(*id)),
            _ => View::Node {
                expr,
                scope: Some(self),
                size: None,
            },
        }
    }

    /// What an identifier in this body's template stands for.
    fn ident(&self, ident: &'a Ident) -> IdentValue<'a> {
        match ident {
            Ident::Named(id) => IdentValue::Local(LocalVarId(self.base + id.0)),
            Ident::Field(id) => IdentValue::Field(self.field(*id)),
            Ident::Table(id) => match export(self.exports, *id) {
                Some(export) => IdentValue::Export(export),
                None => IdentValue::Verbatim,
            },
            Ident::Global(name) => IdentValue::Global(name),
            Ident::Register(_) | Ident::BitRange(_) => IdentValue::Verbatim,
        }
    }
}

/// One resolved identifier.
enum IdentValue<'a> {
    /// A local of this body, rebased into the instruction's id space.
    Local(LocalVarId),
    /// An operand field.
    Field(Resolved),
    /// A sub-table operand that exported a value.
    Export(&'a RuntimeValue),
    /// The identifier stands for itself: a register, a bit range, or a table
    /// operand that exported nothing.
    Verbatim,
    /// A global name compilation never resolved. Cannot occur in a compiled
    /// specification.
    Global(&'a str),
}

/// A p-code expression as one decoded instruction sees it.
///
/// This is a handle, not a tree: a reference into the template and the
/// [`Scope`] that resolves it. Asking for its [`kind`](ExprNode::kind)
/// resolves one level — a field to its value, a table to its export, a local
/// to its rebased id — and hands back the children as further views, so the
/// whole expression is never built.
#[derive(Clone, Copy)]
pub(super) enum View<'a> {
    /// A template node resolved in `scope`, or, when `scope` is `None`, a
    /// node of a value that is already fully resolved (a sub-table export).
    ///
    /// `size` is set for the pointer of a constant-space address export,
    /// which is the value itself taken at the export's declared width.
    Node {
        expr: &'a Expression,
        scope: Option<&'a Scope<'a>>,
        size: Option<usize>,
    },
    /// A sub-table's address export, read through: `*[space]:size ptr`.
    Address {
        ptr: &'a Expression,
        space: SpaceId,
        size: usize,
    },
    /// A field's value.
    Leaf(Resolved),
}

impl<'a> View<'a> {
    /// A node of an already resolved value.
    fn resolved(expr: &'a Expression) -> Self {
        View::Node {
            expr,
            scope: None,
            size: None,
        }
    }

    /// The width [`infer_expr_size`] would give this node if it were
    /// materialised: what it carries, or for a leaf what its storage implies.
    fn inferred_size(self, spec: &Spec) -> Option<usize> {
        self.size().or_else(|| match self.kind() {
            ExprKind::SizedInt { size, .. } => size,
            ExprKind::Ident(ident) => ident_size(spec, &ident),
            _ => None,
        })
    }

    /// The width a compound template node infers from its children, in the
    /// same way [`infer_expr_size`] does for the eagerly expanded tree.
    fn infer(expr: &'a Expression, scope: &'a Scope<'a>) -> Option<usize> {
        let spec = scope.spec;
        match &expr.ty {
            ExpressionTy::SizedInt { size, .. } => *size,
            ExpressionTy::Ident(ident) => ident_size(spec, ident),
            ExpressionTy::Load(load) => load.size,
            ExpressionTy::SubPieceMsb { src, count } => scope
                .node(src)
                .inferred_size(spec)
                .map(|size| size.saturating_sub(*count)),
            ExpressionTy::SubPieceLsb { count, .. } => Some(*count),
            ExpressionTy::Range(_) => None,
            ExpressionTy::FunctionCall { builtin, args } => match builtin {
                Builtin::Carry | Builtin::Scarry | Builtin::Sborrow | Builtin::Nan => Some(1),
                Builtin::Abs | Builtin::Sqrt | Builtin::Floor | Builtin::Ceil | Builtin::Round => {
                    args.first()
                        .and_then(|arg| scope.node(arg).inferred_size(spec))
                }
                _ => None,
            },
            ExpressionTy::PcodeOp { .. }
            | ExpressionTy::MacroCall { .. }
            | ExpressionTy::DeferredCall { .. } => None,
            ExpressionTy::Unop(unop) => match unop.op {
                UnaryOperator::LogicalNot => Some(1),
                UnaryOperator::AddressOf(size) => size,
                _ => scope.node(&unop.e).inferred_size(spec),
            },
            ExpressionTy::Binop(binop) => {
                if binop.op.is_comparison() {
                    Some(1)
                } else {
                    scope.node(&binop.lhs).inferred_size(spec)
                }
            }
        }
    }
}

impl<'a> ExprNode for View<'a> {
    type Args = Args<'a>;

    fn size(self) -> Option<usize> {
        match self {
            View::Leaf(resolved) => resolved.size(),
            View::Address { size, .. } => Some(size),
            View::Node {
                size: Some(size), ..
            } => Some(size),
            View::Node {
                expr, scope: None, ..
            } => expr.size,
            View::Node {
                expr,
                scope: Some(scope),
                ..
            } => match &expr.ty {
                // A local is rebased without a width, whatever the template
                // says; a field or an export has the width of its value.
                ExpressionTy::Ident(ident) => match scope.ident(ident) {
                    IdentValue::Local(_) => None,
                    IdentValue::Field(resolved) => resolved.size(),
                    IdentValue::Export(export) => export.size(),
                    IdentValue::Verbatim | IdentValue::Global(_) => expr.size,
                },
                ExpressionTy::SizedInt { .. } => expr.size,
                _ => expr.size.or_else(|| View::infer(expr, scope)),
            },
        }
    }

    fn kind<'b>(self) -> ExprKind<'b, Self>
    where
        Self: 'b,
    {
        let (expr, scope, size) = match self {
            View::Leaf(resolved) => return resolved.kind(),
            View::Address { ptr, space, size } => {
                return ExprKind::Load(LoadNode {
                    space: LoadSpace::Resolved(space),
                    size: Some(size),
                    ptr: View::resolved(ptr),
                });
            }
            View::Node { expr, scope, size } => (expr, scope, size),
        };
        let child = |expr: &'a Expression| match scope {
            Some(scope) => scope.node(expr),
            None => View::resolved(expr),
        };
        match &expr.ty {
            ExpressionTy::SizedInt {
                value,
                size: literal_size,
            } => ExprKind::SizedInt {
                value: *value,
                size: size.or(*literal_size),
            },
            ExpressionTy::Ident(ident) => match scope.map(|scope| scope.ident(ident)) {
                Some(IdentValue::Local(id)) => ExprKind::Ident(Ident::Named(id)),
                Some(IdentValue::Field(resolved)) => resolved.kind(),
                Some(IdentValue::Export(export)) => export.view().kind(),
                Some(IdentValue::Verbatim | IdentValue::Global(_)) | None => {
                    ExprKind::Ident(ident.clone())
                }
            },
            ExpressionTy::Load(load) => ExprKind::Load(LoadNode {
                space: (&load.space).into(),
                size: load.size,
                ptr: child(&load.ptr),
            }),
            ExpressionTy::Range(range) => ExprKind::Range(RangeNode {
                value: child(&range.value),
                start: range.start,
                size: range.size,
            }),
            ExpressionTy::SubPieceMsb { src, count } => ExprKind::SubPieceMsb {
                src: child(src),
                count: *count,
            },
            ExpressionTy::SubPieceLsb { src, count } => ExprKind::SubPieceLsb {
                src: child(src),
                count: *count,
            },
            ExpressionTy::FunctionCall { builtin, args } => ExprKind::FunctionCall {
                builtin: *builtin,
                args: Args {
                    iter: args.iter(),
                    scope,
                },
            },
            ExpressionTy::PcodeOp { id, args } => ExprKind::PcodeOp {
                id: *id,
                args: Args {
                    iter: args.iter(),
                    scope,
                },
            },
            ExpressionTy::MacroCall { .. } => ExprKind::Internal("macro call"),
            ExpressionTy::DeferredCall { .. } => ExprKind::Internal("deferred call"),
            ExpressionTy::Unop(unop) => ExprKind::Unop {
                op: unop.op,
                e: child(&unop.e),
            },
            ExpressionTy::Binop(binop) => ExprKind::Binop {
                op: binop.op,
                lhs: child(&binop.lhs),
                rhs: child(&binop.rhs),
            },
        }
    }
}

/// The arguments of a call, viewed in the call's scope.
#[derive(Clone)]
pub(super) struct Args<'a> {
    iter: slice::Iter<'a, Expression>,
    scope: Option<&'a Scope<'a>>,
}

impl<'a> Iterator for Args<'a> {
    type Item = View<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let expr = self.iter.next()?;
        Some(match self.scope {
            Some(scope) => scope.node(expr),
            None => View::resolved(expr),
        })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.iter.size_hint()
    }
}

impl ExactSizeIterator for Args<'_> {}

impl RuntimeValue {
    /// This value as an expression node.
    fn view(&self) -> View<'_> {
        match self {
            Self::Expr(expr) => View::resolved(expr),
            // A load from the constant space is the pointer value itself, but
            // the declared size still applies: `*[const]:4 imm` is `imm` as a
            // four-byte value, whatever width `imm` was decoded at.
            Self::Address { ptr, space, size } if *space == SPACE_CONST => View::Node {
                expr: ptr,
                scope: None,
                size: Some(*size),
            },
            Self::Address { ptr, space, size } => View::Address {
                ptr,
                space: *space,
                size: *size,
            },
        }
    }

    /// The pointer directly, ignoring space and size: a branch target.
    fn direct_target_view(&self) -> View<'_> {
        match self {
            Self::Expr(expr) | Self::Address { ptr: expr, .. } => View::resolved(expr),
        }
    }

    /// The width of the value, when it has one.
    pub(super) fn size(&self) -> Option<usize> {
        match self {
            Self::Expr(expr) => expr.size,
            Self::Address { size, .. } => Some(*size),
        }
    }
}

/// Resolves one template statement for the visitor.
///
/// `build`, `delayslot` and `export` are the traversal's business and never
/// reach here.
pub(super) fn statement<'a>(scope: &'a Scope<'a>, statement: &'a Ast) -> StmtKind<'a, View<'a>> {
    match &statement.ty {
        AstNode::Assignment { lhs, size, rhs } => {
            let rhs = scope.node(rhs);
            let size = *size;
            match scope.ident(lhs) {
                IdentValue::Local(id) => StmtKind::Assignment {
                    lhs: Ident::Named(id),
                    size,
                    rhs,
                },
                IdentValue::Field(Resolved::Register { id, .. }) => StmtKind::Assignment {
                    lhs: Ident::Register(id),
                    size,
                    rhs,
                },
                IdentValue::Field(Resolved::Field(id)) => StmtKind::Assignment {
                    lhs: Ident::Field(id),
                    size,
                    rhs,
                },
                // An assignment to something that is not storage keeps only
                // its right-hand side, which the consumer then rejects as a
                // discarded value unless it is a user operation.
                IdentValue::Field(Resolved::Int { .. }) => StmtKind::Expression(rhs),
                IdentValue::Export(RuntimeValue::Expr(export)) => match &export.ty {
                    ExpressionTy::Ident(ident) => StmtKind::Assignment {
                        lhs: ident.clone(),
                        size,
                        rhs,
                    },
                    _ => StmtKind::Expression(rhs),
                },
                IdentValue::Export(RuntimeValue::Address {
                    ptr,
                    space,
                    size: width,
                }) => StmtKind::LoadAssignment {
                    load: LoadNode {
                        space: LoadSpace::Resolved(*space),
                        size: Some(*width),
                        ptr: View::resolved(ptr),
                    },
                    size: Some(*width),
                    rhs,
                },
                IdentValue::Verbatim => StmtKind::Assignment {
                    lhs: lhs.clone(),
                    size,
                    rhs,
                },
                IdentValue::Global(_) => StmtKind::Internal("unresolved global"),
            }
        }
        AstNode::LoadAssignment { lhs, size, rhs } => StmtKind::LoadAssignment {
            load: LoadNode {
                space: (&lhs.space).into(),
                size: lhs.size,
                ptr: scope.node(&lhs.ptr),
            },
            size: *size,
            rhs: scope.node(rhs),
        },
        AstNode::RangeAssignment { lhs, size, rhs } => StmtKind::RangeAssignment {
            range: RangeNode {
                value: scope.node(&lhs.value),
                start: lhs.start,
                size: lhs.size,
            },
            size: *size,
            rhs: scope.node(rhs),
        },
        AstNode::Build(_) => StmtKind::Internal("build statement"),
        AstNode::DelaySlot(_) => StmtKind::Internal("delay-slot directive"),
        AstNode::DeferredBuild(_) => StmtKind::Internal("deferred build statement"),
        AstNode::Export(_) => StmtKind::Internal("export statement"),
        AstNode::Label(name) => StmtKind::Label(scope.label(name)),
        AstNode::Branch { target } => StmtKind::Branch {
            target: scope.target(target, true),
        },
        AstNode::ConditionalBranch { condition, target } => StmtKind::ConditionalBranch {
            condition: scope.node(condition),
            target: scope.target(target, true),
        },
        AstNode::BranchIndirect { target } => StmtKind::BranchIndirect {
            target: scope.node(target),
        },
        // A `call` to a label is left as written: only branches are
        // qualified by their delay-slot scope.
        AstNode::Call { target } => StmtKind::Call {
            target: scope.target(target, false),
        },
        AstNode::CallIndirect { target } => StmtKind::CallIndirect {
            target: scope.node(target),
        },
        AstNode::Return { target } => StmtKind::Return {
            target: scope.node(target),
        },
        AstNode::Expression(expr) => StmtKind::Expression(scope.node(expr)),
    }
}

impl<'a> Scope<'a> {
    fn target(&'a self, target: &'a LabelOrNode, scoped: bool) -> TargetNode<'a, View<'a>> {
        match target {
            LabelOrNode::Label(name) if scoped => TargetNode::Label(self.label(name)),
            LabelOrNode::Label(name) => TargetNode::Label(Cow::Borrowed(name)),
            LabelOrNode::Node(name) => match self.spec.symbols.get(&**name).copied() {
                Some(SymbolId::Field(id)) => TargetNode::Expr(View::Leaf(self.field(id))),
                Some(SymbolId::Table(id)) => match export(self.exports, id) {
                    Some(export) => TargetNode::Expr(export.direct_target_view()),
                    None => TargetNode::Node(name),
                },
                _ => TargetNode::Node(name),
            },
            LabelOrNode::Expr(expr) => TargetNode::Expr(self.node(expr)),
        }
    }
}

/// The value a body exports, resolved in its scope.
pub(super) fn export_value(
    scope: &Scope<'_>,
    expr: &Expression,
) -> Result<RuntimeValue, EmitError> {
    if let ExpressionTy::Load(load) = &expr.ty {
        let ptr = materialize(scope.node(&load.ptr))?;
        let space = match &load.space {
            Some(SpaceRef::Resolved(id)) => *id,
            Some(SpaceRef::Deferred(name)) => return Err(validate::unresolved_space(name)),
            None => scope.spec.default_space,
        };
        let size = load.size.ok_or_else(validate::unsized_address_export)?;
        return Ok(RuntimeValue::Address { ptr, space, size });
    }
    // Exporting an operand that is itself an address export passes the
    // address through rather than reading it.
    if let ExpressionTy::Ident(ident) = &expr.ty
        && let IdentValue::Export(export) = scope.ident(ident)
    {
        return Ok(export.clone());
    }
    Ok(RuntimeValue::Expr(materialize(scope.node(expr))?))
}

/// Builds the owned expression a view stands for.
///
/// This is what the eager expander produced: a template node is rebuilt with
/// its children materialised and its width inferred, and an already resolved
/// value is cloned.
pub(super) fn materialize(view: View<'_>) -> Result<Expression, EmitError> {
    let (expr, scope) = match view {
        View::Leaf(resolved) => return Ok(resolved.into_expr()),
        View::Address { ptr, space, size } => {
            return Ok(RuntimeValue::Address {
                ptr: ptr.clone(),
                space,
                size,
            }
            .into_expr());
        }
        View::Node {
            expr,
            scope: None,
            size: None,
        } => return Ok(expr.clone()),
        View::Node {
            expr,
            scope: None,
            size: Some(size),
        } => {
            return Ok(RuntimeValue::Address {
                ptr: expr.clone(),
                space: SPACE_CONST,
                size,
            }
            .into_expr());
        }
        View::Node {
            expr,
            scope: Some(scope),
            ..
        } => (expr, scope),
    };
    let child = |expr: &Expression| materialize(scope.node(expr));
    let children = |args: &[Expression]| args.iter().map(child).collect::<Result<Vec<_>, _>>();
    let ty = match &expr.ty {
        ExpressionTy::SizedInt { .. } => return Ok(expr.clone()),
        ExpressionTy::Ident(ident) => {
            return Ok(match scope.ident(ident) {
                IdentValue::Local(id) => Expression {
                    ty: ExpressionTy::Ident(Ident::Named(id)),
                    size: None,
                    span: (),
                },
                IdentValue::Field(resolved) => resolved.into_expr(),
                IdentValue::Export(export) => export.clone().into_expr(),
                IdentValue::Verbatim => expr.clone(),
                IdentValue::Global(name) => return Err(validate::unresolved_global(name)),
            });
        }
        ExpressionTy::SubPieceMsb { src, count } => ExpressionTy::SubPieceMsb {
            src: Box::new(child(src)?),
            count: *count,
        },
        ExpressionTy::SubPieceLsb { src, count } => ExpressionTy::SubPieceLsb {
            src: Box::new(child(src)?),
            count: *count,
        },
        ExpressionTy::Load(load) => ExpressionTy::Load(Load {
            space: load.space.clone(),
            size: load.size,
            ptr: Box::new(child(&load.ptr)?),
        }),
        ExpressionTy::Range(range) => ExpressionTy::Range(Range {
            value: Box::new(child(&range.value)?),
            start: range.start,
            size: range.size,
        }),
        ExpressionTy::FunctionCall { builtin, args } => ExpressionTy::FunctionCall {
            builtin: *builtin,
            args: children(args)?,
        },
        ExpressionTy::PcodeOp { id, args } => ExpressionTy::PcodeOp {
            id: *id,
            args: children(args)?,
        },
        ExpressionTy::MacroCall { .. } => return Err(validate::macro_call()),
        ExpressionTy::DeferredCall { name, .. } => return Err(validate::deferred_call(name)),
        ExpressionTy::Unop(unop) => ExpressionTy::Unop(Unop {
            op: unop.op,
            e: Box::new(child(&unop.e)?),
        }),
        ExpressionTy::Binop(binop) => ExpressionTy::Binop(Binop {
            op: binop.op,
            lhs: Box::new(child(&binop.lhs)?),
            rhs: Box::new(child(&binop.rhs)?),
        }),
    };
    let mut expanded = Expression {
        ty,
        size: expr.size,
        span: (),
    };
    infer_expr_size(scope.spec, &mut expanded);
    Ok(expanded)
}
