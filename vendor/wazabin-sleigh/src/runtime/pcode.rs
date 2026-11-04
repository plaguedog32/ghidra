//! From a decoded instruction to its p-code.
//!
//! [`traverse`] walks the instruction's resolved semantics once per consumer
//! and [`view`] resolves each statement in place; this module puts the two
//! together for the three things an [`Instruction`](crate::Instruction) can
//! ask for: the owned AST, the streamed flat p-code, and — for `globalset` —
//! a sub-table's exported address.

mod collect;
mod traverse;
mod view;

use crate::{
    instance::ConstructorInstance,
    objects::table::TableId,
    pmacro::{
        expression::{
            BinaryOperator, Expression, ExpressionTy, Load, Range, SpaceRef, UnaryOperator,
        },
        statement::{AstNode, LabelOrNode},
    },
    runtime::InstructionPcodeContext,
    semantics::{EmitError, PcodeAst, PcodeStatement},
    spec::Spec,
};
use pcode_types::{
    PcodePlan, PcodeSink, SPACE_CONST, SpaceId,
    streaming::{Emitter, LoadNode, Planner, RangeNode, SizeInference, StmtKind, TargetNode},
};
use traverse::{Traversal, Visitor};
use view::View;

/// Visits nothing: for a traversal run only for its side effects, such as the
/// value a sub-table exports.
struct Ignore;

impl Visitor for Ignore {
    fn statement(&mut self, _: StmtKind<'_, View<'_>>) -> Result<(), EmitError> {
        Ok(())
    }

    fn wants_data_flow(&self) -> bool {
        false
    }
}

/// Builds the owned [`PcodeAst`].
struct Materialize {
    statements: Vec<PcodeStatement>,
}

impl Visitor for Materialize {
    fn statement(&mut self, statement: StmtKind<'_, View<'_>>) -> Result<(), EmitError> {
        let expr = view::materialize;
        let target = |target: TargetNode<'_, View<'_>>| -> Result<LabelOrNode, EmitError> {
            Ok(match target {
                TargetNode::Label(name) => LabelOrNode::Label(name.into()),
                TargetNode::Node(name) => LabelOrNode::Node(name.into()),
                TargetNode::Expr(node) => LabelOrNode::Expr(expr(node)?),
            })
        };
        let load = |load: LoadNode<View<'_>>| -> Result<Load, EmitError> {
            Ok(Load {
                space: load.space.into(),
                size: load.size,
                ptr: Box::new(expr(load.ptr)?),
            })
        };
        let ty = match statement {
            StmtKind::Assignment { lhs, size, rhs } => AstNode::Assignment {
                lhs,
                size,
                rhs: expr(rhs)?,
            },
            StmtKind::LoadAssignment {
                load: lhs,
                size,
                rhs,
            } => AstNode::LoadAssignment {
                lhs: load(lhs)?,
                size,
                rhs: expr(rhs)?,
            },
            StmtKind::RangeAssignment {
                range:
                    RangeNode {
                        value,
                        start,
                        size: bits,
                    },
                size,
                rhs,
            } => AstNode::RangeAssignment {
                lhs: Range {
                    value: Box::new(expr(value)?),
                    start,
                    size: bits,
                },
                size,
                rhs: expr(rhs)?,
            },
            StmtKind::Label(name) => AstNode::Label(name.into()),
            StmtKind::Branch { target: t } => AstNode::Branch { target: target(t)? },
            StmtKind::ConditionalBranch {
                condition,
                target: t,
            } => AstNode::ConditionalBranch {
                condition: expr(condition)?,
                target: target(t)?,
            },
            StmtKind::BranchIndirect { target: t } => AstNode::BranchIndirect { target: expr(t)? },
            StmtKind::Call { target: t } => AstNode::Call { target: target(t)? },
            StmtKind::CallIndirect { target: t } => AstNode::CallIndirect { target: expr(t)? },
            StmtKind::Return { target: t } => AstNode::Return { target: expr(t)? },
            StmtKind::Expression(node) => AstNode::Expression(expr(node)?),
            StmtKind::Internal(node) => {
                return Err(EmitError::new(format!("unresolved {node} reached runtime")));
            }
        };
        self.statements.push(PcodeStatement { ty, span: () });
        Ok(())
    }
}

pub(super) fn pcode_ast_for_instance(
    spec: &Spec,
    instance: &ConstructorInstance,
) -> Result<PcodeAst, EmitError> {
    let mut materialize = Materialize {
        statements: Vec::new(),
    };
    Traversal::new(spec, instance).run(instance, &mut materialize)?;
    Ok(PcodeAst {
        statements: materialize.statements,
    })
}

/// Feeds each statement to the p-code planner.
struct Planning(Planner);

impl Visitor for Planning {
    fn statement(&mut self, statement: StmtKind<'_, View<'_>>) -> Result<(), EmitError> {
        self.0.statement(statement);
        Ok(())
    }

    fn wants_data_flow(&self) -> bool {
        false
    }

    fn opaque_statement(&mut self) -> Result<(), EmitError> {
        self.0.opaque_statement();
        Ok(())
    }
}

/// Feeds each statement to the p-code emitter.
struct Emitting<'a, 'p, 's, S: PcodeSink>(Emitter<'a, 'p, 's, InstructionPcodeContext<'a>, S>);

impl<S: PcodeSink> Visitor for Emitting<'_, '_, '_, S> {
    fn statement(&mut self, statement: StmtKind<'_, View<'_>>) -> Result<(), EmitError> {
        self.0
            .statement(statement)
            .map_err(|error| EmitError::new(error.to_string()))
    }
}

/// Feeds each statement to the local-width inference, counting them so the
/// fixed point can be bounded the way the slice-based inference bounds it.
struct Inferring<'a> {
    inference: SizeInference<'a, InstructionPcodeContext<'a>, usize>,
    statements: usize,
}

impl Visitor for Inferring<'_> {
    fn statement(&mut self, statement: StmtKind<'_, View<'_>>) -> Result<(), EmitError> {
        self.inference.statement(statement);
        self.statements += 1;
        Ok(())
    }
}

/// Infers local widths from the emitted statements, for an instruction whose
/// bodies the specification could not fully resolve.
///
/// Each pass over the instruction can discover at least one previously
/// unknown local, and the extra pass propagates a discovery through a chain
/// of locals — the same bound as [`pcode_types::infer_local_sizes`].
fn infer_local_sizes<'a>(
    spec: &'a Spec,
    instance: &ConstructorInstance,
    context: &'a InstructionPcodeContext<'a>,
) -> Result<pcode_types::LocalSizes, EmitError> {
    let mut inferring = Inferring {
        inference: SizeInference::new(context),
        statements: 0,
    };
    let mut passes = 0;
    loop {
        inferring.statements = 0;
        Traversal::new(spec, instance).run(instance, &mut inferring)?;
        passes += 1;
        if !inferring.inference.progressed() || passes > inferring.statements {
            break;
        }
    }
    Ok(inferring.inference.finish())
}

/// Plans this instruction's flat p-code, then streams it into `make_sink`'s
/// sink: the body of
/// [`Instruction::try_pcode_ops_streamed`](crate::Instruction::try_pcode_ops_streamed).
///
/// Two walks over the resolved semantics, neither of which builds an AST: the
/// first feeds the planner and, as a side effect, resolves the local widths
/// the specification computed for each spliced body; the second feeds the
/// emitter. A `make_sink` that refuses the plan ends it there: nothing is
/// streamed.
pub(super) fn stream_instance<S: PcodeSink, E: From<EmitError>>(
    spec: &Spec,
    instance: &ConstructorInstance,
    make_sink: impl FnOnce(&PcodePlan) -> Result<S, E>,
) -> Result<S, E> {
    let context = InstructionPcodeContext::new(spec);

    let mut planning = Planning(Planner::new());
    let mut traversal = Traversal::new(spec, instance);
    traversal
        .run(instance, &mut planning)
        .map_err(EmitError::from)?;

    // Widths the specification already resolved leave the planner nothing
    // to iterate; a body this decode could not resolve falls back to
    // inferring them from the emitted statements.
    let local_sizes = if traversal.widths_resolved {
        let widths = std::mem::take(&mut traversal.local_sizes);
        // Resolving widths early is only sound if it agrees with inferring
        // them from the emitted statements. Check every decode a debug
        // build makes, so any disagreement surfaces on its own instruction.
        #[cfg(debug_assertions)]
        for (id, size) in infer_local_sizes(spec, instance, &context)? {
            debug_assert_eq!(
                widths.get(&id),
                Some(&size),
                "resolved width disagrees with inference for {id:?}"
            );
        }
        widths
    } else {
        infer_local_sizes(spec, instance, &context)?
    };
    let plan = planning.0.finish(local_sizes);

    let mut sink = make_sink(&plan)?;
    let mut emitting = Emitting(Emitter::new(&context, &plan, &mut sink));
    Traversal::new(spec, instance)
        .again(traversal)
        .run(instance, &mut emitting)
        .map_err(EmitError::from)?;
    Ok(sink)
}

/// The address a sub-table operand exports, when it is a compile-time constant.
///
/// `globalset(SomeTable, var)` commits `var` at whatever address `SomeTable`
/// exports. In the corpus those constructors always compute a relocation into a
/// disassembly-action global and then `export *:4 reloc`, which folds to a
/// literal once the operand is decoded. Returns `None` when the export cannot
/// be expanded or does not fold — the caller reports that as a typed decode
/// error rather than guessing an address.
pub(super) fn exported_address(
    spec: &Spec,
    instance: &ConstructorInstance,
    table_id: TableId,
) -> Option<u64> {
    // Built on `instance` so the child sees the same `inst_next` a disassembly
    // action would: effect collection runs before delay slots are decoded, and
    // a `globalset` address is an action-side value either way.
    let export = Traversal::new(spec, instance)
        .visit_child_scoped(instance, table_id, &mut Ignore)
        .ok()??;
    const_fold(&export.into_direct_target_expr())
}

/// Folds an expanded p-code expression to a literal, if it is one.
fn const_fold(expr: &Expression) -> Option<u64> {
    match &expr.ty {
        &ExpressionTy::SizedInt { value, .. } => Some(value),

        ExpressionTy::Unop(unop) => {
            let value = const_fold(&unop.e)?;
            match unop.op {
                UnaryOperator::Minus => Some(value.wrapping_neg()),
                UnaryOperator::BitwiseNot => Some(!value),
                _ => None,
            }
        }

        ExpressionTy::Binop(binop) => {
            let lhs = const_fold(&binop.lhs)?;
            let rhs = const_fold(&binop.rhs)?;
            // Shift distances come from decoded bytes, so they are clamped the
            // same way disassembly-action evaluation clamps them.
            let shift = || u32::try_from(rhs).ok().filter(|&s| s < u64::BITS);
            match binop.op {
                BinaryOperator::Add => Some(lhs.wrapping_add(rhs)),
                BinaryOperator::Sub => Some(lhs.wrapping_sub(rhs)),
                BinaryOperator::Mul => Some(lhs.wrapping_mul(rhs)),
                BinaryOperator::Div => lhs.checked_div(rhs),
                BinaryOperator::BitwiseAnd => Some(lhs & rhs),
                BinaryOperator::BitwiseOr => Some(lhs | rhs),
                BinaryOperator::BitwiseXor => Some(lhs ^ rhs),
                BinaryOperator::LeftShift => shift().map(|s| lhs.wrapping_shl(s)),
                BinaryOperator::RightShift => shift().map(|s| lhs.wrapping_shr(s)),
                _ => None,
            }
        }

        _ => None,
    }
}

/// A runtime p-code value: either an expression or a memory address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimeValue {
    Expr(Expression),
    Address {
        ptr: Expression,
        space: SpaceId,
        size: usize,
    },
}

impl RuntimeValue {
    /// Convert to a load expression (or the ptr directly if constant space).
    pub(crate) fn into_expr(self) -> Expression {
        match self {
            Self::Expr(expr) => expr,
            // A load from the constant space is the pointer value itself, but
            // the declared size still applies: `*[const]:4 imm` is `imm` as a
            // four-byte value, whatever width `imm` was decoded at. Dropping it
            // here made the exported operand carry the field's own width.
            Self::Address { ptr, space, size } if space == SPACE_CONST => {
                let ty = match ptr.ty {
                    // A literal carries its width in the node as well, so
                    // widening the expression alone would leave the two
                    // disagreeing.
                    ExpressionTy::SizedInt { value, .. } => ExpressionTy::SizedInt {
                        value,
                        size: Some(size),
                    },
                    other => other,
                };
                Expression {
                    ty,
                    size: Some(size),
                    span: ptr.span,
                }
            }
            Self::Address { ptr, space, size } => Expression {
                ty: ExpressionTy::Load(Load {
                    space: Some(SpaceRef::Resolved(space)),
                    size: Some(size),
                    ptr: Box::new(ptr),
                }),
                size: Some(size),
                span: (),
            },
        }
    }

    /// Return the pointer directly, ignoring space/size (for branch targets).
    pub(crate) fn into_direct_target_expr(self) -> Expression {
        match self {
            Self::Expr(expr) => expr,
            Self::Address { ptr, .. } => ptr,
        }
    }
}

/// A literal of a known width.
pub(super) fn make_int_expr(value: u64, size: usize) -> Expression {
    Expression {
        ty: ExpressionTy::SizedInt {
            value,
            size: Some(size),
        },
        size: Some(size),
        span: (),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Compiler, Decoder, PcodeSink, SourceDb};
    use pcode_types::{Ident, LabelId, Opcode, Varnode};

    /// A sink for an instruction that is expected to fail before emitting.
    struct Discard;

    impl PcodeSink for Discard {
        fn op(&mut self, _: Opcode, _: Option<Varnode>, _: &[Varnode]) {}
        fn label(&mut self, _: LabelId) {}
        fn branch_label(&mut self, _: Opcode, _: LabelId, _: Option<Varnode>) {}
    }

    /// A body with a load and a store through a space compilation never
    /// resolved. The compiler rejects such a name, so it is planted after
    /// the fact — the shape a blob that bypassed compilation would have.
    #[test]
    fn deferred_load_space_keeps_its_name() {
        let mut sources = SourceDb::new();
        let root = sources.add_file(
            "deferred.sla",
            "define endian=little;
             define space ram type=ram_space size=4 default;
             define space register type=register_space size=4;
             define register offset=0 size=4 [ r0 r1 ];
             define token instr(8) op=(0,7);
             :ld is op=1 { r0 = *:4 r1; }
             :st is op=2 { *:4 r1 = r0; }",
        );
        let mut compiled = Compiler::new(&mut sources).compile(root).expect("compiles");
        let deferred = || Some(SpaceRef::Deferred("segment".into()));
        for mut tree in compiled.spec.trees.iter_mut() {
            for mut constructor in tree.constructors.iter_mut() {
                for statement in &mut constructor.pmacro.body {
                    match &mut statement.ty {
                        AstNode::Assignment { rhs, .. } => {
                            if let ExpressionTy::Load(load) = &mut rhs.ty {
                                load.space = deferred();
                            }
                        }
                        AstNode::LoadAssignment { lhs, .. } => lhs.space = deferred(),
                        _ => {}
                    }
                }
            }
        }

        let decoder = Decoder::new(&compiled);
        let context = compiled.new_context();
        for (bytes, is_store) in [(&[1u8], false), (&[2], true)] {
            let instruction = decoder
                .decode_one(0x1000, bytes, &context)
                .expect("decodes");
            // The owned AST reads exactly as the template does.
            let ast = instruction.pcode_ast().expect("expands");
            let load = match &ast.statements[0].ty {
                AstNode::Assignment { rhs, .. } if !is_store => match &rhs.ty {
                    ExpressionTy::Load(load) => load,
                    other => panic!("a load, not {other:?}"),
                },
                AstNode::LoadAssignment { lhs, .. } if is_store => lhs,
                other => panic!("unexpected statement {other:?}"),
            };
            assert_eq!(load.space, deferred());
            assert!(matches!(
                load.ptr.ty,
                ExpressionTy::Ident(Ident::Register(_))
            ));
            assert!(ast.pretty_print(&compiled).contains("?segment"));

            // Both lowering paths reject it, and agree on why.
            let owned = instruction.pcode_ops().expect_err("cannot lower");
            let streamed = instruction
                .pcode_ops_streamed(|_| Discard)
                .map(|_| ())
                .expect_err("cannot lower");
            assert_eq!(owned, streamed);
            assert_eq!(
                owned.to_string(),
                "unresolved address space reached p-code lowering"
            );
        }
    }
}
