use crate::{
    Builtin, CompiledSpec, Compiler, ContextBytes, ContextDatabase, ContextEffect, ContextError,
    ContextScope, DecodeError, Decoder, DelaySlotError, Instruction, LabelId, Opcode, PcodeSink,
    RegisterId, SourceDb, SpaceId, SpaceType, Varnode, analyze,
    semantics::{
        EmitError, InstructionInfo, PcodeAst, PcodeBinaryOp, PcodeExprKind, PcodeIdent, PcodeLoad,
        PcodeRange, PcodeSpaceRef, PcodeStatementKind, PcodeTarget, RangeParam, SemanticsSink,
    },
};

const EXAMPLE_FIXTURE: &str = include_str!("fixtures/example.sla");
const SEMANTIC_EXPRESSION_FIXTURE: &str = include_str!("fixtures/semantics/expressions.sla");
const SEMANTIC_LOAD_STORE_FIXTURE: &str = include_str!("fixtures/semantics/load_store.sla");
const SEMANTIC_BRANCH_FIXTURE: &str = include_str!("fixtures/semantics/branching.sla");
const SEMANTIC_BUILD_EXPORT_FIXTURE: &str = include_str!("fixtures/semantics/build_export.sla");
const SEMANTIC_USEROP_MACRO_FIXTURE: &str = include_str!("fixtures/semantics/userop_macro.sla");
const SEMANTIC_MACRO_LVALUE_FIXTURE: &str = include_str!("fixtures/semantics/macro_lvalue.sla");

fn pcode_ast(src: &'static str, bytes: &[u8]) -> PcodeAst {
    let sources = Box::leak(Box::new(SourceDb::new()));
    let root = sources.add_file("semantics.sla", src);
    let spec = Box::leak(Box::new(Compiler::new(sources).compile(root).unwrap()));
    let context = spec.new_context();

    Decoder::new(spec)
        .decode_one(0x1000, bytes, &context)
        .unwrap()
        .pcode_ast()
        .unwrap()
}

fn reg(id: usize) -> RegisterId {
    RegisterId::from(id)
}

fn is_reg_expr(expr: &crate::PcodeExpr, id: usize) -> bool {
    matches!(&expr.ty, PcodeExprKind::Ident(PcodeIdent::Register(r)) if *r == reg(id))
}

fn is_const_expr(expr: &crate::PcodeExpr, value: u64, size: Option<usize>) -> bool {
    matches!(&expr.ty, PcodeExprKind::SizedInt { value: v, size: s } if *v == value && *s == size)
}

fn ast_has_no_internal_nodes(ast: &PcodeAst) -> bool {
    fn expr_ok(expr: &crate::PcodeExpr) -> bool {
        match &expr.ty {
            PcodeExprKind::MacroCall { .. } | PcodeExprKind::DeferredCall { .. } => false,
            PcodeExprKind::SubPieceMsb { src, .. } | PcodeExprKind::SubPieceLsb { src, .. } => {
                expr_ok(src)
            }
            PcodeExprKind::Load(load) => expr_ok(&load.ptr),
            PcodeExprKind::Range(range) => expr_ok(&range.value),
            PcodeExprKind::FunctionCall { args, .. } | PcodeExprKind::PcodeOp { args, .. } => {
                args.iter().all(expr_ok)
            }
            PcodeExprKind::Unop(unop) => expr_ok(&unop.e),
            PcodeExprKind::Binop(binop) => expr_ok(&binop.lhs) && expr_ok(&binop.rhs),
            PcodeExprKind::SizedInt { .. } | PcodeExprKind::Ident(_) => true,
        }
    }
    fn target_ok(target: &PcodeTarget) -> bool {
        match target {
            PcodeTarget::Label(_) => true,
            PcodeTarget::Node(_) => false,
            PcodeTarget::Expr(expr) => expr_ok(expr),
        }
    }

    ast.statements.iter().all(|stmt| match &stmt.ty {
        // Every one of these should have been expanded away before a consumer
        // sees the AST: `delayslot` is spliced, not emitted.
        PcodeStatementKind::Build(_)
        | PcodeStatementKind::DeferredBuild(_)
        | PcodeStatementKind::DelaySlot(_)
        | PcodeStatementKind::Export(_) => false,
        PcodeStatementKind::Assignment { rhs, .. }
        | PcodeStatementKind::LoadAssignment { rhs, .. }
        | PcodeStatementKind::RangeAssignment { rhs, .. }
        | PcodeStatementKind::Expression(rhs) => expr_ok(rhs),
        PcodeStatementKind::ConditionalBranch { condition, .. }
        | PcodeStatementKind::BranchIndirect { target: condition }
        | PcodeStatementKind::CallIndirect { target: condition }
        | PcodeStatementKind::Return { target: condition } => expr_ok(condition),
        PcodeStatementKind::Label(_) => true,
        PcodeStatementKind::Branch { target } | PcodeStatementKind::Call { target } => {
            target_ok(target)
        }
    })
}

#[test]
fn decode_one_happy_path() {
    let mut sources = SourceDb::new();
    let root = sources.add_file("example.sla", EXAMPLE_FIXTURE);
    let spec = Compiler::new(&mut sources).compile(root).unwrap();

    let context = spec.new_context();
    let decoder = Decoder::new(&spec);

    let instruction = decoder.decode_one(0, &[0x10, 0x8c], &context).unwrap();

    assert_eq!(instruction.address(), 0);
    assert_eq!(instruction.next_address(), 2);
    assert_eq!(instruction.len(), 2);
    assert_eq!(instruction.bytes(), &[0x10, 0x8c]);
    assert_eq!(instruction.constructor_table().name(), "instruction");
    assert_eq!(instruction.constructor_index(), 0);
    assert_eq!(instruction.operand_count(), 2);
    assert_eq!(instruction.display().unwrap(), "and r3,r4");
}

#[test]
fn decode_one_no_match() {
    let mut sources = SourceDb::new();
    let root = sources.add_file("example.sla", EXAMPLE_FIXTURE);
    let spec = Compiler::new(&mut sources).compile(root).unwrap();

    let context = spec.new_context();
    let decoder = Decoder::new(&spec);

    let error = match decoder.decode_one(0, &[0xff, 0xff], &context) {
        Ok(_) => panic!("expected decode to fail"),
        Err(error) => error,
    };

    assert_eq!(error, DecodeError::NoMatch);
}

#[test]
fn decode_one_invalid_context() {
    let mut sources = SourceDb::new();
    let root = sources.add_file("example.sla", EXAMPLE_FIXTURE);
    let spec = Compiler::new(&mut sources).compile(root).unwrap();

    let context = ContextBytes::from_raw(vec![0]);
    let decoder = Decoder::new(&spec);

    let error = match decoder.decode_one(0, &[0x10, 0x8c], &context) {
        Ok(_) => panic!("expected decode to fail"),
        Err(error) => error,
    };

    assert_eq!(error, DecodeError::InvalidContext);
}

#[test]
fn compile_error() {
    let mut sources = SourceDb::new();
    let root = sources.add_file("bad.sla", "define token tiny(7);");

    let error = match Compiler::new(&mut sources).compile(root) {
        Ok(_) => panic!("expected compilation to fail"),
        Err(error) => error,
    };

    assert_eq!(error.diagnostics().len(), 1);
    assert!(error.diagnostics()[0].message.contains("Token size"));
}

#[test]
fn compile_error_includes_file_id() {
    let mut sources = SourceDb::new();
    let root = sources.add_file("bad.sla", "define token tiny(7);");

    let result = analyze(&mut sources, root);

    assert_eq!(result.diagnostics.len(), 1);
    assert_eq!(result.diagnostics[0].primary.file, root);
}

#[test]
fn unresolved_deferred_macro_call_is_compile_error() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "deferred.sla",
        r#"
define endian=little;
define space ram type=ram_space size=4 default;
define space register type=register_space size=4;
define register offset=0 size=4 [r0];
define token instr(8) op=(0,7);

macro invoke(f, x) {
  f(x);
}

:bad is op=0 { invoke(r0, r0); }
"#,
    );

    let error = match Compiler::new(&mut sources).compile(root) {
        Ok(_) => panic!("expected compile to fail"),
        Err(error) => error,
    };

    assert!(error.diagnostics()[0].message.contains("f"));
}

#[test]
fn recursive_macro_call_is_compile_error() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "recursive.sla",
        r#"
define endian=little;
define space ram type=ram_space size=4 default;
define space register type=register_space size=4;
define register offset=0 size=4 [r0];
define token instr(8) op=(0,7);

macro recurse(x) {
  recurse(x);
}

:bad is op=0 { recurse(r0); }
"#,
    );

    let error = match Compiler::new(&mut sources).compile(root) {
        Ok(_) => panic!("expected compile to fail"),
        Err(error) => error,
    };

    assert!(error.diagnostics()[0].message.contains("recurse"));
}

#[test]
fn spec_api() {
    let mut sources = SourceDb::new();
    let root = sources.add_file("example.sla", EXAMPLE_FIXTURE);
    let spec = Compiler::new(&mut sources).compile(root).unwrap();

    let register = spec.register("r3").unwrap();
    assert_eq!(register.name(), "r3");
    assert_eq!(register.offset(), 12);
    assert_eq!(register.size(), 4);

    let token = spec.token("instr").unwrap();
    assert_eq!(token.name(), "instr");
    assert_eq!(token.size(), 16);

    let field = spec.field("op").unwrap();
    assert_eq!(field.name(), "op");
    assert_eq!(field.width(), 6);

    let space = spec.space("ram").unwrap();
    assert_eq!(space.name(), Some("ram"));

    let table = spec.table("instruction").unwrap();
    assert_eq!(table.name(), "instruction");
    assert_eq!(table.constructor_count(), 3);

    assert!(spec.symbols().any(|symbol| symbol.name == "instruction"));
}

#[test]
fn context_update_fields() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "context.sla",
        include_str!("fixtures/context_update/root.sla"),
    );
    let spec = Compiler::new(&mut sources).compile(root).unwrap();

    let mut context = spec.new_context();
    let mode = spec.field("mode").unwrap();
    spec.set_context_field(&mut context, mode.id, 1).unwrap();
    assert_eq!(context.as_bytes(), &[1]);

    let error = spec
        .set_context_field(&mut context, mode.id, 2)
        .unwrap_err();

    assert_eq!(
        error,
        ContextError::ValueOutOfRange {
            field: mode.id,
            width: 1,
            value: 2
        }
    );

    let op = spec.field("op").unwrap();
    let error = spec.set_context_field(&mut context, op.id, 1).unwrap_err();
    assert_eq!(error, ContextError::NotContextField { field: op.id });
}

#[derive(Default)]
struct RecordingSink {
    instructions: Vec<InstructionInfo>,
}

impl SemanticsSink for RecordingSink {
    fn instruction(
        &mut self,
        instruction: &InstructionInfo,
        _pcode: &PcodeAst,
    ) -> Result<(), EmitError> {
        self.instructions.push(instruction.clone());
        Ok(())
    }
}

#[test]
fn binop() {
    let mut sources = SourceDb::new();
    let root = sources.add_file("example.sla", EXAMPLE_FIXTURE);
    let spec = Compiler::new(&mut sources).compile(root).unwrap();

    let context = spec.new_context();
    let decoder = Decoder::new(&spec);
    let instruction = decoder.decode_one(0x1000, &[0x10, 0x8c], &context).unwrap();
    let mut sink = RecordingSink::default();

    instruction.emit_into(&mut sink).unwrap();

    assert_eq!(sink.instructions.len(), 1);
    assert_eq!(sink.instructions[0].address, 0x1000);

    let ast = instruction.pcode_ast().unwrap();
    println!("{:#?}", ast.statements);
    assert_eq!(ast.statements.len(), 1);
    assert!(ast_has_no_internal_nodes(&ast));
    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::Assignment {
            lhs: PcodeIdent::Register(dst),
            rhs,
            ..
        } if *dst == reg(3)
            && matches!(
                &rhs.ty,
                PcodeExprKind::Binop(binop)
                    if binop.op == PcodeBinaryOp::BitwiseAnd
                        && is_reg_expr(&binop.lhs, 3)
                        && is_reg_expr(&binop.rhs, 4)
            )
    ));
}

#[test]
fn raw_compiler_route_parses_structured_pcode_with_trivia() {
    let ast = pcode_ast(
        r#"
define endian=little;
define space ram type=ram_space size=4 default;
define space register type=register_space size=4;
define register offset=0 size=4 [r0];
define token instr(8) op=(0,7);

:and is op=0 {
  # raw parser must preserve this trivia while compiler lowering ignores it
  r0 = r0 & r0;
}
"#,
        &[0x00],
    );

    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::Assignment {
            lhs: PcodeIdent::Register(dst),
            rhs,
            size: None,
        } if *dst == reg(0)
            && matches!(
                &rhs.ty,
                PcodeExprKind::Binop(binop)
                    if binop.op == PcodeBinaryOp::BitwiseAnd
                        && is_reg_expr(&binop.lhs, 0)
                        && is_reg_expr(&binop.rhs, 0)
            )
    ));
}

#[test]
fn load() {
    let ast = pcode_ast(SEMANTIC_LOAD_STORE_FIXTURE, &[0x11]);
    println!("{:#?}", ast.statements);
    assert_eq!(ast.statements.len(), 1);
    assert!(ast_has_no_internal_nodes(&ast));
    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::Assignment {
            lhs: PcodeIdent::Register(dst),
            rhs,
            ..
        } if *dst == reg(1)
            && matches!(
                &rhs.ty,
                PcodeExprKind::Load(PcodeLoad { ptr, size: Some(4), space: None })
                    if is_reg_expr(ptr, 1)
            )
    ));
}

#[test]
fn named_load() {
    let ast = pcode_ast(SEMANTIC_LOAD_STORE_FIXTURE, &[0x12]);
    println!("{:#?}", ast.statements);
    assert_eq!(ast.statements.len(), 1);
    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::Assignment {
            lhs: PcodeIdent::Register(dst),
            rhs,
            ..
        } if *dst == reg(1)
            && matches!(
                &rhs.ty,
                PcodeExprKind::Load(PcodeLoad {
                    ptr,
                    size: Some(2),
                    space: Some(PcodeSpaceRef::Resolved(space)),
                }) if *space == SpaceId::from(2) && is_reg_expr(ptr, 1)
            )
    ));
}

#[test]
fn load_binds_before_infix_operator() {
    let ast = pcode_ast(SEMANTIC_LOAD_STORE_FIXTURE, &[0x15]);
    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::Assignment {
            rhs,
            ..
        } if matches!(
            &rhs.ty,
            PcodeExprKind::Binop(and)
                if and.op == PcodeBinaryOp::BitwiseAnd
                    && matches!(
                        &and.lhs.ty,
                        PcodeExprKind::Binop(shr)
                            if shr.op == PcodeBinaryOp::RightShift
                                && matches!(&shr.lhs.ty, PcodeExprKind::Load(_))
                    )
        )
    ));
}

#[test]
fn load_accepts_parenthesized_pointer_expression() {
    let ast = pcode_ast(SEMANTIC_LOAD_STORE_FIXTURE, &[0x16]);
    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::Assignment {
            rhs,
            ..
        } if matches!(
            &rhs.ty,
            PcodeExprKind::Load(PcodeLoad { ptr, .. })
                if matches!(&ptr.ty, PcodeExprKind::Binop(add) if add.op == PcodeBinaryOp::Add)
        )
    ));
}

#[test]
fn store() {
    let ast = pcode_ast(SEMANTIC_LOAD_STORE_FIXTURE, &[0x13]);
    println!("{:#?}", ast.statements);
    assert_eq!(ast.statements.len(), 1);
    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::LoadAssignment {
            lhs: PcodeLoad { ptr, size: Some(4), space: None },
            rhs,
            ..
        } if is_reg_expr(ptr, 1) && is_reg_expr(rhs, 1)
    ));
}

#[test]
fn named_store() {
    let ast = pcode_ast(SEMANTIC_LOAD_STORE_FIXTURE, &[0x14]);
    println!("{:#?}", ast.statements);
    assert_eq!(ast.statements.len(), 1);
    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::LoadAssignment {
            lhs: PcodeLoad {
                ptr,
                size: Some(2),
                space: Some(PcodeSpaceRef::Resolved(space)),
            },
            rhs,
            ..
        } if *space == SpaceId::from(2) && is_reg_expr(ptr, 1) && is_reg_expr(rhs, 1)
    ));
}

#[test]
fn zext() {
    let ast = pcode_ast(SEMANTIC_EXPRESSION_FIXTURE, &[0x11]);
    println!("{:#?}", ast.statements);
    assert_eq!(ast.statements.len(), 1);
    assert!(ast_has_no_internal_nodes(&ast));
    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::Assignment { rhs, .. }
            if matches!(
                &rhs.ty,
                PcodeExprKind::FunctionCall { builtin: Builtin::Zext, args }
                    if matches!(&args[0].ty, PcodeExprKind::SubPieceLsb { count: 4, .. })
            )
    ));
}

#[test]
fn sext() {
    let ast = pcode_ast(SEMANTIC_EXPRESSION_FIXTURE, &[0x12]);
    println!("{:#?}", ast.statements);
    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::Assignment { rhs, .. }
            if matches!(&rhs.ty, PcodeExprKind::FunctionCall { builtin: Builtin::Sext, .. })
    ));
}

#[test]
fn bit_range() {
    let ast = pcode_ast(SEMANTIC_EXPRESSION_FIXTURE, &[0x13]);
    println!("{:#?}", ast.statements);
    assert_eq!(ast.statements.len(), 2);
    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::RangeAssignment {
            lhs: PcodeRange {
                start: RangeParam::Literal(3),
                size: RangeParam::Literal(1),
                ..
            },
            ..
        }
    ));
    assert!(matches!(
        &ast.statements[1].ty,
        PcodeStatementKind::Assignment { rhs, .. }
            if matches!(
                &rhs.ty,
                PcodeExprKind::FunctionCall { builtin: Builtin::Zext, args }
                    if matches!(
                        &args[0].ty,
                        PcodeExprKind::Range(PcodeRange {
                            start: RangeParam::Literal(0),
                            size: RangeParam::Literal(8),
                            ..
                        })
                    )
            )
    ));
}

#[test]
fn pcode_ops_lower_expanded_ranges_into_raw_operations() {
    let sources = Box::leak(Box::new(SourceDb::new()));
    let root = sources.add_file("semantics.sla", SEMANTIC_EXPRESSION_FIXTURE);
    let spec = Box::leak(Box::new(Compiler::new(sources).compile(root).unwrap()));
    let instruction = Decoder::new(spec)
        .decode_one(0x1000, &[0x13], &spec.new_context())
        .unwrap();

    let pcode = instruction.pcode_ops().unwrap();
    assert_eq!(
        pcode.ops.iter().map(|op| op.opcode).collect::<Vec<_>>(),
        vec![
            Opcode::IntZext,
            Opcode::IntAnd,
            Opcode::IntLeft,
            Opcode::IntAnd,
            Opcode::IntOr,
            Opcode::IntRight,
            Opcode::IntAnd,
            Opcode::SubPiece,
            Opcode::IntZext,
        ]
    );
    let unique = spec.space("unique").expect("unique space must be public");
    assert!(matches!(unique.space().ty, SpaceType::Unique));
    assert!(
        pcode
            .ops
            .iter()
            .filter_map(|op| op.output)
            .any(|output| output.space == unique.id)
    );
}

/// A local nothing can give a width to is a property of the specification, so
/// it is reported when the specification is compiled rather than when an
/// instruction that uses it happens to be lifted.
#[test]
fn unsizable_locals_are_reported_against_their_constructor() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "unsized.slaspec",
        "define endian=little;
         define space ram type=ram_space size=4 default;
         define space register type=register_space size=4;
         define register offset=0 size=4 [ r0 ];
         define token instr(8) op=(0,7);
         define pcodeop myop;
         :good is op=1 { local tmp = r0 + 1; r0 = tmp; }
         :bad is op=2 { myop(nowidth); }",
    );
    let spec = Compiler::new(&mut sources).compile(root).unwrap();

    let reported: Vec<_> = spec.unsized_locals().collect();
    assert_eq!(reported.len(), 1, "only `bad` has an unsizable local");
    let (file, start, end, count) = reported[0];
    assert_eq!(count, 1);
    assert!(sources.text(file).unwrap()[start..end].contains(":bad"));

    // The good constructor still lifts, and the bad one fails at lift time
    // with the same error it always did — reporting is additive.
    let decoder = Decoder::new(&spec);
    let context = spec.new_context();
    assert!(
        decoder
            .decode_one(0x1000, &[1], &context)
            .unwrap()
            .pcode_ops()
            .is_ok()
    );
    assert!(
        decoder
            .decode_one(0x1000, &[2], &context)
            .unwrap()
            .pcode_ops()
            .is_err()
    );
}

#[test]
fn streamed_pcode_reports_plan_labels_before_operations() {
    let sources = Box::leak(Box::new(SourceDb::new()));
    let root = sources.add_file("semantics.sla", SEMANTIC_BRANCH_FIXTURE);
    let spec = Box::leak(Box::new(Compiler::new(sources).compile(root).unwrap()));
    let context = spec.new_context();

    #[derive(Default)]
    struct Trace {
        labels: Vec<String>,
        events: Vec<String>,
    }

    impl PcodeSink for Trace {
        fn op(&mut self, opcode: Opcode, _output: Option<Varnode>, _inputs: &[Varnode]) {
            self.events.push(format!("{opcode:?}"));
        }

        fn label(&mut self, label: LabelId) {
            self.events.push(format!("label {}", label.index()));
        }

        fn branch_label(&mut self, opcode: Opcode, label: LabelId, _condition: Option<Varnode>) {
            self.events.push(format!("{opcode:?} -> {}", label.index()));
        }
    }

    // `if reg == 0 goto <done>; reg = 1:4; <done>`
    let instruction = Decoder::new(spec)
        .decode_one(0x1000, &[0x02], &context)
        .unwrap();
    let trace = instruction
        .pcode_ops_streamed(|plan| Trace {
            labels: plan
                .labels()
                .iter()
                .map(|label| label.to_string())
                .collect(),
            ..Trace::default()
        })
        .unwrap();
    assert_eq!(trace.labels, vec!["done".to_string()]);
    assert_eq!(
        trace.events,
        vec![
            "IntEqual".to_string(),
            "CBranch -> 0".to_string(),
            "Copy".to_string(),
            "label 0".to_string(),
        ]
    );

    // A direct branch out of the instruction is planned, not streamed as a
    // label, and the collecting API still resolves the same operations.
    let instruction = Decoder::new(spec)
        .decode_one(0x1000, &[0x09], &context)
        .unwrap();
    let planned = instruction
        .pcode_ops_streamed(|plan| {
            let branches = plan.direct_branches().to_vec();
            Trace {
                labels: branches
                    .iter()
                    .map(|target| format!("{target:#x}"))
                    .collect(),
                ..Trace::default()
            }
        })
        .unwrap();
    assert_eq!(planned.labels, vec!["0x1001".to_string()]);
    assert_eq!(planned.events, vec!["Branch".to_string()]);
}

#[test]
fn trunc() {
    let ast = pcode_ast(SEMANTIC_EXPRESSION_FIXTURE, &[0x14]);
    println!("{:#?}", ast.statements);
    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::Assignment { rhs, .. }
            if matches!(&rhs.ty, PcodeExprKind::SubPieceMsb { count: 4, .. })
    ));
}

#[test]
fn branch() {
    let ast = pcode_ast(SEMANTIC_BRANCH_FIXTURE, &[0x01]);
    println!("{:#?}", ast.statements);

    assert_eq!(ast.statements.len(), 2);
    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::Branch {
            target: PcodeTarget::Label(name)
        } if name.as_ref() == "done"
    ));
    assert!(matches!(
        &ast.statements[1].ty,
        PcodeStatementKind::Label(name) if name.as_ref() == "done"
    ));
}

#[test]
fn cbranch() {
    let ast = pcode_ast(SEMANTIC_BRANCH_FIXTURE, &[0x12]);
    println!("{:#?}", ast.statements);

    assert_eq!(ast.statements.len(), 3);
    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::ConditionalBranch {
            condition,
            target: PcodeTarget::Label(label),
        } if label.as_ref() == "done" && matches!(
            &condition.ty,
            PcodeExprKind::Binop(binop)
                if binop.op == PcodeBinaryOp::Equal
                    && is_reg_expr(&binop.lhs, 1)
                    && is_const_expr(&binop.rhs, 0, None)
        )
    ));
    assert!(matches!(
        &ast.statements[2].ty,
        PcodeStatementKind::Label(name) if name.as_ref() == "done"
    ));
}

#[test]
fn branch_ind() {
    let ast = pcode_ast(SEMANTIC_BRANCH_FIXTURE, &[0x13]);
    println!("{:#?}", ast.statements);

    assert_eq!(ast.statements.len(), 1);
    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::BranchIndirect { target } if is_reg_expr(target, 1)
    ));
}

#[test]
fn branch_inst_next() {
    let ast = pcode_ast(SEMANTIC_BRANCH_FIXTURE, &[0x07]);
    println!("{:#?}", ast.statements);

    assert_eq!(ast.statements.len(), 1);
    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::Branch {
            target: PcodeTarget::Expr(target)
        } if is_const_expr(target, 0x1001, Some(4))
    ));
}

#[test]
fn branch_inst_start() {
    let ast = pcode_ast(SEMANTIC_BRANCH_FIXTURE, &[0x08]);
    println!("{:#?}", ast.statements);

    assert_eq!(ast.statements.len(), 1);
    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::Branch {
            target: PcodeTarget::Expr(target)
        } if is_const_expr(target, 0x1000, Some(4))
    ));
}

#[test]
fn branch_exported_target_uses_address_pointer() {
    let ast = pcode_ast(SEMANTIC_BRANCH_FIXTURE, &[0x19]);
    println!("{:#?}", ast.statements);

    assert_eq!(ast.statements.len(), 1);
    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::Branch {
            target: PcodeTarget::Expr(target)
        } if is_const_expr(target, 0x1002, Some(4))
    ));
}

#[test]
fn call() {
    let ast = pcode_ast(SEMANTIC_BRANCH_FIXTURE, &[0x04]);
    println!("{:#?}", ast.statements);
    assert_eq!(ast.statements.len(), 1);

    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::Call {
            target: PcodeTarget::Label(name)
        } if name.as_ref() == "sub"
    ));
}

#[test]
fn call_ind() {
    let ast = pcode_ast(SEMANTIC_BRANCH_FIXTURE, &[0x15]);
    println!("{:#?}", ast.statements);
    assert_eq!(ast.statements.len(), 1);
    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::CallIndirect { target } if is_reg_expr(target, 1)
    ));
}

#[test]
fn ret() {
    let ast = pcode_ast(SEMANTIC_BRANCH_FIXTURE, &[0x16]);
    println!("{:#?}", ast.statements);
    assert_eq!(ast.statements.len(), 1);
    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::Return { target } if is_reg_expr(target, 1)
    ));
}

#[test]
fn pcode_op() {
    let ast = pcode_ast(SEMANTIC_USEROP_MACRO_FIXTURE, &[0x11]);
    println!("{:#?}", ast.statements);
    assert_eq!(ast.statements.len(), 1);
    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::Assignment {
            lhs: PcodeIdent::Register(dst),
            rhs,
            ..
        } if *dst == reg(1)
            && matches!(
                &rhs.ty,
                PcodeExprKind::PcodeOp { id, args }
                    if usize::from(*id) == 0 && args.len() == 1 && is_reg_expr(&args[0], 1)
            )
    ));
}

#[test]
fn macro_use() {
    let ast = pcode_ast(SEMANTIC_USEROP_MACRO_FIXTURE, &[0x12]);
    println!("{:#?}", ast.statements);
    assert_eq!(ast.statements.len(), 1);
    assert!(ast_has_no_internal_nodes(&ast));
    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::Assignment {
            lhs: PcodeIdent::Register(dst),
            rhs,
            ..
        } if *dst == reg(1) && is_const_expr(rhs, 1, Some(4))
    ));
}

/// A macro parameter bound to a bit range or a memory load is an lvalue in
/// the caller: `setone(reg[8,8])` must write that lane and `setone(*:1 reg)`
/// that byte, not a fresh macro-local that nothing reads. x86 `PSHUFD`,
/// `SHUFPS`, the `PMIN`/`PMAX` and `PSLL`/`PSRL` XMM forms all pass lanes as
/// macro outputs and silently produced nothing before this was fixed.
#[test]
fn macro_output_bound_to_a_range_or_load_writes_through() {
    let ast = pcode_ast(SEMANTIC_MACRO_LVALUE_FIXTURE, &[0x13]);
    println!("{:#?}", ast.statements);
    assert_eq!(ast.statements.len(), 1);
    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::RangeAssignment { lhs, rhs, .. }
            if matches!(&lhs.value.ty, PcodeExprKind::Ident(PcodeIdent::Register(dst)) if *dst == reg(1))
                && is_const_expr(rhs, 1, Some(1))
    ));

    let ast = pcode_ast(SEMANTIC_MACRO_LVALUE_FIXTURE, &[0x14]);
    println!("{:#?}", ast.statements);
    assert_eq!(ast.statements.len(), 1);
    assert!(matches!(
        &ast.statements[0].ty,
        PcodeStatementKind::LoadAssignment { lhs, rhs, .. }
            if matches!(&lhs.ptr.ty, PcodeExprKind::Ident(PcodeIdent::Register(dst)) if *dst == reg(1))
                && is_const_expr(rhs, 1, Some(1))
    ));
}

// TODO: this test is not interesting, `build` should be in the middle of the semantic section, and we should check that the emitted instructions are in the right order
// So 1 test without a build statement -> instructions at the start
// Then 1 test with a build statement -> instructions in the middle
#[test]
fn build_load() {
    let ast = pcode_ast(SEMANTIC_BUILD_EXPORT_FIXTURE, &[0x31]);
    println!("{:#?}", ast.statements);
    assert_eq!(ast.statements.len(), 3);
    assert!(ast_has_no_internal_nodes(&ast));
    assert!(matches!(
        &ast.statements[2].ty,
        PcodeStatementKind::Assignment {
            lhs: PcodeIdent::Register(dst),
            rhs,
            ..
        } if *dst == reg(0)
            && matches!(
                &rhs.ty,
                PcodeExprKind::Load(PcodeLoad {
                    ptr,
                    size: Some(4),
                    space: Some(PcodeSpaceRef::Resolved(space)),
                }) if *space == SpaceId::from(1)
                    && matches!(&ptr.ty, PcodeExprKind::Ident(PcodeIdent::Named(_)))
            )
    ));
}

/// Regression: a subtable operand that appears only in a constructor's `is`
/// pattern — never `build`-ed, never in the display, never referenced in the
/// body — must still be auto-built so its semantics are emitted. SLEIGH builds
/// every operand of a constructor, including pattern-only ones.
///
/// This was exposed by open_sleigh commit bab1dd5 ("Relax constraints on REP
/// prefixes"), which moved the REP loop counter guard/decrement into
/// constraint-only `rep_check`/`rep_update` subtables; the decoder previously
/// dropped them. See `collect_non_build_table_refs` in `pmacro.rs`.
#[test]
fn pattern_only_subtable_is_auto_built() {
    const SRC: &str = "\
define endian=little;
define space ram type=ram_space size=2 default;
define space register type=register_space size=2;
define register offset=0 size=2 [ r0 r1 ];
define token instr(16) op=(0,7) sub=(8,15);

# `check` is referenced only in the `is` pattern below: not built, not displayed.
check: is sub=0x01 { r1 = 0:2; }

:test is op=0xaa & check { r0 = 1:2; }
";
    let mut sources = SourceDb::new();
    let root = sources.add_file("auto_build.sla", SRC);
    let spec = Compiler::new(&mut sources).compile(root).unwrap();
    let context = spec.new_context();

    let ast = Decoder::new(&spec)
        .decode_one(0x1000, &[0xaa, 0x01], &context)
        .unwrap()
        .pcode_ast()
        .unwrap();

    let pretty = ast.pretty_print(&spec);
    // The constraint-only subtable's side effect (`r1 = 0:2`) is auto-built and
    // emitted before the constructor body (`r0 = 1:2`).
    assert!(
        pretty.contains("r1 = 0:2"),
        "constraint-only subtable semantics must be auto-built; got:\n{pretty}"
    );
}

/// SLEIGH spells truncation `x(n)`, so `delayslot(1)` would parse as a subpiece
/// of an implicitly-declared local named `delayslot`, compiling cleanly to a
/// statement that reads an uninitialized temporary. `delayslot_stmt` claims the
/// form ahead of `expr_stmt`; this pins that it is read as a directive and not
/// as an expression.
#[test]
fn delayslot_is_a_directive_rather_than_a_truncation() {
    let src = "define endian=little;
         define space ram type=ram_space size=4 default;
         define space register type=register_space size=4;
         define register offset=0 size=4 [ r0 r1 ];
         define token instr(8) op=(0,7);
         :nop is op=2 { r1 = 1; }
         :jmp is op=1 { delayslot(1); goto [r0]; }";

    let mut sources = SourceDb::new();
    let root = sources.add_file("delayslot.sla", src);
    let spec = Compiler::new(&mut sources).compile(root).expect("compiles");

    let instruction = Decoder::new(&spec)
        .decode_one(0x1000, &[1, 2], &spec.new_context())
        .expect("decodes");

    assert_eq!(instruction.delay_slot_len(), 1);
    let pretty = instruction.pcode_ast().expect("emits").pretty_print(&spec);
    assert!(
        pretty.contains("r1 = 1"),
        "the delayed instruction was not spliced; got:\n{pretty}"
    );
    assert!(
        !pretty.contains("delayslot"),
        "a `delayslot` statement reached the emitted AST; got:\n{pretty}"
    );
}

/// `delayslot` used anywhere but as a statement is a diagnostic, not a subpiece
/// of an uninitialized temporary.
#[test]
fn delayslot_as_an_expression_is_rejected() {
    let src = "define endian=little;
         define space ram type=ram_space size=4 default;
         define space register type=register_space size=4;
         define register offset=0 size=4 [ r0 r1 ];
         define token instr(8) op=(0,7);
         :jmp is op=1 { r1 = delayslot(1); goto [r0]; }";

    let mut sources = SourceDb::new();
    let root = sources.add_file("delayslot_expr.sla", src);
    let Err(err) = Compiler::new(&mut sources).compile(root) else {
        panic!("`delayslot` as an expression should not compile");
    };
    assert!(
        err.to_string().contains("delayslot"),
        "unexpected error: {err}"
    );
}

/// A genuine truncation of a real variable still works.
#[test]
fn subpiece_truncation_still_compiles() {
    let src = "define endian=little;
         define space ram type=ram_space size=4 default;
         define space register type=register_space size=4;
         define register offset=0 size=4 [ r0 r1 ];
         define token instr(8) op=(0,7);
         :trunc is op=1 { local tmp:4 = r0; r1 = tmp(1); }";

    let mut sources = SourceDb::new();
    let root = sources.add_file("trunc.sla", src);
    assert!(Compiler::new(&mut sources).compile(root).is_ok());
}

/// A per-token `endian=` declaration is honoured end to end.
///
/// Two separate bugs had to be fixed for this. The builder descended one level
/// too few through the grammar and compared the `endian` rule against
/// `keyword_big`, which is never equal, so every token was built little-endian
/// whatever it declared. And `from_be_value` implemented a bit *reversal*,
/// which is the convention context fields use — a big-endian token needs a byte
/// *permutation*, since a big-endian read changes which byte a value bit lands
/// in but not its position within that byte.
#[test]
fn a_big_endian_token_decodes_big_endian_bytes() {
    fn decodes(token: &str, bytes: &[u8]) -> bool {
        let src = format!(
            "define endian=little;
             define space ram type=ram_space size=4 default;
             {token}
             :hit is f=0x1234 {{ }}"
        );
        let mut sources = SourceDb::new();
        let root = sources.add_file("endian.sla", src);
        let spec = Compiler::new(&mut sources)
            .compile(root)
            .expect("spec compiles");
        let context = spec.new_context();
        Decoder::new(&spec)
            .decode_one(0x1000, bytes, &context)
            .is_ok()
    }

    const LE: &str = "define token instr(16) endian=little f=(0,15);";
    const BE: &str = "define token instr(16) endian=big f=(0,15);";
    const DEFAULT: &str = "define token instr(16) f=(0,15);";

    assert!(decodes(LE, &[0x34, 0x12]));
    assert!(!decodes(LE, &[0x12, 0x34]));

    // Before the parser fix this matched the little-endian order; before the
    // pattern fix it matched neither.
    assert!(decodes(BE, &[0x12, 0x34]));
    assert!(!decodes(BE, &[0x34, 0x12]));

    // An undeclared token still follows the specification-level endianness.
    assert!(decodes(DEFAULT, &[0x34, 0x12]));
    assert!(!decodes(DEFAULT, &[0x12, 0x34]));
}

/// Pattern matching and operand extraction must agree: a pattern that matched
/// cannot then read a different value out of the same bytes. This exercises
/// both halves at once, with fields in two different bytes of a big-endian
/// token.
#[test]
fn big_endian_operand_extraction_agrees_with_matching() {
    const SRC: &str = "define endian=little;
         define space ram type=ram_space size=4 default;
         define token instr(16) endian=big op=(8,15) imm=(0,7);
         :hit imm is op=0xab & imm { }";

    let mut sources = SourceDb::new();
    let root = sources.add_file("split.sla", SRC);
    let spec = Compiler::new(&mut sources)
        .compile(root)
        .expect("spec compiles");
    let context = spec.new_context();
    let decoder = Decoder::new(&spec);

    // Big-endian: the high field `op` is the first byte, `imm` the second.
    let instruction = decoder
        .decode_one(0x1000, &[0xab, 0xcd], &context)
        .expect("matches on the big-endian byte order");
    assert_eq!(instruction.display().unwrap(), "hit 205");

    // The little-endian order must not match.
    assert!(decoder.decode_one(0x1000, &[0xcd, 0xab], &context).is_err());
}

/// Collects every label name a decoded instruction's p-code mentions, both at
/// definition sites and as branch targets.
fn label_names(src: &'static str, bytes: &[u8]) -> Vec<String> {
    let ast = pcode_ast(src, bytes);
    let mut names = Vec::new();
    for statement in &ast.statements {
        match &statement.ty {
            PcodeStatementKind::Label(name) => names.push(format!("def:{name}")),
            PcodeStatementKind::Branch { target }
            | PcodeStatementKind::ConditionalBranch { target, .. } => {
                if let PcodeTarget::Label(name) = target {
                    names.push(format!("goto:{name}"));
                }
            }
            _ => {}
        }
    }
    names
}

/// Expanding one macro twice in a constructor used to emit its label twice
/// under the same name. A consumer that resolves branch targets by name then
/// binds both branches to whichever it saw first — the two macro bodies share a
/// single exit, which is a silent control-flow miscompile.
#[test]
fn macro_labels_are_scoped_per_expansion() {
    const SRC: &str = "define endian=little;
         define space ram type=ram_space size=4 default;
         define space register type=register_space size=4;
         define register offset=0 size=4 [ r0 r1 r2 ];
         define token instr(8) op=(0,7);
         macro clampzero(x) {
            if (x != 0) goto <done>;
            x = 1;
            <done>
         }
         :two is op=1 { clampzero(r0); clampzero(r1); }";

    let names = label_names(SRC, &[1u8]);
    let definitions: Vec<_> = names.iter().filter(|n| n.starts_with("def:")).collect();

    assert_eq!(definitions.len(), 2, "expected one label per expansion");
    assert_ne!(
        definitions[0], definitions[1],
        "two expansions of the same macro must not define the same label: {names:?}"
    );

    // Each branch targets its own expansion's label, in order.
    assert_eq!(
        names,
        vec!["goto:done#0", "def:done#0", "goto:done#1", "def:done#1"]
    );
}

/// A macro with no locals does not advance the local-variable counter, so the
/// label scope cannot be derived from it — this is why expansions are counted
/// separately.
#[test]
fn label_scoping_survives_a_macro_with_no_locals() {
    const SRC: &str = "define endian=little;
         define space ram type=ram_space size=4 default;
         define space register type=register_space size=4;
         define register offset=0 size=4 [ r0 r1 ];
         define token instr(8) op=(0,7);
         macro noloc() {
            goto <skip>;
            <skip>
         }
         :two is op=1 { noloc(); noloc(); }";

    assert_eq!(
        label_names(SRC, &[1u8]),
        vec!["goto:skip#0", "def:skip#0", "goto:skip#1", "def:skip#1"]
    );
}

/// A label written directly in a constructor keeps the name the specification
/// gave it; only macro expansions are namespaced.
#[test]
fn constructor_labels_keep_their_names() {
    const SRC: &str = "define endian=little;
         define space ram type=ram_space size=4 default;
         define space register type=register_space size=4;
         define register offset=0 size=4 [ r0 r1 ];
         define token instr(8) op=(0,7);
         :one is op=1 { if (r0 != 0) goto <done>; r0 = 1; <done> }";

    assert_eq!(label_names(SRC, &[1u8]), vec!["goto:done", "def:done"]);
}

/// `attach values` may map a field to negative numbers. The list took the bare
/// `integer` rule, which has no sign, so any specification using one failed to
/// parse.
#[test]
fn attach_values_accepts_negative_entries() {
    const SRC: &str = "define endian=little;
         define space ram type=ram_space size=4 default;
         define token instr(8) f=(0,1) op=(2,7);
         attach values [ f ] [ -1 0 1 2 ];
         :hit f is op=1 & f { }";

    let mut sources = SourceDb::new();
    let root = sources.add_file("attach.sla", SRC);
    let spec = Compiler::new(&mut sources)
        .compile(root)
        .expect("negative attach values compile");
    let context = spec.new_context();
    let decoder = Decoder::new(&spec);

    // f = 0 selects the first entry, -1.
    let negative = decoder
        .decode_one(0x1000, &[0b0000_0100], &context)
        .expect("decodes");
    assert_eq!(negative.display().unwrap(), "hit -1");

    // f = 2 selects `1`.
    let positive = decoder
        .decode_one(0x1000, &[0b0000_0110], &context)
        .expect("decodes");
    assert_eq!(positive.display().unwrap(), "hit 1");
}

/// `cpool` and `newobject` are built-in SLEIGH functions, but the symbol table
/// was seeded from a hand-maintained list that omitted them, so calling either
/// was reported as an unknown macro. Twelve corpus specifications failed on
/// this alone.
#[test]
fn cpool_and_newobject_are_recognised_builtins() {
    const SRC: &str = "define endian=little;
         define space ram type=ram_space size=4 default;
         define space register type=register_space size=4;
         define register offset=0 size=4 [ r0 r1 ];
         define token instr(8) op=(0,7);
         :ldc is op=1 { r0 = cpool(r1, 0, 1); }
         :new is op=2 { r0 = newobject(r1); }";

    let mut sources = SourceDb::new();
    let root = sources.add_file("cpool.sla", SRC);
    assert!(Compiler::new(&mut sources).compile(root).is_ok());
}

// ── Disassembly-action context effects ────────────────────────────────────────

const CONTEXT_EFFECTS_FIXTURE: &str = include_str!("fixtures/context_effects/root.sla");
const CONTEXT_PHASE_FIXTURE: &str = include_str!("fixtures/context_effects/phase.sla");

fn compile_fixture(name: &str, text: &'static str) -> CompiledSpec {
    let mut sources = SourceDb::new();
    let root = sources.add_file(name.to_string(), text);
    Compiler::new(&mut sources)
        .compile(root)
        .unwrap_or_else(|error| panic!("{name} compiles: {error}"))
}

fn context_effects_spec() -> CompiledSpec {
    compile_fixture("context_effects.sla", CONTEXT_EFFECTS_FIXTURE)
}

/// Decodes one instruction of the context-effects fixture and returns its effects.
fn effects_of(spec: &CompiledSpec, bytes: &[u8], context: &ContextBytes) -> Vec<ContextEffect> {
    Decoder::new(spec)
        .decode_one(0x1000, bytes, context)
        .expect("decodes")
        .context_effects()
        .to_vec()
}

/// A plain assignment steers the rest of *this* decode and then goes away —
/// only `globalset` propagates. Ghidra's model; ruled 2026-08-20.
#[test]
fn a_plain_assignment_reports_no_effect() {
    let spec = context_effects_spec();

    assert!(effects_of(&spec, &[1], &spec.new_context()).is_empty());
}

#[test]
fn a_noflow_assignment_reports_no_effect() {
    let spec = context_effects_spec();

    assert!(effects_of(&spec, &[2], &spec.new_context()).is_empty());
}

/// Decode-locality is about the *construct*, not about the value changing: an
/// assignment that flips a variable away from the context it was decoded with
/// still reports nothing.
#[test]
fn a_plain_assignment_reports_no_effect_even_when_it_changes_the_value() {
    let spec = context_effects_spec();
    let mut context = spec.new_context();
    spec.set_context_field(&mut context, spec.field("mode").unwrap().id, 1)
        .unwrap();

    // `:clearmode` assigns `mode = 0` over an incoming `mode = 1`.
    assert!(effects_of(&spec, &[7], &context).is_empty());
}

#[test]
fn globalset_commits_at_the_next_address_of_a_multi_byte_instruction() {
    let spec = context_effects_spec();
    let mode = spec.field("mode").unwrap().id;

    let effects = effects_of(&spec, &[6, 0], &spec.new_context());

    assert_eq!(
        effects,
        vec![ContextEffect {
            field: mode,
            value: 1,
            scope: ContextScope::At(0x1002),
        }]
    );
}

/// The ARM Thumb interworking shape: `globalset` commits the value the variable
/// holds *at that point*, and the assignment after it puts the old value back.
#[test]
fn globalset_commits_the_value_held_at_that_point_in_the_block() {
    let spec = context_effects_spec();
    let mode = spec.field("mode").unwrap().id;

    let mut context = spec.new_context();
    spec.set_context_field(&mut context, mode, 1).unwrap();

    let effects = effects_of(&spec, &[5], &context);

    assert_eq!(
        effects,
        vec![ContextEffect {
            field: mode,
            value: 0,
            scope: ContextScope::At(0x1001),
        }],
        "expected exactly one commit of 0, and nothing from the trailing `mode=1`"
    );
}

#[test]
fn globalset_onto_a_subtable_operand_uses_its_exported_address() {
    let spec = context_effects_spec();
    let mode = spec.field("mode").unwrap().id;

    // `Target` exports `inst_start + 0x10`.
    let effects = effects_of(&spec, &[8, 1], &spec.new_context());

    assert_eq!(
        effects,
        vec![ContextEffect {
            field: mode,
            value: 1,
            scope: ContextScope::At(0x1010),
        }]
    );
}

#[test]
fn globalset_onto_an_operand_without_an_address_is_a_typed_error() {
    let spec = context_effects_spec();
    let context = spec.new_context();

    let error = match Decoder::new(&spec).decode_one(0x1000, &[9, 2], &context) {
        Ok(_) => panic!("an operand exporting a register has no address to commit at"),
        Err(error) => error,
    };

    assert_eq!(error, DecodeError::UnresolvedGlobalSetAddress);
}

#[test]
fn context_database_answers_the_default_context_for_untouched_addresses() {
    let spec = context_effects_spec();
    let db = ContextDatabase::new(&spec);

    assert_eq!(db.context_at(0x4000), spec.new_context());
}

#[test]
fn context_database_holds_a_committed_value_until_a_later_commit_overrides_it() {
    let spec = context_effects_spec();
    let decoder = Decoder::new(&spec);
    let mut db = ContextDatabase::new(&spec);

    // `:commit` at 0x1000 sets `mode` from 0x1001 onward.
    let first = decoder
        .decode_one(0x1000, &[3], &db.context_at(0x1000))
        .unwrap();
    db.apply(&first);

    assert_eq!(db.context_at(0x1000).as_bytes(), &[0]);
    assert_eq!(db.context_at(0x1001).as_bytes(), &[1]);
    assert_eq!(db.context_at(0x9999).as_bytes(), &[1]);

    // `:uncommit` at 0x2000 overrides it from 0x2001 onward, and only there.
    let second = decoder
        .decode_one(0x2000, &[10], &db.context_at(0x2000))
        .unwrap();
    db.apply(&second);

    assert_eq!(db.context_at(0x1fff).as_bytes(), &[1]);
    assert_eq!(db.context_at(0x2001).as_bytes(), &[0]);
}

#[test]
fn context_database_applies_a_noflow_commit_at_exactly_one_address() {
    let spec = context_effects_spec();
    let decoder = Decoder::new(&spec);
    let mut db = ContextDatabase::new(&spec);

    // `:point` commits `sticky` (noflow) for 0x1001 only.
    let instruction = decoder
        .decode_one(0x1000, &[4], &db.context_at(0x1000))
        .unwrap();
    db.apply(&instruction);

    assert_eq!(db.context_at(0x1000).as_bytes(), &[0]);
    assert_eq!(db.context_at(0x1001).as_bytes(), &[0b10]);
    assert_eq!(db.context_at(0x1002).as_bytes(), &[0]);
}

/// avr8 wraps every instruction in `[ phase=1; ]` to select its own
/// sub-constructors. If that leaked out of the decode, the `phase=0` wrapper
/// would stop matching and the second instruction would not decode at all.
#[test]
fn a_decode_local_phase_toggle_does_not_survive_the_instruction() {
    let spec = compile_fixture("phase.sla", CONTEXT_PHASE_FIXTURE);
    let decoder = Decoder::new(&spec);
    let mut db = ContextDatabase::new(&spec);

    for addr in [0x1000, 0x1001, 0x1002] {
        let instruction = decoder
            .decode_one(addr, &[1], &db.context_at(addr))
            .unwrap_or_else(|error| panic!("wrapper still matches at {addr:#x}: {error}"));
        assert_eq!(instruction.display().unwrap(), "nop");
        assert!(instruction.context_effects().is_empty());
        db.apply(&instruction);

        assert_eq!(
            db.context_at(instruction.next_address()),
            spec.new_context(),
            "the phase toggle escaped the decode"
        );
    }
}

/// The same wrapper must not swallow a real `globalset` underneath it.
#[test]
fn a_globalset_under_a_wrapper_constructor_still_reports() {
    let spec = compile_fixture("phase.sla", CONTEXT_PHASE_FIXTURE);
    let decoder = Decoder::new(&spec);
    let mut db = ContextDatabase::new(&spec);
    let skip = spec.field("skip").unwrap().id;

    let instruction = decoder
        .decode_one(0x1000, &[2], &db.context_at(0x1000))
        .unwrap();

    assert_eq!(
        instruction.context_effects(),
        [ContextEffect {
            field: skip,
            value: 1,
            scope: ContextScope::At(0x1001),
        }]
    );

    // `skip` is `noflow`, so the commit applies at 0x1001 and nowhere else.
    db.apply(&instruction);
    assert_eq!(db.context_at(0x1001).as_bytes(), &[0b10]);
    assert_eq!(db.context_at(0x1002).as_bytes(), &[0]);
}

// ── Delay slots ───────────────────────────────────────────────────────────────

const DELAY_SLOT_FIXTURE: &str = include_str!("fixtures/delay_slot/root.sla");

fn delay_slot_spec() -> CompiledSpec {
    compile_fixture("delay_slot.sla", DELAY_SLOT_FIXTURE)
}

fn decode_delay_slot<'a>(
    spec: &'a CompiledSpec,
    bytes: &'a [u8],
) -> Result<Instruction<'a, 'a>, DecodeError> {
    Decoder::new(spec).decode_one(0x1000, bytes, &spec.new_context())
}

/// `Instruction` has no `Debug`, so error assertions go through this instead of
/// `unwrap_err`.
fn delay_slot_error(spec: &CompiledSpec, bytes: &[u8]) -> DecodeError {
    match decode_delay_slot(spec, bytes) {
        Ok(_) => panic!("expected a decode error for {bytes:02x?}"),
        Err(error) => error,
    }
}

/// Renders emitted statements so a test can assert on their order.
fn pcode_lines(spec: &CompiledSpec, instruction: &Instruction<'_, '_>) -> Vec<String> {
    instruction
        .pcode_ast()
        .expect("emits")
        .statements
        .iter()
        .map(|stmt| stmt.pretty_print(spec))
        .collect()
}

/// The manual's `beq` shape: the comparison is read *before* the delayed
/// instruction is spliced, because that instruction may clobber what it read.
#[test]
fn a_delayed_instruction_is_spliced_at_the_directive_not_appended() {
    let spec = delay_slot_spec();
    // `beqds` then `clobber`, which assigns r1 — one of the compared registers.
    let instruction = decode_delay_slot(&spec, &[0x10, 0x02]).expect("decodes");
    let lines = pcode_lines(&spec, &instruction);

    let compare = lines
        .iter()
        .position(|line| line.contains("r1") && line.contains("=="))
        .unwrap_or_else(|| panic!("no comparison emitted: {lines:?}"));
    let clobber = lines
        .iter()
        .position(|line| line.starts_with("r1 = 0"))
        .unwrap_or_else(|| panic!("delayed instruction not spliced: {lines:?}"));
    let branch = lines
        .iter()
        .position(|line| line.starts_with("if "))
        .unwrap_or_else(|| panic!("no conditional branch emitted: {lines:?}"));

    assert!(
        compare < clobber && clobber < branch,
        "expected compare, then splice, then branch: {lines:?}"
    );
}

/// `inst_next` in the *semantic* section is the address past the delay slot.
#[test]
fn semantic_inst_next_is_past_the_delay_slot() {
    let spec = delay_slot_spec();
    let instruction = decode_delay_slot(&spec, &[0x11, 0x01]).expect("decodes");

    assert_eq!(instruction.len(), 1);
    assert_eq!(instruction.delay_slot_len(), 1);
    assert_eq!(instruction.next_address(), 0x1002);

    let lines = pcode_lines(&spec, &instruction);
    assert!(
        lines
            .iter()
            .any(|line| line.starts_with("ra = 0x1002") || line.starts_with("ra = 4098")),
        "expected `ra` to take the address past the slot: {lines:?}"
    );
}

/// `inst_next` in a *disassembly action* is not extended: a `globalset` on a
/// delay-slot branch still commits at the address right after the branch.
#[test]
fn action_inst_next_stops_before_the_delay_slot() {
    let spec = delay_slot_spec();
    let instruction = decode_delay_slot(&spec, &[0x13, 0x01]).expect("decodes");
    let mode = spec.field("mode").unwrap().id;

    assert_eq!(instruction.delay_slot_len(), 1);
    assert_eq!(instruction.next_address(), 0x1002);
    assert_eq!(
        instruction.context_effects(),
        [ContextEffect {
            field: mode,
            value: 1,
            scope: ContextScope::At(0x1001),
        }],
        "the action-side `inst_next` must exclude the delay slot"
    );
}

#[test]
fn a_two_byte_delay_slot_takes_as_many_instructions_as_it_needs() {
    let spec = delay_slot_spec();

    // Two one-byte instructions.
    let pair = decode_delay_slot(&spec, &[0x12, 0x01, 0x01]).expect("decodes");
    assert_eq!(pair.delay_slot_len(), 2);
    assert_eq!(pair.delay_slots().count(), 2);

    // One two-byte instruction satisfies the same slot on its own.
    let single = decode_delay_slot(&spec, &[0x12, 0x20, 0x00]).expect("decodes");
    assert_eq!(single.delay_slot_len(), 2);
    assert_eq!(single.delay_slots().count(), 1);
}

/// pi32v2's `rep` shape: the slot length is computed by the disassembly action.
#[test]
fn a_delay_slot_length_may_come_from_a_field() {
    let spec = delay_slot_spec();

    let one = decode_delay_slot(&spec, &[0x31, 0x01, 0x01]).expect("decodes");
    assert_eq!(one.delay_slot_len(), 1);

    let two = decode_delay_slot(&spec, &[0x32, 0x01, 0x01]).expect("decodes");
    assert_eq!(two.delay_slot_len(), 2);
}

#[test]
fn running_out_of_bytes_in_a_delay_slot_is_a_typed_error() {
    let spec = delay_slot_spec();

    assert_eq!(
        delay_slot_error(&spec, &[0x10]),
        DecodeError::DelaySlot(DelaySlotError::Truncated)
    );
}

#[test]
fn an_unmatched_instruction_in_a_delay_slot_is_a_typed_error() {
    let spec = delay_slot_spec();

    // No constructor has `hi=0xf`.
    assert_eq!(
        delay_slot_error(&spec, &[0x10, 0xff]),
        DecodeError::DelaySlot(DelaySlotError::NoMatch)
    );
}

#[test]
fn a_delay_slot_inside_a_delay_slot_is_a_typed_error() {
    let spec = delay_slot_spec();

    // `beqds` delaying `jalds`, which wants a delay slot of its own.
    assert_eq!(
        delay_slot_error(&spec, &[0x10, 0x11, 0x01]),
        DecodeError::DelaySlot(DelaySlotError::Nested)
    );
}

/// Splicing must not merge the two bodies' label namespaces: both the delaying
/// and the delayed instruction here declare `done`.
#[test]
fn a_spliced_instruction_gets_its_own_label_scope() {
    let spec = delay_slot_spec();
    let instruction = decode_delay_slot(&spec, &[0x14, 0x03]).expect("decodes");
    let lines = pcode_lines(&spec, &instruction);

    let labels: Vec<&String> = lines
        .iter()
        .filter(|line| line.starts_with('<') && line.ends_with('>'))
        .collect();

    assert_eq!(labels.len(), 2, "expected both labels: {lines:?}");
    assert_ne!(
        labels[0], labels[1],
        "the spliced instruction reused the parent's label name: {lines:?}"
    );

    // And each branch still names a label that exists exactly once.
    for line in lines.iter().filter(|line| line.contains("goto <")) {
        let target = line
            .rsplit_once("goto ")
            .and_then(|(_, rest)| rest.strip_suffix(';'))
            .expect("branch target");
        assert_eq!(
            lines.iter().filter(|l| l.trim() == target).count(),
            1,
            "`{target}` does not name exactly one label: {lines:?}"
        );
    }
}

#[test]
fn a_delay_slot_does_not_change_the_delaying_instructions_display() {
    let spec = delay_slot_spec();
    let instruction = decode_delay_slot(&spec, &[0x11, 0x01]).expect("decodes");

    assert_eq!(instruction.display().unwrap(), "jalds");
    assert_eq!(instruction.bytes(), &[0x11]);

    let delayed: Vec<_> = instruction.delay_slots().collect();
    assert_eq!(delayed.len(), 1);
    assert_eq!(delayed[0].display().unwrap(), "nop");
    assert_eq!(delayed[0].address(), 0x1001);
    assert_eq!(delayed[0].bytes(), &[0x01]);
}

#[test]
fn an_instruction_without_a_delay_slot_reports_none() {
    let spec = delay_slot_spec();
    let instruction = decode_delay_slot(&spec, &[0x01]).expect("decodes");

    assert_eq!(instruction.delay_slot_len(), 0);
    assert_eq!(instruction.delay_slots().count(), 0);
    assert_eq!(instruction.next_address(), 0x1001);
}

/// `inst_next2` is the address past the *following* instruction, which costs a
/// look-ahead decode to measure.
#[test]
fn inst_next2_measures_the_following_instruction() {
    let spec = delay_slot_spec();

    // `skip` then a one-byte `nop`: inst_next2 = 0x1000 + 1 + 1.
    let over_one = decode_delay_slot(&spec, &[0x40, 0x01]).expect("decodes");
    let lines = pcode_lines(&spec, &over_one);
    assert!(
        lines.iter().any(|line| line.contains("4098")),
        "expected inst_next2 = 0x1002: {lines:?}"
    );

    // `skip` then the two-byte instruction: inst_next2 = 0x1000 + 1 + 2.
    let over_two = decode_delay_slot(&spec, &[0x40, 0x20, 0x00]).expect("decodes");
    let lines = pcode_lines(&spec, &over_two);
    assert!(
        lines.iter().any(|line| line.contains("4099")),
        "expected inst_next2 = 0x1003: {lines:?}"
    );
}

#[test]
fn an_unmeasurable_inst_next2_is_a_typed_error() {
    let spec = delay_slot_spec();

    assert_eq!(
        delay_slot_error(&spec, &[0x40]),
        DecodeError::UnresolvedInstNext2
    );
}

#[test]
fn a_second_delayslot_directive_in_one_constructor_is_rejected() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "two_slots.sla",
        "define endian=little;\n\
         define space ram type=ram_space size=4 default;\n\
         define space register type=register_space size=4;\n\
         define register offset=0 size=4 [r0];\n\
         define token instr(8) op=(0,7);\n\
         :bad is op=1 { delayslot(1); r0 = 1; delayslot(1); }\n",
    );

    let error = match Compiler::new(&mut sources).compile(root) {
        Ok(_) => panic!("two directives are rejected"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("at most one `delayslot`"),
        "unexpected diagnostic: {error}"
    );
}

#[test]
fn a_delayslot_argument_that_is_neither_constant_nor_field_is_rejected() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "bad_arg.sla",
        "define endian=little;\n\
         define space ram type=ram_space size=4 default;\n\
         define space register type=register_space size=4;\n\
         define register offset=0 size=4 [r0];\n\
         define token instr(8) op=(0,7);\n\
         :bad is op=1 { delayslot(nope); r0 = 1; }\n",
    );

    let error = match Compiler::new(&mut sources).compile(root) {
        Ok(_) => panic!("an unknown name is rejected"),
        Err(error) => error,
    };
    assert!(
        error.to_string().contains("neither a constant nor a field"),
        "unexpected diagnostic: {error}"
    );
}

// ── Field-versus-field pattern constraints ────────────────────────────────────

const FIELD_COMPARE_LE_FIXTURE: &str = include_str!("fixtures/field_compare/le.sla");
const FIELD_COMPARE_BE_FIXTURE: &str = include_str!("fixtures/field_compare/be.sla");

/// Decodes every `(a, b)` pair for one comparison and checks the set of
/// encodings that match against the arithmetic predicate, exhaustively.
///
/// Three-bit fields make all 64 pairs cheap to enumerate, and the boundaries
/// that a bit-decomposition gets wrong — equal values, zero, all-ones — are all
/// in range.
fn assert_field_comparison(spec: &CompiledSpec, sel: u8, predicate: impl Fn(u8, u8) -> bool) {
    let decoder = Decoder::new(spec);
    let context = spec.new_context();

    for a in 0..8u8 {
        for b in 0..8u8 {
            let byte = (sel << 6) | (b << 3) | a;
            let matched = decoder.decode_one(0x1000, &[byte], &context).is_ok();
            assert_eq!(
                matched,
                predicate(a, b),
                "a={a} b={b} (encoding {byte:#04x}): matched={matched}, expected {}",
                predicate(a, b)
            );
        }
    }
}

const FIELD_COMPARE_ORDERED_FIXTURE: &str = include_str!("fixtures/field_compare/ordered.sla");

/// Every verb `constraint_verb` admits, checked exhaustively against its
/// arithmetic meaning over all 64 `(a, b)` pairs — including the boundaries
/// where rewriting `<=` to `<` (or `>=` to `>`) would run off the end of the
/// field's range.
#[test]
fn every_ordered_comparison_verb_matches_its_predicate() {
    let spec = compile_fixture("field_compare_ordered.sla", FIELD_COMPARE_ORDERED_FIXTURE);
    let decoder = Decoder::new(&spec);
    let context = spec.new_context();

    /// A comparison's source spelling and its arithmetic meaning.
    type Comparison<'a> = (&'a str, &'a dyn Fn(u8, u8) -> bool);

    let predicates: [Comparison<'_>; 16] = [
        ("a=b", &|a, b| a == b),
        ("a!=b", &|a, b| a != b),
        ("a<b", &|a, b| a < b),
        ("a<=b", &|a, b| a <= b),
        ("a>b", &|a, b| a > b),
        ("a>=b", &|a, b| a >= b),
        ("a=3", &|a, _| a == 3),
        ("a!=3", &|a, _| a != 3),
        ("a<3", &|a, _| a < 3),
        ("a<=3", &|a, _| a <= 3),
        ("a>3", &|a, _| a > 3),
        ("a>=3", &|a, _| a >= 3),
        ("a<=7", &|_, _| true),
        ("a>7", &|_, _| false),
        ("a>=0", &|_, _| true),
        ("a<0", &|_, _| false),
    ];

    for (sel, (label, predicate)) in predicates.iter().enumerate() {
        for a in 0..8u16 {
            for b in 0..8u16 {
                let encoding = ((sel as u16) << 6) | (b << 3) | a;
                let matched = decoder
                    .decode_one(0x1000, &encoding.to_le_bytes(), &context)
                    .is_ok();
                assert_eq!(
                    matched,
                    predicate(a as u8, b as u8),
                    "`{label}` with a={a} b={b} (encoding {encoding:#06x})"
                );
            }
        }
    }
}

#[test]
fn field_comparisons_match_their_predicate_exactly() {
    let spec = compile_fixture("field_compare_le.sla", FIELD_COMPARE_LE_FIXTURE);

    assert_field_comparison(&spec, 0, |a, b| a != b);
    assert_field_comparison(&spec, 1, |a, b| a < b);
    assert_field_comparison(&spec, 2, |a, b| a == b);
}

/// The same, on a big-endian token. A big-endian read permutes which *byte* a
/// value bit lands in; a decomposition that reverses bits within the field
/// instead — the convention context fields use — passes the little-endian case
/// and fails here. MIPS, the reason this exists, is big-endian.
#[test]
fn field_comparisons_match_their_predicate_on_a_big_endian_token() {
    let spec = compile_fixture("field_compare_be.sla", FIELD_COMPARE_BE_FIXTURE);

    assert_field_comparison(&spec, 0, |a, b| a != b);
    assert_field_comparison(&spec, 1, |a, b| a < b);
    assert_field_comparison(&spec, 2, |a, b| a == b);
}

/// Compiles a one-constructor spec whose bit pattern is `pattern`, returning
/// the diagnostic text if it fails.
fn compile_pattern(fields: &str, pattern: &str) -> Result<CompiledSpec, String> {
    let src = format!(
        "define endian=little;\n\
         define space ram type=ram_space size=4 default;\n\
         define space register type=register_space size=4;\n\
         define register offset=0 size=1 [ctxreg];\n\
         define context ctxreg cm=(0,0) cn=(1,1);\n\
         define token instr(16) {fields}\n;\n\
         :hit is {pattern} {{ }}\n"
    );
    let mut sources = SourceDb::new();
    let root = sources.add_file("pattern.sla".to_string(), src);
    Compiler::new(&mut sources)
        .compile(root)
        .map_err(|error| error.to_string())
}

/// `CompiledSpec` has no `Debug`, so diagnostics are asserted through this
/// rather than `expect_err`.
fn pattern_error(fields: &str, pattern: &str) -> String {
    match compile_pattern(fields, pattern) {
        Ok(_) => panic!("`{pattern}` should not compile"),
        Err(error) => error,
    }
}

/// `a != a` and `a < a` are unsatisfiable. The `=` case is a no-op pattern, and
/// reusing that for the other two would say the opposite — an empty pattern
/// matches everything.
#[test]
fn comparing_a_field_with_itself_is_unsatisfiable_for_ne_and_lt() {
    for pattern in ["a!=a", "a<a"] {
        let spec = compile_pattern("a=(0,2) b=(3,5)", pattern).expect("compiles");
        let decoder = Decoder::new(&spec);
        let context = spec.new_context();

        for encoding in 0..=u16::MAX {
            assert!(
                decoder
                    .decode_one(0x1000, &encoding.to_le_bytes(), &context)
                    .is_err(),
                "`{pattern}` matched {encoding:#06x}"
            );
        }
    }

    // ... while `a = a` still constrains nothing.
    let spec = compile_pattern("a=(0,2) b=(3,5)", "a=a").expect("compiles");
    assert!(
        Decoder::new(&spec)
            .decode_one(0x1000, &[0xff, 0xff], &spec.new_context())
            .is_ok()
    );
}

#[test]
fn comparing_fields_of_different_widths_is_rejected() {
    let error = pattern_error("a=(0,2) b=(3,7)", "a!=b");
    assert!(
        error.contains("Incompatible field sizes"),
        "unexpected diagnostic: {error}"
    );
}

#[test]
fn comparing_overlapping_fields_is_rejected() {
    let error = pattern_error("a=(0,2) b=(2,4)", "a!=b");
    assert!(error.contains("overlap"), "unexpected diagnostic: {error}");
}

/// The `<` decomposition orders by raw bit weight, which a sign bit inverts.
/// Equality has no such problem, so `!=` on signed fields stays allowed.
#[test]
fn ordered_comparison_of_signed_fields_is_rejected_but_inequality_is_not() {
    let error = pattern_error("a=(0,2) signed b=(3,5) signed", "a<b");
    assert!(
        error.contains("Comparing signed fields"),
        "unexpected diagnostic: {error}"
    );

    compile_pattern("a=(0,2) signed b=(3,5) signed", "a!=b")
        .expect("`!=` is bit equality, so signedness does not matter");
}

#[test]
fn comparing_two_context_fields_is_still_rejected() {
    let error = pattern_error("a=(0,2) b=(3,5)", "cm!=cn");
    assert!(
        error.contains("context fields"),
        "unexpected diagnostic: {error}"
    );
}

const FIELD_COMPARE_MIPS_FIXTURE: &str = include_str!("fixtures/field_compare/mips_shape.sla");

/// The shape MIPS R6 actually uses: 5-bit register fields of a big-endian
/// 32-bit token, compared to each other, with a `!=` against a constant ANDed
/// alongside and an unconstrained constructor competing for the same opcode.
#[test]
fn mips_shaped_register_comparisons_select_the_right_constructor() {
    let spec = compile_fixture("field_compare_mips.sla", FIELD_COMPARE_MIPS_FIXTURE);
    let decoder = Decoder::new(&spec);
    let context = spec.new_context();

    let encode =
        |prime: u32, rs: u32, rt: u32| ((prime << 26) | (rs << 21) | (rt << 16) | 4).to_be_bytes();
    let display = |prime: u32, rs: u32, rt: u32| {
        decoder
            .decode_one(0x1000, &encode(prime, rs, rt), &context)
            .map(|instruction| instruction.display().expect("renders"))
            .map_err(|error| error.to_string())
    };

    // `rs != rt` and `rs = rt` split the same opcode between them.
    assert_eq!(display(7, 17, 18), Ok("nepair 17, 18".into()));
    assert_eq!(display(7, 18, 18), Ok("eqpair 18".into()));
    assert_eq!(display(7, 0, 18), Ok("nepair 0, 18".into()));

    // `rt != 0` is ANDed alongside, and knocks out both.
    assert!(display(7, 17, 0).is_err());
    assert!(display(7, 0, 0).is_err());

    // `rs < rt` is unsigned and strict; anything else falls through.
    assert_eq!(display(8, 17, 18), Ok("ltpair 17, 18".into()));
    assert_eq!(display(8, 1, 31), Ok("ltpair 1, 31".into()));
    assert_eq!(display(8, 18, 17), Ok("anypair 18, 17".into()));
    assert_eq!(display(8, 18, 18), Ok("anypair 18, 18".into()));
    assert_eq!(display(8, 31, 1), Ok("anypair 31, 1".into()));
    // `rs != 0` is ANDed alongside, so rs=0 falls through even though 0 < 18.
    assert_eq!(display(8, 0, 18), Ok("anypair 0, 18".into()));
}

// ── `with` blocks and or-pattern operands ─────────────────────────────────────

const WITH_DEFINITIONS_FIXTURE: &str = include_str!("fixtures/with_block/definitions.sla");
const OR_OPERANDS_FIXTURE: &str = include_str!("fixtures/with_block/or_operands.sla");

/// A `with` block's body is the ordinary definition list, not just
/// constructors. ARM wraps its whole instruction set in one and puts `attach
/// variables` inside; a body restricted to constructors made that a parse
/// error pointing at the `attach`, several hundred lines from the cause.
#[test]
fn a_with_block_body_accepts_definitions() {
    let spec = compile_fixture("with_definitions.sla", WITH_DEFINITIONS_FIXTURE);
    let decoder = Decoder::new(&spec);
    let context = spec.new_context();

    // The token and the attach table defined inside the block are in effect.
    let instruction = decoder
        .decode_one(0x1000, &[0xfd], &context)
        .expect("the inner token's constructor decodes");
    assert_eq!(instruction.display().unwrap(), "reg r1");

    // So is the pcodeop, and the macro.
    assert!(
        decoder
            .decode_one(0x1000, &[0x10], &context)
            .expect("decodes")
            .pcode_ast()
            .is_ok()
    );
}

/// One branch of a `|` may name an operand the other does not.
#[test]
fn or_pattern_branches_may_name_different_operands() {
    let spec = compile_fixture("or_operands.sla", OR_OPERANDS_FIXTURE);
    let decoder = Decoder::new(&spec);
    let context = spec.new_context();

    let display = |op: u8, low: u8| {
        decoder
            .decode_one(0x1000, &[low, op], &context)
            .map(|instruction| instruction.display().expect("renders"))
            .map_err(|error| error.to_string())
    };

    // Left branch, which names `sz`: sz = 2, rd = 5.
    assert_eq!(display(0x10, 0x25), Ok("pick 2, 5".into()));

    // Right branch, which does not. `sz` is still an operand of the
    // constructor, and still read out of the token.
    assert_eq!(display(0x20, 0x35), Ok("pick 3, 5".into()));

    // Neither branch.
    assert!(display(0x30, 0x25).is_err());
}

const RECURSIVE_TABLE_FIXTURE: &str = include_str!("fixtures/with_block/recursive_table.sla");

/// A table that matches itself at the same offset never consumes a byte, so the
/// recursion cannot terminate. Decoding must give up with a typed error rather
/// than overflow the stack — and it must say *cycle*, not *degenerate search*:
/// the two have different causes and different fixes.
#[test]
fn a_table_that_recurses_without_consuming_bytes_reports_a_cycle() {
    let spec = compile_fixture("recursive_table.sla", RECURSIVE_TABLE_FIXTURE);

    let error = match Decoder::new(&spec).decode_one(0x1000, &[1], &spec.new_context()) {
        Ok(_) => panic!("a table matching itself at the same offset cannot resolve"),
        Err(error) => error,
    };

    assert_eq!(error, DecodeError::SearchCycle);
}

// ── Self-recursive tables ─────────────────────────────────────────────────────

const RECURSIVE_LIST_FIXTURE: &str = include_str!("fixtures/recursive_list/root.sla");

/// A table that references itself contributes **one** operand for that
/// reference, not two.
///
/// `concretize_table` returns a placeholder while a table is still being built,
/// and `build_operand` adds the operand; when the placeholder carried one too,
/// a self-recursive table got two. Every level of a recursive list then decoded
/// its own tail twice — 2^depth work — which is what made ARM's `vldmia` with a
/// long register list undecodable.
#[test]
fn a_self_recursive_table_contributes_one_operand_per_reference() {
    use crate::pattern::OperandType;

    let spec = compile_fixture("recursive_list.sla", RECURSIVE_LIST_FIXTURE);
    let inner = spec.spec();

    let (tree_id, tree) = inner
        .trees
        .iter()
        .map(|tree| (tree.id, tree.inner))
        .find(|(_, tree)| &*tree.name == "buildList")
        .expect("the fixture defines `buildList`");
    let self_table = crate::objects::table::TableId::from(usize::from(tree_id));

    let recursive = tree
        .constructors
        .iter()
        .map(|c| c.inner)
        .find(|c| {
            c.token_pattern
                .operands
                .iter()
                .any(|op| op.ty == OperandType::Table(self_table))
        })
        .expect("one constructor recurses");

    let self_references = recursive
        .token_pattern
        .operands
        .iter()
        .filter(|op| op.ty == OperandType::Table(self_table))
        .count();

    assert_eq!(
        self_references,
        1,
        "`buildList` appears {self_references} times in its own operand list; \
         operands are {:?}",
        recursive
            .token_pattern
            .operands
            .iter()
            .map(|op| op.ty)
            .collect::<Vec<_>>()
    );
}

/// A long recursive list decodes in linear work.
///
/// The duplicated operand made this exponential in the list length: a 24-element
/// list needs 2^24 constructor attempts, far past `SEARCH_BUDGET_LIMIT`, so a
/// regression fails fast with [`DecodeError::SearchExhausted`] rather than
/// hanging the suite.
#[test]
fn a_long_recursive_list_decodes_without_exhausting_the_search() {
    let spec = compile_fixture("recursive_list.sla", RECURSIVE_LIST_FIXTURE);
    let decoder = Decoder::new(&spec);
    let context = spec.new_context();

    for length in [1u8, 2, 8, 24, 31] {
        let bytes = [length];
        let instruction = decoder
            .decode_one(0x1000, &bytes, &context)
            .unwrap_or_else(|error| {
                panic!("a {length}-element list must decode, got {error}");
            });

        // One `Reg` per element, so the rendered list pins the recursion depth.
        let display = instruction.display().expect("renders");
        let elements = display.matches('r').count();
        assert_eq!(
            elements, length as usize,
            "expected {length} elements, got {display}"
        );
    }
}

// ── Branch destinations ───────────────────────────────────────────────────────

const BRANCH_TARGET_FIXTURE: &str = include_str!("fixtures/branch_target/root.sla");

/// A literal integer destination is an address in the default space, sized to
/// that space's address width — the same width `inst_next` resolves to.
#[test]
fn a_literal_branch_destination_is_an_address_in_the_default_space() {
    let spec = compile_fixture("branch_target.sla", BRANCH_TARGET_FIXTURE);
    let decoder = Decoder::new(&spec);
    let context = spec.new_context();

    let pcode = |op: u8| {
        let bytes = [op];
        decoder
            .decode_one(0x1000, &bytes, &context)
            .expect("decodes")
            .pcode_ast()
            .expect("emits")
            .pretty_print(&spec)
    };

    // `ram` is `size=4`, so a destination is four bytes wide.
    assert_eq!(pcode(1), "goto 4660:4;");
    assert_eq!(pcode(2), "call 64:4;");
    assert!(
        pcode(3).contains("goto 8:4;"),
        "conditional literal destination: {}",
        pcode(3)
    );

    // The pre-existing forms are untouched.
    assert_eq!(pcode(4), "goto 4097:4;");
    assert!(pcode(5).contains("goto <done>;"), "label: {}", pcode(5));
    assert!(pcode(6).contains("goto [r0];"), "indirect: {}", pcode(6));
}

// ── Disassembly-action locals ─────────────────────────────────────────────────

const ACTION_LOCAL_FIXTURE: &str = include_str!("fixtures/action_local/root.sla");

/// A disassembly-action local is scoped to its constructor, so it may carry a
/// name the shared symbol table has already given to something else.
///
/// Loongarch writes `csr: csr is imm10_14 [csr = ...] { export *[register]:N csr; }`:
/// the action local and the table it belongs to are both called `csr`. Modelling
/// the local as a *named* global made that a "Redefinition of symbol csr". The
/// body reads the name back, so action resolution and p-code resolution have to
/// agree on one per-constructor scope.
#[test]
fn an_action_local_may_shadow_the_table_it_belongs_to() {
    let spec = compile_fixture("action_local.sla", ACTION_LOCAL_FIXTURE);
    let decoder = Decoder::new(&spec);
    let context = spec.new_context();

    // idx = 3, so the action computes `csr = 4 * 3 = 12` and the body exports
    // `*[register]:4 12`. What matters is where the 12 came from: the local,
    // not the table of the same name.
    let bytes = [0x13];
    let pcode = decoder
        .decode_one(0x1000, &bytes, &context)
        .expect("decodes")
        .pcode_ast()
        .expect("emits")
        .pretty_print(&spec);

    assert!(
        pcode.contains("12"),
        "the body should read the action local (4 * 3 = 12); got {pcode}"
    );

    // And in a constructor with no such local, the same name is the table.
    let display = decoder
        .decode_one(0x1000, &bytes, &context)
        .expect("decodes")
        .display()
        .expect("renders");
    assert_eq!(display, "read r0, 12");
}

// ── Ellipsis alignment ────────────────────────────────────────────────────────

const ELLIPSIS_FIXTURE: &str = include_str!("fixtures/ellipsis/root.sla");

/// A `...` that happens not to extend anything is not an error.
///
/// `A ... & B` with both sides the same length is an ordinary fixed pattern.
/// Rejecting it cost four specs; the case that really is broken — an
/// unanchored side *longer* than the fixed one — is still rejected, below.
#[test]
fn an_ellipsis_that_extends_nothing_is_accepted() {
    let spec = compile_fixture("ellipsis.sla", ELLIPSIS_FIXTURE);
    let decoder = Decoder::new(&spec);
    let context = spec.new_context();

    for (bytes, expected) in [([0x15u8], "left"), ([0x25], "left"), ([0x37], "right")] {
        let instruction = decoder
            .decode_one(0x1000, &bytes, &context)
            .expect("decodes");
        assert_eq!(instruction.display().unwrap(), expected);
        assert_eq!(instruction.len(), 1);
    }
}

/// The guard that matters is still in place: an unanchored side longer than
/// the fixed side it is combined with has no consistent length.
#[test]
fn an_ellipsis_longer_than_the_side_it_meets_is_rejected() {
    let src = "define endian=little;
         define space ram type=ram_space size=4 default;
         define space register type=register_space size=4;
         define register offset=0 size=4 [r0];
         define token wide(16) w=(0,15);
         define token narrow(8) n=(0,7);
         :bad is (w=1; w=2) ... & n=3 { r0 = 0; }";

    let mut sources = SourceDb::new();
    let root = sources.add_file("ellipsis_bad.sla".to_string(), src);
    let Err(error) = Compiler::new(&mut sources).compile(root) else {
        panic!("a two-token unanchored side against one fixed token has no length");
    };
    assert!(
        error.to_string().contains("Mismatched"),
        "unexpected diagnostic: {error}"
    );
}

// ── Fields after a `;` ────────────────────────────────────────────────────────

/// Several fields of one token that follows a `;` all start where the
/// left-hand pattern ends.
///
/// x86's memory `PCLMULQDQ` is `... & m128; imm8 & imm8_4 & imm8_0`: three
/// views of the one trailing byte. The walker placed each relative field at
/// the running end of the constructor, which already counted the sibling
/// fields placed before it, so the three were laid end to end and the
/// instruction came out two bytes long. `ea` here stands in for `m128`: it is
/// one byte, or two when its top bit is set.
#[test]
fn fields_of_one_token_after_a_concatenation_share_its_start() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "relative_fields.sla",
        "define endian=little;\n\
         define space ram type=ram_space size=4 default;\n\
         define space register type=register_space size=4;\n\
         define register offset=0 size=4 [r0];\n\
         define token op(8) opc=(0,7);\n\
         define token modrm(8) long=(7,7) base=(0,6);\n\
         define token imm(8) imm8=(0,7) imm8_4=(4,4) imm8_0=(0,0);\n\
         ea: base is long=0 & base { export *[const]:4 base; }\n\
         ea: base is long=1 & base; opc { export *[const]:4 base; }\n\
         :hit ea, imm8, imm8_4, imm8_0 is opc=0x44; ea; imm8 & imm8_4 & imm8_0 { r0 = ea; }\n",
    );
    let spec = Compiler::new(&mut sources).compile(root).expect("compiles");
    let decoder = Decoder::new(&spec);
    let context = spec.new_context();

    // The trailing byte is followed by filler that would be misread as the
    // two single-bit fields if they were placed after `imm8`.
    for (bytes, len, display) in [
        (&[0x44u8, 0x05, 0x11, 0xee, 0xee][..], 3, "hit 5, 17, 1, 1"),
        (&[0x44, 0x85, 0x00, 0x10, 0xee, 0xee], 4, "hit 5, 16, 1, 0"),
        (&[0x44, 0x05, 0x01, 0xee, 0xee], 3, "hit 5, 1, 0, 1"),
    ] {
        let instruction = decoder
            .decode_one(0x1000, bytes, &context)
            .expect("decodes");
        assert_eq!(instruction.len(), len, "{bytes:02x?}");
        assert_eq!(instruction.display().unwrap(), display, "{bytes:02x?}");
    }
}

// ── Load pointers ─────────────────────────────────────────────────────────────

const LOAD_PREFIX_FIXTURE: &str = include_str!("fixtures/load_prefix/root.sla");

/// The pointer of a load may carry a prefix operator.
///
/// Xtensa reads the bytes of a register with `*[register]:1 &:4 bs+1`. The
/// pointer is a *unary* expression, not a full one — the star still binds
/// tighter than any binary operator, so `*:4 r1 + 1` stays `(*:4 r1) + 1`.
#[test]
fn a_load_pointer_may_carry_a_prefix_operator() {
    let spec = compile_fixture("load_prefix.sla", LOAD_PREFIX_FIXTURE);
    let decoder = Decoder::new(&spec);
    let context = spec.new_context();

    let pcode = |op: u8| {
        let bytes = [op];
        decoder
            .decode_one(0x1000, &bytes, &context)
            .expect("decodes")
            .pcode_ast()
            .expect("emits")
            .pretty_print(&spec)
    };

    assert!(
        pcode(1).contains("ptr=&:4 r1"),
        "the prefix belongs to the pointer: {}",
        pcode(1)
    );
    assert!(pcode(2).contains("&:4 r1"), "bare address-of: {}", pcode(2));

    // Precedence is unchanged: the load happens first, then the addition.
    let tight = pcode(3);
    assert!(
        tight.contains("load(") && tight.contains("+ 1"),
        "the star must still bind tighter than `+`: {tight}"
    );
}

// ── Remaining corpus conformance gaps ─────────────────────────────────────────

const CONFORMANCE_FIXTURE: &str = include_str!("fixtures/conformance/root.sla");

/// `_` in an `attach values` list is a slot with nothing attached, and reads
/// back the way an unattached `attach variables` entry does.
#[test]
fn an_attach_values_list_may_have_unattached_slots() {
    let spec = compile_fixture("conformance.sla", CONFORMANCE_FIXTURE);
    let decoder = Decoder::new(&spec);
    let context = spec.new_context();

    for (sel, attached) in [(0u8, "1"), (1, "2"), (2, "4")] {
        let bytes = [0x10 | sel];
        let instruction = decoder
            .decode_one(0x1000, &bytes, &context)
            .expect("decodes");
        assert_eq!(instruction.display().unwrap(), format!("val {attached}"));
    }

    // The fourth slot is `_`: there is no value to render.
    let bytes = [0x13];
    let instruction = decoder
        .decode_one(0x1000, &bytes, &context)
        .expect("decodes");
    assert_eq!(instruction.display(), Err(DecodeError::UnresolvedDisplay));
}

/// A store's pointer is a full expression.
#[test]
fn a_store_pointer_may_be_a_binary_expression() {
    let spec = compile_fixture("conformance.sla", CONFORMANCE_FIXTURE);
    let bytes = [0x20];
    let pcode = Decoder::new(&spec)
        .decode_one(0x1000, &bytes, &spec.new_context())
        .expect("decodes")
        .pcode_ast()
        .expect("emits")
        .pretty_print(&spec);

    assert!(
        pcode.contains("(r0 + 8)") && pcode.contains("= r1"),
        "the whole `r0+8` is the pointer: {pcode}"
    );
}

/// A register read by a disassembly action is the constant zero.
///
/// It has no value at disassembly time. Ghidra models one as a
/// `PatternlessSymbol`, whose pattern expression is zero, and avr32a depends on
/// that: `disp = ACBA + (disp4_8 << 2)` means "relative to whatever `ACBA`
/// holds". Compiling it any other way would reject a spec Ghidra accepts.
#[test]
fn a_register_in_a_disassembly_action_reads_as_zero() {
    let spec = compile_fixture("conformance.sla", CONFORMANCE_FIXTURE);
    let bytes = [0x35];
    let pcode = Decoder::new(&spec)
        .decode_one(0x1000, &bytes, &spec.new_context())
        .expect("decodes")
        .pcode_ast()
        .expect("emits")
        .pretty_print(&spec);

    // arg = 5, so the action computes 0 + (5 << 2) = 20.
    assert!(
        pcode.contains("20"),
        "`ctl` contributes zero, leaving 5 << 2: {pcode}"
    );
}

// ── Diagnostics ───────────────────────────────────────────────────────────────

/// Compilation reports *every* diagnostic, not just the first.
#[test]
fn compile_error_display_lists_all_diagnostics() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "two_errors.sla",
        "define endian=little;\n\
         define space ram type=ram_space size=4 default;\n\
         define space register type=register_space size=4;\n\
         define register offset=0 size=4 [r0];\n\
         define token instr(8) op=(0,7);\n\
         :a is op=1 [ x = nope1; ] { r0 = 1; }\n\
         :b is op=2 [ y = nope2; ] { r0 = 2; }\n",
    );

    let error = match Compiler::new(&mut sources).compile(root) {
        Ok(_) => panic!("both constructors reference undefined fields"),
        Err(error) => error,
    };

    assert!(error.diagnostics().len() >= 2, "{error}");
    let text = error.to_string();
    assert!(text.contains("nope1"), "first diagnostic missing: {text}");
    assert!(text.contains("nope2"), "later diagnostics dropped: {text}");
}

/// `Diagnostic::render` quotes the offending line and underlines the span.
#[test]
fn a_diagnostic_renders_an_annotated_snippet() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "snippet.sla",
        "define endian=little;\ndefine space ram type=ram_space size=4 default;\nnonsense\n",
    );

    let error = match Compiler::new(&mut sources).compile(root) {
        Ok(_) => panic!("`nonsense` is not a SLEIGH item"),
        Err(error) => error,
    };

    let rendered = error.diagnostics()[0].render(&sources);
    assert!(rendered.starts_with("error: "), "{rendered}");
    assert!(rendered.contains("snippet.sla:"), "{rendered}");
    assert!(rendered.contains('^'), "no underline: {rendered}");
}

/// A register read by a disassembly action compiles — matching Ghidra — but
/// says so, rather than silently reading as zero.
#[test]
fn a_register_in_a_disassembly_action_warns() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "regaction.sla",
        "define endian=little;\n\
         define space ram type=ram_space size=4 default;\n\
         define space register type=register_space size=4;\n\
         define register offset=0 size=4 [r0 ctl];\n\
         define token instr(8) op=(0,3) arg=(4,7);\n\
         sub: rel is arg [ rel = ctl + arg; ] { export *:4 rel; }\n\
         :use sub is op=1 & sub { r0 = sub; }\n",
    );

    let analysis = analyze(&mut sources, root);
    let warning = analysis
        .diagnostics
        .iter()
        .find(|d| d.message.contains("reads as 0"))
        .unwrap_or_else(|| panic!("expected a warning, got {:?}", analysis.diagnostics));

    assert_eq!(warning.severity, crate::Severity::Warning);
    assert!(warning.message.contains("ctl"), "{}", warning.message);
}

// ── Signed field display ──────────────────────────────────────────────────────

/// A `signed` field renders its value signed.
///
/// The value is sign-extended when it is read out of the instruction, so
/// rendering it unsigned printed a twenty-digit number where the specification
/// means `-2` — x86 disassembled `ADD RAX,-2` as
/// `ADD RAX,18446744073709551614`.
#[test]
fn a_signed_field_displays_negative_values_as_negative() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "signed.sla",
        "define endian=little;\n\
         define space ram type=ram_space size=4 default;\n\
         define space register type=register_space size=4;\n\
         define register offset=0 size=4 [r0];\n\
         define token instr(16) op=(8,15) simm=(0,7) signed uimm=(0,7);\n\
         :addi simm is op=1 & simm { r0 = r0 + simm; }\n\
         :addu uimm is op=2 & uimm { r0 = r0 + uimm; }\n",
    );
    let spec = Compiler::new(&mut sources).compile(root).expect("compiles");
    let decoder = Decoder::new(&spec);
    let context = spec.new_context();

    let display = |op: u8, imm: u8| {
        decoder
            .decode_one(0x1000, &[imm, op], &context)
            .expect("decodes")
            .display()
            .expect("renders")
    };

    assert_eq!(display(1, 0xfe), "addi -2");
    assert_eq!(display(1, 0x7f), "addi 127");
    assert_eq!(display(1, 0x80), "addi -128");
    assert_eq!(display(1, 0x00), "addi 0");

    // An unsigned field of the same width is unaffected.
    assert_eq!(display(2, 0xfe), "addu 254");
}
