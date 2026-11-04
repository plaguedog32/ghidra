//! Direct branch and call targets through sub-table exports (local fork).
//!
//! Native SLEIGH (`HandleTpl::fix`, `SleighBuilder::generateLocation`)
//! branches to an operand's fixed handle: the export's space and width, with
//! a starred pointer converted from address units to bytes and wrapped into
//! the space's byte domain. Every expected offset here is worked by hand from
//! those definitions; see `wazabin-pcode`'s `qualified_target_tests` for the
//! arithmetic itself. Each instruction is lowered through the owned AST, the
//! slice callback and the streamed planner/emitter, which must agree.

use pcode_types::{DirectDestination, PointerUnits, QualifiedTarget};

use super::streamed::{QUALIFIED_TARGET, Rebuild, assert_equivalent, compile};
use crate::{
    CompiledSpec, Decoder, Instruction, Opcode, PcodeOp, SPACE_CONST, SpaceId, Varnode,
    semantics::{PcodeAst, PcodeExprKind, PcodeIdent, PcodeStatementKind, PcodeTarget},
};

fn space(spec: &CompiledSpec, name: &str) -> SpaceId {
    spec.space(name).unwrap().id
}

fn decode<'a>(spec: &'a CompiledSpec, bytes: &'a [u8]) -> Instruction<'a, 'a> {
    Decoder::new(spec)
        .decode_one(0x1000, bytes, &spec.new_context())
        .unwrap_or_else(|error| panic!("{bytes:02x?} decodes: {error}"))
}

/// Lowers through all three routes, checks they agree, and returns the
/// operations with the streamed plan's destinations.
#[track_caller]
fn lower(
    spec: &CompiledSpec,
    bytes: &[u8],
) -> (Vec<PcodeOp>, Vec<DirectDestination>, Vec<DirectDestination>) {
    let instruction = decode(spec, bytes);
    let ops = assert_equivalent(&instruction).unwrap_or_else(|e| panic!("{bytes:02x?}: {e}"));
    let callback = instruction.pcode_ops_into(|ops| ops.to_vec()).unwrap();
    assert_eq!(callback, ops, "{bytes:02x?}: slice callback");
    let plan = instruction.pcode_ops_streamed(Rebuild::from_plan).unwrap();
    (ops, plan.direct_branches, plan.direct_calls)
}

#[track_caller]
fn refused(spec: &CompiledSpec, bytes: &[u8]) -> String {
    let instruction = decode(spec, bytes);
    let error = assert_equivalent(&instruction).expect_err("refused");
    assert_eq!(
        instruction
            .pcode_ops_into(|ops| ops.len())
            .unwrap_err()
            .to_string(),
        error
    );
    error
}

fn target_of(ast: &PcodeAst, index: usize) -> &PcodeTarget {
    match &ast.statements[index].ty {
        PcodeStatementKind::Branch { target }
        | PcodeStatementKind::ConditionalBranch { target, .. }
        | PcodeStatementKind::Call { target } => target,
        other => panic!("not a direct branch: {other:?}"),
    }
}

fn word_source(word: usize, big: bool) -> String {
    let order = if big { "big" } else { "little" };
    format!(
        "define endian={order};
         define space ram type=ram_space size=2 default;
         define space register type=register_space size=2;
         define space aux type=ram_space size=1 wordsize={word};
         define register offset=0 size=2 [r0];
         define token encoding(8) op=(0,7);
         tgt: is epsilon {{ export *[aux]:2 0x10:1; }}
         :jb is op=19 & tgt {{ goto tgt; }}
         :cb is op=20 & tgt {{ if (r0 == 0) goto tgt; }}
         :cl is op=21 & tgt {{ call tgt; }}"
    )
}

#[test]
fn starred_exports_keep_space_width_and_units_for_every_word_size_and_byte_order() {
    // 0x10 address units of w bytes start at byte 0x10 * w.
    let expected = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
    for (word, offset) in (1..=8).zip(expected) {
        for big in [false, true] {
            let what = format!("word {word}, big {big}");
            let spec = compile("word.sla", &word_source(word, big));
            let aux = space(&spec, "aux");
            let ram = spec.default_space();
            let destination = Varnode::new(aux, offset, 2);

            // The owned AST keeps the export's provenance, and survives a
            // serde round trip unchanged.
            let ast = decode(&spec, &[19]).pcode_ast().unwrap();
            let PcodeTarget::Address(QualifiedTarget {
                space: target_space,
                ptr,
                size: 2,
                units: PointerUnits::AddressUnits,
            }) = target_of(&ast, 0)
            else {
                panic!("{what}: {:?}", ast.statements);
            };
            assert_eq!(*target_space, aux, "{what}");
            assert!(
                matches!(
                    ptr.ty,
                    PcodeExprKind::SizedInt {
                        value: 0x10,
                        size: Some(1)
                    }
                ),
                "{what}: {ptr:?}"
            );
            let json = serde_json::to_string(&ast).unwrap();
            assert_eq!(serde_json::from_str::<PcodeAst>(&json).unwrap(), ast);
            assert!(
                ast.pretty_print(&spec)
                    .contains("address(space=aux, size=2")
            );

            let (ops, branches, calls) = lower(&spec, &[19]);
            assert_eq!(
                ops,
                vec![PcodeOp::new(Opcode::Branch, None, vec![destination])]
            );
            assert_eq!(branches, vec![DirectDestination { space: aux, offset }]);
            assert!(calls.is_empty());
            assert_ne!(aux, ram);

            let (ops, branches, _) = lower(&spec, &[20]);
            assert_eq!(
                ops.iter().map(|op| op.opcode).collect::<Vec<_>>(),
                [Opcode::IntEqual, Opcode::CBranch],
                "{what}"
            );
            // The condition's temporary is the branch's second input.
            assert_eq!(ops[1].inputs, vec![destination, ops[0].output.unwrap()]);
            assert_eq!(branches, vec![DirectDestination { space: aux, offset }]);

            let (ops, branches, calls) = lower(&spec, &[21]);
            assert_eq!(
                ops,
                vec![PcodeOp::new(Opcode::Call, None, vec![destination])]
            );
            assert!(branches.is_empty());
            assert_eq!(calls, vec![DirectDestination { space: aux, offset }]);
        }
    }
}

#[test]
fn each_export_shape_reaches_its_destination() {
    let spec = compile("qualified_target.sla", QUALIFIED_TARGET);
    let aux = space(&spec, "aux");
    let aux16 = space(&spec, "aux16");
    let ram = spec.default_space();
    let branch = |bytes: &[u8]| {
        let (ops, ..) = lower(&spec, bytes);
        assert_eq!(ops.len(), 1, "{bytes:02x?}");
        assert_eq!(ops[0].opcode, Opcode::Branch);
        ops[0].inputs[0]
    };
    // `*[aux]:2 0x10:1`, word size 3.
    assert_eq!(branch(&[1]), Varnode::new(aux, 0x30, 2));
    // Export width, not pointer width: wider and narrower.
    assert_eq!(branch(&[4]), Varnode::new(aux, 0x30, 4));
    assert_eq!(branch(&[5]), Varnode::new(aux, 0x30, 1));
    // `0x110:1` is not truncated to one byte: 0x110 * 3 in a two-byte space.
    assert_eq!(branch(&[6]), Varnode::new(aux16, 0x330, 2));
    // 0x8000000000000000 * 3 wraps to 2^63; its signed remainder modulo 768
    // is -512, so the byte offset is 256.
    assert_eq!(branch(&[7]), Varnode::new(aux, 0x100, 1));
    // A default-space starred export takes the export's width, 2, rather
    // than the one-byte pointer's.
    assert_eq!(branch(&[8]), Varnode::new(ram, 0x10, 2));
    // A decoded field as the pointer: 0x55 * 3 = 0xff; 0xff * 3 = 765, the
    // first byte of the final complete word.
    assert_eq!(branch(&[9, 0x55]), Varnode::new(aux, 0xff, 2));
    assert_eq!(branch(&[9, 0xff]), Varnode::new(aux, 765, 2));
    // Two levels of pass-through exports keep the provenance.
    assert_eq!(branch(&[10]), Varnode::new(aux, 0x30, 2));
    let ast = decode(&spec, &[10]).pcode_ast().unwrap();
    assert!(matches!(
        target_of(&ast, 0),
        PcodeTarget::Address(QualifiedTarget { space, size: 2, .. }) if *space == aux
    ));
    // An ordinary literal target keeps the default space and its width.
    assert_eq!(branch(&[20]), Varnode::new(ram, 0x30, 2));
    let ast = decode(&spec, &[20]).pcode_ast().unwrap();
    assert!(matches!(target_of(&ast, 0), PcodeTarget::Expr(_)));
}

#[test]
fn equal_offsets_in_distinct_spaces_are_distinct_plan_destinations() {
    let spec = compile("qualified_target.sla", QUALIFIED_TARGET);
    let aux = space(&spec, "aux");
    let byte = space(&spec, "byte");
    let ram = spec.default_space();
    let (ops, branches, calls) = lower(&spec, &[11]);
    let at = |space, offset| DirectDestination { space, offset };
    // `dflt` (ram) and `btgt` (byte) both export byte offset 0x10.
    assert_eq!(branches, vec![at(aux, 0x30), at(ram, 0x10), at(byte, 0x10)]);
    assert_eq!(calls, vec![at(ram, 0x10), at(aux, 0x30)]);
    let targets: Vec<Varnode> = ops
        .iter()
        .filter(|op| matches!(op.opcode, Opcode::CBranch | Opcode::Call))
        .map(|op| op.inputs[0])
        .collect();
    assert_eq!(
        targets,
        vec![
            Varnode::new(aux, 0x30, 2),
            Varnode::new(ram, 0x10, 2),
            Varnode::new(byte, 0x10, 2),
            Varnode::new(ram, 0x10, 2),
            Varnode::new(aux, 0x30, 2),
        ]
    );
}

#[test]
fn local_labels_macros_and_delay_slots_are_unchanged() {
    let spec = compile("qualified_target.sla", QUALIFIED_TARGET);
    let aux = space(&spec, "aux");
    let destination = Varnode::new(aux, 0x30, 2);
    let relative = |delta: i64| Varnode::constant(delta as u64, 8);

    // `skip(r1)` expands its own scoped label, then a forward branch to the
    // terminal `<end>` and a backward branch to `<top>` around a call.
    let instruction = decode(&spec, &[12]);
    let (ops, branches, calls) = lower(&spec, &[12]);
    assert_eq!(
        ops.iter().map(|op| op.opcode).collect::<Vec<_>>(),
        [
            Opcode::IntEqual,
            Opcode::CBranch,
            Opcode::Copy,
            Opcode::IntEqual,
            Opcode::CBranch,
            Opcode::Call,
            Opcode::IntSub,
            Opcode::IntNotEqual,
            Opcode::CBranch,
        ]
    );
    // op 1 -> `<out>` before op 3; op 4 -> terminal `<end>` after op 8, at
    // 9; op 8 -> `<top>` at op 5.
    assert_eq!(ops[1].inputs[0], relative(2));
    assert_eq!(ops[4].inputs[0], relative(5));
    assert_eq!(ops[8].inputs[0], relative(-3));
    assert_eq!(ops[5].inputs, vec![destination]);
    assert!(branches.is_empty());
    assert_eq!(
        calls,
        vec![DirectDestination {
            space: aux,
            offset: 0x30
        }]
    );
    let rebuilt = instruction.pcode_ops_streamed(Rebuild::from_plan).unwrap();
    assert_eq!(rebuilt.direct_calls, calls);

    // A delay slot spliced before a qualified branch: the delayed
    // instruction's label is scoped and not terminal, and its relative
    // branch is unchanged.
    let (ops, branches, _) = lower(&spec, &[13, 14]);
    assert_eq!(
        ops.iter().map(|op| op.opcode).collect::<Vec<_>>(),
        [
            Opcode::IntEqual,
            Opcode::CBranch,
            Opcode::Copy,
            Opcode::Branch
        ]
    );
    assert_eq!(ops[1].inputs[0], relative(2));
    assert_eq!(ops[3].inputs, vec![destination]);
    assert_eq!(
        branches,
        vec![DirectDestination {
            space: aux,
            offset: 0x30
        }]
    );
    let ast = decode(&spec, &[13, 14]).pcode_ast().unwrap();
    assert!(
        ast.statements
            .iter()
            .any(|s| matches!(&s.ty, PcodeStatementKind::Label(name) if &**name == "done#ds1"))
    );
}

#[test]
fn unsupported_target_shapes_are_explicit_errors() {
    let spec = compile("qualified_target.sla", QUALIFIED_TARGET);
    let aux = space(&spec, "aux");
    let dynamic = "raw p-code lowering does not support a direct branch or call through a dynamic exported pointer";
    let constant =
        "raw p-code lowering does not support a constant-space direct branch or call target";
    // `*[aux]:2 r0` would need native's LOAD through the pointer: refused,
    // never a guessed indirect branch or default-space literal. The AST
    // still records what was exported.
    assert_eq!(refused(&spec, &[15]), dynamic);
    assert_eq!(refused(&spec, &[16]), dynamic);
    let ast = decode(&spec, &[15]).pcode_ast().unwrap();
    assert!(matches!(
        target_of(&ast, 0),
        PcodeTarget::Address(QualifiedTarget { space, ptr, .. })
            if *space == aux && matches!(ptr.ty, PcodeExprKind::Ident(PcodeIdent::Register(_)))
    ));
    // Native branches to a constant-space handle, which raw p-code reads as
    // a relative branch: refused, for starred and unstarred constants alike.
    assert_eq!(refused(&spec, &[17]), constant);
    assert_eq!(refused(&spec, &[18]), constant);
    let ast = decode(&spec, &[18]).pcode_ast().unwrap();
    assert!(matches!(
        target_of(&ast, 0),
        PcodeTarget::Address(QualifiedTarget {
            space,
            size: 2,
            units: PointerUnits::Bytes,
            ..
        }) if *space == SPACE_CONST
    ));
    // An unstarred register export is still not a direct target.
    assert_eq!(refused(&spec, &[19]), "invalid direct p-code branch target");
    // A refusal is per instruction: the next decode lowers normally.
    let (ops, ..) = lower(&spec, &[1]);
    assert_eq!(ops[0].inputs, vec![Varnode::new(aux, 0x30, 2)]);
}
