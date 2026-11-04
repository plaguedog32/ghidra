//! The streamed lowering against the owned one.
//!
//! [`Instruction::pcode_ops_streamed`] plans and emits straight from the
//! resolved semantics; [`Instruction::pcode_ops`] lowers the owned
//! [`PcodeAst`]. They must agree operation for operation, and the plan the
//! streamed path hands its sink must describe the same instruction the AST
//! does. Each scenario below decodes a shape that stresses one part of the
//! resolution — temporaries, branches, labels, macros, sub-table exports,
//! delay slots, `inst_next2`, width inference — and checks both.

use std::collections::HashMap;

use crate::{
    CompiledSpec, Compiler, Decoder, Instruction, LabelId, Opcode, PcodeOp, PcodePlan, PcodeSink,
    SourceDb, Varnode,
    semantics::{PcodeAst, PcodeExprKind, PcodeStatementKind, PcodeTarget},
};

const BRANCHING: &str = include_str!("fixtures/semantics/branching.sla");
const BUILD_EXPORT: &str = include_str!("fixtures/semantics/build_export.sla");
const EXPRESSIONS: &str = include_str!("fixtures/semantics/expressions.sla");
const LOAD_STORE: &str = include_str!("fixtures/semantics/load_store.sla");
const USEROP_MACRO: &str = include_str!("fixtures/semantics/userop_macro.sla");
const MACRO_LVALUE: &str = include_str!("fixtures/semantics/macro_lvalue.sla");
const STREAMED: &str = include_str!("fixtures/semantics/streamed.sla");
const DELAY_SLOT: &str = include_str!("fixtures/delay_slot/root.sla");

fn compile(name: &str, source: &str) -> CompiledSpec {
    let mut sources = SourceDb::new();
    let root = sources.add_file(name, source);
    Compiler::new(&mut sources)
        .compile(root)
        .unwrap_or_else(|error| panic!("{name} compiles: {error:?}"))
}

/// The sink that rebuilds what [`Instruction::pcode_ops`] returns: it keeps
/// every operation and resolves local branches to the relative offsets flat
/// p-code uses, and it keeps the plan so the test can check it too.
struct Rebuild {
    ops: Vec<PcodeOp>,
    label_ops: HashMap<LabelId, usize>,
    fixups: Vec<(usize, LabelId)>,
    labels: Vec<String>,
    terminal: Vec<bool>,
    direct_branches: Vec<u64>,
    direct_calls: Vec<u64>,
}

impl Rebuild {
    fn from_plan(plan: &PcodePlan) -> Self {
        Self {
            ops: Vec::new(),
            label_ops: HashMap::new(),
            fixups: Vec::new(),
            labels: plan.labels().iter().map(|l| l.to_string()).collect(),
            terminal: (0..plan.labels().len())
                .map(|index| plan.is_terminal(LabelId::from_index(index)))
                .collect(),
            direct_branches: plan.direct_branches().to_vec(),
            direct_calls: plan.direct_calls().to_vec(),
        }
    }

    fn finish(mut self) -> Vec<PcodeOp> {
        for (op_index, label) in &self.fixups {
            let target = self.label_ops[label];
            let relative = target as i64 - *op_index as i64;
            self.ops[*op_index].inputs[0] = Varnode::constant(relative as u64, 8);
        }
        self.ops
    }
}

impl PcodeSink for Rebuild {
    fn op(&mut self, opcode: Opcode, output: Option<Varnode>, inputs: &[Varnode]) {
        self.ops.push(PcodeOp::new(opcode, output, inputs.to_vec()));
    }

    fn label(&mut self, label: LabelId) {
        self.label_ops.insert(label, self.ops.len());
    }

    fn branch_label(&mut self, opcode: Opcode, label: LabelId, condition: Option<Varnode>) {
        let mut inputs = vec![Varnode::constant(0, 8)];
        inputs.extend(condition);
        self.fixups.push((self.ops.len(), label));
        self.ops.push(PcodeOp::new(opcode, None, inputs));
    }
}

/// What the owned AST says the plan should contain.
struct AstFacts {
    labels: Vec<String>,
    terminal: Vec<bool>,
    direct_branches: Vec<u64>,
    direct_calls: Vec<u64>,
}

impl AstFacts {
    fn of(ast: &PcodeAst) -> Self {
        let mut facts = Self {
            labels: Vec::new(),
            terminal: Vec::new(),
            direct_branches: Vec::new(),
            direct_calls: Vec::new(),
        };
        let address = |target: &PcodeTarget| match target {
            PcodeTarget::Expr(expr) => match expr.ty {
                PcodeExprKind::SizedInt { value, .. } => Some(value),
                _ => None,
            },
            _ => None,
        };
        for statement in &ast.statements {
            match &statement.ty {
                PcodeStatementKind::Label(name) if !facts.labels.iter().any(|l| l == &**name) => {
                    facts.labels.push(name.to_string());
                    facts.terminal.push(false);
                }
                PcodeStatementKind::Branch { target }
                | PcodeStatementKind::ConditionalBranch { target, .. } => {
                    if let Some(address) = address(target)
                        && !facts.direct_branches.contains(&address)
                    {
                        facts.direct_branches.push(address);
                    }
                }
                PcodeStatementKind::Call { target } => {
                    if let Some(address) = address(target)
                        && !facts.direct_calls.contains(&address)
                    {
                        facts.direct_calls.push(address);
                    }
                }
                _ => {}
            }
        }
        for statement in ast.statements.iter().rev() {
            let PcodeStatementKind::Label(name) = &statement.ty else {
                break;
            };
            let index = facts.labels.iter().position(|l| l == &**name).unwrap();
            facts.terminal[index] = true;
        }
        facts
    }
}

/// Checks that the streamed path agrees with the owned one on `instruction`,
/// and returns the shared result.
#[track_caller]
fn assert_equivalent(instruction: &Instruction<'_, '_>) -> Result<Vec<PcodeOp>, String> {
    let what = format!("{instruction:?}");
    let owned = instruction.pcode_ops();
    let streamed = instruction.pcode_ops_streamed(Rebuild::from_plan);
    match (owned, streamed) {
        (Ok(owned), Ok(streamed)) => {
            let facts = AstFacts::of(&instruction.pcode_ast().expect("the AST expands"));
            assert_eq!(streamed.labels, facts.labels, "{what}: plan labels");
            assert_eq!(streamed.terminal, facts.terminal, "{what}: terminal labels");
            assert_eq!(
                streamed.direct_branches, facts.direct_branches,
                "{what}: direct branches"
            );
            assert_eq!(
                streamed.direct_calls, facts.direct_calls,
                "{what}: direct calls"
            );
            let ops = streamed.finish();
            assert_eq!(ops, owned.ops, "{what}: operations");
            Ok(ops)
        }
        (Err(owned), Err(streamed)) => {
            assert_eq!(owned, streamed, "{what}: error");
            Err(owned.to_string())
        }
        (Ok(_), Err(error)) => panic!("{what}: only the streamed path failed: {error}"),
        (Err(error), Ok(_)) => panic!("{what}: only the owned path failed: {error}"),
    }
}

fn decode<'a>(spec: &'a CompiledSpec, bytes: &'a [u8]) -> Instruction<'a, 'a> {
    Decoder::new(spec)
        .decode_one(0x1000, bytes, &spec.new_context())
        .unwrap_or_else(|error| panic!("{bytes:02x?} decodes: {error}"))
}

#[track_caller]
fn equivalent_ops(spec: &CompiledSpec, bytes: &[u8]) -> Vec<PcodeOp> {
    assert_equivalent(&decode(spec, bytes))
        .unwrap_or_else(|error| panic!("{bytes:02x?} lowers: {error}"))
}

#[track_caller]
fn equivalent_error(spec: &CompiledSpec, bytes: &[u8]) -> String {
    match assert_equivalent(&decode(spec, bytes)) {
        Ok(_) => panic!("{bytes:02x?} should fail to lower"),
        Err(error) => error,
    }
}

fn opcodes(ops: &[PcodeOp]) -> Vec<Opcode> {
    ops.iter().map(|op| op.opcode).collect()
}

#[test]
fn arithmetic_with_temporaries() {
    let spec = compile("streamed.sla", STREAMED);
    // `a = reg * 3; b = a + reg; reg = b - 1`: three locals, each a unique.
    let ops = equivalent_ops(&spec, &[0x14]);
    assert_eq!(
        opcodes(&ops),
        [Opcode::IntMult, Opcode::IntAdd, Opcode::IntSub]
    );
    let unique = spec.space("unique").unwrap().id;
    assert!(ops[..2].iter().all(|op| op.output.unwrap().space == unique));

    let spec = compile("expressions.sla", EXPRESSIONS);
    // `reg[3,1] = 1:1; reg = zext(reg[0,8])`: bit-range insert and extract.
    let ops = equivalent_ops(&spec, &[0x13]);
    assert!(opcodes(&ops).contains(&Opcode::IntZext));
}

#[test]
fn direct_branch_and_call() {
    let spec = compile("branching.sla", BRANCHING);
    // `goto target`, an address the disassembly action computed.
    let ops = equivalent_ops(&spec, &[0x19]);
    assert_eq!(opcodes(&ops), [Opcode::Branch]);
    assert_eq!(ops[0].inputs[0].offset, 0x1002);

    let spec = compile("streamed.sla", STREAMED);
    let ops = equivalent_ops(&spec, &[0x13]);
    assert_eq!(opcodes(&ops), [Opcode::Call]);
    let ops = equivalent_ops(&spec, &[0x15]);
    assert_eq!(opcodes(&ops), [Opcode::IntEqual, Opcode::CBranch]);
}

#[test]
fn local_label_and_local_branch() {
    let spec = compile("branching.sla", BRANCHING);
    // `goto <done>; <done>` — a terminal label.
    let ops = equivalent_ops(&spec, &[0x01]);
    assert_eq!(opcodes(&ops), [Opcode::Branch]);
    // `if reg == 0 goto <done>; reg = 1:4; <done>`.
    let ops = equivalent_ops(&spec, &[0x12]);
    assert_eq!(
        opcodes(&ops),
        [Opcode::IntEqual, Opcode::CBranch, Opcode::Copy]
    );
    assert_eq!(ops[1].inputs[0], Varnode::constant(2, 8));
}

#[test]
fn macro_invocation_and_macro_expression() {
    let spec = compile("userop_macro.sla", USEROP_MACRO);
    // `setone(reg)`: a macro statement, inlined.
    let ops = equivalent_ops(&spec, &[0x12]);
    assert_eq!(opcodes(&ops), [Opcode::Copy]);
    // `reg = custom(reg)`: a user operation.
    let ops = equivalent_ops(&spec, &[0x01]);
    assert_eq!(opcodes(&ops), [Opcode::CallOther]);

    let spec = compile("macro_lvalue.sla", MACRO_LVALUE);
    equivalent_ops(&spec, &[0x13]);
    equivalent_ops(&spec, &[0x04]);

    let spec = compile("streamed.sla", STREAMED);
    // `reg = dbl(reg)`: a macro whose exported local is the value.
    let ops = equivalent_ops(&spec, &[0x11]);
    assert_eq!(opcodes(&ops), [Opcode::IntAdd, Opcode::Copy]);
    // `reg = custom(reg, 1:4, r2)`: several user-operation inputs.
    let ops = equivalent_ops(&spec, &[0x16]);
    assert_eq!(ops[0].inputs.len(), 4);
}

#[test]
fn subtable_build_and_export() {
    let spec = compile("build_export.sla", BUILD_EXPORT);
    // `load [reg]` and `load [reg]+`: an address export, and one through a
    // local with a side effect in the built body.
    let ops = equivalent_ops(&spec, &[0x01]);
    assert_eq!(opcodes(&ops), [Opcode::Load]);
    let ops = equivalent_ops(&spec, &[0x11]);
    assert_eq!(opcodes(&ops), [Opcode::Copy, Opcode::IntAdd, Opcode::Load]);
    // `store [reg]+ = r0`: the export as a store destination.
    let ops = equivalent_ops(&spec, &[0x32]);
    assert_eq!(*opcodes(&ops).last().unwrap(), Opcode::Store);

    let spec = compile("load_store.sla", LOAD_STORE);
    for byte in 0..=0xff {
        if let Ok(instruction) =
            Decoder::new(&spec).decode_one(0x1000, &[byte], &spec.new_context())
        {
            let _ = assert_equivalent(&instruction);
        }
    }
}

#[test]
fn delay_slot_pcode_is_spliced() {
    let spec = compile("delay_slot.sla", DELAY_SLOT);
    // `beqds` then `clobber`: the compare, then the delayed `r1 = 0`, then
    // the branch.
    let ops = equivalent_ops(&spec, &[0x10, 0x02]);
    assert_eq!(
        opcodes(&ops),
        [Opcode::IntEqual, Opcode::Copy, Opcode::CBranch]
    );
    // `jalds` then `nop`: `ra = inst_next` sees the address past the slot.
    let ops = equivalent_ops(&spec, &[0x11, 0x01]);
    assert_eq!(ops[0].inputs[0], Varnode::constant(0x1002, 4));
    // A two-byte slot filled by one two-byte instruction, and by two.
    equivalent_ops(&spec, &[0x12, 0x20, 0x00]);
    equivalent_ops(&spec, &[0x12, 0x01, 0x02]);
}

#[test]
fn scoped_labels_in_delay_slots() {
    let spec = compile("delay_slot.sla", DELAY_SLOT);
    // `lblds` declares `done`, and so does the `labelled` instruction in its
    // slot: the spliced one is qualified so the two cannot collide. It is
    // declared first, because the slot is spliced ahead of the outer label.
    let instruction = decode(&spec, &[0x14, 0x03]);
    let rebuilt = instruction
        .pcode_ops_streamed(Rebuild::from_plan)
        .expect("lowers");
    assert_eq!(rebuilt.labels, ["done#ds1", "done"]);
    assert_eq!(rebuilt.terminal, [false, false]);
    let ops = equivalent_ops(&spec, &[0x14, 0x03]);
    assert_eq!(
        ops.iter()
            .filter(|op| op.opcode == Opcode::CBranch)
            .map(|op| op.inputs[0].offset)
            .collect::<Vec<_>>(),
        // The outer branch skips the whole slot; the inner one only its own
        // assignment.
        [5, 2]
    );
}

#[test]
fn inst_next_and_inst_next2() {
    let spec = compile("branching.sla", BRANCHING);
    // `goto inst_next` and `goto inst_start`.
    let ops = equivalent_ops(&spec, &[0x07]);
    assert_eq!(ops[0].inputs[0].offset, 0x1001);
    let ops = equivalent_ops(&spec, &[0x08]);
    assert_eq!(ops[0].inputs[0].offset, 0x1000);

    let spec = compile("delay_slot.sla", DELAY_SLOT);
    // `skip` over a one-byte and over a two-byte instruction.
    let ops = equivalent_ops(&spec, &[0x40, 0x01]);
    assert_eq!(ops[1].inputs[0].offset, 0x1002);
    let ops = equivalent_ops(&spec, &[0x40, 0x20, 0x00]);
    assert_eq!(ops[1].inputs[0].offset, 0x1003);
}

#[test]
fn unresolved_width_falls_back_to_inference() {
    let spec = compile("streamed.sla", STREAMED);
    // `local u = sub` where `sub` exports a local of its own: the width of
    // `u` is only known once the emitted statements are inferred over.
    let ops = equivalent_ops(&spec, &[0x02]);
    assert_eq!(opcodes(&ops), [Opcode::Copy, Opcode::Copy, Opcode::IntAdd]);
    assert!(ops.iter().all(|op| op.output.unwrap().size == 4));
    // The register alternative is resolved ahead of time; same shape.
    let ops = equivalent_ops(&spec, &[0x32]);
    assert_eq!(opcodes(&ops), [Opcode::Copy, Opcode::IntAdd]);
}

#[test]
fn typed_failures_agree() {
    let spec = compile("branching.sla", BRANCHING);
    // `call <sub>` names a label nothing declares.
    assert!(equivalent_error(&spec, &[0x04]).contains("unknown p-code label `sub`"));

    let spec = compile(
        "unsized.sla",
        "define endian=little;
         define space ram type=ram_space size=4 default;
         define space register type=register_space size=4;
         define register offset=0 size=4 [ r0 ];
         define token instr(8) op=(0,7);
         define pcodeop myop;
         :bad is op=2 { myop(nowidth); }
         :worse is op=3 { r0 = nowidth; r0 = r0 + nowidth; }",
    );
    // A local nothing can size.
    assert!(equivalent_error(&spec, &[2]).contains("width"));
    // One that inference sizes on the second pass, so it lowers.
    equivalent_ops(&spec, &[3]);
}

/// Every decodable one-byte encoding of every fixture, so a shape none of the
/// scenarios above thought of is still compared.
#[test]
fn every_fixture_encoding_agrees() {
    for (name, source) in [
        ("branching.sla", BRANCHING),
        ("build_export.sla", BUILD_EXPORT),
        ("expressions.sla", EXPRESSIONS),
        ("load_store.sla", LOAD_STORE),
        ("userop_macro.sla", USEROP_MACRO),
        ("macro_lvalue.sla", MACRO_LVALUE),
        ("streamed.sla", STREAMED),
        ("delay_slot.sla", DELAY_SLOT),
    ] {
        let spec = compile(name, source);
        let decoder = Decoder::new(&spec);
        let context = spec.new_context();
        let mut decoded = 0;
        for first in 0..=0xffu8 {
            // The delay-slot fixture needs a second byte to fill the slot.
            for second in 0..=0xffu8 {
                if let Ok(instruction) = decoder.decode_one(0x1000, &[first, second], &context) {
                    let _ = assert_equivalent(&instruction);
                    decoded += 1;
                }
                if name != "delay_slot.sla" {
                    break;
                }
            }
        }
        assert!(decoded > 0, "{name}: nothing decoded");
    }
}
