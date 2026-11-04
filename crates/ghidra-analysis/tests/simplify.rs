use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::Arc;

use ghidra_analysis::*;
use ghidra_cfg::{Cfg, CfgInput, EdgeRole, ProgramPoint};
use ghidra_pcode::machine::{ExecutionInput, Machine, MemoryInit, MemorySnapshot, StopReason};
use ghidra_pcode::{
    AddressSpace, Endianness, Opcode, PcodeInstruction, PcodeOperation, SpaceId, SpaceKind, Value,
    Varnode, evaluate_pure,
};
use ghidra_ssa::{PhiPlacement, StatementId, ValueId, ValueOrigin};

const CODE: u32 = 4;

fn var(space: u32, offset: u64, size: u32) -> Varnode {
    Varnode {
        space: SpaceId(space),
        offset,
        size,
    }
}
fn reg(offset: u64, size: u32) -> Varnode {
    var(2, offset, size)
}
fn uniq(offset: u64, size: u32) -> Varnode {
    var(3, offset, size)
}
fn con(value: u64, size: u32) -> Varnode {
    var(0, value, size)
}
fn label(address: u64) -> Varnode {
    var(CODE, address, 8)
}
fn rel(displacement: i32) -> Varnode {
    con(displacement as u32 as u64, 4)
}
fn op(opcode: Opcode, output: Option<Varnode>, inputs: Vec<Varnode>) -> PcodeOperation {
    PcodeOperation {
        opcode,
        output,
        inputs,
    }
}
fn copy(output: Varnode, input: Varnode) -> PcodeOperation {
    op(Opcode::Copy, Some(output), vec![input])
}
fn unary(opcode: Opcode, output: Varnode, input: Varnode) -> PcodeOperation {
    op(opcode, Some(output), vec![input])
}
fn binary(opcode: Opcode, output: Varnode, a: Varnode, b: Varnode) -> PcodeOperation {
    op(opcode, Some(output), vec![a, b])
}
fn cbranch(target: Varnode, condition: Varnode) -> PcodeOperation {
    op(Opcode::Cbranch, None, vec![target, condition])
}
fn branch(address: u64) -> PcodeOperation {
    op(Opcode::Branch, None, vec![label(address)])
}
fn ret() -> PcodeOperation {
    op(Opcode::Return, None, vec![con(0x9000, 8)])
}
fn ins(address: u64, ops: Vec<PcodeOperation>) -> PcodeInstruction {
    PcodeInstruction {
        address,
        length: 4,
        ops,
    }
}
fn r(index: u64) -> Varnode {
    reg(8 * index, 8)
}
fn flag(index: u64) -> Varnode {
    reg(64 + index, 1)
}
/// The least significant `size` bytes of 8-byte register `index`.
fn low(endian: Endianness, index: u64, size: u32) -> Varnode {
    let base = 8 * index;
    reg(
        if endian == Endianness::Little {
            base
        } else {
            base + 8 - u64::from(size)
        },
        size,
    )
}

fn spaces(endian: Endianness, ram_word: u32) -> Vec<AddressSpace> {
    [
        (0, "const", SpaceKind::Constant),
        (1, "ram", SpaceKind::Ram),
        (2, "register", SpaceKind::Register),
        (3, "unique", SpaceKind::Unique),
        (CODE, "code", SpaceKind::Other),
    ]
    .into_iter()
    .map(|(id, name, kind)| AddressSpace {
        id: SpaceId(id),
        name: name.into(),
        kind,
        address_size: 8,
        word_size: if id == 1 { ram_word } else { 1 },
        endianness: if id == CODE {
            Endianness::Little
        } else {
            endian
        },
    })
    .collect()
}

fn build_in(
    spaces: Vec<AddressSpace>,
    code: SpaceId,
    instructions: Vec<PcodeInstruction>,
    entry: u64,
    options: AnalysisOptions,
) -> Arc<PcodeSsa> {
    let cfg = Arc::new(
        Cfg::new(
            CfgInput::new(spaces, code, entry, instructions),
            Default::default(),
        )
        .unwrap(),
    );
    let analysis = Arc::new(PcodeSsa::new(cfg, &[], options, Default::default()).unwrap());
    analysis.ssa().verify(analysis.raw()).unwrap();
    analysis
}
fn build(
    instructions: Vec<PcodeInstruction>,
    endian: Endianness,
    options: AnalysisOptions,
) -> Arc<PcodeSsa> {
    let entry = instructions.iter().map(|i| i.address).min().unwrap();
    build_in(
        spaces(endian, 1),
        SpaceId(CODE),
        instructions,
        entry,
        options,
    )
}
fn native() -> AnalysisOptions {
    AnalysisOptions::native()
}
fn program_mode() -> AnalysisOptions {
    AnalysisOptions::pcode_program()
}
fn havoc(mut options: AnalysisOptions) -> AnalysisOptions {
    options.unknown_effects = UnknownEffectPolicy::HavocAll;
    options
}
fn placed(mut options: AnalysisOptions, placement: PhiPlacement) -> AnalysisOptions {
    options.phi_placement = placement;
    options
}
fn facts(analysis: &Arc<PcodeSsa>) -> Arc<PcodeConstants> {
    let terms = Arc::new(PcodeExpressions::new(analysis.clone(), Default::default()).unwrap());
    Arc::new(PcodeConstants::new(terms, Default::default()).unwrap())
}
/// Simplify and always check the structural invariants and the independent
/// term evaluator against the original nodes.
fn simplify(analysis: &Arc<PcodeSsa>) -> PcodeSimplification {
    let result = PcodeSimplification::new(facts(analysis), Default::default()).unwrap();
    check_invariants(&result);
    let compared: usize = (0..4).map(|seed| check_reference(&result, seed)).sum();
    assert!(compared > 0 || result.stats().canonical_nodes == 0);
    result
}
fn sid(analysis: &PcodeSsa, address: u64, index: u32) -> StatementId {
    analysis
        .statement_id(ProgramPoint::new(address, index))
        .unwrap()
}
fn defs(analysis: &PcodeSsa, address: u64, index: u32) -> Vec<ValueId> {
    analysis
        .ssa()
        .statement(sid(analysis, address, index))
        .unwrap()
        .defs()
        .to_vec()
}
/// Canonical output term of an explicit operation.
fn out(s: &PcodeSimplification, address: u64, index: u32) -> TermId {
    let id = sid(s.analysis(), address, index);
    s.operation(id).unwrap().unwrap().output().unwrap()
}
/// Canonical term of operand `slot` of an operation.
fn operand(s: &PcodeSimplification, address: u64, index: u32, slot: usize) -> TermId {
    let id = sid(s.analysis(), address, index);
    s.operation(id).unwrap().unwrap().operand(slot).unwrap()
}
fn kind(s: &PcodeSimplification, term: TermId) -> &TermKind {
    &s.term(term).unwrap().kind
}
fn literal(s: &PcodeSimplification, term: TermId) -> Option<u64> {
    match kind(s, term) {
        TermKind::Literal(value) => value.to_u64(),
        _ => None,
    }
}
fn leaf(s: &PcodeSimplification, term: TermId) -> Option<ValueId> {
    match kind(s, term) {
        TermKind::Leaf(value) => Some(*value),
        _ => None,
    }
}
fn apply(s: &PcodeSimplification, term: TermId) -> Option<(Opcode, Vec<TermId>)> {
    match kind(s, term) {
        TermKind::Apply { opcode, inputs } => Some((*opcode, inputs.clone())),
        _ => None,
    }
}
/// The entry value of a register varnode's single storage cell.
fn entry_value(analysis: &PcodeSsa, node: Varnode) -> ValueId {
    let ssa = analysis.ssa();
    (0..ssa.values().len())
        .map(ValueId)
        .find(|&value| {
            matches!(ssa.value(value).unwrap().origin, ValueOrigin::Entry(_))
                && storage(analysis, value) == Some(node)
        })
        .unwrap_or_else(|| panic!("no entry value for {node:?}"))
}

// ---------------------------------------------------------------------------
// Structural invariants: topological IDs, types, unique structure, canonical
// normal forms, mappings, constant-fact agreement and value policies.

fn width(s: &PcodeSimplification, term: TermId) -> u32 {
    match s.term(term).unwrap().ty {
        ExpressionType::Bits(size) => size,
        ExpressionType::Memory(_) => panic!("memory-typed child {term:?}"),
    }
}

fn check_invariants(s: &PcodeSimplification) {
    let program = s.expressions();
    let constants = s.constants();
    let ssa = s.analysis().ssa();
    let terms = s.terms();
    let mut structural = BTreeSet::new();
    let mut reads = BTreeSet::new();
    for (index, term) in terms.iter().enumerate() {
        let id = TermId(index);
        let earlier = |child: TermId| assert!(child.0 < index, "{id:?} references {child:?}");
        let mut children = Vec::new();
        match &term.kind {
            TermKind::Literal(value) => {
                assert_eq!(term.ty, ExpressionType::Bits(value.size()));
                assert_eq!(term.fault, TermFault::None);
            }
            TermKind::Leaf(value) => {
                assert_eq!(term.ty, program.value_type(*value).unwrap());
                assert_eq!(s.value_term(*value).unwrap(), id, "one leaf per value");
                assert_eq!(term.origin, TermOrigin::Value(*value));
            }
            TermKind::Join(pieces) => {
                assert!(pieces.len() >= 2, "{id:?} single-piece join");
                let mut next = 0;
                for (i, piece) in pieces.iter().enumerate() {
                    earlier(piece.term);
                    assert_eq!(piece.lsb_byte, next);
                    assert_eq!(width(s, piece.term), piece.size);
                    next += piece.size;
                    children.push(piece.term);
                    assert!(
                        !matches!(kind(s, piece.term), TermKind::Join(_)),
                        "nested join"
                    );
                    if i > 0 {
                        let previous = pieces[i - 1].term;
                        assert!(
                            !(literal_value(s, previous).is_some()
                                && literal_value(s, piece.term).is_some()),
                            "adjacent literal pieces"
                        );
                        if let (
                            TermKind::Extract {
                                term: a,
                                lsb_byte: ka,
                            },
                            TermKind::Extract {
                                term: b,
                                lsb_byte: kb,
                            },
                        ) = (kind(s, previous), kind(s, piece.term))
                        {
                            assert!(
                                !(a == b && ka + pieces[i - 1].size == *kb),
                                "mergeable slices"
                            );
                        }
                    }
                }
                assert_eq!(term.ty, ExpressionType::Bits(next));
                let top = pieces.last().unwrap().term;
                assert!(
                    !literal_value(s, top).is_some_and(|v| v.bits().bits() == 0),
                    "zero-topped join is a zero extension"
                );
            }
            TermKind::Extract {
                term: source,
                lsb_byte,
            } => {
                earlier(*source);
                children.push(*source);
                let ExpressionType::Bits(size) = term.ty else {
                    panic!("memory extract")
                };
                assert!(lsb_byte + size <= width(s, *source));
                assert!(size < width(s, *source), "full-width extract");
                assert!(!matches!(
                    kind(s, *source),
                    TermKind::Extract { .. } | TermKind::Literal(_)
                ));
            }
            TermKind::Apply { opcode, inputs } => {
                for &input in inputs {
                    earlier(input);
                    width(s, input);
                    children.push(input);
                }
                let all_literal = inputs.iter().all(|&i| literal_value(s, i).is_some());
                if term.fault == TermFault::Here {
                    assert_eq!(term.identity(), TermIdentity::Distinct);
                } else {
                    assert!(!all_literal, "{id:?} unfolded literal application");
                    assert!(!matches!(opcode, Opcode::Copy | Opcode::Cast));
                    if inputs.len() == 2
                        && let Some(c) = literal_value(s, inputs[1])
                    {
                        let zero = c.bits().bits() == 0;
                        let identity = match opcode {
                            Opcode::IntAdd | Opcode::IntOr | Opcode::IntXor => zero,
                            Opcode::IntLeft | Opcode::IntRight | Opcode::IntSright => zero,
                            Opcode::IntMult => c.to_u64() == Some(1),
                            Opcode::IntAnd => c.bits().count_ones() == u64::from(c.size()) * 8,
                            Opcode::IntSub => true,
                            _ => false,
                        };
                        assert!(!identity, "{id:?} {opcode} kept an identity");
                    }
                    if matches!(
                        opcode,
                        Opcode::IntAdd | Opcode::IntMult | Opcode::IntAnd | Opcode::IntOr
                    ) {
                        assert!(
                            literal_value(s, inputs[0]).is_none(),
                            "literal before term in {opcode}"
                        );
                    }
                }
            }
            TermKind::ReadMemory {
                node,
                version,
                address,
                ..
            } => {
                assert!(reads.insert(*node), "two read terms for one node");
                assert_eq!(term.fault, TermFault::Here);
                assert!(term.reads_memory);
                assert!(matches!(
                    program.value_type(*version).unwrap(),
                    ExpressionType::Memory(_)
                ));
                assert_eq!(s.node_term(*node).unwrap(), Some(id));
                if let TermAddress::Pointer {
                    term: pointer,
                    address_size,
                    ..
                } = address
                {
                    earlier(*pointer);
                    assert_eq!(width(s, *pointer), u32::from(*address_size));
                }
            }
            TermKind::WriteMemory {
                node,
                address,
                value,
                ..
            } => {
                earlier(*value);
                assert!(matches!(term.ty, ExpressionType::Memory(_)));
                assert_eq!(s.node_term(*node).unwrap(), Some(id));
                if let TermAddress::Pointer { term: pointer, .. } = address {
                    earlier(*pointer);
                }
            }
        }
        if term.identity() == TermIdentity::Structural {
            assert!(
                structural.insert(format!("{:?}{:?}", term.ty, term.kind)),
                "duplicate structural term {id:?}"
            );
            let faulty = children.iter().any(|&c| s.term(c).unwrap().may_fault());
            assert_eq!(
                term.fault == TermFault::Subterm,
                faulty,
                "{id:?} fault scope"
            );
        }
    }
    // Node mappings.
    for (index, node) in program.nodes().iter().enumerate() {
        let id = ExpressionId(index);
        let term = s.node_term(id).unwrap();
        if let ExpressionKind::SsaValue(value) = node.kind {
            assert_eq!(term, Some(s.value_term(value).unwrap()));
        }
        if let Some(term) = term {
            assert_eq!(s.term(term).unwrap().ty, node.ty, "node {index} type");
            match constants.expression(id).unwrap() {
                ConstantFact::Constant(expected) => {
                    assert_eq!(kind(s, term), &TermKind::Literal(expected.clone()));
                }
                ConstantFact::Unreached => {
                    assert!(matches!(node.kind, ExpressionKind::SsaValue(_)))
                }
                ConstantFact::Unknown => {}
            }
        }
    }
    let mut executed = 0;
    for operation in s.operations() {
        let operation = operation.unwrap();
        let live = constants
            .is_statement_executable(operation.source.statement)
            .unwrap();
        assert_eq!(operation.executable, live);
        if !live {
            assert!(operation.output().is_none());
            assert!((0..operation.source.operands.len()).all(|i| operation.operand(i).is_none()));
            continue;
        }
        executed += 1;
        for (slot, source) in operation.source.operands.iter().enumerate() {
            assert_eq!(
                source.expression().is_some(),
                operation.operand(slot).is_some()
            );
        }
        assert_eq!(
            operation.source.output.is_some(),
            operation.output().is_some()
        );
    }
    assert_eq!(executed, s.stats().executed_operations);
    // Value policies.
    for (index, value) in ssa.values().iter().enumerate() {
        let id = ValueId(index);
        let term = s.value_term(id).unwrap();
        match constants.value(id).unwrap() {
            ConstantFact::Constant(c) => {
                assert_eq!(kind(s, term), &TermKind::Literal(c.clone()));
            }
            ConstantFact::Unreached => assert_eq!(leaf(s, term), Some(id)),
            ConstantFact::Unknown => match program.definition(id).unwrap() {
                ExpressionDefinition::Expression(root) => {
                    if leaf(s, term) != Some(id) {
                        assert!(s.is_propagated(id).unwrap());
                        assert_eq!(s.node_term(*root).unwrap(), Some(term));
                        let t = s.term(term).unwrap();
                        assert!(!t.may_fault() && !t.reads_memory);
                    } else {
                        let root_term = s.term(s.node_term(*root).unwrap().unwrap()).unwrap();
                        assert!(
                            root_term.may_fault()
                                || root_term.reads_memory
                                || matches!(root_term.ty, ExpressionType::Memory(_))
                        );
                    }
                }
                // Phis, entries, undefined resets and opaque outputs stay
                // identities: never literals, never zero.
                _ => assert_eq!(leaf(s, term), Some(id), "{value:?}"),
            },
        }
    }
    // Faults and refused folds.
    assert_eq!(s.faults().len(), constants.faults().len());
    for (fault, original) in s.faults().iter().zip(constants.faults()) {
        assert_eq!(fault.node, original.expression);
        assert_eq!(fault.statement, original.statement);
        assert_eq!(s.term(fault.term).unwrap().fault, TermFault::Here);
        assert_eq!(s.node_term(fault.node).unwrap(), Some(fault.term));
    }
    for refused in s.refused_folds() {
        let (opcode, inputs) = apply(s, refused.term).unwrap();
        assert_eq!(opcode, refused.opcode);
        let values: Vec<Value> = inputs
            .iter()
            .map(|&i| literal_value(s, i).unwrap().clone())
            .collect();
        let ExpressionType::Bits(size) = s.term(refused.term).unwrap().ty else {
            panic!()
        };
        assert!(evaluate_pure(opcode, &values, size).is_err());
        assert_eq!(s.node_term(refused.node).unwrap(), Some(refused.term));
    }
    let stats = s.stats();
    assert_eq!(stats.terms, terms.len());
    assert_eq!(stats.refused_folds, s.refused_folds().len());
    assert_eq!(
        stats.literal_bytes,
        terms
            .iter()
            .filter_map(|t| match &t.kind {
                TermKind::Literal(v) => Some(v.size() as usize),
                _ => None,
            })
            .sum::<usize>()
    );
}

fn literal_value(s: &PcodeSimplification, term: TermId) -> Option<&Value> {
    match kind(s, term) {
        TermKind::Literal(value) => Some(value),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Independent reference: evaluate original nodes and canonical terms in the
// same random environment. Leaf values (entries, phis, resets, opaque
// outputs) and memory reads are random; constant facts are their constants;
// every other executed value is computed from its original definition. Joins
// and extracts are composed here byte by byte, independently of the engine.

#[derive(Clone, Debug, PartialEq)]
enum Fail {
    /// The term's own operation, or a memory read, failed.
    Own,
    /// A subterm of the same statement failed: still a required evaluation.
    Local,
    /// An SSA input already failed; the statement would not be reached.
    Inherited,
}
type R = Result<Value, Fail>;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

fn random_value(rng: &mut Rng, size: u32) -> Value {
    let bytes: Vec<u8> = match rng.below(6) {
        0 => vec![0; size as usize],
        1 => {
            let mut b = vec![0; size as usize];
            b[0] = 1;
            b
        }
        2 => vec![0xff; size as usize],
        3 => {
            let mut b = vec![0; size as usize];
            b[0] = rng.below(8) as u8;
            b
        }
        _ => (0..size).map(|_| rng.next() as u8).collect(),
    };
    Value::from_le_bytes(&bytes).unwrap()
}

fn compose(parts: &[(u32, Value)], total: u32) -> Value {
    let mut bytes = vec![0u8; total as usize];
    for (lsb, value) in parts {
        for (i, byte) in value.to_le_bytes().into_iter().enumerate() {
            bytes[*lsb as usize + i] = byte;
        }
    }
    Value::from_le_bytes(&bytes).unwrap()
}
fn slice(value: &Value, lsb: u32, size: u32) -> Value {
    let bytes = value.to_le_bytes();
    Value::from_le_bytes(&bytes[lsb as usize..(lsb + size) as usize]).unwrap()
}
fn inherit<T>(
    results: impl IntoIterator<Item = R>,
    f: impl FnOnce(Vec<Value>) -> T,
) -> Result<T, Fail> {
    let mut values = Vec::new();
    for result in results {
        values.push(result.map_err(|_| Fail::Inherited)?);
    }
    Ok(f(values))
}

/// Evaluate every canonical term once, in ID (topological) order.
fn eval_terms(
    s: &PcodeSimplification,
    env: &[Option<R>],
    read: &mut dyn FnMut(ExpressionId, u32) -> R,
) -> Vec<Option<R>> {
    let mut out: Vec<Option<R>> = Vec::with_capacity(s.terms().len());
    for term in s.terms() {
        let get =
            |out: &Vec<Option<R>>, t: TermId| out[t.0].clone().unwrap_or(Err(Fail::Inherited));
        let value = match &term.kind {
            TermKind::Literal(v) => Some(Ok(v.clone())),
            TermKind::Leaf(v) => Some(env[v.0].clone().unwrap_or(Err(Fail::Inherited))),
            TermKind::Join(pieces) => {
                let ExpressionType::Bits(total) = term.ty else {
                    unreachable!()
                };
                Some(inherit(
                    pieces.iter().map(|p| get(&out, p.term)),
                    |values| {
                        let parts: Vec<_> = pieces
                            .iter()
                            .zip(values)
                            .map(|(p, v)| (p.lsb_byte, v))
                            .collect();
                        compose(&parts, total)
                    },
                ))
            }
            TermKind::Extract {
                term: source,
                lsb_byte,
            } => {
                let ExpressionType::Bits(size) = term.ty else {
                    unreachable!()
                };
                Some(
                    get(&out, *source)
                        .map(|v| slice(&v, *lsb_byte, size))
                        .map_err(|_| Fail::Inherited),
                )
            }
            TermKind::Apply { opcode, inputs } => {
                let ExpressionType::Bits(size) = term.ty else {
                    unreachable!()
                };
                Some(
                    inherit(inputs.iter().map(|&i| get(&out, i)), |values| {
                        evaluate_pure(*opcode, &values, size).map_err(|_| Fail::Own)
                    })
                    .and_then(|r| r),
                )
            }
            TermKind::ReadMemory { node, .. } => {
                let ExpressionType::Bits(size) = term.ty else {
                    unreachable!()
                };
                Some(read(*node, size))
            }
            TermKind::WriteMemory { .. } => None,
        };
        out.push(value);
    }
    out
}

/// Combine child results: an inherited failure means the statement is not
/// reached; otherwise a failing subterm is a local failure.
fn local(results: Vec<R>) -> Result<Vec<Value>, Fail> {
    if results.iter().any(|r| r == &Err(Fail::Inherited)) {
        return Err(Fail::Inherited);
    }
    results
        .into_iter()
        .map(|r| r.map_err(|_| Fail::Local))
        .collect()
}

/// Evaluate original nodes in ID order. `None` marks a node whose SSA input is
/// not yet known.
fn eval_nodes(
    program: &PcodeExpressions,
    env: &[Option<R>],
    read: &mut dyn FnMut(ExpressionId, u32) -> R,
) -> Vec<Option<R>> {
    let mut out: Vec<Option<R>> = Vec::with_capacity(program.nodes().len());
    for (index, node) in program.nodes().iter().enumerate() {
        let size = match node.ty {
            ExpressionType::Bits(size) => size,
            ExpressionType::Memory(_) => {
                out.push(None);
                continue;
            }
        };
        let get = |out: &Vec<Option<R>>, n: ExpressionId| out[n.0].clone();
        let value = match &node.kind {
            ExpressionKind::Constant(v) => Some(Ok(v.clone())),
            ExpressionKind::SsaValue(v) => env[v.0].clone().map(|r| r.map_err(|_| Fail::Inherited)),
            ExpressionKind::Join(pieces) => pieces
                .iter()
                .map(|p| get(&out, p.value))
                .collect::<Option<Vec<_>>>()
                .map(|values| {
                    local(values).map(|values| {
                        let parts: Vec<_> = pieces
                            .iter()
                            .zip(values)
                            .map(|(p, v)| (p.lsb_byte, v))
                            .collect();
                        compose(&parts, size)
                    })
                }),
            ExpressionKind::Extract { value, lsb_byte } => get(&out, *value)
                .map(|r| local(vec![r]).map(|values| slice(&values[0], *lsb_byte, size))),
            ExpressionKind::Pure { opcode, inputs } => inputs
                .iter()
                .map(|&i| get(&out, i))
                .collect::<Option<Vec<_>>>()
                .map(|values| {
                    local(values).and_then(|values| {
                        evaluate_pure(*opcode, &values, size).map_err(|_| Fail::Own)
                    })
                }),
            ExpressionKind::ReadMemory { .. } => Some(read(ExpressionId(index), size)),
            ExpressionKind::WriteMemory { .. } => None,
        };
        out.push(value);
    }
    out
}

/// Returns the number of exact or fault comparisons made.
fn check_reference(s: &PcodeSimplification, seed: u64) -> usize {
    let program = s.expressions();
    let constants = s.constants();
    let ssa = s.analysis().ssa();
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let mut env: Vec<Option<R>> = vec![None; ssa.values().len()];
    let mut computed = Vec::new();
    for (value, slot) in env.iter_mut().enumerate() {
        let id = ValueId(value);
        let ExpressionType::Bits(size) = program.value_type(id).unwrap() else {
            continue;
        };
        match constants.value(id).unwrap() {
            ConstantFact::Constant(c) => *slot = Some(Ok(c.clone())),
            ConstantFact::Unreached => {}
            ConstantFact::Unknown => match program.definition(id).unwrap() {
                ExpressionDefinition::Expression(root) => computed.push((id, *root)),
                _ => *slot = Some(Ok(random_value(&mut rng, size))),
            },
        }
    }
    // Some reads fail, like uninitialized or unmapped memory.
    let mut memory: HashMap<ExpressionId, R> = HashMap::new();
    let mut read_rng = Rng(seed ^ 0x5555_aaaa_1234_5678 | 1);
    let mut read = |node: ExpressionId, size: u32| -> R {
        memory
            .entry(node)
            .or_insert_with(|| {
                if read_rng.below(5) == 0 {
                    Err(Fail::Own)
                } else {
                    Ok(random_value(&mut read_rng, size))
                }
            })
            .clone()
    };
    // Definitions can refer to later nodes, so iterate to a fixpoint.
    let mut nodes = eval_nodes(program, &env, &mut read);
    loop {
        let mut progress = false;
        for &(value, root) in &computed {
            if env[value.0].is_none()
                && let Some(result) = nodes[root.0].clone()
            {
                env[value.0] = Some(result);
                progress = true;
            }
        }
        if !progress {
            break;
        }
        nodes = eval_nodes(program, &env, &mut read);
    }
    for &(value, _) in &computed {
        assert!(
            env[value.0].is_some(),
            "executed value {value:?} not computed"
        );
    }
    let terms = eval_terms(s, &env, &mut read);
    let mut compared = 0;
    let mut compare = |what: &str, original: &Option<R>, canonical: &Option<R>| match original {
        Some(Ok(expected)) => {
            assert_eq!(
                canonical.as_ref(),
                Some(&Ok(expected.clone())),
                "{what} seed {seed}"
            );
            compared += 1;
        }
        Some(Err(Fail::Own | Fail::Local)) => {
            assert!(
                matches!(canonical, Some(Err(_))),
                "{what}: a faulting evaluation disappeared (seed {seed})"
            );
            compared += 1;
        }
        _ => {}
    };
    for (index, node) in program.nodes().iter().enumerate() {
        if !matches!(node.ty, ExpressionType::Bits(_)) {
            continue;
        }
        if let Some(term) = s.node_term(ExpressionId(index)).unwrap() {
            compare(&format!("node {index}"), &nodes[index], &terms[term.0]);
        }
    }
    for (value, _) in computed {
        let term = s.value_term(value).unwrap();
        compare(&format!("value {value:?}"), &env[value.0], &terms[term.0]);
    }
    compared
}

// ---------------------------------------------------------------------------
// Concrete oracle: run the Machine one operation at a time. After each
// executed operation, evaluate every defined scalar value's canonical term
// from the concrete values of the leaves it mentions, and compare it with the
// machine state.

fn rebuild(spaces: &[AddressSpace], snapshot: &MemorySnapshot) -> Machine {
    let mut machine = Machine::new(spaces.to_vec(), 1 << 20).unwrap();
    for region in &snapshot.regions {
        machine
            .map_bytes(region.space, region.offset, &region.bytes)
            .unwrap();
    }
    machine
}

fn storage(analysis: &PcodeSsa, value: ValueId) -> Option<Varnode> {
    let variable = analysis.ssa().value(value).unwrap().variable;
    match &analysis.layout().variables()[variable.0].location {
        StorageLocation::Scalar {
            bank, offset, size, ..
        } => Some(Varnode {
            space: bank.space,
            offset: *offset,
            size: *size,
        }),
        StorageLocation::Memory { .. } => None,
    }
}

fn eval_one(s: &PcodeSimplification, term: TermId, env: &[Option<Value>]) -> Option<Value> {
    let mut memo: HashMap<usize, Option<Value>> = HashMap::new();
    let mut stack = vec![(term, false)];
    while let Some((t, expanded)) = stack.pop() {
        if memo.contains_key(&t.0) {
            continue;
        }
        let node = s.term(t).unwrap();
        let children: Vec<TermId> = match &node.kind {
            TermKind::Join(p) => p.iter().map(|p| p.term).collect(),
            TermKind::Extract { term, .. } => vec![*term],
            TermKind::Apply { inputs, .. } => inputs.clone(),
            _ => vec![],
        };
        if !expanded {
            stack.push((t, true));
            stack.extend(children.into_iter().map(|c| (c, false)));
            continue;
        }
        let get = |c: &TermId| memo[&c.0].clone();
        let size = match node.ty {
            ExpressionType::Bits(size) => size,
            ExpressionType::Memory(_) => 0,
        };
        let value = match &node.kind {
            TermKind::Literal(v) => Some(v.clone()),
            TermKind::Leaf(v) => env[v.0].clone(),
            TermKind::Join(pieces) => pieces
                .iter()
                .map(|p| get(&p.term).map(|v| (p.lsb_byte, v)))
                .collect::<Option<Vec<_>>>()
                .map(|parts| compose(&parts, size)),
            TermKind::Extract { term, lsb_byte } => get(term).map(|v| slice(&v, *lsb_byte, size)),
            TermKind::Apply { opcode, inputs } => inputs
                .iter()
                .map(get)
                .collect::<Option<Vec<_>>>()
                .and_then(|values| evaluate_pure(*opcode, &values, size).ok()),
            TermKind::ReadMemory { .. } | TermKind::WriteMemory { .. } => {
                panic!("value terms never contain memory accesses")
            }
        };
        memo.insert(t.0, value);
    }
    memo[&term.0].clone()
}

fn check_concrete(s: &PcodeSimplification, initial: &MemorySnapshot, max_frames: usize) -> usize {
    let analysis = s.analysis();
    let cfg = analysis.cfg();
    let ssa = analysis.ssa();
    let spaces = cfg.spaces();
    let mut env: Vec<Option<Value>> = vec![None; ssa.values().len()];
    let start = rebuild(spaces, initial);
    for (index, value) in ssa.values().iter().enumerate() {
        if let ValueOrigin::Entry(_) = value.origin
            && let Some(node) = storage(analysis, ValueId(index))
        {
            env[index] = start.read_varnode(&node).ok();
        }
    }
    let mut state = initial.clone();
    let mut address = cfg.entry_address();
    let mut checks = 0;
    for _ in 0..max_frames {
        let instruction = cfg.instruction_at(address).unwrap().clone();
        let mut before = rebuild(spaces, &state);
        let mut operations = 0;
        let stop = loop {
            operations += 1;
            if operations > 64 {
                return checks;
            }
            let mut after = rebuild(spaces, &state);
            let Ok(report) = after.run(
                std::slice::from_ref(&instruction),
                cfg.code_space(),
                address,
                operations,
            ) else {
                return checks;
            };
            if report.trace.len() < operations as usize {
                state = after.snapshot();
                break report.stop;
            }
            let event = &report.trace[operations as usize - 1];
            let point = ProgramPoint::new(event.address, event.operation as u32);
            let node = cfg.block_of(point).unwrap();
            if cfg.block_points(node).unwrap()[0] == point {
                for phi in ssa.block(node).unwrap().renamed().unwrap().phis() {
                    if let Some(storage) = storage(analysis, phi.value()) {
                        env[phi.value().0] = before.read_varnode(&storage).ok();
                    }
                }
            }
            let id = analysis.statement_id(point).unwrap();
            assert!(s.constants().is_statement_executable(id).unwrap());
            for &value in ssa.statement(id).unwrap().defs() {
                let Some(storage) = storage(analysis, value) else {
                    continue;
                };
                env[value.0] = after.read_varnode(&storage).ok();
                let term = s.value_term(value).unwrap();
                if let (Some(expected), Some(actual)) =
                    (env[value.0].clone(), eval_one(s, term, &env))
                {
                    assert_eq!(actual, expected, "value {value:?} at {point}");
                    checks += 1;
                }
            }
            if !matches!(report.stop, StopReason::BudgetExhausted { .. }) {
                state = after.snapshot();
                break report.stop;
            }
            before = after;
        };
        let target = match stop {
            StopReason::FallThrough { next_address } => Some(next_address),
            StopReason::ExternalTransfer { target, kind } if kind != "return" => Some(target),
            _ => None,
        };
        match target.filter(|&target| cfg.instruction_at(target).is_some()) {
            Some(target) => address = target,
            None => return checks,
        }
    }
    checks
}

fn state(endian: Endianness, seed: u64) -> MemorySnapshot {
    let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
    let mut registers = Vec::new();
    for _ in 0..8 {
        let value = match seed % 3 {
            0 => 0,
            1 => rng.below(4),
            _ => rng.next(),
        };
        let mut bytes = value.to_le_bytes().to_vec();
        if endian == Endianness::Big {
            bytes.reverse();
        }
        registers.extend(bytes);
    }
    for _ in 0..4 {
        registers.push(if seed % 3 == 2 {
            rng.below(256) as u8
        } else {
            (seed % 2) as u8
        });
    }
    MemorySnapshot {
        regions: vec![
            MemoryInit {
                space: SpaceId(2),
                offset: 0,
                bytes: registers,
            },
            MemoryInit {
                space: SpaceId(1),
                offset: 0x100,
                bytes: (0..64).map(|i| i as u8).collect(),
            },
        ],
        truncated: false,
    }
}

/// Random programs over aliased registers, flags, temporaries and memory with
/// the operations the rewrites target.
fn random_program(rng: &mut Rng, endian: Endianness) -> Vec<PcodeInstruction> {
    const CONSTANTS: [u64; 7] = [0, 1, 2, 7, 0xff, u64::MAX, 0x8000_0000_0000_0000];
    let count = 3 + rng.below(7);
    let mut program = Vec::new();
    for i in 0..count {
        let address = 0x1000 + 4 * i;
        let mut ops = Vec::new();
        let full = |rng: &mut Rng| r(rng.below(4));
        let literal = |rng: &mut Rng| con(CONSTANTS[rng.below(7) as usize], 8);
        let operand = |rng: &mut Rng| {
            if rng.below(3) == 0 {
                literal(rng)
            } else {
                full(rng)
            }
        };
        let flag_operand = |rng: &mut Rng| {
            if rng.below(3) == 0 {
                con([0, 1, 0xff][rng.below(3) as usize], 1)
            } else {
                flag(rng.below(3))
            }
        };
        let condition = |rng: &mut Rng| {
            if rng.below(5) == 0 {
                con(rng.below(2), 1)
            } else {
                flag(rng.below(3))
            }
        };
        for _ in 0..1 + rng.below(4) {
            match rng.below(23) {
                0 => ops.push(copy(full(rng), literal(rng))),
                1 => ops.push(copy(full(rng), full(rng))),
                2 | 3 => {
                    let opcode = [
                        Opcode::IntAdd,
                        Opcode::IntSub,
                        Opcode::IntXor,
                        Opcode::IntAnd,
                        Opcode::IntOr,
                        Opcode::IntMult,
                    ][rng.below(6) as usize];
                    ops.push(binary(opcode, full(rng), full(rng), operand(rng)));
                }
                4 => {
                    let opcode =
                        [Opcode::IntDiv, Opcode::IntRem, Opcode::IntSdiv][rng.below(3) as usize];
                    let divisor = if rng.below(2) == 0 {
                        con([0, 3][rng.below(2) as usize], 8)
                    } else {
                        full(rng)
                    };
                    ops.push(binary(opcode, full(rng), operand(rng), divisor));
                }
                5 => {
                    let opcode = [
                        Opcode::IntEqual,
                        Opcode::IntNotequal,
                        Opcode::IntLess,
                        Opcode::IntSlessequal,
                    ][rng.below(4) as usize];
                    ops.push(binary(opcode, flag(rng.below(3)), full(rng), operand(rng)));
                }
                6 => ops.push(unary(
                    Opcode::BoolNegate,
                    flag(rng.below(3)),
                    flag(rng.below(3)),
                )),
                7 => {
                    let opcode =
                        [Opcode::BoolAnd, Opcode::BoolOr, Opcode::BoolXor][rng.below(3) as usize];
                    ops.push(binary(
                        opcode,
                        flag(rng.below(3)),
                        flag(rng.below(3)),
                        flag_operand(rng),
                    ));
                }
                8 => {
                    let size = [1, 4][rng.below(2) as usize];
                    let source = if rng.below(2) == 0 {
                        con(CONSTANTS[rng.below(7) as usize], size)
                    } else {
                        low(endian, rng.below(4), size)
                    };
                    ops.push(copy(low(endian, rng.below(4), size), source));
                }
                9 => ops.push(unary(
                    Opcode::IntZext,
                    full(rng),
                    if rng.below(2) == 0 {
                        flag(rng.below(3))
                    } else {
                        low(endian, rng.below(4), 4)
                    },
                )),
                10 => ops.push(unary(
                    Opcode::IntSext,
                    full(rng),
                    low(endian, rng.below(4), 4),
                )),
                11 => ops.push(binary(
                    Opcode::Subpiece,
                    flag(rng.below(3)),
                    full(rng),
                    con(rng.below(9), 4),
                )),
                12 => ops.push(binary(
                    Opcode::Subpiece,
                    low(endian, rng.below(4), 4),
                    full(rng),
                    con(rng.below(6), 4),
                )),
                13 => ops.push(binary(
                    Opcode::Piece,
                    full(rng),
                    if rng.below(3) == 0 {
                        con(0, 4)
                    } else {
                        low(endian, rng.below(4), 4)
                    },
                    low(endian, rng.below(4), 4),
                )),
                14 => {
                    let opcode = [Opcode::IntLeft, Opcode::IntRight, Opcode::IntSright]
                        [rng.below(3) as usize];
                    ops.push(binary(
                        opcode,
                        full(rng),
                        full(rng),
                        con([0, 1, 8, 64, 65][rng.below(5) as usize], 4),
                    ));
                }
                15 => {
                    let opcode = [Opcode::IntNegate, Opcode::Int2Comp][rng.below(2) as usize];
                    let target = full(rng);
                    ops.push(unary(opcode, target, full(rng)));
                    ops.push(unary(opcode, full(rng), target));
                }
                16 => {
                    ops.push(copy(uniq(0, 8), operand(rng)));
                    ops.push(binary(Opcode::IntAdd, full(rng), uniq(0, 8), operand(rng)));
                }
                17 => ops.push(op(
                    Opcode::Load,
                    Some(full(rng)),
                    vec![con(1, 4), con(0x100 + 8 * rng.below(4), 8)],
                )),
                18 => ops.push(op(
                    Opcode::Store,
                    None,
                    vec![con(1, 4), con(0x100 + 8 * rng.below(4), 8), operand(rng)],
                )),
                19 => {
                    let opcode = [Opcode::IntNotequal, Opcode::IntEqual][rng.below(2) as usize];
                    ops.push(binary(
                        opcode,
                        flag(rng.below(3)),
                        flag(rng.below(3)),
                        con(rng.below(2), 1),
                    ));
                }
                20 => {
                    if rng.below(2) == 0 {
                        ops.push(copy(full(rng), var(1, 0x100 + 8 * rng.below(4), 8)));
                    } else {
                        ops.push(unary(
                            Opcode::IntZext,
                            full(rng),
                            var(1, 0x100 + 8 * rng.below(4), 4),
                        ));
                    }
                }
                21 => {
                    let opcode = [Opcode::IntLeft, Opcode::IntRight, Opcode::IntSright]
                        [rng.below(3) as usize];
                    let target = full(rng);
                    ops.push(binary(opcode, target, full(rng), con(rng.below(9), 8)));
                    ops.push(binary(opcode, full(rng), target, con(rng.below(9), 8)));
                }
                _ => {
                    let target = full(rng);
                    ops.push(binary(Opcode::IntAdd, target, full(rng), literal(rng)));
                    ops.push(binary(Opcode::IntAdd, full(rng), target, literal(rng)));
                }
            }
        }
        if i + 1 == count {
            ops.push(ret());
        } else {
            match rng.below(6) {
                0 => ops.push(cbranch(
                    label(0x1000 + 4 * rng.below(count)),
                    condition(rng),
                )),
                1 => ops.push(branch(0x1000 + 4 * rng.below(count))),
                2 => {
                    let here = ops.len() as i64;
                    let target = rng.below(ops.len() as u64 + 2) as i64;
                    ops.push(cbranch(rel((target - here) as i32), condition(rng)));
                }
                _ => {}
            }
        }
        program.push(ins(address, ops));
    }
    program
}

#[test]
fn generated_programs_match_the_reference_and_the_concrete_machine() {
    let mut checks = 0;
    let mut compared = 0;
    let mut rules = [0usize; 32];
    for seed in 0..90u64 {
        let endian = if seed % 2 == 0 {
            Endianness::Little
        } else {
            Endianness::Big
        };
        let mut rng = Rng(seed.wrapping_mul(0x2545_f491_4f6c_dd1d) | 1);
        let program = random_program(&mut rng, endian);
        let base = if seed % 3 == 0 {
            native()
        } else {
            program_mode()
        };
        for placement in [PhiPlacement::Pruned, PhiPlacement::Unpruned] {
            let analysis = build(program.clone(), endian, placed(base, placement));
            let result = simplify(&analysis);
            for seed in 4..8 {
                compared += check_reference(&result, seed);
            }
            for (i, rule) in Rule::ALL.iter().enumerate() {
                rules[i] += result.stats().rule(*rule);
            }
            for state_seed in 0..4 {
                checks += check_concrete(&result, &state(endian, state_seed), 48);
            }
        }
    }
    eprintln!("{checks} concrete machine checks, {compared} reference comparisons");
    assert!(checks > 2_000, "{checks} concrete checks");
    assert!(compared > 20_000, "{compared} reference comparisons");
    // The generator exercises every rewrite.
    for (i, rule) in Rule::ALL.iter().enumerate() {
        assert!(rules[i] > 0, "{} never fired", rule.name());
    }
}

// ---------------------------------------------------------------------------
// Targeted semantics.

#[test]
fn identities_keep_their_operand_and_annihilators_are_not_applied() {
    for endian in [Endianness::Little, Endianness::Big] {
        let analysis = build(
            vec![
                ins(
                    0x1000,
                    vec![
                        binary(Opcode::IntAdd, r(1), r(0), con(0, 8)),
                        binary(Opcode::IntSub, r(1), r(0), con(0, 8)),
                        binary(Opcode::IntOr, r(1), con(0, 8), r(0)),
                        binary(Opcode::IntXor, r(1), r(0), con(0, 8)),
                        binary(Opcode::IntAnd, r(1), r(0), con(u64::MAX, 8)),
                        binary(Opcode::IntMult, r(1), con(1, 8), r(0)),
                        binary(Opcode::IntLeft, r(1), r(0), con(0, 1)),
                        binary(Opcode::IntSright, r(1), r(0), con(0, 4)),
                        unary(Opcode::Copy, r(1), r(0)),
                        unary(Opcode::Cast, r(1), r(0)),
                        binary(Opcode::IntAnd, r(1), r(0), r(0)),
                    ],
                ),
                ins(
                    0x1004,
                    vec![
                        // Annihilators would discard a nonconstant evaluation.
                        binary(Opcode::IntMult, r(1), r(0), con(0, 8)),
                        binary(Opcode::IntAnd, r(1), r(0), con(0, 8)),
                        binary(Opcode::IntXor, r(1), r(0), r(0)),
                        binary(Opcode::IntSub, r(1), r(0), r(0)),
                        binary(Opcode::IntOr, r(1), r(0), con(u64::MAX, 8)),
                        // Shifts past the width would also discard r0.
                        binary(Opcode::IntLeft, r(1), r(0), con(64, 4)),
                        ret(),
                    ],
                ),
            ],
            endian,
            program_mode(),
        );
        let s = simplify(&analysis);
        let input = s.value_term(entry_value(&analysis, r(0))).unwrap();
        for index in 0..11 {
            assert_eq!(out(&s, 0x1000, index), input, "identity {index}");
        }
        for index in 0..6 {
            let term = out(&s, 0x1004, index);
            assert!(literal(&s, term).is_none(), "annihilator {index} folded");
            assert!(apply(&s, term).unwrap().1.contains(&input));
        }
        assert!(!s.policy().annihilators);
        assert!(s.stats().rule(Rule::Identity) >= 7);
        assert!(s.stats().rule(Rule::Idempotent) >= 1);
        assert!(s.stats().rule(Rule::CopyCast) >= 2);
    }
}

#[test]
fn faulting_folds_are_refused_kept_distinct_and_not_propagated() {
    let analysis = build(
        vec![ins(
            0x1000,
            vec![
                binary(Opcode::IntDiv, r(1), con(5, 8), con(0, 8)),
                binary(Opcode::IntDiv, r(2), con(5, 8), con(0, 8)),
                binary(Opcode::IntAdd, r(3), r(1), con(0, 8)),
                binary(Opcode::IntDiv, r(4), con(12, 8), con(4, 8)),
                // The divisor is unknown: the division may fault.
                binary(Opcode::IntDiv, r(5), r(0), r(6)),
                binary(Opcode::IntRem, r(5), r(0), r(6)),
                binary(Opcode::IntAdd, r(7), r(5), con(1, 8)),
                ret(),
            ],
        )],
        Endianness::Little,
        program_mode(),
    );
    let s = simplify(&analysis);
    let first = out(&s, 0x1000, 0);
    let second = out(&s, 0x1000, 1);
    // Identical faulting applications keep one term per original node.
    assert_ne!(first, second);
    for term in [first, second] {
        assert_eq!(s.term(term).unwrap().fault, TermFault::Here);
    }
    assert_eq!(s.refused_folds().len(), 2);
    assert!(matches!(
        *s.refused_folds()[0].error,
        ghidra_pcode::Error::DivisionByZero
    ));
    // The constant-propagation faults keep their statements and points.
    assert_eq!(s.faults().len(), 2);
    assert_eq!(s.faults()[0].statement, sid(&analysis, 0x1000, 0));
    assert_eq!(s.faults()[0].term, first);
    // A use of the faulting result keeps the SSA leaf, so the trap stays at
    // its own statement; the identity still applies to that leaf.
    let faulted = defs(&analysis, 0x1000, 0)[0];
    assert_eq!(out(&s, 0x1000, 2), s.value_term(faulted).unwrap());
    assert_eq!(leaf(&s, out(&s, 0x1000, 2)), Some(faulted));
    // A successful division of literals is an exact fold.
    assert_eq!(literal(&s, out(&s, 0x1000, 3)), Some(3));
    // An unknown divisor: distinct, and uses refer to the leaf.
    let division = out(&s, 0x1000, 4);
    assert_eq!(s.term(division).unwrap().fault, TermFault::Here);
    let remainder = defs(&analysis, 0x1000, 5)[0];
    let (opcode, inputs) = apply(&s, out(&s, 0x1000, 6)).unwrap();
    assert_eq!(opcode, Opcode::IntAdd);
    assert_eq!(leaf(&s, inputs[0]), Some(remainder));
    assert!(!s.term(out(&s, 0x1000, 6)).unwrap().may_fault());
}

#[test]
fn definitions_propagate_into_uses_that_appear_earlier_in_node_order() {
    // Entry 0x1010 computes values, then branches back to 0x1000, whose
    // block has a lower node ID and earlier expression IDs.
    let analysis = build_in(
        spaces(Endianness::Little, 1),
        SpaceId(CODE),
        vec![
            ins(
                0x1000,
                vec![
                    binary(Opcode::IntAdd, r(3), r(2), con(5, 8)),
                    unary(Opcode::Copy, r(4), r(1)),
                    ret(),
                ],
            ),
            ins(
                0x1010,
                vec![
                    binary(Opcode::IntXor, r(1), r(0), con(0x55, 8)),
                    unary(Opcode::Copy, r(2), r(1)),
                    binary(Opcode::IntAdd, r(2), r(2), con(3, 8)),
                    branch(0x1000),
                ],
            ),
        ],
        0x1010,
        program_mode(),
    );
    let s = simplify(&analysis);
    let use_node = s
        .expressions()
        .operation(sid(&analysis, 0x1000, 0))
        .unwrap()
        .output
        .unwrap();
    let root = s
        .expressions()
        .operation(sid(&analysis, 0x1010, 2))
        .unwrap()
        .output
        .unwrap();
    assert!(
        use_node < root,
        "the use precedes the definition in node order"
    );
    let input = s.value_term(entry_value(&analysis, r(0))).unwrap();
    let xor = out(&s, 0x1010, 0);
    assert_eq!(apply(&s, xor).unwrap().1[0], input);
    // r2 = (r0 ^ 0x55) + 3, then r3 = r2 + 5 reassociates to + 8.
    let (opcode, inputs) = apply(&s, out(&s, 0x1000, 0)).unwrap();
    assert_eq!(opcode, Opcode::IntAdd);
    assert_eq!(inputs[0], xor);
    assert_eq!(literal(&s, inputs[1]), Some(8));
    // The copy forwards the propagated term.
    assert_eq!(out(&s, 0x1000, 1), xor);
    assert_eq!(s.value_term(defs(&analysis, 0x1000, 1)[0]).unwrap(), xor);
    assert!(s.is_propagated(defs(&analysis, 0x1010, 1)[0]).unwrap());
    assert!(s.stats().rule(Rule::Reassociate) >= 1);
    assert!(s.stats().forwarded_outputs >= 1);
}

#[test]
fn joins_extracts_and_aliases_reassemble_in_both_byte_orders() {
    for endian in [Endianness::Little, Endianness::Big] {
        let analysis = build(
            vec![
                ins(
                    0x1000,
                    vec![
                        // r0 is split into aliased cells by the 1- and 4-byte
                        // accesses below; the full read reassembles them.
                        binary(Opcode::IntAdd, r(0), r(1), con(9, 8)),
                        unary(Opcode::Copy, r(2), r(0)),
                        unary(Opcode::Copy, low(endian, 0, 1), flag(0)),
                        unary(Opcode::Copy, r(3), r(0)),
                        unary(Opcode::Copy, low(endian, 1, 4), low(endian, 0, 4)),
                    ],
                ),
                ins(
                    0x1004,
                    vec![
                        binary(Opcode::Subpiece, low(endian, 2, 4), r(2), con(0, 4)),
                        binary(Opcode::Subpiece, low(endian, 2, 4), r(2), con(4, 4)),
                        unary(Opcode::IntZext, r(3), low(endian, 1, 4)),
                        binary(Opcode::Subpiece, flag(1), r(3), con(0, 4)),
                        binary(Opcode::Subpiece, low(endian, 3, 4), r(3), con(4, 4)),
                        binary(Opcode::Piece, r(2), con(0, 4), low(endian, 1, 4)),
                        binary(Opcode::Piece, r(3), low(endian, 1, 4), low(endian, 1, 4)),
                        ret(),
                    ],
                ),
            ],
            endian,
            program_mode(),
        );
        let s = simplify(&analysis);
        let sum = out(&s, 0x1000, 0);
        // Copying r0 (written whole) reads the reassembled cells: the slices
        // merge back into the sum.
        assert_eq!(out(&s, 0x1000, 1), sum, "{endian:?}");
        // After a partial write, the full read is a join of the new low byte
        // and the old upper bytes.
        let mixed = out(&s, 0x1000, 3);
        let TermKind::Join(pieces) = kind(&s, mixed) else {
            panic!("{endian:?} mixed read {:?}", kind(&s, mixed))
        };
        assert_eq!(pieces.len(), 2);
        assert_eq!((pieces[0].size, pieces[1].size), (1, 7));
        assert_eq!(
            pieces[0].term,
            s.value_term(entry_value(&analysis, flag(0))).unwrap()
        );
        assert_eq!(
            kind(&s, pieces[1].term),
            &TermKind::Extract {
                term: sum,
                lsb_byte: 1
            }
        );
        // SUBPIECE becomes an extract of the propagated sum.
        assert_eq!(
            kind(&s, out(&s, 0x1004, 0)),
            &TermKind::Extract {
                term: sum,
                lsb_byte: 0
            }
        );
        assert_eq!(
            kind(&s, out(&s, 0x1004, 1)),
            &TermKind::Extract {
                term: sum,
                lsb_byte: 4
            }
        );
        let narrow = s.value_term(defs(&analysis, 0x1000, 4)[0]).unwrap();
        // The low part of a zero extension is its input; the high part is
        // zero although the constant facts only know the whole as unknown.
        let zext = out(&s, 0x1004, 2);
        assert_eq!(apply(&s, zext), Some((Opcode::IntZext, vec![narrow])));
        // Its low byte is the low byte of the 4-byte copy, which is the
        // partial write of flag 0.
        let raw = s.value_term(entry_value(&analysis, flag(0))).unwrap();
        assert_eq!(out(&s, 0x1004, 3), raw);
        assert_eq!(literal(&s, out(&s, 0x1004, 4)), Some(0));
        assert!(s.stats().literals_beyond_constants >= 1);
        // PIECE with a zero high half is the same zero extension term.
        assert_eq!(out(&s, 0x1004, 5), zext);
        // PIECE of the 4-byte join with itself flattens to four pieces.
        let TermKind::Join(halves) = kind(&s, out(&s, 0x1004, 6)) else {
            panic!("piece is a join")
        };
        assert_eq!(
            halves.iter().map(|p| p.size).collect::<Vec<_>>(),
            [1, 3, 1, 3]
        );
        assert!(halves[0].term == raw && halves[2].term == raw);
        assert!(s.stats().rule(Rule::JoinFlatten) > 0);
        for rule in [
            Rule::SubpieceExtract,
            Rule::PieceJoin,
            Rule::JoinMerge,
            Rule::JoinZext,
            Rule::ExtractJoin,
            Rule::ExtractExtension,
            Rule::Propagate,
        ] {
            assert!(s.stats().rule(rule) > 0, "{endian:?} {}", rule.name());
        }
        for seed in 0..6 {
            check_concrete(&s, &state(endian, seed), 8);
        }
    }
}

#[test]
fn extension_extracts_never_discard_a_read_that_may_fault() {
    for endian in [Endianness::Little, Endianness::Big] {
        let analysis = build(
            vec![ins(
                0x1000,
                vec![
                    // r0 and r1 are split into 4-byte cells by the accesses
                    // below, so each write extracts both halves.
                    unary(Opcode::IntZext, r(0), var(1, 0x100, 4)),
                    unary(Opcode::IntZext, r(1), low(endian, 2, 4)),
                    unary(Opcode::Copy, low(endian, 3, 4), low(endian, 0, 4)),
                    unary(Opcode::Copy, low(endian, 3, 4), low(endian, 1, 4)),
                    binary(Opcode::Subpiece, low(endian, 2, 4), r(0), con(4, 4)),
                    binary(Opcode::Subpiece, low(endian, 2, 4), r(1), con(4, 4)),
                    ret(),
                ],
            )],
            endian,
            program_mode(),
        );
        let s = simplify(&analysis);
        // The register input does not fault: its zero bytes are literal.
        assert_eq!(literal(&s, out(&s, 0x1000, 5)), Some(0));
        // The memory read may fault, so its zero-extended high half keeps
        // the read; it is never presented as a bare zero.
        let high = defs(&analysis, 0x1000, 0)
            .into_iter()
            .map(|value| {
                let ExpressionDefinition::Expression(root) =
                    s.expressions().definition(value).unwrap()
                else {
                    panic!()
                };
                s.node_term(*root).unwrap().unwrap()
            })
            .find(|&term| matches!(kind(&s, term), TermKind::Extract { lsb_byte: 4, .. }))
            .expect("high half keeps the read");
        assert_eq!(s.term(high).unwrap().fault, TermFault::Subterm);
        assert!(s.term(high).unwrap().reads_memory);
        // Values computed from the read are leaves at their uses.
        let read_low = s.value_term(defs(&analysis, 0x1000, 0)[0]).unwrap();
        assert!(leaf(&s, read_low).is_some());
        assert!(literal(&s, out(&s, 0x1000, 4)).is_none());
        assert!(!s.policy().discards_faulting_subterms);
    }
}

#[test]
fn wide_values_keep_exact_widths_up_to_512_bytes() {
    let wide = reg(0x200, 512);
    let half = reg(0x200, 256);
    let analysis = build(
        vec![ins(
            0x1000,
            vec![
                binary(Opcode::IntAdd, wide, wide, con(0, 512)),
                unary(Opcode::Copy, half, con(3, 256)),
                binary(Opcode::IntXor, reg(0x600, 512), wide, con(0, 512)),
                binary(Opcode::Subpiece, reg(0x800, 3), wide, con(255, 4)),
                ret(),
            ],
        )],
        Endianness::Little,
        program_mode(),
    );
    let s = simplify(&analysis);
    let low_half = s.value_term(entry_value(&analysis, half)).unwrap();
    // The identity keeps the 512-byte join of the two entry halves.
    let TermKind::Join(entry) = kind(&s, out(&s, 0x1000, 0)) else {
        panic!("entry join")
    };
    assert_eq!(entry.len(), 2);
    assert_eq!(entry[0].term, low_half);
    assert!(entry.iter().all(|p| p.size == 256));
    // After the half write, the read joins the 256-byte literal with the
    // upper entry half.
    let TermKind::Join(pieces) = kind(&s, out(&s, 0x1000, 2)) else {
        panic!("join")
    };
    assert_eq!(literal_value(&s, pieces[0].term).unwrap().size(), 256);
    assert_eq!(literal(&s, pieces[0].term), Some(3));
    assert_eq!(pieces[1].term, entry[1].term);
    // Bytes 255..258 straddle the literal and the upper half.
    let TermKind::Join(straddle) = kind(&s, out(&s, 0x1000, 3)) else {
        panic!("straddle")
    };
    assert_eq!(literal(&s, straddle[0].term), Some(0));
    assert_eq!(straddle[0].size, 1);
    assert_eq!(
        kind(&s, straddle[1].term),
        &TermKind::Extract {
            term: entry[1].term,
            lsb_byte: 0
        }
    );
    assert_eq!(
        s.term(out(&s, 0x1000, 3)).unwrap().ty,
        ExpressionType::Bits(3)
    );
}

#[test]
fn memory_reads_and_writes_stay_distinct_unforwarded_and_keep_word_addresses() {
    for word in [1, 2, 4, 8] {
        let analysis = build_in(
            spaces(Endianness::Big, word),
            SpaceId(CODE),
            vec![ins(
                0x1000,
                vec![
                    op(Opcode::Load, Some(r(1)), vec![con(1, 4), r(0)]),
                    op(Opcode::Load, Some(r(2)), vec![con(1, 4), r(0)]),
                    binary(Opcode::IntAdd, r(3), r(0), con(0, 8)),
                    op(Opcode::Store, None, vec![con(1, 4), r(3), con(7, 8)]),
                    op(Opcode::Load, Some(r(4)), vec![con(1, 4), r(0)]),
                    binary(Opcode::IntAdd, r(5), r(1), con(0, 8)),
                    unary(Opcode::Copy, r(6), var(1, 0x40, 8)),
                    unary(Opcode::Copy, var(1, 0x48, 8), r(6)),
                    ret(),
                ],
            )],
            0x1000,
            program_mode(),
        );
        let s = simplify(&analysis);
        let pointer = s.value_term(entry_value(&analysis, r(0))).unwrap();
        let first = out(&s, 0x1000, 0);
        let second = out(&s, 0x1000, 1);
        // Two loads of the same address and version stay two terms.
        assert_ne!(first, second);
        for term in [first, second] {
            let TermKind::ReadMemory {
                address, version, ..
            } = kind(&s, term)
            else {
                panic!("read")
            };
            assert_eq!(
                *address,
                TermAddress::Pointer {
                    term: pointer,
                    word_size: word,
                    address_size: 8
                }
            );
            assert!(matches!(
                s.analysis().ssa().value(*version).unwrap().origin,
                ValueOrigin::Entry(_)
            ));
        }
        // The store's address simplifies to the pointer; its value is kept.
        let store = s
            .expressions()
            .operation(sid(&analysis, 0x1000, 3))
            .unwrap();
        let written = defs(&analysis, 0x1000, 3)[0];
        let ExpressionDefinition::Expression(root) = s.expressions().definition(written).unwrap()
        else {
            panic!()
        };
        let TermKind::WriteMemory { address, value, .. } =
            kind(&s, s.node_term(*root).unwrap().unwrap())
        else {
            panic!("write")
        };
        assert!(matches!(address, TermAddress::Pointer { term, .. } if *term == pointer));
        assert_eq!(literal(&s, *value), Some(7));
        assert!(store.indirect_memory.is_some());
        // The later load reads the new version and is not forwarded.
        let TermKind::ReadMemory { version, .. } = kind(&s, out(&s, 0x1000, 4)) else {
            panic!("load after store")
        };
        assert_eq!(*version, written);
        // Load results are leaves at their uses.
        let loaded = defs(&analysis, 0x1000, 0)[0];
        assert_eq!(leaf(&s, out(&s, 0x1000, 5)), Some(loaded));
        // Memory states are leaves.
        assert_eq!(leaf(&s, s.value_term(written).unwrap()), Some(written));
        // Fixed varnodes keep byte offsets in word spaces.
        let TermKind::ReadMemory { address, .. } = kind(&s, operand(&s, 0x1000, 6, 0)) else {
            panic!("fixed read")
        };
        assert_eq!(*address, TermAddress::ByteOffset(0x40));
        assert!(!s.policy().shares_memory_terms && !s.policy().forwards_memory);
    }
}

#[test]
fn phis_resets_opaque_outputs_and_entries_remain_leaves() {
    // A loop whose carried value is a phi, with temporaries reset on native
    // re-entry and a havoc call.
    let looped = vec![
        ins(0x1000, vec![copy(r(0), con(0, 8))]),
        ins(
            0x1004,
            vec![
                copy(uniq(0, 8), r(0)),
                binary(Opcode::IntAdd, r(0), uniq(0, 8), con(1, 8)),
                binary(Opcode::IntAdd, r(1), r(0), con(0, 8)),
                binary(Opcode::IntLess, flag(0), r(0), con(10, 8)),
                cbranch(label(0x1004), flag(0)),
            ],
        ),
        ins(
            0x1008,
            vec![
                op(Opcode::Call, None, vec![label(0x8000)]),
                binary(Opcode::IntAdd, r(2), r(0), con(0, 8)),
                ret(),
            ],
        ),
    ];
    for options in [havoc(native()), havoc(program_mode())] {
        let analysis = build(looped.clone(), Endianness::Little, options);
        let s = simplify(&analysis);
        let ssa = analysis.ssa();
        for (index, value) in ssa.values().iter().enumerate() {
            let id = ValueId(index);
            let term = s.value_term(id).unwrap();
            let definition = s.expressions().definition(id).unwrap();
            if matches!(
                definition,
                ExpressionDefinition::Phi(_)
                    | ExpressionDefinition::Entry(_)
                    | ExpressionDefinition::Undefined { .. }
                    | ExpressionDefinition::Opaque { .. }
            ) && !matches!(s.constants().value(id).unwrap(), ConstantFact::Constant(_))
            {
                assert_eq!(leaf(&s, term), Some(id), "{value:?}");
            }
        }
        // The loop counter is r0 = phi + 1; uses refer to the phi leaf.
        let counter = out(&s, 0x1004, 1);
        let (opcode, inputs) = apply(&s, counter).unwrap();
        assert_eq!(opcode, Opcode::IntAdd);
        let phi = leaf(&s, inputs[0]).expect("phi leaf");
        assert!(matches!(
            ssa.value(phi).unwrap().origin,
            ValueOrigin::Phi(_)
        ));
        assert_eq!(out(&s, 0x1004, 2), counter);
        // After the call, r0 is an opaque output, never a literal.
        let after = operand(&s, 0x1008, 1, 0);
        let opaque = leaf(&s, after).expect("opaque leaf");
        assert!(matches!(
            s.expressions().definition(opaque).unwrap(),
            ExpressionDefinition::Opaque { .. }
        ));
        assert_eq!(out(&s, 0x1008, 1), after);
        let call = s.operation(sid(&analysis, 0x1008, 0)).unwrap().unwrap();
        assert!(call.executable && call.output().is_none());
        let undefined = ssa
            .values()
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                matches!(
                    s.expressions().definition(ValueId(*i)).unwrap(),
                    ExpressionDefinition::Undefined { .. }
                )
            })
            .count();
        assert_eq!(
            undefined > 0,
            options.unique_scope == UniqueScope::Instruction
        );
    }
    // An entry self-loop: the phi meets the virtual entry operand.
    let analysis = build(
        vec![ins(
            0x1000,
            vec![
                binary(Opcode::IntAdd, r(0), r(0), con(2, 8)),
                binary(Opcode::IntSub, r(1), r(0), con(2, 8)),
                cbranch(label(0x1000), flag(0)),
                ret(),
            ],
        )],
        Endianness::Little,
        native(),
    );
    let s = simplify(&analysis);
    // (phi + 2) - 2 reassociates to the phi itself.
    let phi = leaf(&s, out(&s, 0x1000, 1)).expect("phi leaf");
    assert!(matches!(
        analysis.ssa().value(phi).unwrap().origin,
        ValueOrigin::Phi(_)
    ));
    assert!(s.stats().rule(Rule::SubtractConstant) > 0);
}

#[test]
fn boolean_rewrites_require_normalized_operands_and_floats_keep_their_operations() {
    let float = |bits: u64| con(bits, 8);
    let analysis = build(
        vec![ins(
            0x1000,
            vec![
                // An arbitrary byte: x && 1 keeps only bit 0, not x.
                binary(Opcode::BoolAnd, flag(1), flag(0), con(1, 1)),
                binary(Opcode::IntEqual, flag(2), r(0), r(1)),
                binary(Opcode::BoolAnd, flag(3), flag(2), con(1, 1)),
                binary(Opcode::IntNotequal, flag(3), flag(2), con(0, 1)),
                binary(Opcode::IntNotequal, flag(3), flag(0), con(0, 1)),
                binary(Opcode::BoolOr, flag(3), flag(0), con(0, 1)),
                binary(Opcode::BoolAnd, flag(3), flag(0), con(0xff, 1)),
                binary(Opcode::IntLess, flag(2), r(0), r(1)),
                unary(Opcode::BoolNegate, flag(3), flag(2)),
                unary(Opcode::BoolNegate, flag(3), flag(3)),
                // Floating point: no identities, exact literal folds only.
                binary(Opcode::FloatAdd, r(2), r(0), float(0)),
                binary(Opcode::FloatMult, r(3), r(0), float(0x3ff0_0000_0000_0000)),
                binary(
                    Opcode::FloatAdd,
                    r(4),
                    float(0x3ff0_0000_0000_0000),
                    float(0x3ff0_0000_0000_0000),
                ),
                binary(Opcode::IntAdd, r(5), r(2), con(0, 8)),
                ret(),
            ],
        )],
        Endianness::Little,
        program_mode(),
    );
    let s = simplify(&analysis);
    let raw = s.value_term(entry_value(&analysis, flag(0))).unwrap();
    let (opcode, inputs) = apply(&s, out(&s, 0x1000, 0)).unwrap();
    assert_eq!((opcode, inputs[0]), (Opcode::BoolAnd, raw));
    assert_eq!(literal(&s, inputs[1]), Some(1));
    let equal = out(&s, 0x1000, 1);
    assert!(s.term(equal).unwrap().boolean);
    assert_eq!(out(&s, 0x1000, 2), equal);
    assert_eq!(out(&s, 0x1000, 3), equal);
    assert_eq!(
        apply(&s, out(&s, 0x1000, 4)).unwrap().0,
        Opcode::IntNotequal
    );
    assert_eq!(out(&s, 0x1000, 5), raw);
    assert_eq!(out(&s, 0x1000, 6), raw);
    // !(a < b) is b <= a; a second negation restores a < b.
    let less = out(&s, 0x1000, 7);
    let (opcode, inputs) = apply(&s, out(&s, 0x1000, 8)).unwrap();
    assert_eq!(opcode, Opcode::IntLessequal);
    assert_eq!(inputs, {
        let mut swapped = apply(&s, less).unwrap().1;
        swapped.reverse();
        swapped
    });
    assert_eq!(out(&s, 0x1000, 9), less);
    for index in [10, 11] {
        let term = s.term(out(&s, 0x1000, index)).unwrap();
        assert_eq!(term.fault, TermFault::Here);
    }
    assert_eq!(
        literal(&s, out(&s, 0x1000, 12)),
        Some(0x4000_0000_0000_0000)
    );
    // A use of a float result keeps its leaf.
    let sum = defs(&analysis, 0x1000, 10)[0];
    assert_eq!(leaf(&s, out(&s, 0x1000, 13)), Some(sum));
    assert!(!s.policy().float_identities && s.policy().normalized_boolean_rewrites);
}

#[test]
fn reassociation_and_commutation_share_integer_terms_but_not_pointer_metadata() {
    let analysis = build(
        vec![ins(
            0x1000,
            vec![
                binary(Opcode::IntAdd, r(2), r(0), r(1)),
                binary(Opcode::IntAdd, r(3), r(1), r(0)),
                binary(Opcode::IntAdd, r(4), r(0), con(1, 8)),
                binary(Opcode::IntAdd, r(4), r(4), con(2, 8)),
                binary(Opcode::IntSub, r(5), r(0), con(1, 8)),
                binary(Opcode::IntSub, r(5), r(5), con(u64::MAX, 8)),
                binary(Opcode::IntMult, r(6), con(3, 8), r(0)),
                binary(Opcode::IntMult, r(6), r(6), con(5, 8)),
                op(Opcode::Ptradd, Some(r(7)), vec![r(0), con(2, 8), con(4, 8)]),
                op(Opcode::Ptradd, Some(r(7)), vec![r(7), con(1, 8), con(4, 8)]),
                binary(Opcode::IntLeft, r(1), r(0), con(1, 8)),
                binary(Opcode::IntLeft, r(1), r(1), con(2, 8)),
                ret(),
            ],
        )],
        Endianness::Little,
        program_mode(),
    );
    let s = simplify(&analysis);
    let input = s.value_term(entry_value(&analysis, r(0))).unwrap();
    assert_eq!(out(&s, 0x1000, 0), out(&s, 0x1000, 1));
    assert!(s.stats().shared_terms > 0);
    let (opcode, inputs) = apply(&s, out(&s, 0x1000, 3)).unwrap();
    assert_eq!(
        (opcode, inputs[0], literal(&s, inputs[1])),
        (Opcode::IntAdd, input, Some(3))
    );
    // (r0 - 1) - (-1) is r0.
    assert_eq!(out(&s, 0x1000, 5), input);
    let (opcode, inputs) = apply(&s, out(&s, 0x1000, 7)).unwrap();
    assert_eq!(
        (opcode, inputs[0], literal(&s, inputs[1])),
        (Opcode::IntMult, input, Some(15))
    );
    // Shifts are not reassociated: (r0 << 1) << 2 keeps both shifts.
    let (opcode, inputs) = apply(&s, out(&s, 0x1000, 11)).unwrap();
    assert_eq!(opcode, Opcode::IntLeft);
    assert_eq!(inputs[0], out(&s, 0x1000, 10));
    assert_eq!(literal(&s, inputs[1]), Some(2));
    // PTRADD keeps its operands and metadata; it is not reassociated.
    let (opcode, inputs) = apply(&s, out(&s, 0x1000, 9)).unwrap();
    assert_eq!(opcode, Opcode::Ptradd);
    assert_eq!(inputs[0], out(&s, 0x1000, 8));
    assert_eq!(literal(&s, inputs[2]), Some(4));
    assert!(!s.policy().reorders_pointer_or_metadata);
}

#[test]
fn unreached_statements_are_not_simplified_and_new_literal_conditions_do_not_prune() {
    let analysis = build(
        vec![
            ins(
                0x1000,
                vec![copy(flag(0), con(1, 1)), cbranch(label(0x1008), flag(0))],
            ),
            ins(
                0x1004,
                vec![
                    binary(Opcode::IntAdd, r(1), con(2, 8), con(3, 8)),
                    branch(0x1008),
                ],
            ),
            ins(
                0x1008,
                vec![
                    unary(Opcode::IntZext, r(2), flag(1)),
                    binary(Opcode::Subpiece, flag(2), r(2), con(4, 4)),
                    cbranch(label(0x1010), flag(2)),
                ],
            ),
            ins(0x100c, vec![ret()]),
            ins(0x1010, vec![ret()]),
        ],
        Endianness::Little,
        program_mode(),
    );
    let s = simplify(&analysis);
    let skipped = s.operation(sid(&analysis, 0x1004, 0)).unwrap().unwrap();
    assert!(!skipped.executable);
    assert!(skipped.output().is_none() && skipped.operand(0).is_none());
    assert!(
        s.node_term(skipped.source.output.unwrap())
            .unwrap()
            .is_none()
    );
    let value = defs(&analysis, 0x1004, 0)[0];
    assert!(s.constants().value(value).unwrap().is_unreached());
    // The unreached sum is never presented as the literal 5.
    assert_eq!(leaf(&s, s.value_term(value).unwrap()), Some(value));
    assert!(s.stats().skipped_operations >= 2);
    assert!(s.stats().unmapped_nodes > 0);
    // The high byte of a zero extension is literal zero, but the original
    // feasibility of both outcomes is unchanged.
    assert_eq!(literal(&s, operand(&s, 0x1008, 2, 1)), Some(0));
    assert_eq!(s.stats().new_literal_conditions, 1);
    let cfg = analysis.cfg();
    let node = cfg.block_of(ProgramPoint::new(0x1008, 2)).unwrap();
    for (edge, record) in cfg.edges().iter().enumerate() {
        if record.from == node {
            assert!(matches!(
                record.role,
                EdgeRole::ConditionTrue | EdgeRole::ConditionFalse
            ));
            assert!(s.constants().is_cfg_edge_feasible(edge).unwrap());
        }
    }
    assert!(!s.policy().prunes_control);
    assert!(s.policy().constants.prunes_constant_branches);
}

fn chain(count: u64, opcode: Opcode, literal_operand: bool) -> Vec<PcodeInstruction> {
    let mut program = Vec::new();
    for i in 0..count {
        program.push(ins(
            0x1000 + 4 * i,
            vec![binary(
                opcode,
                r(0),
                r(0),
                if literal_operand {
                    con(i % 5 + 1, 8)
                } else {
                    r(1)
                },
            )],
        ));
    }
    program.push(ins(0x1000 + 4 * count, vec![ret()]));
    program
}

fn scaled(instructions: Vec<PcodeInstruction>) -> PcodeSimplification {
    let analysis = build(instructions, Endianness::Little, program_mode());
    let result = PcodeSimplification::new(facts(&analysis), Default::default()).unwrap();
    check_invariants(&result);
    result
}

#[test]
fn deep_chains_are_iterative_reduced_and_linear() {
    let (small, large) = (12_000u64, 24_000u64);
    // An unknown start: each sum reassociates to r0 + constant.
    let s = scaled(chain(large, Opcode::IntAdd, true));
    let last = out(&s, 0x1000 + 4 * (large - 1), 0);
    let (opcode, inputs) = apply(&s, last).unwrap();
    assert_eq!(opcode, Opcode::IntAdd);
    assert!(leaf(&s, inputs[0]).is_some());
    let expected: u64 = (0..large).map(|i| i % 5 + 1).sum();
    assert_eq!(literal(&s, inputs[1]), Some(expected));
    let reduced = s.stats().work;
    let half = scaled(chain(small, Opcode::IntAdd, true)).stats().work;
    // A nonliteral operand: a 50,000-deep canonical term chain.
    let deep = scaled(chain(large, Opcode::IntMult, false));
    let mut depth = 0;
    let mut cursor = out(&deep, 0x1000 + 4 * (large - 1), 0);
    while let Some((Opcode::IntMult, inputs)) = apply(&deep, cursor) {
        depth += 1;
        cursor = if leaf(&deep, inputs[0]).is_some() {
            inputs[1]
        } else {
            inputs[0]
        };
    }
    assert_eq!(depth, large);
    let deep_half = scaled(chain(small, Opcode::IntMult, false)).stats().work;
    for (small_work, large_work) in [(half, reduced), (deep_half, deep.stats().work)] {
        assert!(
            large_work * 10 <= small_work * 22,
            "{small_work} -> {large_work}"
        );
        assert!(large_work <= 100 * large, "{large_work}");
    }
}

#[test]
fn shared_wide_fan_out_terms_are_consed_once() {
    let mut ops = Vec::new();
    for i in 0..2_000u64 {
        ops.push(binary(Opcode::IntAdd, r(1 + i % 6), r(0), r(7)));
        ops.push(binary(Opcode::IntXor, uniq(8 * i, 8), r(7), r(0)));
    }
    ops.push(ret());
    let analysis = build(vec![ins(0x1000, ops)], Endianness::Little, program_mode());
    let s = PcodeSimplification::new(facts(&analysis), Default::default()).unwrap();
    check_invariants(&s);
    let sum = out(&s, 0x1000, 0);
    let xor = out(&s, 0x1000, 1);
    for i in 0..2_000u32 {
        assert_eq!(out(&s, 0x1000, 2 * i), sum);
        assert_eq!(out(&s, 0x1000, 2 * i + 1), xor);
    }
    assert!(s.stats().shared_terms >= 3_998);
    let computed = s
        .terms()
        .iter()
        .filter(|t| !matches!(t.kind, TermKind::Leaf(_)))
        .count();
    assert!(computed < 20, "{computed}");
}

fn limit_case() -> Arc<PcodeSsa> {
    build(
        vec![
            ins(
                0x1000,
                vec![
                    binary(Opcode::IntAdd, r(0), r(1), con(0, 8)),
                    binary(Opcode::IntDiv, r(2), con(1, 8), con(0, 8)),
                    binary(Opcode::Piece, reg(0x100, 16), r(0), con(0x1234, 8)),
                    binary(Opcode::Subpiece, r(3), reg(0x100, 16), con(8, 4)),
                    binary(Opcode::IntSub, r(4), r(3), con(1, 8)),
                    binary(Opcode::IntSub, r(4), r(4), con(1, 8)),
                ],
            ),
            ins(
                0x1004,
                vec![
                    binary(Opcode::IntLess, flag(0), r(4), con(3, 8)),
                    cbranch(label(0x1000), flag(0)),
                    ret(),
                ],
            ),
        ],
        Endianness::Little,
        native(),
    )
}

#[test]
fn every_limit_is_exact_and_exhaustion_returns_no_result() {
    let analysis = limit_case();
    let constants = facts(&analysis);
    let defaults = SimplifyLimits::default();
    let base = PcodeSimplification::new(constants.clone(), defaults).unwrap();
    check_invariants(&base);
    let stats = base.stats();
    assert!(stats.refused_folds == 1 && stats.literal_bytes > 0 && stats.live_peak > 1);
    let run = |limits: SimplifyLimits| PcodeSimplification::new(constants.clone(), limits);
    let exact = |limits: SimplifyLimits| assert_eq!(run(limits).unwrap().stats(), stats);
    let below = |limits: SimplifyLimits, name: &str| match run(limits) {
        Err(SimplifyError::Limit(found)) => assert_eq!(found, name),
        other => panic!("expected {name} limit, got {:?}", other.map(|s| s.stats())),
    };
    let ssa = analysis.ssa();
    let statements: usize = ssa
        .blocks()
        .iter()
        .filter_map(|b| b.renamed())
        .map(|b| b.statements().len())
        .sum();
    let cases: [(SimplifyLimits, SimplifyLimits, &str); 8] = [
        (
            SimplifyLimits {
                max_values: ssa.values().len(),
                ..defaults
            },
            SimplifyLimits {
                max_values: ssa.values().len() - 1,
                ..defaults
            },
            "values",
        ),
        (
            SimplifyLimits {
                max_expression_nodes: constants.expressions().nodes().len(),
                ..defaults
            },
            SimplifyLimits {
                max_expression_nodes: constants.expressions().nodes().len() - 1,
                ..defaults
            },
            "expression nodes",
        ),
        (
            SimplifyLimits {
                max_statements: statements,
                ..defaults
            },
            SimplifyLimits {
                max_statements: statements - 1,
                ..defaults
            },
            "statements",
        ),
        (
            SimplifyLimits {
                max_terms: stats.terms,
                ..defaults
            },
            SimplifyLimits {
                max_terms: stats.terms - 1,
                ..defaults
            },
            "terms",
        ),
        (
            SimplifyLimits {
                max_term_inputs: stats.term_inputs,
                ..defaults
            },
            SimplifyLimits {
                max_term_inputs: stats.term_inputs - 1,
                ..defaults
            },
            "term inputs",
        ),
        (
            SimplifyLimits {
                max_literal_bytes: stats.literal_bytes,
                ..defaults
            },
            SimplifyLimits {
                max_literal_bytes: stats.literal_bytes - 1,
                ..defaults
            },
            "literal bytes",
        ),
        (
            SimplifyLimits {
                max_live: stats.live_peak,
                ..defaults
            },
            SimplifyLimits {
                max_live: stats.live_peak - 1,
                ..defaults
            },
            "live",
        ),
        (
            SimplifyLimits {
                max_work: stats.work,
                ..defaults
            },
            SimplifyLimits {
                max_work: stats.work - 1,
                ..defaults
            },
            "work",
        ),
    ];
    for (fits, short, name) in cases {
        exact(fits);
        below(short, name);
    }
}

#[test]
fn results_are_deterministic_owned_send_sync_and_lookups_are_checked() {
    fn send_sync_clone<T: Send + Sync + Clone>() {}
    send_sync_clone::<PcodeSimplification>();
    send_sync_clone::<Term>();
    send_sync_clone::<RefusedFold>();
    let analysis = limit_case();
    let constants = facts(&analysis);
    let first = PcodeSimplification::new(constants.clone(), Default::default()).unwrap();
    // Each run uses a fresh randomly seeded map; IDs do not depend on it.
    for _ in 0..4 {
        let again = PcodeSimplification::new(constants.clone(), Default::default()).unwrap();
        assert_eq!(
            format!("{:?}", again.terms()),
            format!("{:?}", first.terms())
        );
        assert_eq!(again.stats(), first.stats());
    }
    // An independently rebuilt snapshot gives the same canonical IDs.
    let rebuilt = PcodeSimplification::new(facts(&limit_case()), Default::default()).unwrap();
    assert_eq!(
        format!("{:?}", rebuilt.terms()),
        format!("{:?}", first.terms())
    );
    assert!(Arc::ptr_eq(first.constants(), &constants));
    assert!(Arc::ptr_eq(first.expressions(), constants.expressions()));
    assert!(Arc::ptr_eq(first.analysis(), &analysis));
    let cloned = first.clone();
    assert!(Arc::ptr_eq(cloned.constants(), &constants));
    assert!(matches!(
        first.term(TermId(first.terms().len())),
        Err(SimplifyError::UnknownTerm(_))
    ));
    assert!(matches!(
        first.value_term(ValueId(analysis.ssa().values().len())),
        Err(SimplifyError::UnknownValue(_))
    ));
    assert!(matches!(
        first.node_term(ExpressionId(constants.expressions().nodes().len())),
        Err(SimplifyError::UnknownExpression(_))
    ));
    assert!(
        first
            .operation(StatementId {
                node: analysis.ssa().graph().node_count(),
                index: 0
            })
            .is_err()
    );
    assert!(
        first
            .operation(StatementId {
                node: analysis.ssa().entry(),
                index: 1000
            })
            .is_err()
    );
    // Terms reference earlier IDs, so a consumer can stream them in order.
    let names: BTreeSet<_> = Rule::ALL.iter().map(|r| r.name()).collect();
    assert_eq!(names.len(), Rule::ALL.len());
}

#[test]
fn raw_examples_reduce_without_claiming_new_control_flow() {
    let examples = [
        include_str!("../../../examples/pcode/sum-loop.json"),
        include_str!("../../../examples/pcode/alias-branch.json"),
    ];
    for (index, text) in examples.into_iter().enumerate() {
        let input: ExecutionInput = serde_json::from_str(text).unwrap();
        for options in [program_mode(), native()] {
            let analysis = build_in(
                input.spaces.clone(),
                input.code_space,
                input.instructions.clone(),
                input.entry,
                options,
            );
            let s = simplify(&analysis);
            let stats = s.stats();
            // Every executed operation has its terms; values reduce to
            // literals, propagated terms or leaves.
            assert!(stats.executed_operations > 0);
            assert_eq!(
                stats.literal_values + stats.propagated_values + stats.leaf_values,
                analysis.ssa().values().len()
            );
            assert!(stats.rule(Rule::Propagate) > 0, "example {index}");
            assert!(
                stats.literal_outputs + stats.forwarded_outputs > 0,
                "example {index}"
            );
            let feasible: Vec<bool> = (0..analysis.cfg().edges().len())
                .map(|e| s.constants().is_cfg_edge_feasible(e).unwrap())
                .collect();
            let again = facts(&analysis);
            for (edge, &f) in feasible.iter().enumerate() {
                assert_eq!(again.is_cfg_edge_feasible(edge).unwrap(), f);
            }
        }
    }
    // alias-branch: the 8-byte read after the join merges the phi'd low byte
    // with the untouched upper bytes of the first write.
    let input: ExecutionInput = serde_json::from_str(examples[1]).unwrap();
    let analysis = build_in(
        input.spaces,
        input.code_space,
        input.instructions,
        input.entry,
        program_mode(),
    );
    let s = simplify(&analysis);
    let joins = s
        .terms()
        .iter()
        .filter(|t| matches!(&t.kind, TermKind::Join(p) if p.len() == 2 && p[0].size == 1))
        .count();
    assert!(joins >= 1);
    let mut machine_checks = 0;
    for seed in 0..6 {
        let mut snapshot = state(Endianness::Little, seed);
        snapshot.regions.extend(input.memory.iter().cloned());
        machine_checks += check_concrete(&s, &snapshot, 16);
    }
    assert!(machine_checks > 0);
}

#[test]
fn every_expression_and_value_maps_to_its_namespace() {
    let analysis = limit_case();
    let s = simplify(&analysis);
    let mut by_origin: BTreeMap<String, usize> = BTreeMap::new();
    for term in s.terms() {
        let key = match term.origin {
            TermOrigin::Node(node) => {
                assert!(node.0 < s.expressions().nodes().len());
                "node"
            }
            TermOrigin::Value(value) => {
                assert!(value.0 < analysis.ssa().values().len());
                "value"
            }
        };
        *by_origin.entry(key.into()).or_default() += 1;
    }
    assert!(by_origin["node"] > 0 && by_origin["value"] > 0);
}
