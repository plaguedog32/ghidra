use std::collections::BTreeSet;
use std::sync::Arc;

use ghidra_analysis::*;
use ghidra_cfg::{Arrival, Cfg, CfgInput, EdgeRole, ProgramPoint};
use ghidra_pcode::machine::{Machine, MemoryInit, MemorySnapshot, StopReason};
use ghidra_pcode::{
    AddressSpace, Endianness, Opcode, PcodeInstruction, PcodeOperation, SpaceId, SpaceKind, Value,
    Varnode, evaluate_pure,
};
use ghidra_ssa::{
    DefUseError, DefUseIndex, DefUseResource, EntryState, PhiPlacement, Predecessor, StatementId,
    ValueId, ValueOrigin,
};

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

fn spaces(endian: Endianness) -> Vec<AddressSpace> {
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
        word_size: 1,
        endianness: if id == CODE {
            Endianness::Little
        } else {
            endian
        },
    })
    .collect()
}

fn build(
    instructions: Vec<PcodeInstruction>,
    endian: Endianness,
    options: AnalysisOptions,
) -> Arc<PcodeSsa> {
    let entry = instructions.iter().map(|i| i.address).min().unwrap();
    let cfg = Arc::new(
        Cfg::new(
            CfgInput::new(spaces(endian), SpaceId(CODE), entry, instructions),
            Default::default(),
        )
        .unwrap(),
    );
    let analysis = Arc::new(PcodeSsa::new(cfg, &[], options, Default::default()).unwrap());
    analysis.ssa().verify(analysis.raw()).unwrap();
    analysis
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

fn terms(analysis: &Arc<PcodeSsa>) -> Arc<PcodeExpressions> {
    Arc::new(PcodeExpressions::new(analysis.clone(), Default::default()).unwrap())
}
/// Propagate and always check the independent reference fixpoint.
fn propagate(analysis: &Arc<PcodeSsa>) -> PcodeConstants {
    let facts = PcodeConstants::new(terms(analysis), Default::default()).unwrap();
    check_reference(&facts);
    facts
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
/// The complete output term of an explicit operation.
fn out<'a>(facts: &'a PcodeConstants, address: u64, index: u32) -> ConstantFact<'a> {
    let id = sid(facts.analysis(), address, index);
    let output = facts.expressions().operation(id).unwrap().output.unwrap();
    facts.expression(output).unwrap()
}
fn number(fact: ConstantFact<'_>) -> Option<u64> {
    fact.constant().and_then(Value::to_u64)
}
fn block(analysis: &PcodeSsa, address: u64) -> usize {
    analysis
        .cfg()
        .block_of(ProgramPoint::new(address, 0))
        .unwrap()
}
fn cfg_edge(analysis: &PcodeSsa, from: u64, role: EdgeRole) -> usize {
    let cfg = analysis.cfg();
    let node = cfg
        .block_of(ProgramPoint::new(
            from,
            cfg.instruction_at(from).unwrap().ops.len().max(1) as u32 - 1,
        ))
        .unwrap();
    cfg.edges()
        .iter()
        .position(|edge| edge.from == node && edge.role == role)
        .unwrap()
}

// ---------------------------------------------------------------------------
// Independent reference: dense round-robin Kleene iteration from bottom. It
// recomputes every executable node, phi, definition and branch from scratch
// each round and evaluates terms recursively. It shares only the documented
// transfer functions, not the worklists, plans, counters or edge indexes.

#[derive(Clone, Debug, PartialEq, Eq)]
enum R {
    Unreached,
    Const(Value),
    Unknown,
}
fn rank(fact: &R) -> u8 {
    match fact {
        R::Unreached => 0,
        R::Const(_) => 1,
        R::Unknown => 2,
    }
}
fn observed(fact: ConstantFact<'_>) -> R {
    match fact {
        ConstantFact::Unreached => R::Unreached,
        ConstantFact::Constant(value) => R::Const(value.clone()),
        ConstantFact::Unknown => R::Unknown,
    }
}
fn r_join(a: &R, b: &R) -> R {
    match (a, b) {
        (R::Unknown, _) | (_, R::Unknown) => R::Unknown,
        (R::Unreached, other) | (other, R::Unreached) => other.clone(),
        (R::Const(x), R::Const(y)) if x == y => R::Const(x.clone()),
        _ => R::Unknown,
    }
}
fn children(kind: &ExpressionKind) -> Vec<ExpressionId> {
    match kind {
        ExpressionKind::Join(parts) => parts.iter().map(|p| p.value).collect(),
        ExpressionKind::Extract { value, .. } => vec![*value],
        ExpressionKind::Pure { inputs, .. } => inputs.clone(),
        _ => Vec::new(),
    }
}
/// Evaluated inputs, or the combined non-constant fact.
fn r_inputs(
    program: &PcodeExpressions,
    kind: &ExpressionKind,
    values: &[R],
) -> Result<Vec<Value>, R> {
    let facts: Vec<R> = children(kind)
        .into_iter()
        .map(|child| r_eval(program, child, values))
        .collect();
    if facts.contains(&R::Unknown) {
        return Err(R::Unknown);
    }
    if facts.contains(&R::Unreached) {
        return Err(R::Unreached);
    }
    Ok(facts
        .into_iter()
        .map(|fact| match fact {
            R::Const(value) => value,
            _ => unreachable!(),
        })
        .collect())
}
fn r_eval(program: &PcodeExpressions, id: ExpressionId, values: &[R]) -> R {
    let node = program.node(id).unwrap();
    let size = match node.ty {
        ExpressionType::Bits(size) => size as usize,
        ExpressionType::Memory(_) => 0,
    };
    match &node.kind {
        ExpressionKind::Constant(value) => return R::Const(value.clone()),
        ExpressionKind::SsaValue(value) => return values[value.0].clone(),
        ExpressionKind::ReadMemory { .. } | ExpressionKind::WriteMemory { .. } => {
            return R::Unknown;
        }
        _ => {}
    }
    let inputs = match r_inputs(program, &node.kind, values) {
        Ok(inputs) => inputs,
        Err(fact) => return fact,
    };
    match &node.kind {
        ExpressionKind::Join(parts) => {
            let mut bytes = vec![0; size];
            for (part, value) in parts.iter().zip(&inputs) {
                bytes[part.lsb_byte as usize..][..part.size as usize]
                    .copy_from_slice(&value.to_le_bytes());
            }
            R::Const(Value::from_le_bytes(&bytes).unwrap())
        }
        ExpressionKind::Extract { lsb_byte, .. } => R::Const(
            Value::from_le_bytes(&inputs[0].to_le_bytes()[*lsb_byte as usize..][..size]).unwrap(),
        ),
        ExpressionKind::Pure { opcode, .. } => {
            evaluate_pure(*opcode, &inputs, size as u32).map_or(R::Unknown, R::Const)
        }
        _ => unreachable!(),
    }
}
fn r_faults(program: &PcodeExpressions, id: ExpressionId, values: &[R]) -> bool {
    let node = program.node(id).unwrap();
    let ExpressionKind::Pure { opcode, .. } = &node.kind else {
        return false;
    };
    let ExpressionType::Bits(size) = node.ty else {
        return false;
    };
    match r_inputs(program, &node.kind, values) {
        Ok(inputs) => evaluate_pure(*opcode, &inputs, size).is_err(),
        Err(_) => false,
    }
}
/// Terms an executed statement must give facts to: operands, the operation
/// result, definition roots, and everything below them (memory addresses and
/// stored values included).
fn statement_terms(program: &PcodeExpressions, id: StatementId, into: &mut BTreeSet<usize>) {
    let analysis = program.analysis();
    let mut stack = Vec::new();
    if let Some(operation) = program.operation(id) {
        stack.extend(
            operation
                .operands
                .iter()
                .filter_map(ExpressionOperand::expression),
        );
        stack.extend(operation.output);
    }
    for value in analysis.ssa().statement(id).unwrap().defs() {
        if let ExpressionDefinition::Expression(root) = program.definition(*value).unwrap() {
            stack.push(*root);
        }
    }
    while let Some(term) = stack.pop() {
        if !into.insert(term.0) {
            continue;
        }
        let kind = &program.node(term).unwrap().kind;
        stack.extend(children(kind));
        match kind {
            ExpressionKind::ReadMemory {
                address: ExpressionAddress::Pointer { value, .. },
                ..
            } => stack.push(*value),
            ExpressionKind::WriteMemory { address, value, .. } => {
                stack.push(*value);
                if let ExpressionAddress::Pointer { value, .. } = address {
                    stack.push(*value);
                }
            }
            _ => {}
        }
    }
}

struct Reference {
    values: Vec<R>,
    nodes: Vec<bool>,
    cfg_edges: Vec<bool>,
    graph_edges: BTreeSet<(usize, usize)>,
}

fn reference(program: &PcodeExpressions) -> Reference {
    let analysis = program.analysis();
    let ssa = analysis.ssa();
    let graph = ssa.graph();
    let cfg = analysis.cfg();
    let mut values: Vec<R> = ssa
        .values()
        .iter()
        .map(|value| match value.origin {
            ValueOrigin::Entry(_) => R::Unknown,
            _ => R::Unreached,
        })
        .collect();
    let mut nodes = vec![false; graph.node_count()];
    let mut cfg_edges = vec![false; cfg.edges().len()];
    let graph_edges = |cfg_edges: &[bool], nodes: &[bool]| {
        let mut set = BTreeSet::new();
        for (id, edge) in cfg.edges().iter().enumerate() {
            if !cfg_edges[id] {
                continue;
            }
            match analysis.edge_reset(id) {
                Some(reset) => {
                    set.insert((edge.from, reset));
                    if nodes[reset] {
                        set.insert((reset, edge.to));
                    }
                }
                None => {
                    set.insert((edge.from, edge.to));
                }
            }
        }
        set
    };
    let update = |values: &mut Vec<R>, value: ValueId, fact: R, changed: &mut bool| {
        if values[value.0] != fact {
            assert!(
                rank(&fact) >= rank(&values[value.0]),
                "reference is monotone"
            );
            values[value.0] = fact;
            *changed = true;
        }
    };
    loop {
        let mut changed = false;
        let feasible = graph_edges(&cfg_edges, &nodes);
        for (node, executed) in nodes.iter_mut().enumerate() {
            let live = node == ssa.entry()
                || graph
                    .predecessors(node)
                    .unwrap()
                    .iter()
                    .any(|&from| feasible.contains(&(from, node)));
            if !live {
                continue;
            }
            if !*executed {
                *executed = true;
                changed = true;
            }
            let block = ssa.block(node).unwrap().renamed().unwrap();
            for phi in block.phis() {
                let mut fact = R::Unreached;
                for (index, predecessor) in block.incoming().iter().enumerate() {
                    let enabled = match predecessor {
                        Predecessor::Entry => true,
                        Predecessor::Node(from) => feasible.contains(&(*from, node)),
                    };
                    if enabled {
                        fact = r_join(&fact, &values[phi.operands()[index].0]);
                    }
                }
                update(&mut values, phi.value(), fact, &mut changed);
            }
            for statement in block.statements() {
                for &value in statement.defs() {
                    let fact = match program.definition(value).unwrap() {
                        ExpressionDefinition::Expression(root) => r_eval(program, *root, &values),
                        ExpressionDefinition::Undefined { .. }
                        | ExpressionDefinition::Opaque { .. } => R::Unknown,
                        other => panic!("statement definition {other:?}"),
                    };
                    update(&mut values, value, fact, &mut changed);
                }
            }
            if node < cfg.block_count() {
                let last = StatementId {
                    node,
                    index: block.statements().len() - 1,
                };
                let condition = program
                    .operation(last)
                    .filter(|operation| operation.opcode == Opcode::Cbranch)
                    .map(|operation| {
                        r_eval(
                            program,
                            operation.operands[1].expression().unwrap(),
                            &values,
                        )
                    });
                for (id, edge) in cfg.edges().iter().enumerate() {
                    if edge.from != node {
                        continue;
                    }
                    let truth = match &condition {
                        Some(R::Const(value)) => Some(value.to_u64() != Some(0)),
                        _ => None,
                    };
                    let enabled = match edge.role {
                        EdgeRole::ConditionTrue => {
                            condition == Some(R::Unknown) || truth == Some(true)
                        }
                        EdgeRole::ConditionFalse => {
                            condition == Some(R::Unknown) || truth == Some(false)
                        }
                        _ => true,
                    };
                    if enabled && !cfg_edges[id] {
                        cfg_edges[id] = true;
                        changed = true;
                    }
                }
            }
        }
        if !changed {
            let graph_edges = graph_edges(&cfg_edges, &nodes);
            return Reference {
                values,
                nodes,
                cfg_edges,
                graph_edges,
            };
        }
    }
}

fn check_reference(facts: &PcodeConstants) {
    let program = facts.expressions();
    let analysis = program.analysis();
    let ssa = analysis.ssa();
    let graph = ssa.graph();
    let cfg = analysis.cfg();
    let expected = reference(program);
    for (index, fact) in expected.values.iter().enumerate() {
        assert_eq!(
            &observed(facts.value(ValueId(index)).unwrap()),
            fact,
            "value {index}"
        );
    }
    let mut executed = BTreeSet::new();
    for node in 0..graph.node_count() {
        assert_eq!(
            facts.is_node_executable(node).unwrap(),
            expected.nodes[node],
            "node {node}"
        );
        for &from in graph.predecessors(node).unwrap() {
            assert_eq!(
                facts.is_edge_executable(from, node).unwrap(),
                expected.graph_edges.contains(&(from, node)),
                "edge {from} -> {node}"
            );
        }
        if let Some(block) = ssa.block(node).unwrap().renamed() {
            for index in 0..block.statements().len() {
                let id = StatementId { node, index };
                assert_eq!(
                    facts.is_statement_executable(id).unwrap(),
                    expected.nodes[node]
                );
                if expected.nodes[node] {
                    statement_terms(program, id, &mut executed);
                }
            }
        }
    }
    for (edge, &feasible) in expected.cfg_edges.iter().enumerate() {
        assert_eq!(
            facts.is_cfg_edge_feasible(edge).unwrap(),
            feasible,
            "CFG edge {edge}"
        );
    }
    let mut faults = BTreeSet::new();
    for id in 0..program.nodes().len() {
        let term = ExpressionId(id);
        let fact = match &program.node(term).unwrap().kind {
            ExpressionKind::SsaValue(value) => expected.values[value.0].clone(),
            _ if executed.contains(&id) => {
                if r_faults(program, term, &expected.values) {
                    faults.insert(id);
                }
                r_eval(program, term, &expected.values)
            }
            _ => R::Unreached,
        };
        assert_eq!(observed(facts.expression(term).unwrap()), fact, "term {id}");
    }
    let reported: BTreeSet<_> = facts.faults().iter().map(|f| f.expression.0).collect();
    assert_eq!(reported, faults);
    assert_eq!(
        reported.len(),
        facts.faults().len(),
        "each term faults once"
    );
    let stats = facts.stats();
    assert_eq!(
        stats.executable_nodes,
        expected.nodes.iter().filter(|n| **n).count()
    );
    assert_eq!(
        stats.feasible_cfg_edges,
        expected.cfg_edges.iter().filter(|e| **e).count()
    );
    assert_eq!(stats.executable_edges, expected.graph_edges.len());
    assert_eq!(stats.faults, facts.faults().len());
    let count = |rank_value| {
        expected
            .values
            .iter()
            .filter(|f| rank(f) == rank_value)
            .count()
    };
    assert_eq!(stats.unreached_values, count(0));
    assert_eq!(stats.constant_values, count(1));
    assert_eq!(stats.unknown_values, count(2));
    assert_eq!(facts.constants().count(), count(1));
    assert!(stats.value_changes <= 2 * expected.values.len());
    assert!(stats.evaluations <= program.nodes().len());
    assert!(stats.feasible_cfg_edges <= cfg.edges().len());
    check_sparse_bounds(facts, &expected.nodes);
}

/// Bounds derived from the SSA shape alone. Each value rises at most twice
/// and then reaches only its own def-use sites, so a pass that rescanned
/// statements or phis per change would exceed them.
fn check_sparse_bounds(facts: &PcodeConstants, executable: &[bool]) {
    let ssa = facts.analysis().ssa();
    let stats = facts.stats();
    // The nested index is built under its own budget and reported separately.
    let index = DefUseIndex::new(ssa, facts.limits().def_use).unwrap();
    assert_eq!(stats.def_use_work, index.work());
    let statements: usize = (0..ssa.graph().node_count())
        .filter(|&node| executable[node])
        .map(|node| {
            ssa.block(node)
                .unwrap()
                .renamed()
                .unwrap()
                .statements()
                .len()
        })
        .sum();
    assert_eq!(
        stats.executed_statements, statements,
        "each statement runs once"
    );
    assert!(stats.notifications <= 2 * index.total_statement_uses());
    // Node visit, newly feasible edge, and two rises per phi operand use.
    assert!(stats.phi_folds <= 4 * ssa.phi_operand_count());
    assert!(stats.executable_edges <= ssa.graph().edge_count());
}

// ---------------------------------------------------------------------------
// Concrete oracle: run the real Machine one operation at a time from snapshots
// and check every executed point's node, block-entry edge and phis, and every
// constant definition, against the facts.

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

fn check_constant(facts: &PcodeConstants, machine: &Machine, value: ValueId) -> usize {
    let analysis = facts.analysis();
    match facts.value(value).unwrap() {
        ConstantFact::Constant(expected) => {
            let node = storage(analysis, value).expect("memory values are never constant");
            let actual = machine
                .read_varnode(&node)
                .expect("a constant fact names initialized storage");
            assert_eq!(&actual, expected, "value {value:?} in {node:?}");
            1
        }
        ConstantFact::Unreached => panic!("executed value {value:?} is unreached"),
        ConstantFact::Unknown => 0,
    }
}

fn check_point(
    facts: &PcodeConstants,
    before: &Machine,
    after: &Machine,
    point: ProgramPoint,
    previous: Option<ProgramPoint>,
) -> usize {
    let analysis = facts.analysis();
    let cfg = analysis.cfg();
    let ssa = analysis.ssa();
    let node = cfg.block_of(point).unwrap();
    assert!(facts.is_node_executable(node).unwrap(), "executed {point}");
    let id = analysis.statement_id(point).unwrap();
    assert!(facts.is_statement_executable(id).unwrap());
    let mut checks = 1;
    if cfg.block_points(node).unwrap()[0] == point {
        match previous {
            None => assert_eq!(node, cfg.entry()),
            Some(previous) => {
                let from = cfg.block_of(previous).unwrap();
                let taken = cfg.edges().iter().enumerate().any(|(edge, e)| {
                    e.from == from
                        && e.to == node
                        && facts.is_cfg_edge_feasible(edge).unwrap()
                        && match analysis.edge_reset(edge) {
                            Some(reset) => {
                                facts.is_node_executable(reset).unwrap()
                                    && facts.is_edge_executable(from, reset).unwrap()
                                    && facts.is_edge_executable(reset, node).unwrap()
                            }
                            None => facts.is_edge_executable(from, node).unwrap(),
                        }
                });
                assert!(taken, "transition {previous} -> {point} is feasible");
            }
        }
        for phi in ssa.block(node).unwrap().renamed().unwrap().phis() {
            checks += check_constant(facts, before, phi.value());
        }
    }
    if id.index > 0
        && let Some(AdaptedStatement::UndefinedTemporaries { .. }) =
            analysis.statement(StatementId {
                node: id.node,
                index: id.index - 1,
            })
    {
        let reset = StatementId {
            node: id.node,
            index: id.index - 1,
        };
        for value in ssa.statement(reset).unwrap().defs() {
            assert!(facts.value(*value).unwrap().is_unknown());
        }
    }
    for value in ssa.statement(id).unwrap().defs() {
        checks += check_constant(facts, after, *value);
    }
    checks
}

fn check_concrete(facts: &PcodeConstants, initial: &MemorySnapshot, max_frames: usize) -> usize {
    let analysis = facts.analysis();
    let cfg = analysis.cfg();
    let spaces = cfg.spaces();
    let mut state = initial.clone();
    let mut address = cfg.entry_address();
    let mut previous = None;
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
                SpaceId(CODE),
                address,
                operations,
            ) else {
                return checks; // A faulting or uninitialized operation ends the run.
            };
            if report.trace.len() < operations as usize {
                state = after.snapshot();
                break report.stop;
            }
            let event = &report.trace[operations as usize - 1];
            let point = ProgramPoint::new(event.address, event.operation as u32);
            checks += check_point(facts, &before, &after, point, previous);
            previous = Some(point);
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
            None => {
                let from = cfg.block_of(previous.unwrap()).unwrap();
                assert!(
                    cfg.edges()
                        .iter()
                        .enumerate()
                        .any(|(edge, e)| e.from == from
                            && e.arrival == Arrival::Exit
                            && facts.is_cfg_edge_feasible(edge).unwrap()
                            && facts.is_node_executable(e.to).unwrap())
                );
                return checks + 1;
            }
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

fn random_program(rng: &mut Rng, endian: Endianness) -> Vec<PcodeInstruction> {
    const CONSTANTS: [u64; 5] = [0, 1, 2, 7, 0xff];
    let count = 3 + rng.below(7);
    let mut program = Vec::new();
    for i in 0..count {
        let address = 0x1000 + 4 * i;
        let mut ops = Vec::new();
        let full = |rng: &mut Rng| r(rng.below(4));
        let literal = |rng: &mut Rng| con(CONSTANTS[rng.below(5) as usize], 8);
        let operand = |rng: &mut Rng| {
            if rng.below(3) == 0 {
                literal(rng)
            } else {
                full(rng)
            }
        };
        let condition = |rng: &mut Rng| {
            if rng.below(4) == 0 {
                con(rng.below(2), 1)
            } else {
                flag(rng.below(2))
            }
        };
        for _ in 0..1 + rng.below(3) {
            match rng.below(13) {
                0 | 1 => ops.push(copy(full(rng), literal(rng))),
                2 => ops.push(copy(full(rng), full(rng))),
                3 => {
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
                    let opcode = [Opcode::IntDiv, Opcode::IntRem][rng.below(2) as usize];
                    let divisor = if rng.below(2) == 0 {
                        con([0, 3][rng.below(2) as usize], 8)
                    } else {
                        full(rng)
                    };
                    ops.push(binary(opcode, full(rng), operand(rng), divisor));
                }
                5 => {
                    let opcode = [Opcode::IntEqual, Opcode::IntNotequal, Opcode::IntLess]
                        [rng.below(3) as usize];
                    ops.push(binary(opcode, flag(rng.below(2)), full(rng), operand(rng)));
                }
                6 => ops.push(op(
                    Opcode::BoolNegate,
                    Some(flag(rng.below(2))),
                    vec![flag(rng.below(2))],
                )),
                7 => {
                    let size = [1, 4][rng.below(2) as usize];
                    ops.push(copy(
                        low(endian, rng.below(4), size),
                        con(CONSTANTS[rng.below(5) as usize], size),
                    ));
                }
                8 => ops.push(op(
                    Opcode::IntZext,
                    Some(full(rng)),
                    vec![flag(rng.below(2))],
                )),
                9 => ops.push(binary(
                    Opcode::Subpiece,
                    flag(rng.below(2)),
                    full(rng),
                    con(rng.below(8), 4),
                )),
                10 => {
                    ops.push(copy(uniq(0, 8), operand(rng)));
                    ops.push(binary(Opcode::IntAdd, full(rng), uniq(0, 8), operand(rng)));
                }
                11 => ops.push(op(
                    Opcode::Load,
                    Some(full(rng)),
                    vec![con(1, 4), con(0x100 + 8 * rng.below(4), 8)],
                )),
                _ => ops.push(op(
                    Opcode::Store,
                    None,
                    vec![con(1, 4), con(0x100 + 8 * rng.below(4), 8), operand(rng)],
                )),
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

fn concrete(facts: &PcodeConstants, endian: Endianness) -> usize {
    (0..6)
        .map(|seed| check_concrete(facts, &state(endian, seed), 64))
        .sum()
}
fn placements() -> [PhiPlacement; 2] {
    [PhiPlacement::Pruned, PhiPlacement::Unpruned]
}
fn phi_facts<'a>(facts: &'a PcodeConstants, node: usize) -> Vec<ConstantFact<'a>> {
    facts
        .analysis()
        .ssa()
        .block(node)
        .unwrap()
        .renamed()
        .unwrap()
        .phis()
        .iter()
        .map(|phi| facts.value(phi.value()).unwrap())
        .collect()
}

#[test]
fn diamonds_keep_equal_constants_and_merge_conflicts_to_unknown() {
    let program = |head: Vec<PcodeOperation>| {
        vec![
            ins(0x1000, head),
            ins(
                0x1004,
                vec![copy(r(0), con(5, 8)), copy(r(1), con(1, 8)), branch(0x100c)],
            ),
            ins(0x1008, vec![copy(r(0), con(5, 8)), copy(r(1), con(2, 8))]),
            ins(0x100c, vec![copy(r(2), r(0)), copy(r(3), r(1)), ret()]),
        ]
    };
    for options in [native(), program_mode()] {
        for placement in placements() {
            let options = placed(options, placement);
            let analysis = build(
                program(vec![cbranch(label(0x1008), flag(0))]),
                Endianness::Little,
                options,
            );
            let facts = propagate(&analysis);
            assert_eq!(number(out(&facts, 0x100c, 0)), Some(5));
            assert!(out(&facts, 0x100c, 1).is_unknown());
            for address in [0x1000, 0x1004, 0x1008, 0x100c] {
                assert!(facts.is_node_executable(block(&analysis, address)).unwrap());
            }
            assert!(concrete(&facts, Endianness::Little) > 20);

            // A literal true condition kills the fallthrough side.
            let analysis = build(
                program(vec![cbranch(label(0x1008), con(1, 1))]),
                Endianness::Little,
                options,
            );
            let facts = propagate(&analysis);
            assert!(!facts.is_node_executable(block(&analysis, 0x1004)).unwrap());
            assert!(
                !facts
                    .is_cfg_edge_feasible(cfg_edge(&analysis, 0x1000, EdgeRole::ConditionFalse))
                    .unwrap()
            );
            assert!(
                facts
                    .is_cfg_edge_feasible(cfg_edge(&analysis, 0x1000, EdgeRole::ConditionTrue))
                    .unwrap()
            );
            assert!(
                facts
                    .value(defs(&analysis, 0x1004, 1)[0])
                    .unwrap()
                    .is_unreached()
            );
            assert!(out(&facts, 0x1004, 1).is_unreached());
            assert_eq!(number(out(&facts, 0x100c, 1)), Some(2));
            assert!(concrete(&facts, Endianness::Little) > 20);

            // A computed constant false condition kills the taken side.
            let analysis = build(
                program(vec![
                    binary(Opcode::IntLess, flag(0), con(7, 8), con(3, 8)),
                    cbranch(label(0x1008), flag(0)),
                ]),
                Endianness::Little,
                options,
            );
            let facts = propagate(&analysis);
            assert!(!facts.is_node_executable(block(&analysis, 0x1008)).unwrap());
            assert_eq!(number(out(&facts, 0x100c, 0)), Some(5));
            assert_eq!(number(out(&facts, 0x100c, 1)), Some(1));
            assert!(concrete(&facts, Endianness::Little) > 20);
        }
    }
}

#[test]
fn undefined_incoming_paths_are_unknown_not_optimistic() {
    let program = |condition: Varnode| {
        vec![
            ins(0x1000, vec![cbranch(label(0x1008), condition)]),
            ins(
                0x1004,
                vec![copy(uniq(0, 8), con(5, 8)), copy(r(1), con(5, 8))],
            ),
            ins(
                0x1008,
                vec![copy(r(0), uniq(0, 8)), copy(r(2), r(1)), ret()],
            ),
        ]
    };
    for placement in placements() {
        let options = placed(program_mode(), placement);
        let analysis = build(program(flag(0)), Endianness::Little, options);
        let facts = propagate(&analysis);
        // The program-scoped unique is undefined on the branch path.
        assert!(out(&facts, 0x1008, 0).is_unknown());
        assert!(out(&facts, 0x1008, 1).is_unknown());
        for (index, value) in analysis.ssa().values().iter().enumerate() {
            if let ValueOrigin::Entry(_) = value.origin {
                assert!(facts.value(ValueId(index)).unwrap().is_unknown());
            }
        }
        concrete(&facts, Endianness::Little);

        // With the undefined path infeasible, the same reads are constant.
        let analysis = build(program(con(0, 1)), Endianness::Little, options);
        let facts = propagate(&analysis);
        assert_eq!(number(out(&facts, 0x1008, 0)), Some(5));
        assert_eq!(number(out(&facts, 0x1008, 1)), Some(5));
        assert!(concrete(&facts, Endianness::Little) > 10);

        // Registers declared undefined are unknown too.
        let mut undefined = options;
        undefined.entry.registers = EntryState::Undefined;
        let analysis = build(program(flag(0)), Endianness::Little, undefined);
        let facts = propagate(&analysis);
        assert!(out(&facts, 0x1008, 1).is_unknown());
    }
}

#[test]
fn entry_self_loops_meet_the_virtual_entry_operand() {
    let program = |condition: Varnode, source: Varnode| {
        vec![
            ins(
                0x1000,
                vec![
                    copy(r(1), source),
                    copy(source, con(5, 8)),
                    cbranch(rel(-2), condition),
                ],
            ),
            ins(0x1004, vec![ret()]),
        ]
    };
    for (options, source) in [
        (native(), r(0)),
        (program_mode(), r(0)),
        (program_mode(), uniq(0, 8)),
    ] {
        for placement in placements() {
            let options = placed(options, placement);
            let analysis = build(program(flag(0), source), Endianness::Little, options);
            let facts = propagate(&analysis);
            let entry = analysis.ssa().entry();
            let block = analysis.ssa().block(entry).unwrap().renamed().unwrap();
            assert_eq!(block.incoming()[0], Predecessor::Entry);
            assert!(block.incoming().contains(&Predecessor::Node(entry)));
            assert!(facts.is_edge_executable(entry, entry).unwrap());
            assert!(!block.phis().is_empty());
            assert!(phi_facts(&facts, entry).iter().all(|f| f.is_unknown()));
            // The backedge operand is 5, but the entry operand is not.
            assert!(out(&facts, 0x1000, 0).is_unknown());
            assert_eq!(number(out(&facts, 0x1000, 1)), Some(5));
            concrete(&facts, Endianness::Little);

            let analysis = build(program(con(0, 1), source), Endianness::Little, options);
            let facts = propagate(&analysis);
            assert!(!facts.is_edge_executable(entry, entry).unwrap());
            assert!(out(&facts, 0x1000, 0).is_unknown());
        }
    }
}

#[test]
fn optimistic_loops_keep_invariant_constants_and_dead_updates() {
    let instructions = vec![
        ins(0x1000, vec![copy(r(0), con(1, 8))]),
        ins(
            0x1004,
            vec![
                binary(Opcode::IntNotequal, flag(1), r(0), con(1, 8)),
                cbranch(label(0x1010), flag(1)),
            ],
        ),
        ins(
            0x1008,
            vec![copy(r(2), r(0)), cbranch(label(0x1004), flag(0))],
        ),
        ins(0x100c, vec![ret()]),
        ins(0x1010, vec![copy(r(0), con(2, 8)), branch(0x1004)]),
    ];
    for options in [native(), program_mode()] {
        for placement in placements() {
            let analysis = build(
                instructions.clone(),
                Endianness::Little,
                placed(options, placement),
            );
            let facts = propagate(&analysis);
            let header = block(&analysis, 0x1004);
            let update = block(&analysis, 0x1010);
            assert!(!facts.is_node_executable(update).unwrap());
            assert!(!facts.is_edge_executable(update, header).unwrap());
            assert!(
                facts
                    .is_edge_executable(block(&analysis, 0x1008), header)
                    .unwrap()
            );
            assert!(
                !facts
                    .is_cfg_edge_feasible(cfg_edge(&analysis, 0x1004, EdgeRole::ConditionTrue))
                    .unwrap()
            );
            assert!(
                phi_facts(&facts, header)
                    .iter()
                    .any(|fact| number(*fact) == Some(1))
            );
            assert_eq!(number(out(&facts, 0x1004, 0)), Some(0));
            assert_eq!(number(out(&facts, 0x1008, 0)), Some(1));
            assert!(out(&facts, 0x1010, 0).is_unreached());
            assert!(concrete(&facts, Endianness::Little) > 20);
        }
    }
}

#[test]
fn backedges_delay_feasibility_until_the_loop_value_rises() {
    let program = |step: u64, latch: Vec<PcodeOperation>| {
        let mut tail = vec![binary(Opcode::IntAdd, r(0), r(0), con(step, 8))];
        tail.extend(latch);
        vec![
            ins(0x1000, vec![copy(r(0), con(0, 8))]),
            ins(
                0x1004,
                vec![
                    binary(Opcode::IntEqual, flag(1), r(0), con(0, 8)),
                    cbranch(label(0x100c), flag(1)),
                ],
            ),
            ins(0x1008, vec![copy(r(1), con(2, 8)), branch(0x1010)]),
            ins(0x100c, vec![copy(r(1), con(1, 8))]),
            ins(0x1010, tail),
            ins(0x1014, vec![copy(r(3), r(1)), ret()]),
        ]
    };
    for options in [native(), program_mode()] {
        for placement in placements() {
            let options = placed(options, placement);
            // The else side is infeasible until the backedge makes r0 unknown.
            let analysis = build(
                program(
                    1,
                    vec![
                        binary(Opcode::IntLess, flag(0), r(0), con(3, 8)),
                        cbranch(label(0x1004), flag(0)),
                    ],
                ),
                Endianness::Little,
                options,
            );
            let facts = propagate(&analysis);
            assert!(facts.is_node_executable(block(&analysis, 0x1008)).unwrap());
            assert!(
                phi_facts(&facts, block(&analysis, 0x1004))
                    .iter()
                    .all(|f| f.is_unknown())
            );
            assert!(out(&facts, 0x1014, 0).is_unknown());
            assert!(concrete(&facts, Endianness::Little) > 60);

            // A zero step keeps r0 = 0, so the else side stays dead forever.
            let analysis = build(
                program(0, vec![cbranch(label(0x1004), flag(2))]),
                Endianness::Little,
                options,
            );
            let facts = propagate(&analysis);
            assert!(!facts.is_node_executable(block(&analysis, 0x1008)).unwrap());
            assert_eq!(number(out(&facts, 0x1010, 0)), Some(0));
            assert_eq!(number(out(&facts, 0x1014, 0)), Some(1));
            concrete(&facts, Endianness::Little);
        }
    }
}

#[test]
fn irreducible_cycles_converge_from_both_entries() {
    let instructions = vec![
        ins(
            0x1000,
            vec![copy(r(0), con(7, 8)), cbranch(label(0x100c), flag(0))],
        ),
        ins(
            0x1004,
            vec![
                copy(r(1), r(0)),
                binary(Opcode::IntAdd, r(2), r(2), con(1, 8)),
                binary(Opcode::IntLess, flag(1), r(2), con(5, 8)),
                cbranch(label(0x100c), flag(1)),
            ],
        ),
        ins(0x1008, vec![branch(0x1014)]),
        ins(
            0x100c,
            vec![copy(r(3), r(0)), cbranch(label(0x1004), flag(0))],
        ),
        ins(0x1010, vec![branch(0x1014)]),
        ins(0x1014, vec![copy(r(4), r(1)), copy(r(5), r(0)), ret()]),
    ];
    for options in [native(), program_mode()] {
        for placement in placements() {
            let analysis = build(
                instructions.clone(),
                Endianness::Little,
                placed(options, placement),
            );
            let facts = propagate(&analysis);
            let entry = analysis.ssa().entry();
            let (a, b) = (block(&analysis, 0x1004), block(&analysis, 0x100c));
            // Two entries into one cycle: neither block dominates the other.
            assert!(facts.is_edge_executable(entry, a).unwrap());
            assert!(facts.is_edge_executable(entry, b).unwrap());
            assert!(facts.is_edge_executable(a, b).unwrap());
            assert!(facts.is_edge_executable(b, a).unwrap());
            assert_eq!(number(out(&facts, 0x1004, 0)), Some(7));
            assert_eq!(number(out(&facts, 0x100c, 0)), Some(7));
            assert!(out(&facts, 0x1004, 1).is_unknown());
            // r1 is undefined-by-input on the entry -> B -> exit path.
            assert!(out(&facts, 0x1014, 0).is_unknown());
            assert_eq!(number(out(&facts, 0x1014, 1)), Some(7));
            assert!(concrete(&facts, Endianness::Little) > 30);
        }
    }
}

#[test]
fn native_resets_are_unknown_while_relative_branches_keep_temporaries() {
    fn reset_defs(facts: &PcodeConstants, node: usize) -> Vec<ConstantFact<'_>> {
        let block = facts
            .analysis()
            .ssa()
            .block(node)
            .unwrap()
            .renamed()
            .unwrap();
        assert!(matches!(
            facts.analysis().statement(StatementId { node, index: 0 }),
            Some(AdaptedStatement::UndefinedTemporaries { .. })
        ));
        block.statements()[0]
            .defs()
            .iter()
            .map(|value| facts.value(*value).unwrap())
            .collect()
    }
    for placement in placements() {
        let options = placed(native(), placement);
        // A relative backedge to op 1 keeps the frame: the phi meets 5 and 5.
        let analysis = build(
            vec![
                ins(
                    0x1000,
                    vec![
                        copy(uniq(0, 8), con(5, 8)),
                        copy(r(1), uniq(0, 8)),
                        copy(uniq(0, 8), con(5, 8)),
                        cbranch(rel(-2), flag(0)),
                    ],
                ),
                ins(0x1004, vec![ret()]),
            ],
            Endianness::Little,
            options,
        );
        let facts = propagate(&analysis);
        assert_eq!(number(out(&facts, 0x1000, 1)), Some(5));
        let loop_block = analysis
            .cfg()
            .block_of(ProgramPoint::new(0x1000, 1))
            .unwrap();
        assert!(facts.is_edge_executable(loop_block, loop_block).unwrap());
        assert!(concrete(&facts, Endianness::Little) > 20);

        // A native self-jump re-enters through a reset node.
        let program = |condition: Varnode| {
            vec![
                ins(
                    0x1000,
                    vec![
                        copy(r(1), uniq(0, 8)),
                        copy(uniq(0, 8), con(5, 8)),
                        cbranch(label(0x1000), condition),
                    ],
                ),
                ins(0x1004, vec![ret()]),
            ]
        };
        let analysis = build(program(flag(0)), Endianness::Little, options);
        let facts = propagate(&analysis);
        let edge = cfg_edge(&analysis, 0x1000, EdgeRole::ConditionTrue);
        let reset = analysis.edge_reset(edge).unwrap();
        assert!(facts.is_node_executable(reset).unwrap());
        assert!(reset_defs(&facts, reset).iter().all(|f| f.is_unknown()));
        assert!(out(&facts, 0x1000, 0).is_unknown());
        concrete(&facts, Endianness::Little);

        // With a false condition the reset never executes.
        let analysis = build(program(con(0, 1)), Endianness::Little, options);
        let facts = propagate(&analysis);
        let edge = cfg_edge(&analysis, 0x1000, EdgeRole::ConditionTrue);
        let reset = analysis.edge_reset(edge).unwrap();
        assert!(!facts.is_cfg_edge_feasible(edge).unwrap());
        assert!(!facts.is_node_executable(reset).unwrap());
        assert!(reset_defs(&facts, reset).iter().all(|f| f.is_unreached()));

        // A relative branch to op 0 has no reset: its operand is the
        // constant definition, while the entry operand is undefined.
        let analysis = build(
            vec![
                ins(
                    0x1000,
                    vec![
                        copy(r(1), uniq(0, 8)),
                        copy(uniq(0, 8), con(5, 8)),
                        cbranch(rel(-2), flag(0)),
                    ],
                ),
                ins(0x1004, vec![ret()]),
            ],
            Endianness::Little,
            options,
        );
        let facts = propagate(&analysis);
        assert_eq!(
            analysis.ssa().graph().node_count(),
            analysis.cfg().node_count()
        );
        let entry = analysis.ssa().entry();
        let block = analysis.ssa().block(entry).unwrap().renamed().unwrap();
        let back = block.incoming_index(Predecessor::Node(entry)).unwrap();
        let mut saw = false;
        for phi in block.phis() {
            if number(facts.value(phi.operands()[back]).unwrap()) == Some(5) {
                saw = true;
                assert!(facts.value(phi.operands()[0]).unwrap().is_unknown());
                assert!(facts.value(phi.value()).unwrap().is_unknown());
            }
        }
        assert!(saw);

        // A reset statement inside a merged block executes as unknown.
        let merged = vec![
            ins(0x1000, vec![copy(uniq(0, 8), con(5, 8))]),
            ins(0x1004, vec![copy(r(1), uniq(0, 8)), ret()]),
        ];
        let analysis = build(merged.clone(), Endianness::Little, options);
        let facts = propagate(&analysis);
        let read = sid(&analysis, 0x1004, 0);
        let reset = StatementId {
            node: read.node,
            index: read.index - 1,
        };
        assert!(matches!(
            analysis.statement(reset),
            Some(AdaptedStatement::UndefinedTemporaries {
                address: 0x1004,
                ..
            })
        ));
        for value in analysis.ssa().statement(reset).unwrap().defs() {
            assert!(facts.value(*value).unwrap().is_unknown());
        }
        assert!(out(&facts, 0x1004, 0).is_unknown());
        concrete(&facts, Endianness::Little);
        // Program scope keeps the persistent unique.
        let analysis = build(
            merged,
            Endianness::Little,
            placed(program_mode(), placement),
        );
        let facts = propagate(&analysis);
        assert_eq!(number(out(&facts, 0x1004, 0)), Some(5));
        concrete(&facts, Endianness::Little);
    }
}

#[test]
fn duplicate_semantic_outcomes_and_reset_edges_follow_the_taken_role() {
    for placement in placements() {
        let options = placed(native(), placement);
        // CBRANCH +1: both outcomes reach the same point and graph edge.
        for (condition, taken) in [
            (con(1, 1), Some(true)),
            (con(0, 1), Some(false)),
            (flag(0), None),
        ] {
            let analysis = build(
                vec![ins(
                    0x1000,
                    vec![cbranch(rel(1), condition), copy(r(0), con(3, 8)), ret()],
                )],
                Endianness::Little,
                options,
            );
            let facts = propagate(&analysis);
            let cfg = analysis.cfg();
            let entry = cfg.entry();
            let edges: Vec<_> = cfg
                .edges()
                .iter()
                .enumerate()
                .filter(|(_, e)| e.from == entry)
                .collect();
            assert_eq!(edges.len(), 2);
            assert_eq!(edges[0].1.to, edges[1].1.to);
            for (id, edge) in &edges {
                let expected = match (edge.role, taken) {
                    (_, None) => true,
                    (EdgeRole::ConditionTrue, Some(t)) => t,
                    (EdgeRole::ConditionFalse, Some(t)) => !t,
                    _ => unreachable!(),
                };
                assert_eq!(facts.is_cfg_edge_feasible(*id).unwrap(), expected);
            }
            assert!(facts.is_edge_executable(entry, edges[0].1.to).unwrap());
            assert_eq!(number(out(&facts, 0x1000, 1)), Some(3));
        }

        // Both outcomes enter the next instruction natively: two reset nodes.
        for (condition, taken) in [
            (con(1, 1), Some(true)),
            (con(0, 1), Some(false)),
            (flag(0), None),
        ] {
            let analysis = build(
                vec![
                    ins(
                        0x1000,
                        vec![copy(r(0), con(1, 8)), cbranch(label(0x1004), condition)],
                    ),
                    ins(
                        0x1004,
                        vec![copy(uniq(0, 8), r(0)), copy(r(1), uniq(0, 8)), ret()],
                    ),
                ],
                Endianness::Little,
                options,
            );
            let facts = propagate(&analysis);
            let on_true = analysis
                .edge_reset(cfg_edge(&analysis, 0x1000, EdgeRole::ConditionTrue))
                .unwrap();
            let on_false = analysis
                .edge_reset(cfg_edge(&analysis, 0x1000, EdgeRole::ConditionFalse))
                .unwrap();
            assert_ne!(on_true, on_false);
            assert_eq!(
                facts.is_node_executable(on_true).unwrap(),
                taken != Some(false)
            );
            assert_eq!(
                facts.is_node_executable(on_false).unwrap(),
                taken != Some(true)
            );
            assert_eq!(number(out(&facts, 0x1004, 1)), Some(1));
            assert!(concrete(&facts, Endianness::Little) > 10);
        }
    }
}

#[test]
fn aliases_join_and_extract_by_significance_in_both_byte_orders() {
    for endian in [Endianness::Little, Endianness::Big] {
        for options in [native(), program_mode()] {
            let analysis = build(
                vec![ins(
                    0x1000,
                    vec![
                        copy(r(0), con(0x1122_3344_5566_7788, 8)),
                        copy(low(endian, 0, 1), con(0xaa, 1)),
                        copy(r(1), r(0)),
                        copy(low(endian, 2, 4), low(endian, 0, 4)),
                        copy(r(3), r(2)),
                        binary(Opcode::Subpiece, reg(80, 2), r(1), con(1, 4)),
                        binary(Opcode::Piece, r(4), low(endian, 2, 4), low(endian, 0, 4)),
                        ret(),
                    ],
                )],
                endian,
                options,
            );
            let facts = propagate(&analysis);
            assert_eq!(number(out(&facts, 0x1000, 2)), Some(0x1122_3344_5566_77aa));
            assert_eq!(number(out(&facts, 0x1000, 3)), Some(0x5566_77aa));
            // Half of r2 is input state, so the whole value is unknown.
            assert!(out(&facts, 0x1000, 4).is_unknown());
            assert_eq!(number(out(&facts, 0x1000, 5)), Some(0x6677));
            assert_eq!(number(out(&facts, 0x1000, 6)), Some(0x5566_77aa_5566_77aa));
            assert!(concrete(&facts, endian) > 30);
        }
    }
}

#[test]
fn memory_loads_and_opaque_effects_stay_unknown() {
    let analysis = build(
        vec![ins(
            0x1000,
            vec![
                op(
                    Opcode::Store,
                    None,
                    vec![con(1, 4), con(0x100, 8), con(0x42, 8)],
                ),
                op(Opcode::Load, Some(r(0)), vec![con(1, 4), con(0x100, 8)]),
                copy(var(1, 0x200, 8), con(7, 8)),
                copy(r(1), var(1, 0x200, 8)),
                ret(),
            ],
        )],
        Endianness::Little,
        native(),
    );
    let facts = propagate(&analysis);
    assert!(out(&facts, 0x1000, 1).is_unknown());
    assert!(out(&facts, 0x1000, 3).is_unknown());
    for value in 0..analysis.ssa().values().len() {
        if storage(&analysis, ValueId(value)).is_none() {
            assert!(facts.value(ValueId(value)).unwrap().constant().is_none());
        }
    }
    let store = facts
        .expressions()
        .operation(sid(&analysis, 0x1000, 0))
        .unwrap();
    let pointer = store.operands[1].expression().unwrap();
    let stored = store.operands[2].expression().unwrap();
    assert_eq!(number(facts.expression(pointer).unwrap()), Some(0x100));
    assert_eq!(number(facts.expression(stored).unwrap()), Some(0x42));
    concrete(&facts, Endianness::Little);

    // Opaque userops and calls redefine the whole observed domain.
    let analysis = build(
        vec![
            ins(
                0x1000,
                vec![
                    copy(r(0), con(5, 8)),
                    op(Opcode::Callother, None, vec![con(3, 4), r(0)]),
                    copy(r(1), r(0)),
                ],
            ),
            ins(
                0x1004,
                vec![
                    copy(r(2), con(9, 8)),
                    op(Opcode::Call, None, vec![label(0x5000)]),
                ],
            ),
            ins(0x1008, vec![copy(r(3), r(2)), ret()]),
        ],
        Endianness::Little,
        havoc(native()),
    );
    let facts = propagate(&analysis);
    let userop = facts
        .expressions()
        .operation(sid(&analysis, 0x1000, 1))
        .unwrap();
    assert_eq!(
        number(
            facts
                .expression(userop.operands[1].expression().unwrap())
                .unwrap()
        ),
        Some(5)
    );
    for value in defs(&analysis, 0x1000, 1) {
        assert!(facts.value(value).unwrap().is_unknown());
    }
    assert!(out(&facts, 0x1000, 2).is_unknown());
    let call = analysis.cfg().calls()[0];
    assert!(
        facts
            .is_cfg_edge_feasible(cfg_edge(&analysis, 0x1004, EdgeRole::CallReturn))
            .unwrap()
    );
    assert!(
        facts
            .is_cfg_edge_feasible(cfg_edge(&analysis, 0x1004, EdgeRole::CallNoReturn))
            .unwrap()
    );
    assert!(facts.is_node_executable(call.no_return).unwrap());
    assert!(facts.is_node_executable(call.continuation).unwrap());
    // The call's havoc makes r2 unknown even though it was 9 before.
    assert!(out(&facts, 0x1008, 0).is_unknown());
}

#[test]
fn indirect_targets_are_facts_but_never_new_edges() {
    for options in [native(), havoc(native())] {
        let analysis = build(
            vec![
                ins(
                    0x1000,
                    vec![
                        copy(r(0), con(0x1008, 8)),
                        op(Opcode::Branchind, None, vec![r(0)]),
                    ],
                ),
                ins(0x1004, vec![ret()]),
                ins(0x1008, vec![copy(r(1), con(1, 8)), ret()]),
            ],
            Endianness::Little,
            options,
        );
        let facts = propagate(&analysis);
        let operation = facts
            .expressions()
            .operation(sid(&analysis, 0x1000, 1))
            .unwrap();
        let target = operation.operands[0].expression().unwrap();
        assert_eq!(number(facts.expression(target).unwrap()), Some(0x1008));
        let indirect = cfg_edge(&analysis, 0x1000, EdgeRole::IndirectBranch);
        assert!(facts.is_cfg_edge_feasible(indirect).unwrap());
        assert!(
            facts
                .is_node_executable(analysis.cfg().edges()[indirect].to)
                .unwrap()
        );
        assert!(!facts.is_node_executable(block(&analysis, 0x1008)).unwrap());
        // The target is not even CFG-reachable: its raw statement never runs.
        assert!(
            !analysis
                .ssa()
                .is_reachable(block(&analysis, 0x1008))
                .unwrap()
        );
        assert!(
            !facts
                .is_statement_executable(sid(&analysis, 0x1008, 0))
                .unwrap()
        );
    }
    let analysis = build(
        vec![
            ins(
                0x1000,
                vec![
                    copy(r(0), con(0x1008, 8)),
                    op(Opcode::Callind, None, vec![r(0)]),
                ],
            ),
            ins(0x1004, vec![ret()]),
            ins(0x1008, vec![copy(r(1), con(1, 8)), ret()]),
        ],
        Endianness::Little,
        havoc(native()),
    );
    let facts = propagate(&analysis);
    assert!(facts.is_node_executable(block(&analysis, 0x1004)).unwrap());
    assert!(!facts.is_node_executable(block(&analysis, 0x1008)).unwrap());
}

#[test]
fn metadata_wide_values_and_faulting_operations_are_exact_or_unknown() {
    let big = |offset: u64| reg(0x1000 + offset, 512);
    let analysis = build(
        vec![ins(
            0x1000,
            vec![
                binary(
                    Opcode::Subpiece,
                    reg(0x100, 2),
                    con(0x1122_3344_5566_7788, 8),
                    con(2, 4),
                ),
                binary(Opcode::IntDiv, r(1), con(10, 8), con(0, 8)),
                binary(Opcode::FloatAdd, reg(0x110, 3), con(1, 3), con(2, 3)),
                binary(Opcode::IntSub, big(0), con(0, 512), con(1, 512)),
                binary(Opcode::IntAdd, big(0x200), big(0), con(2, 512)),
                binary(Opcode::IntMult, big(0x400), big(0), big(0)),
                op(Opcode::IntZext, Some(big(0x600)), vec![reg(0x100, 2)]),
                copy(reg(0x1000, 1), con(0x7f, 1)),
                copy(big(0x800), big(0)),
                binary(Opcode::IntEqual, flag(0), r(1), r(1)),
                cbranch(rel(2), flag(0)),
                copy(r(2), con(3, 8)),
                ret(),
            ],
        )],
        Endianness::Little,
        native(),
    );
    let facts = propagate(&analysis);
    let wide = |bytes: Vec<u8>| Value::from_le_bytes(&bytes).unwrap();
    let mut one = vec![0; 512];
    one[0] = 1;
    let mut zext = vec![0; 512];
    zext[..2].copy_from_slice(&[0x66, 0x55]);
    let mut joined = vec![0xff; 512];
    joined[0] = 0x7f;
    assert_eq!(number(out(&facts, 0x1000, 0)), Some(0x5566));
    assert!(out(&facts, 0x1000, 1).is_unknown());
    assert!(out(&facts, 0x1000, 2).is_unknown());
    assert_eq!(
        out(&facts, 0x1000, 3).constant(),
        Some(&wide(vec![0xff; 512]))
    );
    assert_eq!(out(&facts, 0x1000, 4).constant(), Some(&wide(one.clone())));
    assert_eq!(out(&facts, 0x1000, 5).constant(), Some(&wide(one)));
    assert_eq!(out(&facts, 0x1000, 6).constant(), Some(&wide(zext)));
    assert_eq!(out(&facts, 0x1000, 8).constant(), Some(&wide(joined)));
    assert!(out(&facts, 0x1000, 9).is_unknown());
    // A fault does not cut control: both outcomes after it are feasible.
    assert_eq!(number(out(&facts, 0x1000, 11)), Some(3));
    let faults = facts.faults();
    assert_eq!(faults.len(), 2);
    assert!(matches!(
        faults[0].error,
        ghidra_pcode::Error::DivisionByZero
    ));
    assert_eq!(faults[0].opcode, Opcode::IntDiv);
    assert_eq!(faults[0].statement, sid(&analysis, 0x1000, 1));
    assert_eq!(faults[1].opcode, Opcode::FloatAdd);
    for fault in faults {
        // The original operation term is kept, not replaced.
        assert!(matches!(
            facts.expressions().node(fault.expression).unwrap().kind,
            ExpressionKind::Pure { opcode, .. } if opcode == fault.opcode
        ));
        assert!(facts.expression(fault.expression).unwrap().is_unknown());
    }
    for value in defs(&analysis, 0x1000, 1) {
        assert!(facts.value(value).unwrap().is_unknown());
    }
    assert!(facts.stats().constant_bytes >= 5 * 512);
}

#[test]
fn executed_joins_refold_on_late_values_and_late_edges() {
    for options in [native(), program_mode()] {
        for placement in placements() {
            let options = placed(options, placement);
            // The join executes with both sides equal to 0. Only afterwards
            // does the loop raise r0, and with it the left side's operand: the
            // join's phi must refold on that value change alone.
            let analysis = build(
                vec![
                    ins(0x1000, vec![copy(r(0), con(0, 8))]),
                    ins(0x1004, vec![cbranch(label(0x100c), flag(0))]),
                    ins(0x1008, vec![copy(r(1), r(0)), branch(0x1010)]),
                    ins(0x100c, vec![copy(r(1), con(0, 8))]),
                    ins(
                        0x1010,
                        vec![
                            copy(r(2), r(1)),
                            binary(Opcode::IntAdd, r(0), r(0), con(1, 8)),
                            cbranch(label(0x1004), flag(1)),
                        ],
                    ),
                    ins(0x1014, vec![ret()]),
                ],
                Endianness::Little,
                options,
            );
            let facts = propagate(&analysis);
            assert!(out(&facts, 0x1008, 0).is_unknown());
            assert_eq!(number(out(&facts, 0x100c, 0)), Some(0));
            assert!(out(&facts, 0x1010, 0).is_unknown());
            assert!(concrete(&facts, Endianness::Little) > 40);

            // The edge P -> J becomes feasible only after the loop makes P's
            // condition unknown. Its operand r1 = 7 was settled long before
            // and never changes again: the new edge itself must fold it.
            let analysis = build(
                vec![
                    ins(0x1000, vec![copy(r(0), con(0, 8))]),
                    ins(
                        0x1004,
                        vec![
                            copy(r(1), con(7, 8)),
                            binary(Opcode::IntEqual, flag(1), r(0), con(0, 8)),
                            cbranch(label(0x1010), flag(1)),
                        ],
                    ),
                    ins(
                        0x1008,
                        vec![copy(r(2), r(1)), cbranch(label(0x1004), flag(0))],
                    ),
                    ins(0x100c, vec![ret()]),
                    ins(
                        0x1010,
                        vec![
                            copy(r(1), con(9, 8)),
                            binary(Opcode::IntAdd, r(0), r(0), con(1, 8)),
                            branch(0x1008),
                        ],
                    ),
                ],
                Endianness::Little,
                options,
            );
            let facts = propagate(&analysis);
            let late = cfg_edge(&analysis, 0x1004, EdgeRole::ConditionFalse);
            assert!(facts.is_cfg_edge_feasible(late).unwrap());
            assert_eq!(number(out(&facts, 0x1004, 0)), Some(7));
            assert_eq!(number(out(&facts, 0x1010, 0)), Some(9));
            assert!(out(&facts, 0x1008, 0).is_unknown());
            assert!(concrete(&facts, Endianness::Little) > 40);
        }
    }
}

#[test]
fn repeated_uses_and_repeated_phi_operands_rise_together() {
    // One statement reads the loop value twice. No algebraic identity is
    // applied, so `r0 ^ r0` and `r0 == r0` become unknown with r0.
    let program = |step: u64| {
        vec![
            ins(0x1000, vec![copy(r(0), con(1, 8))]),
            ins(
                0x1004,
                vec![
                    binary(Opcode::IntXor, r(1), r(0), r(0)),
                    binary(Opcode::IntMult, r(2), r(0), r(0)),
                    binary(Opcode::IntEqual, flag(1), r(0), r(0)),
                    cbranch(label(0x100c), flag(1)),
                ],
            ),
            ins(0x1008, vec![copy(r(3), con(9, 8))]),
            ins(
                0x100c,
                vec![
                    binary(Opcode::IntAdd, r(0), r(0), con(step, 8)),
                    cbranch(label(0x1004), flag(0)),
                ],
            ),
            ins(0x1010, vec![ret()]),
        ]
    };
    for options in [native(), program_mode()] {
        for placement in placements() {
            let options = placed(options, placement);
            let analysis = build(program(1), Endianness::Little, options);
            let xor = sid(&analysis, 0x1004, 0);
            assert_eq!(analysis.ssa().statement(xor).unwrap().uses().len(), 2);
            let facts = propagate(&analysis);
            for index in 0..3 {
                assert!(out(&facts, 0x1004, index).is_unknown(), "op {index}");
            }
            // The unknown condition keeps both outcomes, including the one
            // the concrete machine never takes.
            assert!(facts.is_node_executable(block(&analysis, 0x1008)).unwrap());
            assert!(concrete(&facts, Endianness::Little) > 20);

            // A zero step keeps r0 = 1 on every path.
            let analysis = build(program(0), Endianness::Little, options);
            let facts = propagate(&analysis);
            assert_eq!(number(out(&facts, 0x1004, 0)), Some(0));
            assert_eq!(number(out(&facts, 0x1004, 1)), Some(1));
            assert_eq!(number(out(&facts, 0x1004, 2)), Some(1));
            assert!(!facts.is_node_executable(block(&analysis, 0x1008)).unwrap());
            assert!(out(&facts, 0x1008, 0).is_unreached());
            assert!(concrete(&facts, Endianness::Little) > 20);
        }
    }

    // A join whose phi reads the same value on two incoming edges.
    let program = |middle: Varnode, other: u64| {
        vec![
            ins(
                0x1000,
                vec![copy(r(0), con(5, 8)), cbranch(label(0x100c), flag(0))],
            ),
            ins(0x1004, vec![cbranch(label(0x1010), middle)]),
            ins(0x1008, vec![copy(r(0), con(other, 8))]),
            ins(0x100c, vec![copy(r(1), r(0)), ret()]),
            ins(0x1010, vec![branch(0x100c)]),
        ]
    };
    for placement in placements() {
        let options = placed(native(), placement);
        for (middle, other, expected) in [
            (flag(1), 5, Some(5)),
            (flag(1), 6, None),
            (con(1, 1), 6, Some(5)),
        ] {
            let analysis = build(program(middle, other), Endianness::Little, options);
            let facts = propagate(&analysis);
            let join = block(&analysis, 0x100c);
            let renamed = analysis.ssa().block(join).unwrap().renamed().unwrap();
            assert_eq!(renamed.incoming().len(), 3);
            let phi = renamed
                .phis()
                .iter()
                .find(|phi| phi.operands().len() == 3 && phi.operands()[0] == phi.operands()[2])
                .expect("r0 phi repeats the entry block's value");
            assert_eq!(number(facts.value(phi.value()).unwrap()), expected);
            assert_eq!(number(out(&facts, 0x100c, 0)), expected);
            if expected.is_none() {
                assert!(facts.value(phi.value()).unwrap().is_unknown());
            }
            concrete(&facts, Endianness::Little);
        }
    }
}

#[test]
fn calls_keep_both_outcomes_and_clobber_branch_inputs() {
    let program = |call: bool| {
        let mut head = vec![copy(flag(0), con(1, 1)), copy(r(2), con(9, 8))];
        if call {
            head.push(op(Opcode::Call, None, vec![label(0x5000)]));
        }
        vec![
            ins(0x1000, head),
            ins(0x1004, vec![cbranch(label(0x100c), flag(0))]),
            ins(0x1008, vec![copy(r(3), con(1, 8)), ret()]),
            ins(0x100c, vec![copy(r(3), con(2, 8)), copy(r(4), r(2)), ret()]),
        ]
    };
    for placement in placements() {
        let options = placed(havoc(native()), placement);
        let analysis = build(program(true), Endianness::Little, options);
        let facts = propagate(&analysis);
        let call = analysis.cfg().calls()[0];
        assert!(facts.is_node_executable(call.continuation).unwrap());
        assert!(facts.is_node_executable(call.no_return).unwrap());
        // The opaque call may change the flag, so both outcomes stay feasible.
        assert!(facts.is_node_executable(block(&analysis, 0x1008)).unwrap());
        assert!(facts.is_node_executable(block(&analysis, 0x100c)).unwrap());
        assert!(out(&facts, 0x100c, 1).is_unknown());
        let policy = facts.policy();
        assert!(!policy.summarizes_calls && !policy.models_opaque_effects);
        assert_eq!(policy.analysis, analysis.options());
        assert_eq!(
            facts.feasible_cfg_edges().count(),
            facts.stats().feasible_cfg_edges
        );

        // Without the call, the same constant flag prunes the fallthrough.
        let analysis = build(program(false), Endianness::Little, options);
        let facts = propagate(&analysis);
        assert!(!facts.is_node_executable(block(&analysis, 0x1008)).unwrap());
        assert_eq!(number(out(&facts, 0x100c, 1)), Some(9));
        assert!(concrete(&facts, Endianness::Little) > 5);
    }
}

#[test]
fn only_fixpoint_faults_are_reported_and_faults_never_cut_control() {
    let program = |step: u64| {
        vec![
            ins(0x1000, vec![copy(r(0), con(0, 8))]),
            ins(
                0x1004,
                vec![
                    binary(Opcode::IntDiv, r(1), con(10, 8), r(0)),
                    binary(Opcode::IntAdd, r(0), r(0), con(step, 8)),
                    cbranch(label(0x1004), flag(0)),
                ],
            ),
            ins(0x1008, vec![copy(r(2), con(7, 8)), ret()]),
        ]
    };
    for options in [native(), program_mode()] {
        for placement in placements() {
            let options = placed(options, placement);
            // The divisor is 0 only until the backedge raises it: the fault
            // seen on the first visit is not a fact of the fixpoint.
            let analysis = build(program(1), Endianness::Little, options);
            let facts = propagate(&analysis);
            assert!(out(&facts, 0x1004, 0).is_unknown());
            assert!(facts.faults().is_empty());
            assert!(facts.stats().evaluations > 0);
            assert_eq!(number(out(&facts, 0x1008, 0)), Some(7));

            // A divisor that stays 0 faults at the fixpoint, once.
            let analysis = build(program(0), Endianness::Little, options);
            let facts = propagate(&analysis);
            let faults = facts.faults();
            assert_eq!(faults.len(), 1);
            assert_eq!(faults[0].statement, sid(&analysis, 0x1004, 0));
            assert!(matches!(
                faults[0].error,
                ghidra_pcode::Error::DivisionByZero
            ));
            assert!(out(&facts, 0x1004, 0).is_unknown());
            assert!(!facts.policy().faults_cut_control);
            for edge in [
                cfg_edge(&analysis, 0x1004, EdgeRole::ConditionTrue),
                cfg_edge(&analysis, 0x1004, EdgeRole::ConditionFalse),
            ] {
                assert!(facts.is_cfg_edge_feasible(edge).unwrap());
            }
            assert_eq!(number(out(&facts, 0x1004, 1)), Some(0));
            assert_eq!(number(out(&facts, 0x1008, 0)), Some(7));
        }
    }
}

#[test]
fn entry_backedges_meet_the_undefined_entry_operand_and_reset_nodes() {
    let program = |condition: Varnode| {
        vec![
            ins(
                0x1000,
                vec![
                    copy(r(1), uniq(0, 8)),
                    copy(uniq(0, 8), con(5, 8)),
                    copy(r(4), r(2)),
                ],
            ),
            ins(
                0x1004,
                vec![copy(r(2), con(4, 8)), cbranch(label(0x1000), condition)],
            ),
            ins(0x1008, vec![copy(r(5), r(1)), ret()]),
        ]
    };
    for placement in placements() {
        // Native: the backedge re-enters 0x1000 through a reset node.
        let options = placed(native(), placement);
        let analysis = build(program(flag(0)), Endianness::Little, options);
        let facts = propagate(&analysis);
        let entry = analysis.ssa().entry();
        let back = cfg_edge(&analysis, 0x1004, EdgeRole::ConditionTrue);
        assert_eq!(analysis.cfg().edges()[back].to, entry);
        let reset = analysis.edge_reset(back).expect("native re-entry resets");
        assert!(facts.is_node_executable(reset).unwrap());
        assert!(facts.is_edge_executable(entry, reset).unwrap());
        assert!(facts.is_edge_executable(reset, entry).unwrap());
        let renamed = analysis.ssa().block(entry).unwrap().renamed().unwrap();
        assert_eq!(
            renamed.incoming(),
            &[Predecessor::Entry, Predecessor::Node(reset)]
        );
        assert!(phi_facts(&facts, entry).iter().all(|f| f.is_unknown()));
        assert!(out(&facts, 0x1000, 0).is_unknown());
        assert!(out(&facts, 0x1000, 2).is_unknown());
        assert!(out(&facts, 0x1008, 0).is_unknown());
        concrete(&facts, Endianness::Little);

        let analysis = build(program(con(0, 1)), Endianness::Little, options);
        let facts = propagate(&analysis);
        let back = cfg_edge(&analysis, 0x1004, EdgeRole::ConditionTrue);
        let reset = analysis.edge_reset(back).unwrap();
        assert!(!facts.is_node_executable(reset).unwrap());
        assert!(!facts.is_edge_executable(reset, entry).unwrap());
        assert!(out(&facts, 0x1000, 0).is_unknown());
        assert!(out(&facts, 0x1000, 2).is_unknown());

        // Program scope: no reset, but the entry operand is still undefined
        // while the backedge brings 5, so the read stays unknown.
        let options = placed(program_mode(), placement);
        let analysis = build(program(flag(0)), Endianness::Little, options);
        let facts = propagate(&analysis);
        assert_eq!(
            analysis.ssa().graph().node_count(),
            analysis.cfg().node_count()
        );
        assert!(facts.is_edge_executable(entry, entry).unwrap());
        assert!(out(&facts, 0x1000, 0).is_unknown());
        assert!(out(&facts, 0x1000, 2).is_unknown());
        assert_eq!(number(out(&facts, 0x1000, 1)), Some(5));
        concrete(&facts, Endianness::Little);
    }
}

#[test]
fn metadata_operands_bind_by_role_and_odd_widths_wrap() {
    for endian in [Endianness::Little, Endianness::Big] {
        let analysis = build(
            vec![ins(
                0x1000,
                vec![
                    op(
                        Opcode::Insert,
                        Some(reg(0x200, 4)),
                        vec![con(0xffff_ffff, 4), con(5, 1), con(4, 4), con(4, 4)],
                    ),
                    op(
                        Opcode::Zpull,
                        Some(reg(0x208, 1)),
                        vec![con(0x1234_5678, 4), con(8, 4), con(8, 4)],
                    ),
                    op(
                        Opcode::Spull,
                        Some(reg(0x210, 4)),
                        vec![con(0x8000, 4), con(8, 4), con(8, 4)],
                    ),
                    op(
                        Opcode::Ptradd,
                        Some(reg(0x218, 8)),
                        vec![con(0x1000, 8), con(3, 8), con(8, 8)],
                    ),
                    binary(Opcode::IntAdd, reg(0x220, 3), con(0xff_ffff, 3), con(2, 3)),
                    binary(
                        Opcode::IntAdd,
                        reg(0x228, 5),
                        con(0xff_ffff_fffe, 5),
                        con(3, 5),
                    ),
                    binary(
                        Opcode::IntAdd,
                        reg(0x230, 16),
                        con(u64::MAX, 16),
                        con(1, 16),
                    ),
                    // Read back through a 2-byte alias of the 5-byte result.
                    copy(
                        reg(0x240, 2),
                        reg(
                            if endian == Endianness::Little {
                                0x228
                            } else {
                                0x22b
                            },
                            2,
                        ),
                    ),
                    ret(),
                ],
            )],
            endian,
            native(),
        );
        let facts = propagate(&analysis);
        // Expected values are computed by hand from the P-code reference.
        assert_eq!(number(out(&facts, 0x1000, 0)), Some(0xffff_ff5f));
        assert_eq!(number(out(&facts, 0x1000, 1)), Some(0x56));
        assert_eq!(number(out(&facts, 0x1000, 2)), Some(0xffff_ff80));
        assert_eq!(number(out(&facts, 0x1000, 3)), Some(0x1018));
        assert_eq!(number(out(&facts, 0x1000, 4)), Some(1));
        assert_eq!(out(&facts, 0x1000, 4).constant().unwrap().size(), 3);
        assert_eq!(number(out(&facts, 0x1000, 5)), Some(1));
        assert_eq!(out(&facts, 0x1000, 5).constant().unwrap().size(), 5);
        let mut carry = vec![0; 16];
        carry[8] = 1;
        assert_eq!(
            out(&facts, 0x1000, 6).constant(),
            Some(&Value::from_le_bytes(&carry).unwrap())
        );
        assert_eq!(number(out(&facts, 0x1000, 7)), Some(1));
        // Metadata operands are their own constant terms, in operand order.
        for (index, roles) in [(0, &[2, 3][..]), (1, &[1, 2]), (2, &[1, 2]), (3, &[2])] {
            let operation = facts
                .expressions()
                .operation(sid(&analysis, 0x1000, index))
                .unwrap();
            for (position, operand) in operation.operands.iter().enumerate() {
                let metadata = matches!(operand, ExpressionOperand::ConstantMetadata { .. });
                assert_eq!(
                    metadata,
                    roles.contains(&position),
                    "op {index} input {position}"
                );
                let fact = facts.expression(operand.expression().unwrap()).unwrap();
                assert!(fact.constant().is_some());
            }
        }
        assert!(concrete(&facts, endian) > 20);
    }
}

fn limit_case() -> Arc<PcodeSsa> {
    build(
        vec![
            ins(0x1000, vec![copy(r(0), con(0, 8))]),
            ins(
                0x1004,
                vec![
                    binary(Opcode::IntEqual, flag(1), r(0), con(0, 8)),
                    cbranch(label(0x100c), flag(1)),
                ],
            ),
            ins(
                0x1008,
                vec![
                    copy(r(1), con(2, 8)),
                    binary(Opcode::IntDiv, r(2), con(1, 8), con(0, 8)),
                    branch(0x1010),
                ],
            ),
            ins(0x100c, vec![copy(r(1), con(1, 8)), copy(uniq(0, 8), r(1))]),
            ins(
                0x1010,
                vec![
                    binary(Opcode::IntAdd, r(0), r(0), con(1, 8)),
                    op(Opcode::Store, None, vec![con(1, 4), r(0), r(1)]),
                    binary(Opcode::IntLess, flag(0), r(0), con(3, 8)),
                    cbranch(label(0x1004), flag(0)),
                ],
            ),
            ins(0x1014, vec![copy(r(3), r(1)), ret()]),
        ],
        Endianness::Little,
        native(),
    )
}

#[test]
fn every_limit_is_exact_and_exhaustion_returns_no_result() {
    let analysis = limit_case();
    let program = terms(&analysis);
    let defaults = ConstantLimits::default();
    let base = PcodeConstants::new(program.clone(), defaults).unwrap();
    check_reference(&base);
    let stats = base.stats();
    assert!(stats.faults == 1 && stats.constant_bytes > 0 && stats.queue_peak > 1);
    let run = |limits: ConstantLimits| PcodeConstants::new(program.clone(), limits);
    let exact = |limits: ConstantLimits| assert_eq!(run(limits).unwrap().stats(), stats);
    let below = |limits: ConstantLimits, name: &str| match run(limits) {
        Err(ConstantError::Limit(found)) => assert_eq!(found, name),
        other => panic!("expected {name} limit, got {:?}", other.map(|f| f.stats())),
    };
    exact(ConstantLimits {
        max_work: stats.work,
        ..defaults
    });
    below(
        ConstantLimits {
            max_work: stats.work - 1,
            ..defaults
        },
        "work",
    );
    let ssa = analysis.ssa();
    let statements: usize = ssa
        .blocks()
        .iter()
        .filter_map(|b| b.renamed())
        .map(|b| b.statements().len())
        .sum();
    type Set = fn(&mut ConstantLimits, usize);
    let cases: [(usize, &str, Set); 9] = [
        (stats.constant_bytes, "constant bytes", |l, n| {
            l.max_constant_bytes = n
        }),
        (stats.plan_records, "plan records", |l, n| {
            l.max_plan_records = n
        }),
        (stats.queue_peak, "queue", |l, n| l.max_queue = n),
        (ssa.values().len(), "values", |l, n| l.max_values = n),
        (ssa.graph().node_count(), "graph nodes", |l, n| {
            l.max_graph_nodes = n
        }),
        (ssa.graph().edge_count(), "graph edges", |l, n| {
            l.max_graph_edges = n
        }),
        (analysis.cfg().edges().len(), "CFG edges", |l, n| {
            l.max_cfg_edges = n
        }),
        (statements, "statements", |l, n| l.max_statements = n),
        (program.nodes().len(), "expression nodes", |l, n| {
            l.max_expression_nodes = n
        }),
    ];
    for (count, name, set) in cases {
        let mut limits = defaults;
        set(&mut limits, count);
        exact(limits);
        set(&mut limits, count - 1);
        below(limits, name);
    }
    // The nested def-use index keeps its own exact budget.
    let mut limits = defaults;
    limits.def_use.max_work = stats.def_use_work;
    exact(limits);
    limits.def_use.max_work -= 1;
    assert!(matches!(
        run(limits),
        Err(ConstantError::DefUse(DefUseError::LimitExceeded {
            resource: DefUseResource::Work
        }))
    ));
    let mut limits = defaults;
    limits.def_use.max_values = ssa.values().len() - 1;
    assert!(matches!(
        run(limits),
        Err(ConstantError::DefUse(DefUseError::LimitExceeded {
            resource: DefUseResource::Values
        }))
    ));
    let uses = DefUseIndex::new(ssa, defaults.def_use)
        .unwrap()
        .total_uses();
    let mut limits = defaults;
    limits.def_use.max_uses = uses;
    exact(limits);
    limits.def_use.max_uses = uses - 1;
    assert!(matches!(
        run(limits),
        Err(ConstantError::DefUse(DefUseError::LimitExceeded {
            resource: DefUseResource::Uses
        }))
    ));
}

/// A long dependence chain. When `looped`, the backedge raises the header
/// phi after the whole chain is constant, so every value rises twice.
fn chain(count: u64, looped: bool) -> Vec<PcodeInstruction> {
    let mut program = vec![ins(0x1000, vec![copy(r(0), con(0, 8))])];
    for i in 1..=count {
        program.push(ins(
            0x1000 + 4 * i,
            vec![
                binary(Opcode::IntAdd, r(0), r(0), con(1, 8)),
                binary(Opcode::IntAdd, r(1), r(0), con(i, 8)),
            ],
        ));
    }
    let end = 0x1000 + 4 * (count + 1);
    program.push(ins(
        end,
        if looped {
            vec![cbranch(label(0x1004), flag(0)), ret()]
        } else {
            vec![ret()]
        },
    ));
    program
}

/// One loop-carried value read by `count` statements.
fn fan_out(count: u64) -> Vec<PcodeInstruction> {
    let mut program = vec![ins(0x1000, vec![copy(r(0), con(0, 8))])];
    for i in 1..=count {
        program.push(ins(
            0x1000 + 4 * i,
            vec![binary(Opcode::IntAdd, r(1), r(0), con(i, 8))],
        ));
    }
    let end = 0x1000 + 4 * (count + 1);
    program.push(ins(
        end,
        vec![
            binary(Opcode::IntAdd, r(0), r(0), con(1, 8)),
            cbranch(label(0x1004), flag(0)),
            ret(),
        ],
    ));
    program
}

fn scaled_work(instructions: Vec<PcodeInstruction>) -> (u64, PcodeConstants) {
    let analysis = build(instructions, Endianness::Little, native());
    let facts = PcodeConstants::new(terms(&analysis), Default::default()).unwrap();
    // The dense reference is quadratic here; the structural bounds are not.
    let executable: Vec<bool> = (0..analysis.ssa().graph().node_count())
        .map(|node| facts.is_node_executable(node).unwrap())
        .collect();
    check_sparse_bounds(&facts, &executable);
    (facts.stats().work, facts)
}

#[test]
fn large_sparse_chains_and_loops_scale_linearly() {
    let (small, n) = (4_000u64, 8_000u64);
    let (straight_small, _) = scaled_work(chain(small, false));
    let (straight, facts) = scaled_work(chain(n, false));
    let last = 0x1000 + 4 * n;
    assert_eq!(number(out(&facts, last, 0)), Some(n));
    assert_eq!(number(out(&facts, last, 1)), Some(2 * n));
    let (looped_small, _) = scaled_work(chain(small, true));
    let (looped, facts) = scaled_work(chain(n, true));
    assert!(out(&facts, last, 1).is_unknown());
    assert!(facts.stats().value_changes > 4 * n as usize);
    let (fan_small, _) = scaled_work(fan_out(small));
    let (fan, facts) = scaled_work(fan_out(n));
    assert!(out(&facts, 0x1004, 0).is_unknown());
    for (small_work, large_work) in [
        (straight_small, straight),
        (looped_small, looped),
        (fan_small, fan),
    ] {
        // Doubling the program at most roughly doubles the work; a per-value
        // rescan of statements or uses would quadruple it.
        assert!(
            large_work * 10 <= small_work * 22,
            "{small_work} -> {large_work}"
        );
        assert!(
            large_work <= 300 * n,
            "{large_work} work for {n} instructions"
        );
    }
}

#[test]
fn facts_are_owned_deterministic_and_send_sync() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<PcodeConstants>();
    send_sync::<ConstantError>();
    let analysis = limit_case();
    let program = terms(&analysis);
    let first = PcodeConstants::new(program.clone(), Default::default()).unwrap();
    let second = PcodeConstants::new(program.clone(), Default::default()).unwrap();
    assert_eq!(first.stats(), second.stats());
    for value in 0..analysis.ssa().values().len() {
        assert_eq!(
            first.value(ValueId(value)).unwrap(),
            second.value(ValueId(value)).unwrap()
        );
    }
    let count = analysis.ssa().values().len();
    drop(program);
    drop(analysis);
    drop(second);
    // The facts own their expression snapshot.
    assert_eq!(first.analysis().ssa().values().len(), count);
    assert!(matches!(
        first.value(ValueId(count)),
        Err(ConstantError::UnknownValue(_))
    ));
    assert!(first.is_node_executable(usize::MAX).is_err());
    assert!(first.is_cfg_edge_feasible(usize::MAX).is_err());
    assert!(
        first
            .is_statement_executable(StatementId {
                node: first.analysis().ssa().entry(),
                index: usize::MAX
            })
            .is_err()
    );
}

/// Facts at every supplied operation's definitions, plus CFG flow facts;
/// independent of phi placement.
fn signature(facts: &PcodeConstants) -> (Vec<Vec<R>>, Vec<bool>, Vec<bool>) {
    let analysis = facts.analysis();
    let cfg = analysis.cfg();
    let mut definitions = Vec::new();
    for &point in cfg.points() {
        let id = analysis.statement_id(point).unwrap();
        if let Ok(statement) = analysis.ssa().statement(id) {
            definitions.push(
                statement
                    .defs()
                    .iter()
                    .map(|v| observed(facts.value(*v).unwrap()))
                    .collect(),
            );
        }
    }
    (
        definitions,
        (0..cfg.node_count())
            .map(|n| facts.is_node_executable(n).unwrap())
            .collect(),
        (0..cfg.edges().len())
            .map(|e| facts.is_cfg_edge_feasible(e).unwrap())
            .collect(),
    )
}

#[test]
fn generated_programs_match_the_reference_and_concrete_machine() {
    let mut rng = Rng(0x2545_f491_4f6c_dd1d);
    let (mut checks, mut constants, mut dead, mut faults, mut conditional) = (0, 0, 0, 0, 0);
    for _ in 0..48 {
        for endian in [Endianness::Little, Endianness::Big] {
            let instructions = random_program(&mut rng, endian);
            for mode in [native(), program_mode()] {
                let mut signatures = Vec::new();
                for placement in placements() {
                    let analysis = build(instructions.clone(), endian, placed(mode, placement));
                    let facts = propagate(&analysis);
                    for seed in 0..3 {
                        checks += check_concrete(&facts, &state(endian, seed), 40);
                    }
                    let stats = facts.stats();
                    constants += stats.constant_values;
                    faults += stats.faults;
                    dead += (0..analysis.cfg().block_count())
                        .filter(|&n| {
                            analysis.ssa().is_reachable(n).unwrap()
                                && !facts.is_node_executable(n).unwrap()
                        })
                        .count();
                    conditional += analysis
                        .cfg()
                        .edges()
                        .iter()
                        .enumerate()
                        .filter(|(id, e)| {
                            e.role == EdgeRole::ConditionTrue
                                && facts.is_node_executable(e.from).unwrap()
                                && !facts.is_cfg_edge_feasible(*id).unwrap()
                        })
                        .count();
                    signatures.push(signature(&facts));
                }
                assert_eq!(signatures[0], signatures[1], "placement-independent facts");
            }
        }
    }
    assert!(checks > 8_000, "{checks} concrete checks");
    assert!(constants > 1_000, "{constants} constants");
    assert!(dead > 20, "{dead} dead reachable blocks");
    assert!(faults > 5, "{faults} faults");
    assert!(conditional > 10, "{conditional} statically false branches");
}
