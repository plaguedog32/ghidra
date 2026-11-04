//! Sparse conditional constant propagation over typed P-code expressions.
//!
//! This is classic whole-value SCCP: one lattice element per SSA value and per
//! expression term, executable graph nodes, and feasible edges. It reads an
//! immutable `PcodeExpressions` snapshot and returns owned facts. It never
//! rewrites terms, executes target code, or resolves indirect control.

use std::collections::VecDeque;
use std::sync::Arc;

use ghidra_cfg::{EdgeId, EdgeRole};
use ghidra_pcode::{Opcode, Value, evaluate_pure};
use ghidra_ssa::{
    DefUseError, DefUseIndex, DefUseLimits, NodeId, PhiId, Predecessor, StatementId, ValueId,
    ValueOrigin,
};
use thiserror::Error;

use crate::{
    AnalysisOptions, ExpressionAddress, ExpressionDefinition, ExpressionError, ExpressionId,
    ExpressionKind, ExpressionOperation, ExpressionType, PcodeExpressions, PcodeSsa,
};

/// One element of the constant lattice, ordered `Unreached < Constant < Unknown`.
/// Two different constants meet to `Unknown`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConstantFact<'a> {
    /// Bottom. No definition of this value runs on an executable path of the
    /// supplied CFG. It is never used for undefined or unknown state.
    Unreached,
    /// Every executable definition produces exactly this bit vector.
    Constant(&'a Value),
    /// Top (overdefined). Inputs, undefined state, memory, loads, opaque
    /// effects, faulting evaluations and conflicting merges are all here.
    Unknown,
}

impl<'a> ConstantFact<'a> {
    pub fn constant(self) -> Option<&'a Value> {
        match self {
            Self::Constant(value) => Some(value),
            _ => None,
        }
    }
    pub fn is_unreached(self) -> bool {
        self == Self::Unreached
    }
    pub fn is_unknown(self) -> bool {
        self == Self::Unknown
    }
}

/// Every count is checked before the matching allocation or growth. Work is
/// a fresh deterministic budget; the nested def-use index has its own.
#[derive(Clone, Copy, Debug)]
pub struct ConstantLimits {
    /// Augmented SSA graph nodes, including exits and reset nodes.
    pub max_graph_nodes: usize,
    /// Distinct augmented SSA graph edges.
    pub max_graph_edges: usize,
    /// Semantic CFG edges.
    pub max_cfg_edges: usize,
    pub max_values: usize,
    /// Renamed statements in SSA-reachable nodes.
    pub max_statements: usize,
    pub max_expression_nodes: usize,
    /// Statement plan records: terms, child links, parent links, SSA leaf
    /// records and definition-root records, summed over executed statements.
    pub max_plan_records: usize,
    /// Pending entries in the global edge+value worklists, and separately in
    /// each statement-local traversal or propagation stack.
    pub max_queue: usize,
    /// Bytes of evaluated constant results, reserved before each evaluation
    /// (a faulting one keeps its reservation). Literal payloads and COPY/CAST
    /// results are shared, not counted again.
    pub max_constant_bytes: usize,
    pub max_work: u64,
    pub def_use: DefUseLimits,
}

impl Default for ConstantLimits {
    fn default() -> Self {
        Self {
            max_graph_nodes: 1_000_000,
            max_graph_edges: 4_000_000,
            max_cfg_edges: 2_000_000,
            max_values: 2_000_000,
            max_statements: 1_000_000,
            max_expression_nodes: 4_000_000,
            max_plan_records: 32_000_000,
            max_queue: 8_000_000,
            max_constant_bytes: 64 * 1024 * 1024,
            max_work: 200_000_000,
            def_use: DefUseLimits::default(),
        }
    }
}

#[derive(Debug, Error)]
pub enum ConstantError {
    #[error("constant propagation limit exceeded: {0}")]
    Limit(&'static str),
    #[error(transparent)]
    DefUse(#[from] DefUseError),
    #[error(transparent)]
    Expression(#[from] ExpressionError),
    #[error(transparent)]
    Pcode(#[from] ghidra_pcode::Error),
    #[error("unknown SSA value {0:?}")]
    UnknownValue(ValueId),
    #[error("unknown graph node {0}")]
    UnknownNode(NodeId),
    #[error("no SSA graph edge {from} -> {to}")]
    UnknownEdge { from: NodeId, to: NodeId },
    #[error("unknown CFG edge {0}")]
    UnknownCfgEdge(EdgeId),
    #[error("unknown renamed statement {0:?}")]
    UnknownStatement(StatementId),
    #[error("inconsistent constant-propagation input: {0}")]
    Inconsistent(&'static str),
}

type Result<T> = std::result::Result<T, ConstantError>;

/// A pure operation whose inputs are all constant in the final facts but
/// whose evaluation fails: a trap such as division by zero, an unsupported
/// opcode or float format, or operands the evaluator rejects. Its result stays
/// `Unknown`; the term itself is unchanged and control is not cut. Faults seen
/// only in optimistic intermediate states, whose inputs later became
/// `Unknown`, are not reported.
#[derive(Debug)]
pub struct EvaluationFault {
    pub statement: StatementId,
    pub expression: ExpressionId,
    pub opcode: Opcode,
    pub error: ghidra_pcode::Error,
}

/// Totals for one run. `work` excludes the nested def-use build, which is
/// reported separately in `def_use_work`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ConstantStats {
    pub work: u64,
    pub def_use_work: u64,
    pub executable_nodes: usize,
    /// Feasible distinct edges of the augmented SSA graph.
    pub executable_edges: usize,
    pub feasible_cfg_edges: usize,
    pub executed_statements: usize,
    pub plan_records: usize,
    pub queue_peak: usize,
    /// Lattice raises of SSA values (at most two per value).
    pub value_changes: usize,
    pub phi_folds: usize,
    /// Statement-local propagations started by a changed SSA leaf.
    pub notifications: usize,
    /// Calls to `ghidra_pcode::evaluate_pure`.
    pub evaluations: usize,
    pub faults: usize,
    pub constant_bytes: usize,
    pub constant_values: usize,
    pub unknown_values: usize,
    pub unreached_values: usize,
}

/// The fixed conservative choices behind a result, with the snapshot options
/// that decide entry state, temporary lifetime, effects and phi placement.
/// None of the fixed choices is configurable yet; this record lets a consumer
/// report exactly what the facts assume.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct ConstantPolicy {
    /// The analyzed `PcodeSsa` options. Every entry value, `Input` or
    /// `Undefined`, and every native temporary reset is `Unknown`.
    pub analysis: AnalysisOptions,
    /// Always `false`: memory states, LOAD results and fixed-offset memory
    /// reads are `Unknown`, and stores are never forwarded to loads.
    pub models_memory: bool,
    /// Always `false`: opaque call, userop and runtime definitions are `Unknown`.
    pub models_opaque_effects: bool,
    /// Always `true`: a constant block-ending CBRANCH condition enables only
    /// its taken outcome. Every other control outcome stays feasible.
    pub prunes_constant_branches: bool,
    /// Always `false`: constant BRANCHIND/CALLIND targets never add edges.
    pub resolves_indirect_targets: bool,
    /// Always `false`: call return and no-return outcomes both stay feasible.
    pub summarizes_calls: bool,
    /// Always `false`: a failing evaluation is `Unknown` and keeps every CFG
    /// outcome of its block.
    pub faults_cut_control: bool,
}

/// Owned SCCP facts for one expression snapshot. Facts are the least fixpoint
/// of the documented transfer functions, so they do not depend on worklist
/// order. Feasibility is relative to the supplied CFG, which may itself omit
/// unresolved indirect targets; it is not complete machine control flow.
#[derive(Debug)]
pub struct PcodeConstants {
    expressions: Arc<PcodeExpressions>,
    limits: ConstantLimits,
    values: Vec<Slot>,
    nodes: Vec<Slot>,
    pool: Vec<Value>,
    executable: Vec<bool>,
    edge_start: Vec<usize>,
    feasible: Vec<bool>,
    cfg_feasible: Vec<bool>,
    faults: Vec<EvaluationFault>,
    stats: ConstantStats,
}

impl PcodeConstants {
    pub fn new(expressions: Arc<PcodeExpressions>, limits: ConstantLimits) -> Result<Self> {
        let output = Engine::run(&expressions, limits)?;
        Ok(Self {
            expressions,
            limits,
            values: output.values,
            nodes: output.nodes,
            pool: output.pool,
            executable: output.visited,
            edge_start: output.edge_start,
            feasible: output.feasible,
            cfg_feasible: output.cfg_feasible,
            faults: output.faults,
            stats: output.stats,
        })
    }

    pub fn expressions(&self) -> &Arc<PcodeExpressions> {
        &self.expressions
    }
    pub fn analysis(&self) -> &Arc<PcodeSsa> {
        self.expressions.analysis()
    }
    pub fn limits(&self) -> ConstantLimits {
        self.limits
    }
    pub fn stats(&self) -> ConstantStats {
        self.stats
    }
    /// The fixed conservative policies and the snapshot options they assume.
    pub fn policy(&self) -> ConstantPolicy {
        ConstantPolicy {
            analysis: self.analysis().options(),
            models_memory: false,
            models_opaque_effects: false,
            prunes_constant_branches: true,
            resolves_indirect_targets: false,
            summarizes_calls: false,
            faults_cut_control: false,
        }
    }

    pub fn value(&self, value: ValueId) -> Result<ConstantFact<'_>> {
        let slot = *self
            .values
            .get(value.0)
            .ok_or(ConstantError::UnknownValue(value))?;
        self.fact(slot)
    }

    /// The fact of one term. An SSA leaf has its value's fact. Every other
    /// term is `Unreached` unless its statement executed.
    pub fn expression(&self, id: ExpressionId) -> Result<ConstantFact<'_>> {
        match &self.expressions.node(id)?.kind {
            ExpressionKind::SsaValue(value) => self.value(*value),
            _ => self.fact(self.nodes[id.0]),
        }
    }

    /// Every value proven constant, in ascending value order.
    pub fn constants(&self) -> impl Iterator<Item = (ValueId, &Value)> + '_ {
        self.values
            .iter()
            .enumerate()
            .filter(|(_, slot)| slot.level() == Level::Constant)
            .map(|(index, slot)| {
                // Constant slots are validated when they are created.
                let value = constant(&self.expressions, &self.pool, *slot)
                    .expect("constant slot names a constant");
                (ValueId(index), value)
            })
    }

    pub fn is_node_executable(&self, node: NodeId) -> Result<bool> {
        self.executable
            .get(node)
            .copied()
            .ok_or(ConstantError::UnknownNode(node))
    }

    /// A statement executes exactly when its graph node is executable. Raw
    /// statements of SSA-unreachable nodes are valid IDs that never execute.
    pub fn is_statement_executable(&self, statement: StatementId) -> Result<bool> {
        let executable = *self
            .executable
            .get(statement.node)
            .ok_or(ConstantError::UnknownNode(statement.node))?;
        let count = self.analysis().raw().blocks[statement.node].len();
        if statement.index >= count {
            return Err(ConstantError::UnknownStatement(statement));
        }
        Ok(executable)
    }

    /// Feasibility of one distinct edge of the augmented SSA graph. Several
    /// semantic CFG edges can share it; it is feasible if any of them is.
    pub fn is_edge_executable(&self, from: NodeId, to: NodeId) -> Result<bool> {
        let graph = self.analysis().ssa().graph();
        let predecessors = graph
            .predecessors(to)
            .map_err(|_| ConstantError::UnknownNode(to))?;
        let position = predecessors
            .binary_search(&from)
            .map_err(|_| ConstantError::UnknownEdge { from, to })?;
        Ok(self.feasible[self.edge_start[to] + position])
    }

    /// Feasibility of one semantic CFG edge. For an edge split by a reset
    /// node, this is the feasibility of its first hop.
    pub fn is_cfg_edge_feasible(&self, edge: EdgeId) -> Result<bool> {
        self.cfg_feasible
            .get(edge)
            .copied()
            .ok_or(ConstantError::UnknownCfgEdge(edge))
    }

    pub fn executable_nodes(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.executable
            .iter()
            .enumerate()
            .filter_map(|(node, &live)| live.then_some(node))
    }

    /// Feasible semantic CFG edges in ascending `EdgeId` order.
    pub fn feasible_cfg_edges(&self) -> impl Iterator<Item = EdgeId> + '_ {
        self.cfg_feasible
            .iter()
            .enumerate()
            .filter_map(|(edge, &feasible)| feasible.then_some(edge))
    }

    /// Faults in discovery order. Each term faults at most once.
    pub fn faults(&self) -> &[EvaluationFault] {
        &self.faults
    }

    fn fact(&self, slot: Slot) -> Result<ConstantFact<'_>> {
        Ok(match slot {
            Slot::Unreached => ConstantFact::Unreached,
            Slot::Unknown => ConstantFact::Unknown,
            constant_slot => {
                ConstantFact::Constant(constant(&self.expressions, &self.pool, constant_slot)?)
            }
        })
    }
}

const NONE: usize = usize::MAX;
const IN_PROGRESS: usize = usize::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Slot {
    Unreached,
    /// The payload of an expression `Constant` term, shared rather than copied.
    Literal(ExpressionId),
    /// An owned evaluated constant.
    Pool(usize),
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Level {
    Unreached,
    Constant,
    Unknown,
}

impl Slot {
    fn level(self) -> Level {
        match self {
            Self::Unreached => Level::Unreached,
            Self::Literal(_) | Self::Pool(_) => Level::Constant,
            Self::Unknown => Level::Unknown,
        }
    }
}

fn constant<'a>(program: &'a PcodeExpressions, pool: &'a [Value], slot: Slot) -> Result<&'a Value> {
    match slot {
        Slot::Literal(id) => match &program.node(id)?.kind {
            ExpressionKind::Constant(value) => Ok(value),
            _ => Err(ConstantError::Inconsistent("literal slot")),
        },
        Slot::Pool(index) => pool
            .get(index)
            .ok_or(ConstantError::Inconsistent("constant pool")),
        _ => Err(ConstantError::Inconsistent("nonconstant slot")),
    }
}

/// Terms a statement plan must contain: evaluation inputs plus memory
/// addresses and stored values, so every executed operand has a fact.
fn discovery_children(
    kind: &ExpressionKind,
    mut visit: impl FnMut(ExpressionId) -> Result<()>,
) -> Result<()> {
    match kind {
        ExpressionKind::Join(pieces) => {
            for piece in pieces {
                visit(piece.value)?;
            }
        }
        ExpressionKind::Extract { value, .. } => visit(*value)?,
        ExpressionKind::Pure { inputs, .. } => {
            for &input in inputs {
                visit(input)?;
            }
        }
        ExpressionKind::ReadMemory { address, .. } => {
            if let ExpressionAddress::Pointer { value, .. } = address {
                visit(*value)?;
            }
        }
        ExpressionKind::WriteMemory { address, value, .. } => {
            visit(*value)?;
            if let ExpressionAddress::Pointer { value, .. } = address {
                visit(*value)?;
            }
        }
        ExpressionKind::Constant(_) | ExpressionKind::SsaValue(_) => {}
    }
    Ok(())
}

fn words(bytes: u32) -> usize {
    (bytes as usize).div_ceil(8)
}

/// `floor(log2 n) + 2` units for one binary search over `n` records.
fn search_cost(length: usize) -> usize {
    (usize::BITS - length.leading_zeros()) as usize + 1
}

/// Conservative deterministic cost of one `evaluate_pure` call, charged
/// before evaluation: linear in 64-bit operand words (input clones, reads
/// and the wrapped result), plus a quadratic term for multiplication,
/// division and integer-to-float decimal conversion, and a fixed float term.
fn evaluation_cost(opcode: Opcode, inputs: &[u32], output: u32) -> usize {
    use Opcode::*;
    const FLOAT: usize = 256;
    let linear: usize = inputs.iter().map(|&size| words(size)).sum::<usize>() + words(output);
    let width = |index: usize| inputs.get(index).map_or(1, |&size| words(size) + 1);
    4 + 2 * linear
        + match opcode {
            IntMult => width(0) * width(1),
            Ptradd => width(0) + width(1) * width(2),
            IntDiv | IntRem | IntSdiv | IntSrem => 2 * width(0) * width(1),
            FloatInt2Float => FLOAT + 8 * width(0) * width(0),
            FloatEqual | FloatNotequal | FloatLess | FloatLessequal | FloatNan | FloatAdd
            | FloatDiv | FloatMult | FloatSub | FloatNeg | FloatAbs | FloatSqrt
            | FloatFloat2Float | FloatTrunc | FloatCeil | FloatFloor | FloatRound => FLOAT,
            _ => 0,
        }
}

struct Budget {
    used: u64,
    limit: u64,
}

impl Budget {
    fn charge(&mut self, amount: usize) -> Result<()> {
        self.used = u64::try_from(amount)
            .ok()
            .and_then(|amount| self.used.checked_add(amount))
            .filter(|&used| used <= self.limit)
            .ok_or(ConstantError::Limit("work"))?;
        Ok(())
    }
    fn search(&mut self, length: usize) -> Result<()> {
        self.charge(search_cost(length))
    }
    /// `n * (ceil(log2 n) + 1)` for one comparison sort.
    fn sort(&mut self, n: usize) -> Result<()> {
        if n > 1 {
            let levels = (usize::BITS - (n - 1).leading_zeros()) as usize + 1;
            self.charge(n.checked_mul(levels).ok_or(ConstantError::Limit("work"))?)?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    node: ExpressionId,
    slot: Slot,
    children: usize,
    child_count: usize,
    parents: usize,
    parent_count: usize,
    /// Child slots still `Unreached`; meaningful for computations only.
    pending: usize,
    root: bool,
}

#[derive(Clone, Copy, Debug)]
struct Plan {
    statement: StatementId,
    leaves: (usize, usize),
    roots: (usize, usize),
    /// Global entry of a block-ending CBRANCH condition, or `NONE`.
    condition: usize,
}

struct Output {
    values: Vec<Slot>,
    nodes: Vec<Slot>,
    pool: Vec<Value>,
    visited: Vec<bool>,
    edge_start: Vec<usize>,
    feasible: Vec<bool>,
    cfg_feasible: Vec<bool>,
    faults: Vec<EvaluationFault>,
    stats: ConstantStats,
}

struct Engine<'a> {
    program: &'a PcodeExpressions,
    analysis: &'a PcodeSsa,
    def_use: DefUseIndex,
    limits: ConstantLimits,
    budget: Budget,
    stats: ConstantStats,
    values: Vec<Slot>,
    nodes: Vec<Slot>,
    pool: Vec<Value>,
    /// Faults with their plan entries; filtered against final facts.
    faults: Vec<(usize, EvaluationFault)>,
    // Augmented graph: edge IDs are `edge_start[to] + position in predecessors(to)`.
    visited: Vec<bool>,
    edge_start: Vec<usize>,
    edge_target: Vec<NodeId>,
    /// Operand index of each edge in its target's phi/incoming list.
    edge_incoming: Vec<usize>,
    feasible: Vec<bool>,
    incoming_start: Vec<usize>,
    /// Edge per incoming slot of a reachable block; `NONE` is the virtual entry.
    incoming_edges: Vec<usize>,
    // Semantic CFG edges.
    out_start: Vec<usize>,
    cfg_first: Vec<usize>,
    cfg_feasible: Vec<bool>,
    // Statements and statement-local plans.
    statement_start: Vec<usize>,
    plans: Vec<Option<Plan>>,
    entries: Vec<Entry>,
    links: Vec<usize>,
    leaves: Vec<(ValueId, usize)>,
    roots: Vec<(usize, ValueId)>,
    /// Non-leaf term: 0 unclaimed, `IN_PROGRESS`, or owning entry + 1.
    /// SSA leaf: the last statement stamp that collected it.
    tags: Vec<usize>,
    scratch: Vec<ExpressionId>,
    stack: Vec<ExpressionId>,
    local: Vec<usize>,
    cursor: Vec<usize>,
    pending_roots: Vec<(ExpressionId, ValueId)>,
    // Global worklists.
    edge_queue: VecDeque<usize>,
    value_queue: VecDeque<ValueId>,
    queued: Vec<bool>,
}

impl<'a> Engine<'a> {
    fn run(program: &'a PcodeExpressions, limits: ConstantLimits) -> Result<Output> {
        let analysis: &PcodeSsa = program.analysis();
        let ssa = analysis.ssa();
        let graph = ssa.graph();
        let cfg = analysis.cfg();
        let mut budget = Budget {
            used: 0,
            limit: limits.max_work,
        };
        let node_count = graph.node_count();
        let edge_count = graph.edge_count();
        let value_count = ssa.values().len();
        let expression_count = program.nodes().len();
        let cfg_edge_count = cfg.edges().len();
        if node_count > limits.max_graph_nodes {
            return Err(ConstantError::Limit("graph nodes"));
        }
        if edge_count > limits.max_graph_edges {
            return Err(ConstantError::Limit("graph edges"));
        }
        if cfg_edge_count > limits.max_cfg_edges {
            return Err(ConstantError::Limit("CFG edges"));
        }
        if value_count > limits.max_values {
            return Err(ConstantError::Limit("values"));
        }
        if expression_count > limits.max_expression_nodes {
            return Err(ConstantError::Limit("expression nodes"));
        }
        if ssa.blocks().len() != node_count
            || node_count < cfg.node_count()
            || ssa.entry() >= node_count
        {
            return Err(ConstantError::Inconsistent("SSA graph shape"));
        }
        budget.charge(node_count)?;
        let mut statements = 0usize;
        let mut incoming = 0usize;
        for block in ssa.blocks() {
            if let Some(block) = block.renamed() {
                statements = statements
                    .checked_add(block.statements().len())
                    .filter(|&n| n <= limits.max_statements)
                    .ok_or(ConstantError::Limit("statements"))?;
                incoming = incoming
                    .checked_add(block.incoming().len())
                    .filter(|&n| n <= edge_count + 1)
                    .ok_or(ConstantError::Inconsistent("incoming edge count"))?;
            }
        }
        // The nested index has its own limits and work budget.
        let def_use = DefUseIndex::new(ssa, limits.def_use)?;
        if def_use.value_count() != value_count || def_use.node_count() != node_count {
            return Err(ConstantError::Inconsistent("def-use snapshot"));
        }
        let slots = [
            value_count.checked_mul(2),
            node_count.checked_mul(4).and_then(|n| n.checked_add(3)),
            edge_count.checked_mul(3),
            Some(incoming),
            cfg_edge_count
                .checked_mul(2)
                .and_then(|n| n.checked_add(cfg.node_count() + 1)),
            expression_count.checked_mul(2),
            Some(statements),
        ]
        .into_iter()
        .try_fold(0usize, |total, n| n.and_then(|n| total.checked_add(n)))
        .ok_or(ConstantError::Limit("work"))?;
        budget.charge(slots)?;
        let mut engine = Engine {
            program,
            analysis,
            def_use,
            limits,
            budget,
            stats: ConstantStats::default(),
            values: vec![Slot::Unreached; value_count],
            nodes: vec![Slot::Unreached; expression_count],
            pool: Vec::new(),
            faults: Vec::new(),
            visited: vec![false; node_count],
            edge_start: Vec::with_capacity(node_count + 1),
            edge_target: Vec::with_capacity(edge_count),
            edge_incoming: vec![NONE; edge_count],
            feasible: vec![false; edge_count],
            incoming_start: Vec::with_capacity(node_count + 1),
            incoming_edges: Vec::with_capacity(incoming),
            out_start: vec![0; cfg.node_count() + 1],
            cfg_first: Vec::with_capacity(cfg_edge_count),
            cfg_feasible: vec![false; cfg_edge_count],
            statement_start: Vec::with_capacity(node_count + 1),
            plans: vec![None; statements],
            entries: Vec::new(),
            links: Vec::new(),
            leaves: Vec::new(),
            roots: Vec::new(),
            tags: vec![0; expression_count],
            scratch: Vec::new(),
            stack: Vec::new(),
            local: Vec::new(),
            cursor: Vec::new(),
            pending_roots: Vec::new(),
            edge_queue: VecDeque::new(),
            value_queue: VecDeque::new(),
            queued: vec![false; value_count],
        };
        engine.stats.def_use_work = engine.def_use.work();
        engine.index_graph()?;
        engine.index_cfg()?;
        for (index, value) in ssa.values().iter().enumerate() {
            engine.budget.charge(1)?;
            if let ValueOrigin::Entry(_) = value.origin {
                // Inputs and declared-undefined state are unknown, never bottom.
                engine.values[index] = Slot::Unknown;
            }
        }
        engine.visit(ssa.entry())?;
        loop {
            engine.budget.charge(1)?;
            if let Some(edge) = engine.edge_queue.pop_front() {
                engine.process_edge(edge)?;
            } else if let Some(value) = engine.value_queue.pop_front() {
                engine.process_value(value)?;
            } else {
                break;
            }
        }
        engine.finish()
    }

    fn index_graph(&mut self) -> Result<()> {
        let ssa = self.analysis.ssa();
        let graph = ssa.graph();
        let mut start = 0usize;
        for node in 0..graph.node_count() {
            self.budget.charge(1)?;
            self.edge_start.push(start);
            let predecessors = graph
                .predecessors(node)
                .map_err(|_| ConstantError::Inconsistent("graph node"))?;
            for _ in predecessors {
                self.budget.charge(1)?;
                self.edge_target.push(node);
            }
            start += predecessors.len();
        }
        self.edge_start.push(start);
        if start != graph.edge_count() {
            return Err(ConstantError::Inconsistent("graph edge count"));
        }
        for node in 0..graph.node_count() {
            self.budget.charge(1)?;
            self.incoming_start.push(self.incoming_edges.len());
            let Some(block) = ssa.blocks()[node].renamed() else {
                continue;
            };
            for (index, predecessor) in block.incoming().iter().enumerate() {
                self.budget.charge(1)?;
                match *predecessor {
                    Predecessor::Entry if node == ssa.entry() => self.incoming_edges.push(NONE),
                    Predecessor::Entry => {
                        return Err(ConstantError::Inconsistent("virtual entry edge"));
                    }
                    Predecessor::Node(from) => {
                        let edge = self.graph_edge(from, node)?;
                        self.edge_incoming[edge] = index;
                        self.incoming_edges.push(edge);
                    }
                }
            }
        }
        self.incoming_start.push(self.incoming_edges.len());
        Ok(())
    }

    fn index_cfg(&mut self) -> Result<()> {
        let cfg = self.analysis.cfg();
        let mut previous = 0;
        for (id, edge) in cfg.edges().iter().enumerate() {
            self.budget.charge(1)?;
            if edge.from < previous || edge.from >= cfg.block_count() {
                return Err(ConstantError::Inconsistent("CFG edge order"));
            }
            previous = edge.from;
            self.out_start[edge.from + 1] += 1;
            let hop = self.analysis.edge_reset(id).unwrap_or(edge.to);
            let first = self.graph_edge(edge.from, hop)?;
            self.cfg_first.push(first);
        }
        for node in 0..cfg.node_count() {
            self.budget.charge(1)?;
            self.out_start[node + 1] += self.out_start[node];
        }
        let ssa = self.analysis.ssa();
        let mut start = 0usize;
        for block in ssa.blocks() {
            self.budget.charge(1)?;
            self.statement_start.push(start);
            if let Some(block) = block.renamed() {
                start += block.statements().len();
            }
        }
        self.statement_start.push(start);
        Ok(())
    }

    fn graph_edge(&mut self, from: NodeId, to: NodeId) -> Result<usize> {
        let predecessors = self
            .analysis
            .ssa()
            .graph()
            .predecessors(to)
            .map_err(|_| ConstantError::UnknownNode(to))?;
        self.budget.search(predecessors.len())?;
        let position = predecessors
            .binary_search(&from)
            .map_err(|_| ConstantError::UnknownEdge { from, to })?;
        Ok(self.edge_start[to] + position)
    }

    fn queue_room(&mut self, length: usize) -> Result<()> {
        if length >= self.limits.max_queue {
            return Err(ConstantError::Limit("queue"));
        }
        self.stats.queue_peak = self.stats.queue_peak.max(length + 1);
        Ok(())
    }

    fn global_room(&mut self) -> Result<()> {
        self.queue_room(self.edge_queue.len() + self.value_queue.len())
    }

    fn push_term(&mut self, term: ExpressionId) -> Result<()> {
        self.queue_room(self.stack.len())?;
        self.stack.push(term);
        Ok(())
    }

    fn record(&mut self, amount: usize) -> Result<()> {
        self.stats.plan_records = self
            .stats
            .plan_records
            .checked_add(amount)
            .filter(|&n| n <= self.limits.max_plan_records)
            .ok_or(ConstantError::Limit("plan records"))?;
        Ok(())
    }

    fn enable(&mut self, edge: usize) -> Result<()> {
        self.budget.charge(1)?;
        if self.feasible[edge] {
            return Ok(());
        }
        self.global_room()?;
        self.feasible[edge] = true;
        self.stats.executable_edges += 1;
        self.edge_queue.push_back(edge);
        Ok(())
    }

    fn set_value(&mut self, value: ValueId, slot: Slot) -> Result<()> {
        self.budget.charge(1)?;
        let current = *self
            .values
            .get(value.0)
            .ok_or(ConstantError::UnknownValue(value))?;
        match slot.level().cmp(&current.level()) {
            std::cmp::Ordering::Less => Err(ConstantError::Inconsistent("non-monotone value")),
            // Roots only rise and phis join first, so an equal-level update
            // must carry the same constant; never keep one of two silently.
            std::cmp::Ordering::Equal if self.join(current, slot)? != current => {
                Err(ConstantError::Inconsistent("conflicting constant update"))
            }
            std::cmp::Ordering::Equal => Ok(()),
            std::cmp::Ordering::Greater => {
                self.values[value.0] = slot;
                self.stats.value_changes += 1;
                if !self.queued[value.0] {
                    self.global_room()?;
                    self.queued[value.0] = true;
                    self.value_queue.push_back(value);
                }
                Ok(())
            }
        }
    }

    /// Least upper bound. Equal constants keep the left slot; comparing two
    /// distinct slots is charged by width before the payloads are read.
    fn join(&mut self, left: Slot, right: Slot) -> Result<Slot> {
        Ok(match (left, right) {
            (Slot::Unknown, _) | (_, Slot::Unknown) => Slot::Unknown,
            (Slot::Unreached, other) | (other, Slot::Unreached) => other,
            (a, b) if a == b => a,
            (a, b) => {
                let size = constant(self.program, &self.pool, a)?.size();
                self.budget.charge(words(size) + 1)?;
                if constant(self.program, &self.pool, a)? == constant(self.program, &self.pool, b)?
                {
                    a
                } else {
                    Slot::Unknown
                }
            }
        })
    }

    fn incoming_feasible(&self, node: NodeId, operand: usize) -> Result<bool> {
        let index = self.incoming_start[node] + operand;
        if index >= self.incoming_start[node + 1] {
            return Err(ConstantError::Inconsistent("phi operand edge"));
        }
        Ok(match self.incoming_edges[index] {
            NONE => true,
            edge => self.feasible[edge],
        })
    }

    fn fold(&mut self, phi: PhiId, operand: usize) -> Result<()> {
        self.budget.charge(1)?;
        self.stats.phi_folds += 1;
        let phi = self
            .analysis
            .ssa()
            .phi(phi)
            .map_err(|_| ConstantError::Inconsistent("phi"))?;
        let source = *phi
            .operands()
            .get(operand)
            .ok_or(ConstantError::Inconsistent("phi operand"))?;
        let incoming = *self
            .values
            .get(source.0)
            .ok_or(ConstantError::UnknownValue(source))?;
        let current = self.values[phi.value().0];
        let joined = self.join(current, incoming)?;
        self.set_value(phi.value(), joined)
    }

    fn visit(&mut self, node: NodeId) -> Result<()> {
        self.budget.charge(1)?;
        if self.visited[node] {
            return Ok(());
        }
        self.visited[node] = true;
        self.stats.executable_nodes += 1;
        let ssa = self.analysis.ssa();
        let block = ssa.blocks()[node]
            .renamed()
            .ok_or(ConstantError::Inconsistent(
                "executable node is SSA-unreachable",
            ))?;
        for (index, phi) in block.phis().iter().enumerate() {
            for operand in 0..phi.operands().len() {
                self.budget.charge(1)?;
                if self.incoming_feasible(node, operand)? {
                    self.fold(PhiId { node, index }, operand)?;
                }
            }
        }
        for index in 0..block.statements().len() {
            self.execute(StatementId { node, index })?;
        }
        let cfg = self.analysis.cfg();
        if node < cfg.block_count() {
            self.update_out_edges(node)?;
        } else if node >= cfg.node_count() {
            // A reset node has one unconditional successor.
            let successors = ssa
                .graph()
                .successors(node)
                .map_err(|_| ConstantError::Inconsistent("reset node"))?;
            for &to in successors {
                let edge = self.graph_edge(node, to)?;
                self.enable(edge)?;
            }
        }
        Ok(())
    }

    fn process_edge(&mut self, edge: usize) -> Result<()> {
        let node = self.edge_target[edge];
        if !self.visited[node] {
            return self.visit(node);
        }
        let operand = self.edge_incoming[edge];
        if operand == NONE {
            return Err(ConstantError::Inconsistent(
                "feasible edge into SSA-unreachable node",
            ));
        }
        let block =
            self.analysis.ssa().blocks()[node]
                .renamed()
                .ok_or(ConstantError::Inconsistent(
                    "executable node is SSA-unreachable",
                ))?;
        for index in 0..block.phis().len() {
            self.fold(PhiId { node, index }, operand)?;
        }
        Ok(())
    }

    fn process_value(&mut self, value: ValueId) -> Result<()> {
        self.queued[value.0] = false;
        let uses = self.def_use.statement_uses(value)?.len();
        let mut last = None;
        for index in 0..uses {
            self.budget.charge(1)?;
            let site = self.def_use.statement_uses(value)?[index];
            if last == Some(site.statement) {
                continue;
            }
            last = Some(site.statement);
            let flat = self.flat(site.statement)?;
            if let Some(plan) = self.plans[flat] {
                self.notify(plan, value)?;
            }
        }
        let uses = self.def_use.phi_uses(value)?.len();
        for index in 0..uses {
            self.budget.charge(1)?;
            let site = self.def_use.phi_uses(value)?[index];
            if self.visited[site.phi.node] && self.incoming_feasible(site.phi.node, site.operand)? {
                self.fold(site.phi, site.operand)?;
            }
        }
        Ok(())
    }

    fn flat(&self, statement: StatementId) -> Result<usize> {
        let start = *self
            .statement_start
            .get(statement.node)
            .ok_or(ConstantError::Inconsistent("statement node"))?;
        let index = start + statement.index;
        if index >= self.statement_start[statement.node + 1] {
            return Err(ConstantError::Inconsistent("statement index"));
        }
        Ok(index)
    }

    fn execute(&mut self, id: StatementId) -> Result<()> {
        self.budget.charge(1)?;
        self.stats.executed_statements += 1;
        let flat = self.flat(id)?;
        let program = self.program;
        let ssa = self.analysis.ssa();
        let defs = ssa
            .statement(id)
            .map_err(|_| ConstantError::Inconsistent("renamed statement"))?
            .defs();
        let operation = program.operation(id);
        self.pending_roots.clear();
        let mut unknown = 0;
        for &value in defs {
            self.budget.charge(1)?;
            match program.definition(value)? {
                ExpressionDefinition::Expression(root) => self.pending_roots.push((*root, value)),
                // Fresh native temporaries and opaque effects are unknown on
                // execution, never bottom or zero.
                ExpressionDefinition::Undefined { .. } | ExpressionDefinition::Opaque { .. } => {
                    unknown += 1;
                }
                ExpressionDefinition::Entry(_) | ExpressionDefinition::Phi(_) => {
                    return Err(ConstantError::Inconsistent("statement definition origin"));
                }
            }
        }
        if operation.is_some() || !self.pending_roots.is_empty() {
            self.build_plan(id, flat, operation)?;
        }
        if unknown > 0 {
            for &value in defs {
                self.budget.charge(1)?;
                if !matches!(
                    program.definition(value)?,
                    ExpressionDefinition::Expression(_)
                ) {
                    self.set_value(value, Slot::Unknown)?;
                }
            }
        }
        Ok(())
    }

    /// Collect the statement's needed terms once, link them in ascending ID
    /// (topological) order, and evaluate each term from its children.
    fn build_plan(
        &mut self,
        id: StatementId,
        flat: usize,
        operation: Option<&ExpressionOperation>,
    ) -> Result<()> {
        let program = self.program;
        let stamp = flat + 1;
        self.stack.clear();
        self.scratch.clear();
        let mut roots = std::mem::take(&mut self.pending_roots);
        if let Some(operation) = operation {
            for operand in &operation.operands {
                self.budget.charge(1)?;
                if let Some(term) = operand.expression() {
                    self.push_term(term)?;
                }
            }
            if let Some(output) = operation.output {
                self.push_term(output)?;
            }
        }
        for &(root, _) in &roots {
            self.push_term(root)?;
        }
        while let Some(term) = self.stack.pop() {
            self.budget.charge(1)?;
            let node = program.node(term)?;
            if let ExpressionKind::SsaValue(_) = node.kind {
                if self.tags[term.0] == stamp {
                    continue;
                }
                self.tags[term.0] = stamp;
            } else {
                match self.tags[term.0] {
                    0 => self.tags[term.0] = IN_PROGRESS,
                    IN_PROGRESS => continue,
                    _ => {
                        return Err(ConstantError::Inconsistent(
                            "expression term shared between statements",
                        ));
                    }
                }
            }
            self.record(1)?;
            self.scratch.push(term);
            discovery_children(&node.kind, |child| {
                self.budget.charge(1)?;
                if child.0 >= term.0 {
                    return Err(ConstantError::Inconsistent("expression edge order"));
                }
                self.push_term(child)
            })?;
        }
        let count = self.scratch.len();
        self.budget.sort(count)?;
        self.scratch.sort_unstable();
        let base = self.entries.len();
        for position in 0..count {
            self.budget.charge(1)?;
            let term = self.scratch[position];
            if !matches!(program.node(term)?.kind, ExpressionKind::SsaValue(_)) {
                self.tags[term.0] = base + position + 1;
            }
            self.entries.push(Entry {
                node: term,
                slot: Slot::Unreached,
                children: 0,
                child_count: 0,
                parents: 0,
                parent_count: 0,
                pending: 0,
                root: false,
            });
        }
        // Evaluation children. Memory reads/writes are unknown sources.
        let first_link = self.links.len();
        for position in 0..count {
            let term = self.scratch[position];
            let start = self.links.len();
            let node = program.node(term)?;
            let inputs: &[ExpressionId] = match &node.kind {
                ExpressionKind::Pure { inputs, .. } => inputs,
                ExpressionKind::Extract { value, .. } => std::slice::from_ref(value),
                _ => &[],
            };
            let link = |engine: &mut Self, child: ExpressionId| -> Result<()> {
                engine.budget.search(count)?;
                let at = engine.scratch[..count]
                    .binary_search(&child)
                    .map_err(|_| ConstantError::Inconsistent("plan child"))?;
                engine.record(1)?;
                engine.links.push(base + at);
                Ok(())
            };
            if let ExpressionKind::Join(pieces) = &node.kind {
                for piece in pieces {
                    link(self, piece.value)?;
                }
            }
            for &child in inputs {
                link(self, child)?;
            }
            let entry = &mut self.entries[base + position];
            entry.children = start;
            entry.child_count = self.links.len() - start;
        }
        // Parent links by counting sort over the plan's child links.
        let child_links = self.links.len() - first_link;
        self.record(child_links)?;
        self.budget.charge(2 * count + 2 * child_links + 1)?;
        self.cursor.clear();
        self.cursor.resize(count, 0);
        for link in first_link..first_link + child_links {
            self.cursor[self.links[link] - base] += 1;
        }
        let parent_base = self.links.len();
        let mut next = parent_base;
        for position in 0..count {
            let entry = &mut self.entries[base + position];
            entry.parents = next;
            entry.parent_count = self.cursor[position];
            self.cursor[position] = next;
            next += entry.parent_count;
        }
        self.links.resize(parent_base + child_links, 0);
        for position in 0..count {
            let entry = self.entries[base + position];
            for link in entry.children..entry.children + entry.child_count {
                let child = self.links[link] - base;
                let at = self.cursor[child];
                self.links[at] = base + position;
                self.cursor[child] += 1;
            }
        }
        // SSA leaves sorted by value, then definition roots sorted by entry.
        let leaf_start = self.leaves.len();
        for position in 0..count {
            self.budget.charge(1)?;
            if let ExpressionKind::SsaValue(value) = program.node(self.scratch[position])?.kind {
                self.record(1)?;
                self.leaves.push((value, base + position));
            }
        }
        self.budget.sort(self.leaves.len() - leaf_start)?;
        self.leaves[leaf_start..].sort_unstable();
        let root_start = self.roots.len();
        for &(root, value) in &roots {
            self.budget.search(count)?;
            let at = self.scratch[..count]
                .binary_search(&root)
                .map_err(|_| ConstantError::Inconsistent("plan root"))?;
            self.record(1)?;
            self.roots.push((base + at, value));
            self.entries[base + at].root = true;
        }
        self.budget.sort(self.roots.len() - root_start)?;
        self.roots[root_start..].sort_unstable();
        roots.clear();
        self.pending_roots = roots;
        let condition = self.condition_entry(id, operation, base, count)?;
        let plan = Plan {
            statement: id,
            leaves: (leaf_start, self.leaves.len()),
            roots: (root_start, self.roots.len()),
            condition,
        };
        self.plans[flat] = Some(plan);
        for entry in base..base + count {
            self.budget.charge(1)?;
            let term = self.entries[entry].node;
            let slot = match &program.node(term)?.kind {
                ExpressionKind::Constant(_) => Slot::Literal(term),
                ExpressionKind::SsaValue(value) => *self
                    .values
                    .get(value.0)
                    .ok_or(ConstantError::UnknownValue(*value))?,
                ExpressionKind::ReadMemory { .. } | ExpressionKind::WriteMemory { .. } => {
                    Slot::Unknown
                }
                _ => {
                    let Entry {
                        children,
                        child_count,
                        ..
                    } = self.entries[entry];
                    let mut unknown = false;
                    let mut pending = 0;
                    for link in children..children + child_count {
                        self.budget.charge(1)?;
                        match self.entries[self.links[link]].slot.level() {
                            Level::Unknown => unknown = true,
                            Level::Unreached => pending += 1,
                            Level::Constant => {}
                        }
                    }
                    self.entries[entry].pending = pending;
                    if unknown {
                        Slot::Unknown
                    } else if pending > 0 {
                        Slot::Unreached
                    } else {
                        self.evaluate(entry, id)?
                    }
                }
            };
            self.entries[entry].slot = slot;
            if !matches!(program.node(term)?.kind, ExpressionKind::SsaValue(_)) {
                self.nodes[term.0] = slot;
            }
        }
        for index in plan.roots.0..plan.roots.1 {
            let (entry, value) = self.roots[index];
            self.set_value(value, self.entries[entry].slot)?;
        }
        Ok(())
    }

    /// The condition term of a CBRANCH that ends its CFG block.
    fn condition_entry(
        &mut self,
        id: StatementId,
        operation: Option<&ExpressionOperation>,
        base: usize,
        count: usize,
    ) -> Result<usize> {
        let cfg = self.analysis.cfg();
        let Some(operation) = operation.filter(|op| op.opcode == Opcode::Cbranch) else {
            return Ok(NONE);
        };
        let block = self.analysis.ssa().blocks()[id.node]
            .renamed()
            .ok_or(ConstantError::Inconsistent("CBRANCH block"))?;
        let last = cfg.block_points(id.node).and_then(<[_]>::last);
        if id.index + 1 != block.statements().len() || last != Some(&operation.point) {
            return Err(ConstantError::Inconsistent(
                "CBRANCH is not its block terminator",
            ));
        }
        let condition = operation
            .operands
            .get(1)
            .and_then(|operand| operand.expression())
            .ok_or(ConstantError::Inconsistent("CBRANCH condition"))?;
        self.budget.search(count)?;
        let at = self.scratch[..count]
            .binary_search(&condition)
            .map_err(|_| ConstantError::Inconsistent("CBRANCH condition term"))?;
        Ok(base + at)
    }

    fn notify(&mut self, plan: Plan, value: ValueId) -> Result<()> {
        let slot = self.values[value.0];
        let (start, end) = plan.leaves;
        self.budget.search(end - start)?;
        let mut index = start + self.leaves[start..end].partition_point(|&(v, _)| v < value);
        self.local.clear();
        while index < end && self.leaves[index].0 == value {
            self.budget.charge(1)?;
            let entry = self.leaves[index].1;
            match slot.level().cmp(&self.entries[entry].slot.level()) {
                std::cmp::Ordering::Less => {
                    return Err(ConstantError::Inconsistent("non-monotone leaf"));
                }
                std::cmp::Ordering::Equal => {}
                std::cmp::Ordering::Greater => {
                    self.entries[entry].slot = slot;
                    self.queue_room(self.local.len())?;
                    self.local.push(entry);
                }
            }
            index += 1;
        }
        if self.local.is_empty() {
            return Ok(());
        }
        self.stats.notifications += 1;
        self.propagate(plan)
    }

    /// Push raised entries to their parents. Each entry rises at most twice
    /// and each computation is evaluated at most once, when its last
    /// unreached child becomes constant.
    fn propagate(&mut self, plan: Plan) -> Result<()> {
        let mut condition = false;
        while let Some(entry) = self.local.pop() {
            self.budget.charge(1)?;
            let current = self.entries[entry];
            let level = current.slot.level();
            if current.root {
                self.update_roots(plan, entry)?;
            }
            condition |= entry == plan.condition;
            for link in current.parents..current.parents + current.parent_count {
                self.budget.charge(1)?;
                let parent = self.links[link];
                let before = self.entries[parent].slot;
                if before == Slot::Unknown {
                    continue;
                }
                let after = match level {
                    Level::Unknown => Slot::Unknown,
                    Level::Constant => {
                        let pending = self.entries[parent]
                            .pending
                            .checked_sub(1)
                            .ok_or(ConstantError::Inconsistent("plan pending count"))?;
                        self.entries[parent].pending = pending;
                        if pending > 0 {
                            continue;
                        }
                        self.evaluate(parent, plan.statement)?
                    }
                    Level::Unreached => {
                        return Err(ConstantError::Inconsistent("non-monotone term"));
                    }
                };
                if after.level() <= before.level() {
                    return Err(ConstantError::Inconsistent("non-monotone term"));
                }
                self.entries[parent].slot = after;
                let term = self.entries[parent].node;
                self.nodes[term.0] = after;
                self.queue_room(self.local.len())?;
                self.local.push(parent);
            }
        }
        if condition {
            self.update_out_edges(plan.statement.node)?;
        }
        Ok(())
    }

    fn update_roots(&mut self, plan: Plan, entry: usize) -> Result<()> {
        let (start, end) = plan.roots;
        self.budget.search(end - start)?;
        let mut index = start + self.roots[start..end].partition_point(|&(e, _)| e < entry);
        while index < end && self.roots[index].0 == entry {
            let value = self.roots[index].1;
            self.set_value(value, self.entries[entry].slot)?;
            index += 1;
        }
        Ok(())
    }

    /// Evaluate a computation whose children are all at least constant. The
    /// width-dependent cost and the output bytes are checked first.
    fn evaluate(&mut self, entry: usize, statement: StatementId) -> Result<Slot> {
        let program = self.program;
        let Entry {
            node: term,
            children,
            child_count,
            ..
        } = self.entries[entry];
        let node = program.node(term)?;
        let ExpressionType::Bits(size) = node.ty else {
            return Err(ConstantError::Inconsistent("memory-typed computation"));
        };
        for link in children..children + child_count {
            self.budget.charge(1)?;
            match self.entries[self.links[link]].slot.level() {
                Level::Unknown => return Ok(Slot::Unknown),
                Level::Unreached => {
                    return Err(ConstantError::Inconsistent("evaluated before its inputs"));
                }
                Level::Constant => {}
            }
        }
        let child =
            |engine: &Self, index: usize| engine.entries[engine.links[children + index]].slot;
        match &node.kind {
            ExpressionKind::Pure { opcode, inputs } => {
                if inputs.len() != child_count {
                    return Err(ConstantError::Inconsistent("pure arity"));
                }
                if matches!(opcode, Opcode::Copy | Opcode::Cast) && child_count == 1 {
                    let slot = child(self, 0);
                    if constant(program, &self.pool, slot)?.size() == size {
                        self.budget.charge(1)?;
                        return Ok(slot);
                    }
                }
                self.budget.charge(child_count)?;
                let mut widths = Vec::with_capacity(child_count);
                for index in 0..child_count {
                    widths.push(constant(program, &self.pool, child(self, index))?.size());
                }
                self.budget
                    .charge(evaluation_cost(*opcode, &widths, size))?;
                self.reserve(size)?;
                // The evaluator reads a contiguous `[Value]`. These clones are
                // charged as work in `evaluation_cost` and dropped after the
                // call; only the result is retained and counted as bytes.
                let mut arguments = Vec::with_capacity(child_count);
                for index in 0..child_count {
                    arguments.push(constant(program, &self.pool, child(self, index))?.clone());
                }
                self.stats.evaluations += 1;
                match evaluate_pure(*opcode, &arguments, size) {
                    Ok(result) if result.size() == size => Ok(self.store(result)),
                    Ok(_) => Err(ConstantError::Inconsistent("evaluated width")),
                    Err(error) => {
                        self.faults.push((
                            entry,
                            EvaluationFault {
                                statement,
                                expression: term,
                                opcode: *opcode,
                                error,
                            },
                        ));
                        Ok(Slot::Unknown)
                    }
                }
            }
            ExpressionKind::Join(pieces) => {
                if pieces.len() != child_count {
                    return Err(ConstantError::Inconsistent("join arity"));
                }
                self.budget
                    .charge((size as usize).saturating_add(2 * child_count))?;
                self.reserve(size)?;
                let mut bytes = vec![0u8; size as usize];
                let mut covered = 0u32;
                for (index, piece) in pieces.iter().enumerate() {
                    let value = constant(program, &self.pool, child(self, index))?;
                    if piece.lsb_byte != covered || value.size() != piece.size {
                        return Err(ConstantError::Inconsistent("join pieces"));
                    }
                    covered = covered
                        .checked_add(piece.size)
                        .filter(|&end| end <= size)
                        .ok_or(ConstantError::Inconsistent("join pieces"))?;
                    bytes[piece.lsb_byte as usize..covered as usize]
                        .copy_from_slice(&value.to_le_bytes());
                }
                if covered != size {
                    return Err(ConstantError::Inconsistent("join coverage"));
                }
                Ok(self.store(Value::from_le_bytes(&bytes)?))
            }
            ExpressionKind::Extract { lsb_byte, .. } => {
                let source = constant(program, &self.pool, child(self, 0))?;
                let source_size = source.size();
                let end = lsb_byte
                    .checked_add(size)
                    .filter(|&end| end <= source_size)
                    .ok_or(ConstantError::Inconsistent("extract range"))?;
                self.budget
                    .charge(source_size as usize + size as usize + 1)?;
                self.reserve(size)?;
                let bytes = constant(program, &self.pool, child(self, 0))?.to_le_bytes();
                Ok(self.store(Value::from_le_bytes(
                    &bytes[*lsb_byte as usize..end as usize],
                )?))
            }
            _ => Err(ConstantError::Inconsistent("not a computation")),
        }
    }

    /// Charge an evaluated result's bytes before evaluating it. A faulting
    /// evaluation keeps its charge, so the total is an exact limit.
    fn reserve(&mut self, size: u32) -> Result<()> {
        self.stats.constant_bytes = self
            .stats
            .constant_bytes
            .checked_add(size as usize)
            .filter(|&n| n <= self.limits.max_constant_bytes)
            .ok_or(ConstantError::Limit("constant bytes"))?;
        Ok(())
    }

    fn store(&mut self, value: Value) -> Slot {
        self.pool.push(value);
        Slot::Pool(self.pool.len() - 1)
    }

    /// Enable semantic out-edges of a CFG block. CBRANCH enables only its
    /// actual outcome for a constant condition and both for an unknown one.
    /// Every other role (calls' return/no-return, returns, unresolved
    /// indirect branches, unimplemented) is enabled unconditionally.
    fn update_out_edges(&mut self, node: NodeId) -> Result<()> {
        let cfg = self.analysis.cfg();
        let condition = self.condition_slot(node)?;
        for id in self.out_start[node]..self.out_start[node + 1] {
            self.budget.charge(1)?;
            if self.cfg_feasible[id] {
                continue;
            }
            let role = cfg.edges()[id].role;
            let enabled = match role {
                EdgeRole::ConditionTrue | EdgeRole::ConditionFalse => {
                    let slot = condition.ok_or(ConstantError::Inconsistent(
                        "conditional edge without CBRANCH condition",
                    ))?;
                    match slot.level() {
                        Level::Unreached => false,
                        Level::Unknown => true,
                        Level::Constant => {
                            let value = constant(self.program, &self.pool, slot)?;
                            self.budget.charge(words(value.size()) + 1)?;
                            let taken =
                                constant(self.program, &self.pool, slot)?.to_u64() != Some(0);
                            taken == (role == EdgeRole::ConditionTrue)
                        }
                    }
                }
                _ => true,
            };
            if enabled {
                self.cfg_feasible[id] = true;
                self.stats.feasible_cfg_edges += 1;
                self.enable(self.cfg_first[id])?;
            }
        }
        Ok(())
    }

    fn condition_slot(&mut self, node: NodeId) -> Result<Option<Slot>> {
        self.budget.charge(1)?;
        let (start, end) = (self.statement_start[node], self.statement_start[node + 1]);
        if start == end {
            return Ok(None);
        }
        Ok(self.plans[end - 1]
            .filter(|plan| plan.condition != NONE)
            .map(|plan| self.entries[plan.condition].slot))
    }

    fn finish(mut self) -> Result<Output> {
        // An optimistic intermediate state can fault (for example a divisor
        // that is 0 until a backedge raises it). Keep only faults whose
        // inputs are still all constant in the fixpoint.
        let mut faults = Vec::with_capacity(self.faults.len());
        for (entry, fault) in std::mem::take(&mut self.faults) {
            let Entry {
                children,
                child_count,
                ..
            } = self.entries[entry];
            self.budget.charge(child_count + 1)?;
            if (children..children + child_count)
                .all(|link| self.entries[self.links[link]].slot.level() == Level::Constant)
            {
                faults.push(fault);
            }
        }
        self.stats.faults = faults.len();
        self.budget.charge(self.values.len())?;
        for slot in &self.values {
            match slot.level() {
                Level::Unreached => self.stats.unreached_values += 1,
                Level::Constant => self.stats.constant_values += 1,
                Level::Unknown => self.stats.unknown_values += 1,
            }
        }
        self.stats.work = self.budget.used;
        Ok(Output {
            values: self.values,
            nodes: self.nodes,
            pool: self.pool,
            visited: self.visited,
            edge_start: self.edge_start,
            feasible: self.feasible,
            cfg_feasible: self.cfg_feasible,
            faults,
            stats: self.stats,
        })
    }
}
