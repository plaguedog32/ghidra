use std::fmt;
use std::sync::Arc;

use ghidra_graph::{Graph, NodeId};
use ghidra_pcode::{AddressSpace, PcodeInstruction, PcodeOperation, SpaceId};

use crate::CfgError;

/// Index into [`Cfg::edges`].
pub type EdgeId = usize;

/// Stable identity of one executable position: an operation of a supplied
/// instruction, or the explicit no-op point (`operation_index == 0`) of an
/// instruction that has no P-code operations. Ordering is canonical.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProgramPoint {
    pub address: u64,
    pub operation_index: u32,
}

impl ProgramPoint {
    pub const fn new(address: u64, operation_index: u32) -> Self {
        Self {
            address,
            operation_index,
        }
    }
}

impl fmt::Display for ProgramPoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "0x{:X}:{}", self.address, self.operation_index)
    }
}

/// What executes at a [`ProgramPoint`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Statement<'a> {
    Operation(&'a PcodeOperation),
    /// Placeholder for a supplied instruction with zero operations. It has no
    /// effects and falls through to `address + length`.
    NoOp,
}

/// Owned build input. Instructions may be in any order; the built [`Cfg`]
/// keeps this exact backing data, shares it through `Arc`, and never edits it.
#[derive(Clone, Debug)]
pub struct CfgInput {
    pub spaces: Arc<[AddressSpace]>,
    pub code_space: SpaceId,
    /// Address of the supplied instruction that starts the function.
    pub entry: u64,
    pub instructions: Arc<[PcodeInstruction]>,
}

impl CfgInput {
    pub fn new(
        spaces: impl Into<Arc<[AddressSpace]>>,
        code_space: SpaceId,
        entry: u64,
        instructions: impl Into<Arc<[PcodeInstruction]>>,
    ) -> Self {
        Self {
            spaces: spaces.into(),
            code_space,
            entry,
            instructions: instructions.into(),
        }
    }
}

/// Construction limits. Every count is checked before the corresponding
/// processing or output allocation; `max_work` bounds one build.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_spaces: usize,
    pub max_instructions: usize,
    /// Total operations across all instructions.
    pub max_operations: usize,
    /// Total input plus output varnode references.
    pub max_operand_refs: usize,
    pub max_blocks: usize,
    /// Semantic edges, including those into terminal exit nodes.
    pub max_edges: usize,
    pub max_exits: usize,
    pub max_work: u64,
    /// Retained by the built [`Graph`]; each graph analysis has its own budget.
    pub graph: ghidra_graph::Limits,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_spaces: 256,
            max_instructions: 1_000_000,
            max_operations: 4_000_000,
            max_operand_refs: 16_000_000,
            max_blocks: 1_000_000,
            max_edges: 2_000_000,
            max_exits: 1_000_000,
            max_work: 1_000_000_000,
            graph: ghidra_graph::Limits::default(),
        }
    }
}

/// The P-code outcome that produced an edge. Roles survive even when the
/// canonical [`Graph`] collapses edges with the same endpoints.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum EdgeRole {
    /// Sequential flow from a non-control operation or no-op point.
    Fallthrough,
    /// Unconditional `BRANCH`.
    Branch,
    /// `CBRANCH` condition false: the next operation or instruction.
    ConditionFalse,
    /// `CBRANCH` condition true: its label.
    ConditionTrue,
    /// `BRANCHIND`: always an unresolved terminal outcome.
    IndirectBranch,
    /// Conservative possible continuation after `CALL`/`CALLIND` returns.
    CallReturn,
    /// The call did not return here; always a terminal outcome.
    CallNoReturn,
    /// `RETURN`.
    Return,
    /// `UNIMPLEMENTED`: unknown semantics, flow stops.
    Unimplemented,
}

/// How control arrives at an edge's target. Per-instruction temporary state
/// survives only [`Arrival::SameInstruction`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Arrival {
    /// Within the current instruction frame: a relative P-code branch
    /// (including one to operation 0) or sequential flow inside an instruction.
    SameInstruction,
    /// A new native instruction frame starts at the target instruction's first
    /// point: fallthrough from the previous instruction, a direct code-address
    /// branch (including one to its own instruction), or a relative branch to
    /// the end of the current instruction.
    InstructionEntry,
    /// The target is a terminal exit node; no supplied point executes next.
    Exit,
}

/// One semantic edge. `source` is always the last point of block `from`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Edge {
    pub from: NodeId,
    pub to: NodeId,
    pub source: ProgramPoint,
    pub role: EdgeRole,
    pub arrival: Arrival,
}

/// Typed outcome represented by a terminal graph node.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ExitKind {
    /// `RETURN`; its runtime target is not resolved.
    Return,
    /// Flow to `address + length` where no supplied instruction starts.
    OutsideFallthrough { target: u64 },
    /// Flow to `address + length` when that is past the end of the code space.
    SpaceEndFallthrough,
    /// Direct `BRANCH`/`CBRANCH` to an address no supplied instruction covers.
    ExternalBranch { target: u64 },
    /// Unsupported: a direct branch into the interior of a supplied instruction.
    InteriorBranch { target: u64, instruction: u64 },
    /// `BRANCHIND`; the target is unresolved and may be anywhere.
    UnresolvedIndirectBranch,
    /// A `CALL`/`CALLIND` whose callee did not return to its continuation.
    CallNoReturn,
    /// `UNIMPLEMENTED`; behavior is unknown.
    Unimplemented,
}

/// A terminal graph node. Each has exactly one incoming edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Exit {
    pub node: NodeId,
    pub from: NodeId,
    pub source: ProgramPoint,
    pub role: EdgeRole,
    pub kind: ExitKind,
}

/// Where a direct code address lies relative to the supplied instructions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum TargetLocation {
    InstructionStart,
    /// Strictly inside the supplied instruction starting at `instruction`.
    InstructionInterior {
        instruction: u64,
    },
    NotSupplied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum CallTarget {
    Direct {
        address: u64,
        location: TargetLocation,
    },
    Indirect,
}

/// A call site. The callee never receives an intra-procedural edge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CallSite {
    pub point: ProgramPoint,
    pub block: NodeId,
    pub target: CallTarget,
    /// Target of the [`EdgeRole::CallReturn`] edge (a block or an exit node).
    pub continuation: NodeId,
    /// The [`ExitKind::CallNoReturn`] node.
    pub no_return: NodeId,
}

/// A `CALLOTHER` site. Its effects are unknown; it is not a block boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UseropSite {
    pub point: ProgramPoint,
    pub block: NodeId,
    /// Constant input0, the user-defined operation index.
    pub userop: u64,
}

/// Unsupplied bytes `[start, end)` between two adjacent supplied instructions.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Gap {
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NodeKind<'a> {
    /// A basic block's points in execution order (never empty).
    Block(&'a [ProgramPoint]),
    Exit(&'a Exit),
}

/// Immutable intra-procedural CFG over owned P-code.
///
/// Graph node IDs `0..block_count()` are basic blocks ordered by first point;
/// `block_count()..node_count()` are terminal exits ordered by their source
/// block and outcome. Both orders are independent of input instruction order.
#[derive(Clone, Debug)]
pub struct Cfg {
    pub(crate) spaces: Arc<[AddressSpace]>,
    pub(crate) code_space: SpaceId,
    pub(crate) entry_address: u64,
    pub(crate) instructions: Arc<[PcodeInstruction]>,
    /// Canonical rank -> index in `instructions`.
    pub(crate) order: Vec<usize>,
    /// Canonical rank -> instruction address (ascending).
    pub(crate) addresses: Vec<u64>,
    /// Canonical rank -> first index in `points`; one trailing sentinel.
    pub(crate) point_start: Vec<usize>,
    pub(crate) points: Vec<ProgramPoint>,
    /// Block -> first index in `points`; one trailing sentinel.
    pub(crate) block_start: Vec<usize>,
    pub(crate) edges: Vec<Edge>,
    /// Node -> first index in `edges`; one trailing sentinel.
    pub(crate) out_start: Vec<usize>,
    pub(crate) in_edges: Vec<EdgeId>,
    pub(crate) in_start: Vec<usize>,
    pub(crate) exits: Vec<Exit>,
    pub(crate) calls: Vec<CallSite>,
    pub(crate) userops: Vec<UseropSite>,
    pub(crate) gaps: Vec<Gap>,
    pub(crate) graph: Arc<Graph>,
    pub(crate) entry: NodeId,
    pub(crate) limits: Limits,
    pub(crate) work: u64,
}

impl Cfg {
    /// Validate the input and build the CFG and its canonical [`Graph`].
    pub fn new(input: CfgInput, limits: Limits) -> Result<Self, CfgError> {
        crate::build::build(input, limits)
    }

    pub fn graph(&self) -> &Graph {
        &self.graph
    }
    pub fn shared_graph(&self) -> Arc<Graph> {
        Arc::clone(&self.graph)
    }
    /// Basic-block node containing the entry instruction's first point.
    pub fn entry(&self) -> NodeId {
        self.entry
    }
    pub fn entry_address(&self) -> u64 {
        self.entry_address
    }
    pub fn code_space(&self) -> SpaceId {
        self.code_space
    }
    pub fn spaces(&self) -> &[AddressSpace] {
        &self.spaces
    }
    pub fn shared_spaces(&self) -> Arc<[AddressSpace]> {
        Arc::clone(&self.spaces)
    }
    /// Supplied instructions in their original order, unchanged.
    pub fn instructions(&self) -> &[PcodeInstruction] {
        &self.instructions
    }
    pub fn shared_instructions(&self) -> Arc<[PcodeInstruction]> {
        Arc::clone(&self.instructions)
    }
    /// Supplied instructions in ascending address order.
    pub fn canonical_instructions(&self) -> impl ExactSizeIterator<Item = &PcodeInstruction> + '_ {
        self.order.iter().map(|&index| &self.instructions[index])
    }
    pub fn instruction_at(&self, address: u64) -> Option<&PcodeInstruction> {
        let rank = self.addresses.binary_search(&address).ok()?;
        Some(&self.instructions[self.order[rank]])
    }
    pub fn limits(&self) -> Limits {
        self.limits
    }
    /// Deterministic work units spent by the build, excluding graph construction.
    pub fn build_work(&self) -> u64 {
        self.work
    }

    pub fn node_count(&self) -> usize {
        self.out_start.len() - 1
    }
    pub fn block_count(&self) -> usize {
        self.block_start.len() - 1
    }
    pub fn exit_count(&self) -> usize {
        self.exits.len()
    }
    pub fn is_block(&self, node: NodeId) -> bool {
        node < self.block_count()
    }
    pub fn node(&self, node: NodeId) -> Option<NodeKind<'_>> {
        if let Some(points) = self.block_points(node) {
            Some(NodeKind::Block(points))
        } else {
            self.exit(node).map(NodeKind::Exit)
        }
    }
    pub fn block_points(&self, node: NodeId) -> Option<&[ProgramPoint]> {
        if !self.is_block(node) {
            return None;
        }
        Some(&self.points[self.block_start[node]..self.block_start[node + 1]])
    }
    pub fn exit(&self, node: NodeId) -> Option<&Exit> {
        self.exits.get(node.checked_sub(self.block_count())?)
    }
    /// Terminal outcomes in node order.
    pub fn exits(&self) -> &[Exit] {
        &self.exits
    }
    /// Every exit node, suitable for [`Graph::post_dominators`].
    pub fn exit_nodes(&self) -> impl ExactSizeIterator<Item = NodeId> + '_ {
        self.exits.iter().map(|exit| exit.node)
    }

    /// Every point in canonical order, including unreachable and no-op points.
    pub fn points(&self) -> &[ProgramPoint] {
        &self.points
    }
    pub fn statement(&self, point: ProgramPoint) -> Option<Statement<'_>> {
        let rank = self.addresses.binary_search(&point.address).ok()?;
        let instruction = &self.instructions[self.order[rank]];
        if instruction.ops.is_empty() {
            (point.operation_index == 0).then_some(Statement::NoOp)
        } else {
            instruction
                .ops
                .get(point.operation_index as usize)
                .map(Statement::Operation)
        }
    }
    /// Basic block containing a point.
    pub fn block_of(&self, point: ProgramPoint) -> Option<NodeId> {
        let rank = self.addresses.binary_search(&point.address).ok()?;
        let start = self.point_start[rank];
        let index = start.checked_add(point.operation_index as usize)?;
        if index >= self.point_start[rank + 1] {
            return None;
        }
        Some(self.block_start.partition_point(|&first| first <= index) - 1)
    }

    /// All semantic edges, grouped by source node in ascending order.
    pub fn edges(&self) -> &[Edge] {
        &self.edges
    }
    /// Outgoing edges in outcome order: fallthrough/false/call-return first.
    pub fn out_edges(&self, node: NodeId) -> Option<&[Edge]> {
        let end = *self.out_start.get(node.checked_add(1)?)?;
        Some(&self.edges[self.out_start[node]..end])
    }
    /// Incoming edge IDs in ascending ID order.
    pub fn in_edges(&self, node: NodeId) -> Option<&[EdgeId]> {
        let end = *self.in_start.get(node.checked_add(1)?)?;
        Some(&self.in_edges[self.in_start[node]..end])
    }

    /// Call sites in canonical point order.
    pub fn calls(&self) -> &[CallSite] {
        &self.calls
    }
    /// `CALLOTHER` sites in canonical point order.
    pub fn userops(&self) -> &[UseropSite] {
        &self.userops
    }
    /// Address gaps between consecutive supplied instructions, ascending.
    pub fn gaps(&self) -> &[Gap] {
        &self.gaps
    }
}
