//! Remove phi operations with edge-specific copies, retaining one mutable
//! storage slot for every SSA value. This is a lowering plan, not a rewrite of
//! the immutable source SSA or an interference/coalescing pass.
use std::{collections::BTreeMap, fmt, ops::Range, sync::Arc};

use ghidra_graph::{Graph, NodeId};

use crate::{
    Block, CopyError, CopyLimits, CopyMove, CopyResource, CopySlot, ParallelCopy,
    ParallelCopySchedule, Predecessor, RenamedStatement, Ssa,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhiLoweringLimits {
    pub max_values: usize,
    /// All input phi operands, including identity copies that are omitted.
    pub max_phi_operands: usize,
    pub max_copy_blocks: usize,
    pub max_moves: usize,
    /// This pass's work, including nested parallel-copy scheduling.
    pub max_work: u64,
    /// Output graph size and its separate construction work budget. With no
    /// copy blocks the original `Arc<Graph>` is reused and retains its own
    /// analysis limits; no graph construction work is spent in that case.
    pub graph: ghidra_graph::Limits,
}

impl Default for PhiLoweringLimits {
    fn default() -> Self {
        Self {
            max_values: 16_000_000,
            max_phi_operands: 16_000_000,
            max_copy_blocks: 1_000_000,
            max_moves: 32_000_000,
            max_work: 200_000_000,
            graph: ghidra_graph::Limits::default(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhiLoweringResource {
    Values,
    PhiOperands,
    CopyBlocks,
    Moves,
    Work,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PhiLoweringError {
    LimitExceeded {
        resource: PhiLoweringResource,
    },
    Graph(ghidra_graph::Error),
    Copy(CopyError),
    /// Defensive consistency check; public Ssa constructors maintain these
    /// invariants and the immutable snapshot cannot be edited by callers.
    InvalidSource(&'static str),
}

impl fmt::Display for PhiLoweringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded { resource } => {
                write!(f, "phi lowering {resource:?} limit exceeded")
            }
            Self::Graph(error) => write!(f, "phi lowering graph: {error}"),
            Self::Copy(error) => write!(f, "phi lowering copies: {error}"),
            Self::InvalidSource(reason) => write!(f, "invalid SSA for phi lowering: {reason}"),
        }
    }
}

impl std::error::Error for PhiLoweringError {}

impl From<ghidra_graph::Error> for PhiLoweringError {
    fn from(error: ghidra_graph::Error) -> Self {
        Self::Graph(error)
    }
}

impl From<CopyError> for PhiLoweringError {
    fn from(error: CopyError) -> Self {
        match error {
            CopyError::LimitExceeded { resource } => match resource {
                CopyResource::Slots => limit(PhiLoweringResource::Values),
                CopyResource::Copies => limit(PhiLoweringResource::PhiOperands),
                CopyResource::Moves => limit(PhiLoweringResource::Moves),
                CopyResource::Work => limit(PhiLoweringResource::Work),
                CopyResource::Temporaries => Self::Copy(error),
            },
            other => Self::Copy(other),
        }
    }
}

type Result<T> = std::result::Result<T, PhiLoweringError>;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PhiLoweringStats {
    pub values: usize,
    pub eliminated_phis: usize,
    pub phi_operands: usize,
    pub identity_copies: usize,
    pub parallel_copies: usize,
    pub copy_blocks: usize,
    pub moves: usize,
    /// Scheduling uses at most one shared scratch slot. No slot is initialized
    /// to a constant. Current uncoalesced SSA phis do not require a scratch.
    pub temporaries: usize,
    pub graph_rebuilt: bool,
    pub work: u64,
}

/// A synthetic block on exactly one original incoming edge. For Entry this is
/// a prologue executed once; backedges to the original entry bypass it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhiCopyBlock {
    pub node: NodeId,
    pub predecessor: Predecessor,
    pub target: NodeId,
    moves: Range<usize>,
}

/// Original nodes keep their IDs and statement order. Reachable nodes expose
/// no phi operations; their effects are in the edge copy blocks instead.
#[derive(Debug, Clone, Copy)]
pub enum LoweredNode<'a> {
    Block {
        source: NodeId,
        statements: &'a [RenamedStatement],
    },
    Unreachable {
        source: NodeId,
        statement_count: usize,
    },
    Copies(&'a PhiCopyBlock),
}

/// Immutable owned lowering from SSA values to mutable value slots. A slot's
/// index is its source ValueId index. Original statements still read every use
/// before writing their definition slots, with multi-def statements atomic.
/// Entry Input/Undefined values retain their source meaning, never zero.
#[derive(Debug, Clone)]
pub struct PhiLowering {
    source: Arc<Ssa>,
    graph: Arc<Graph>,
    entry: NodeId,
    blocks: Vec<PhiCopyBlock>,
    moves: Vec<CopyMove>,
    redirects: BTreeMap<(Predecessor, NodeId), NodeId>,
    limits: PhiLoweringLimits,
    stats: PhiLoweringStats,
}

impl PhiLowering {
    pub fn new(source: Arc<Ssa>, limits: PhiLoweringLimits) -> Result<Self> {
        let values = source.values().len();
        let phi_operands = source.phi_operand_count();
        if values > limits.max_values {
            return Err(limit(PhiLoweringResource::Values));
        }
        if phi_operands > limits.max_phi_operands {
            return Err(limit(PhiLoweringResource::PhiOperands));
        }
        graph_shape(
            source.node_count(),
            source.graph().edge_count(),
            limits.graph,
        )?;
        if source.node_count() != source.graph().node_count() {
            return Err(PhiLoweringError::InvalidSource(
                "block and graph node counts disagree",
            ));
        }
        let mut budget = Budget {
            maximum: limits.max_work,
            work: 0,
        };
        budget.charge(1)?;
        let mut blocks = Vec::new();
        let mut moves = Vec::new();
        let mut redirects = BTreeMap::new();
        let mut entry = source.entry();
        let mut stats = PhiLoweringStats {
            values,
            eliminated_phis: source.phi_count(),
            ..Default::default()
        };
        for (target, block) in source.blocks().iter().enumerate() {
            budget.charge(1)?;
            let Block::Reachable(block) = block else {
                continue;
            };
            if block.phis().is_empty() {
                continue;
            }
            for (operand, &predecessor) in block.incoming().iter().enumerate() {
                budget.charge(1)?;
                stats.phi_operands = stats
                    .phi_operands
                    .checked_add(block.phis().len())
                    .filter(|n| *n <= limits.max_phi_operands)
                    .ok_or_else(|| limit(PhiLoweringResource::PhiOperands))?;
                budget.charge(block.phis().len())?;
                let mut copies = Vec::with_capacity(block.phis().len());
                for phi in block.phis() {
                    let from =
                        *phi.operands()
                            .get(operand)
                            .ok_or(PhiLoweringError::InvalidSource(
                                "phi incoming arity mismatch",
                            ))?;
                    if from == phi.value() {
                        stats.identity_copies += 1;
                    } else {
                        copies.push(ParallelCopy {
                            destination: CopySlot(phi.value().0),
                            source: CopySlot(from.0),
                        });
                    }
                }
                if copies.is_empty() {
                    continue;
                }
                let count = blocks
                    .len()
                    .checked_add(1)
                    .filter(|n| *n <= limits.max_copy_blocks)
                    .ok_or_else(|| limit(PhiLoweringResource::CopyBlocks))?;
                let nodes = source
                    .node_count()
                    .checked_add(count)
                    .ok_or_else(|| graph_limit(ghidra_graph::Resource::Nodes))?;
                let edges = source
                    .graph()
                    .edge_count()
                    .checked_add(count)
                    .ok_or_else(|| graph_limit(ghidra_graph::Resource::Edges))?;
                graph_shape(nodes, edges, limits.graph)?;
                let schedule = ParallelCopySchedule::new(
                    values,
                    &copies,
                    CopyLimits {
                        max_slots: limits.max_values,
                        max_copies: copies.len(),
                        max_moves: limits.max_moves - moves.len(),
                        max_temporaries: 1,
                        max_work: limits.max_work - budget.work,
                    },
                )?;
                budget.add_work(schedule.work())?;
                budget.charge(schedule.moves().len())?;
                let start = moves.len();
                moves.extend_from_slice(schedule.moves());
                let node = nodes - 1;
                budget.tree(count)?;
                if redirects.insert((predecessor, target), node).is_some() {
                    return Err(PhiLoweringError::InvalidSource("duplicate incoming edge"));
                }
                if predecessor == Predecessor::Entry {
                    if target != source.entry() {
                        return Err(PhiLoweringError::InvalidSource(
                            "virtual entry enters a nonentry block",
                        ));
                    }
                    entry = node;
                }
                stats.parallel_copies += copies.len();
                stats.temporaries = stats.temporaries.max(schedule.temporary_count());
                blocks.push(PhiCopyBlock {
                    node,
                    predecessor,
                    target,
                    moves: start..moves.len(),
                });
            }
        }
        if stats.phi_operands != phi_operands {
            return Err(PhiLoweringError::InvalidSource(
                "phi operand count disagrees with blocks",
            ));
        }
        let graph = if blocks.is_empty() {
            source.graph().clone()
        } else {
            let edge_count = source.graph().edge_count() + blocks.len(); // Checked before block growth.
            budget.charge(source.node_count())?;
            budget.charge(edge_count)?; // Preflight edge-vector allocation and each push.
            let mut edges = Vec::with_capacity(edge_count);
            for from in 0..source.node_count() {
                for &to in source.graph().successors(from)? {
                    budget.tree(blocks.len())?;
                    if let Some(&via) = redirects.get(&(Predecessor::Node(from), to)) {
                        edges.push((from, via));
                        edges.push((via, to));
                    } else {
                        edges.push((from, to));
                    }
                }
            }
            budget.charge(blocks.len())?;
            for block in &blocks {
                if block.predecessor == Predecessor::Entry {
                    edges.push((block.node, block.target));
                }
            }
            if edges.len() != edge_count {
                return Err(PhiLoweringError::InvalidSource(
                    "copy block does not match a source edge",
                ));
            }
            Arc::new(Graph::new(
                source.node_count() + blocks.len(),
                edges,
                limits.graph,
            )?)
        };
        stats.copy_blocks = blocks.len();
        stats.moves = moves.len();
        stats.graph_rebuilt = !blocks.is_empty();
        stats.work = budget.work;
        Ok(Self {
            source,
            graph,
            entry,
            blocks,
            moves,
            redirects,
            limits,
            stats,
        })
    }

    pub fn source(&self) -> &Arc<Ssa> {
        &self.source
    }
    pub fn graph(&self) -> &Arc<Graph> {
        &self.graph
    }
    pub fn entry(&self) -> NodeId {
        self.entry
    }
    pub fn limits(&self) -> PhiLoweringLimits {
        self.limits
    }
    pub fn stats(&self) -> PhiLoweringStats {
        self.stats
    }
    pub fn copy_blocks(&self) -> &[PhiCopyBlock] {
        &self.blocks
    }
    pub fn moves(&self) -> &[CopyMove] {
        &self.moves
    }

    /// A copy block for the original semantic edge, or None when it needs no
    /// copies (or does not exist). Entry denotes the one-shot prologue.
    pub fn copy_block_for(&self, predecessor: Predecessor, target: NodeId) -> Option<NodeId> {
        self.redirects.get(&(predecessor, target)).copied()
    }

    pub fn node(&self, node: NodeId) -> Option<LoweredNode<'_>> {
        if node < self.source.node_count() {
            Some(match &self.source.blocks()[node] {
                Block::Reachable(block) => LoweredNode::Block {
                    source: node,
                    statements: block.statements(),
                },
                Block::Unreachable { statement_count } => LoweredNode::Unreachable {
                    source: node,
                    statement_count: *statement_count,
                },
            })
        } else {
            self.blocks
                .get(node - self.source.node_count())
                .map(LoweredNode::Copies)
        }
    }

    /// Scheduled moves of a synthetic copy block; None for original or invalid
    /// nodes. No caller-supplied range or node can index outside the snapshot.
    pub fn block_moves(&self, node: NodeId) -> Option<&[CopyMove]> {
        let block = self
            .blocks
            .get(node.checked_sub(self.source.node_count())?)?;
        Some(&self.moves[block.moves.clone()])
    }
}

fn limit(resource: PhiLoweringResource) -> PhiLoweringError {
    PhiLoweringError::LimitExceeded { resource }
}

fn graph_limit(resource: ghidra_graph::Resource) -> PhiLoweringError {
    PhiLoweringError::Graph(ghidra_graph::Error::LimitExceeded { resource })
}

fn graph_shape(nodes: usize, edges: usize, limits: ghidra_graph::Limits) -> Result<()> {
    if nodes > limits.max_nodes {
        return Err(graph_limit(ghidra_graph::Resource::Nodes));
    }
    if edges > limits.max_edges {
        return Err(graph_limit(ghidra_graph::Resource::Edges));
    }
    Ok(())
}

struct Budget {
    maximum: u64,
    work: u64,
}

impl Budget {
    fn add_work(&mut self, work: u64) -> Result<()> {
        self.work = self
            .work
            .checked_add(work)
            .filter(|n| *n <= self.maximum)
            .ok_or_else(|| limit(PhiLoweringResource::Work))?;
        Ok(())
    }
    fn charge(&mut self, amount: usize) -> Result<()> {
        self.add_work(u64::try_from(amount).map_err(|_| limit(PhiLoweringResource::Work))?)
    }
    fn tree(&mut self, maximum_entries: usize) -> Result<()> {
        self.charge(1 + (usize::BITS - maximum_entries.leading_zeros()) as usize)
    }
}
