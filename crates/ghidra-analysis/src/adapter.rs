use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ghidra_cfg::{Arrival, Cfg, EdgeId, ProgramPoint, Statement};
use ghidra_graph::{Graph, NodeId};
use ghidra_pcode::{PcodeOperation, SpaceKind, Varnode};
use ghidra_ssa::{
    EntryState, PhiPlacement, RawProgram, RawStatement, Ssa, StatementId, VariableId,
};
use thiserror::Error;

use crate::{
    EffectClass, Lifetime, OperationBindings, StorageError, StorageId, StorageLayout,
    StorageLimits, StorageLocation, UniqueScope,
};

/// Unknown semantics must be rejected or retained as an explicit opaque state
/// transformation. Neither choice treats a call or userop as a pure operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UnknownEffectPolicy {
    Reject,
    /// Read and redefine every variable in the observed storage domain. The
    /// operation remains opaque; this does not resolve its control flow or ABI.
    HavocAll,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryPolicy {
    pub registers: EntryState,
    pub program_uniques: EntryState,
    pub memory: EntryState,
}

impl Default for EntryPolicy {
    fn default() -> Self {
        Self {
            registers: EntryState::Input,
            program_uniques: EntryState::Undefined,
            memory: EntryState::Input,
        }
    }
}

/// Temporary lifetime is required explicitly. Instruction-scoped temporaries
/// always start undefined, regardless of the program-unique entry policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AnalysisOptions {
    pub unique_scope: UniqueScope,
    pub unknown_effects: UnknownEffectPolicy,
    pub entry: EntryPolicy,
    /// Pruning omits phis for storage that is dead on entry to the join.
    pub phi_placement: PhiPlacement,
}

impl AnalysisOptions {
    pub fn native() -> Self {
        Self {
            unique_scope: UniqueScope::Instruction,
            unknown_effects: UnknownEffectPolicy::Reject,
            entry: EntryPolicy::default(),
            phi_placement: PhiPlacement::Pruned,
        }
    }

    pub fn pcode_program() -> Self {
        Self {
            unique_scope: UniqueScope::Program,
            ..Self::native()
        }
    }
}

/// Budgets for the adapter are separate from storage construction, graph
/// construction/analysis, and SSA. Every nested phase has its own finite budget.
#[derive(Clone, Copy, Debug)]
pub struct AnalysisLimits {
    pub max_nodes: usize,
    /// Semantic edge records after splitting instruction-entry edges.
    pub max_edges: usize,
    pub max_statements: usize,
    /// A conservative preallocation bound: operand widths in bytes plus operand
    /// records. It can reject an input before the actual partition count does.
    pub max_binding_parts: usize,
    /// Exact raw SSA use/definition references, including resets and havoc.
    pub max_operand_refs: usize,
    pub max_work: u64,
    pub storage: StorageLimits,
    pub graph: ghidra_graph::Limits,
    pub ssa: ghidra_ssa::Limits,
}

impl Default for AnalysisLimits {
    fn default() -> Self {
        Self {
            max_nodes: 1_000_000,
            max_edges: 2_000_000,
            max_statements: 1_000_000,
            max_binding_parts: 8_000_000,
            max_operand_refs: 8_000_000,
            max_work: 100_000_000,
            storage: StorageLimits::default(),
            graph: ghidra_graph::Limits::default(),
            ssa: ghidra_ssa::Limits::default(),
        }
    }
}

#[derive(Debug, Error)]
pub enum AnalysisError {
    #[error("P-code SSA limit exceeded: {0}")]
    Limit(&'static str),
    #[error("{effects:?} at {point} needs an explicit effect policy")]
    UnknownEffects {
        point: ProgramPoint,
        effects: EffectClass,
    },
    #[error(transparent)]
    Storage(#[from] StorageError),
    #[error(transparent)]
    Graph(#[from] ghidra_graph::Error),
    #[error(transparent)]
    Ssa(#[from] ghidra_ssa::Error),
}

type Result<T> = std::result::Result<T, AnalysisError>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppliedEffects {
    Explicit,
    Conservative(EffectClass),
}

/// Metadata for every raw statement, including unreachable statements. SSA
/// drops unreachable renamed statements; these source records remain intact.
#[derive(Clone, Debug)]
pub enum AdaptedStatement {
    Operation {
        point: ProgramPoint,
        bindings: OperationBindings,
        effects: AppliedEffects,
    },
    NoOp {
        point: ProgramPoint,
    },
    /// These definitions mean undefined fresh state, never zero or a copy of
    /// the preceding frame. They must not be evaluated as ordinary assignments.
    UndefinedTemporaries {
        address: u64,
        variables: Vec<StorageId>,
    },
}

/// Owned P-code-to-SSA bridge. Original CFG node IDs and terminal exits retain
/// their IDs. Synthetic reset nodes, when needed, are appended to the graph.
#[derive(Debug)]
pub struct PcodeSsa {
    cfg: Arc<Cfg>,
    layout: StorageLayout,
    raw: RawProgram,
    ssa: Ssa,
    statements: Vec<Vec<AdaptedStatement>>,
    points: BTreeMap<ProgramPoint, StatementId>,
    edge_resets: Vec<Option<NodeId>>,
    options: AnalysisOptions,
    work: u64,
}

struct BuildBudget {
    remaining: u64,
    statements: usize,
    bindings: usize,
    refs: usize,
    limits: AnalysisLimits,
}

fn add(count: &mut usize, amount: usize, maximum: usize, name: &'static str) -> Result<()> {
    *count = count
        .checked_add(amount)
        .filter(|&n| n <= maximum)
        .ok_or(AnalysisError::Limit(name))?;
    Ok(())
}

impl BuildBudget {
    fn charge(&mut self, amount: usize) -> Result<()> {
        self.remaining = self
            .remaining
            .checked_sub(u64::try_from(amount).map_err(|_| AnalysisError::Limit("work"))?)
            .ok_or(AnalysisError::Limit("work"))?;
        Ok(())
    }

    fn map(&mut self, count: usize) -> Result<()> {
        self.charge((usize::BITS - count.leading_zeros()) as usize + 1)
    }

    fn statement(&mut self, refs: usize) -> Result<()> {
        add(
            &mut self.statements,
            1,
            self.limits.max_statements,
            "statements",
        )?;
        add(
            &mut self.refs,
            refs,
            self.limits.max_operand_refs,
            "operand references",
        )?;
        self.charge(refs.saturating_add(1))
    }

    // Bound expansion before layout.operation allocates per-alias bindings.
    fn operation(&mut self, op: &PcodeOperation, spaces: usize, instructions: usize) -> Result<()> {
        let mut bound = 2usize; // An implicit LOAD/STORE token and output token.
        for node in op.inputs.iter().chain(op.output.iter()) {
            self.charge(1)?;
            bound = bound
                .checked_add(node.size as usize + 1)
                .ok_or(AnalysisError::Limit("binding parts"))?;
        }
        add(
            &mut self.bindings,
            bound,
            self.limits.max_binding_parts,
            "binding parts",
        )?;
        // Covers binding lookup, scalar pieces, declared def/use construction
        // and copies. Ordered-map charges include a worst-case domain height.
        let height: usize = [self.limits.storage.max_variables, spaces, instructions]
            .into_iter()
            .map(|count| (usize::BITS - count.leading_zeros()) as usize + 2)
            .sum();
        self.charge(
            bound
                .checked_mul(height)
                .ok_or(AnalysisError::Limit("work"))?,
        )
    }
}

impl PcodeSsa {
    /// Extra register aliases can expose architecture/ABI state not explicitly
    /// named by the supplied operations. They participate in partitions and
    /// conservative effects. No architectural aliases or call ABI are guessed.
    pub fn new(
        cfg: Arc<Cfg>,
        extra_registers: &[Varnode],
        options: AnalysisOptions,
        limits: AnalysisLimits,
    ) -> Result<Self> {
        if cfg.node_count() > limits.max_nodes {
            return Err(AnalysisError::Limit("nodes"));
        }
        if cfg.edges().len() > limits.max_edges {
            return Err(AnalysisError::Limit("edges"));
        }
        if cfg.points().len() > limits.max_statements {
            return Err(AnalysisError::Limit("statements"));
        }
        let mut budget = BuildBudget {
            remaining: limits.max_work,
            statements: 0,
            bindings: 0,
            refs: 0,
            limits,
        };
        budget.charge(cfg.node_count())?;
        let layout = StorageLayout::build(
            cfg.spaces(),
            cfg.instructions(),
            extra_registers,
            options.unique_scope,
            limits.storage,
        )?;
        let mut register_spaces = BTreeSet::new();
        for space in cfg.spaces() {
            budget.map(cfg.spaces().len())?;
            if space.kind == SpaceKind::Register {
                register_spaces.insert(space.id);
            }
        }
        let mut temporaries: BTreeMap<u64, Vec<StorageId>> = BTreeMap::new();
        let mut states = Vec::with_capacity(layout.variables().len());
        for variable in layout.variables() {
            budget.charge(1)?;
            let state = match variable.location {
                StorageLocation::Scalar { bank, .. } => match bank.lifetime {
                    Lifetime::Instruction(address) => {
                        budget.map(cfg.instructions().len())?;
                        temporaries.entry(address).or_default().push(variable.id);
                        EntryState::Undefined
                    }
                    Lifetime::Program => {
                        budget.map(register_spaces.len())?;
                        if register_spaces.contains(&bank.space) {
                            options.entry.registers
                        } else {
                            options.entry.program_uniques
                        }
                    }
                },
                StorageLocation::Memory { .. } => options.entry.memory,
            };
            states.push(state);
        }

        // Split only instruction-entry edges whose destination has temporaries.
        // A relative branch to op 0 can share the very same CFG endpoints with
        // a native self-jump, so the semantic edges must be examined separately.
        let mut node_count = cfg.node_count();
        let mut edge_count = cfg.edges().len();
        let mut edge_resets = Vec::with_capacity(cfg.edges().len());
        for edge in cfg.edges() {
            budget.charge(1)?;
            let address = cfg.block_points(edge.to).map(|p| p[0].address);
            let reset = if edge.arrival == Arrival::InstructionEntry
                && let Some(address) = address
            {
                budget.map(temporaries.len())?;
                temporaries.contains_key(&address)
            } else {
                false
            };
            if reset {
                let node = node_count;
                add(&mut node_count, 1, limits.max_nodes, "nodes")?;
                add(&mut edge_count, 1, limits.max_edges, "edges")?;
                edge_resets.push(Some(node));
            } else {
                edge_resets.push(None);
            }
        }
        budget.charge(node_count)?;
        let mut raw = RawProgram {
            variables: states,
            blocks: vec![Vec::new(); node_count],
        };
        let mut statements = vec![Vec::new(); node_count];
        let mut points = BTreeMap::new();
        for (node, (raw_block, records)) in raw
            .blocks
            .iter_mut()
            .zip(statements.iter_mut())
            .take(cfg.block_count())
            .enumerate()
        {
            let mut address = None;
            for &point in cfg.block_points(node).expect("CFG block") {
                budget.charge(1)?;
                if address.is_some_and(|previous| previous != point.address) {
                    budget.map(temporaries.len())?;
                    if let Some(variables) = temporaries.get(&point.address) {
                        push_reset(raw_block, records, point.address, variables, &mut budget)?;
                    }
                }
                address = Some(point.address);
                let (statement, origin) = match cfg.statement(point).expect("CFG point") {
                    Statement::NoOp => {
                        budget.statement(0)?;
                        (RawStatement::default(), AdaptedStatement::NoOp { point })
                    }
                    Statement::Operation(operation) => {
                        budget.operation(
                            operation,
                            cfg.spaces().len(),
                            cfg.instructions().len(),
                        )?;
                        let bindings = layout.operation(point.address, operation)?;
                        let effects = bindings.effects;
                        if effects != EffectClass::Explicit
                            && options.unknown_effects == UnknownEffectPolicy::Reject
                        {
                            return Err(AnalysisError::UnknownEffects { point, effects });
                        }
                        let declared = bindings.declared_def_use()?;
                        let conservative = effects != EffectClass::Explicit;
                        let count = declared
                            .uses
                            .len()
                            .checked_add(
                                if conservative {
                                    layout.variables().len().checked_mul(2)
                                } else {
                                    Some(declared.definitions.len())
                                }
                                .ok_or(AnalysisError::Limit("operand references"))?,
                            )
                            .ok_or(AnalysisError::Limit("operand references"))?;
                        budget.statement(count)?;
                        let mut uses: Vec<_> =
                            declared.uses.into_iter().map(|v| VariableId(v.0)).collect();
                        let defs = if conservative {
                            uses.extend(layout.variables().iter().map(|v| VariableId(v.id.0)));
                            layout
                                .variables()
                                .iter()
                                .map(|v| VariableId(v.id.0))
                                .collect()
                        } else {
                            declared
                                .definitions
                                .into_iter()
                                .map(|v| VariableId(v.0))
                                .collect()
                        };
                        (
                            RawStatement { uses, defs },
                            AdaptedStatement::Operation {
                                point,
                                bindings,
                                effects: if conservative {
                                    AppliedEffects::Conservative(effects)
                                } else {
                                    AppliedEffects::Explicit
                                },
                            },
                        )
                    }
                };
                budget.map(cfg.points().len())?;
                points.insert(
                    point,
                    StatementId {
                        node,
                        index: raw_block.len(),
                    },
                );
                raw_block.push(statement);
                records.push(origin);
            }
        }
        let mut edges = Vec::with_capacity(edge_count);
        for (id, edge) in cfg.edges().iter().enumerate() {
            budget.charge(2)?;
            if let Some(reset) = edge_resets[id] {
                let address = cfg.block_points(edge.to).expect("instruction entry")[0].address;
                budget.map(temporaries.len())?;
                push_reset(
                    &mut raw.blocks[reset],
                    &mut statements[reset],
                    address,
                    &temporaries[&address],
                    &mut budget,
                )?;
                edges.extend([(edge.from, reset), (reset, edge.to)]);
            } else {
                edges.push((edge.from, edge.to));
            }
        }
        let graph = Arc::new(Graph::new(node_count, edges, limits.graph)?);
        let ssa = Ssa::construct_with(graph, cfg.entry(), &raw, limits.ssa, options.phi_placement)?;
        Ok(Self {
            cfg,
            layout,
            raw,
            ssa,
            statements,
            points,
            edge_resets,
            options,
            work: limits.max_work - budget.remaining,
        })
    }

    pub fn cfg(&self) -> &Arc<Cfg> {
        &self.cfg
    }
    pub fn layout(&self) -> &StorageLayout {
        &self.layout
    }
    pub fn raw(&self) -> &RawProgram {
        &self.raw
    }
    pub fn ssa(&self) -> &Ssa {
        &self.ssa
    }
    pub fn options(&self) -> AnalysisOptions {
        self.options
    }
    /// Adapter work only, excluding its bounded nested construction phases.
    pub fn build_work(&self) -> u64 {
        self.work
    }
    pub fn statement_id(&self, point: ProgramPoint) -> Option<StatementId> {
        self.points.get(&point).copied()
    }
    pub fn statement(&self, id: StatementId) -> Option<&AdaptedStatement> {
        self.statements.get(id.node)?.get(id.index)
    }
    /// An original semantic CFG edge follows `from -> reset -> to` when this
    /// returns a node, and `from -> to` otherwise. Invalid edge IDs return None.
    pub fn edge_reset(&self, edge: EdgeId) -> Option<NodeId> {
        self.edge_resets.get(edge).copied().flatten()
    }
}

fn push_reset(
    raw: &mut Vec<RawStatement>,
    statements: &mut Vec<AdaptedStatement>,
    address: u64,
    variables: &[StorageId],
    budget: &mut BuildBudget,
) -> Result<()> {
    budget.statement(variables.len())?;
    raw.push(RawStatement {
        uses: Vec::new(),
        defs: variables.iter().map(|v| VariableId(v.0)).collect(),
    });
    statements.push(AdaptedStatement::UndefinedTemporaries {
        address,
        variables: variables.to_vec(),
    });
    Ok(())
}
