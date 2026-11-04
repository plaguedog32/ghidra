use ghidra_graph::NodeId;

/// Dense caller-declared variable identity: valid IDs are `0..variable_count`.
///
/// The engine attaches no meaning to a variable. A caller decides what one
/// stands for (a register, a stack slot, a temporary) and must resolve any
/// aliasing or partial overlap before construction.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct VariableId(pub usize);

/// Dense SSA value identity: valid IDs are `0..Ssa::values().len()`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ValueId(pub usize);

/// What a variable holds when execution enters the function.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum EntryState {
    /// A caller-supplied input (a parameter or live-in machine state).
    Input,
    /// Explicitly undefined. It is never replaced by an invented constant.
    Undefined,
}

/// Where phis are placed. Both modes place them only at the iterated
/// dominance frontier of a variable's reachable definitions.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub enum PhiPlacement {
    /// Every iterated-frontier block gets a phi, live or not, so some phis
    /// can be dead. This is what `Ssa::construct` builds.
    #[default]
    Unpruned,
    /// Only iterated-frontier blocks where the variable is live on entry get
    /// a phi: some entry path through the block reads the variable before
    /// any raw statement writes it. No phi is dead. Built by
    /// `Ssa::construct_pruned`.
    Pruned,
}

/// One raw statement: read every `uses` operand, then write every `defs` operand.
///
/// Uses may repeat a variable; each occurrence is an independent use slot. Defs
/// are simultaneous, so a variable may occur at most once in `defs`. A variable
/// may be both read and written: the read observes the value from before the
/// statement.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RawStatement {
    pub uses: Vec<VariableId>,
    pub defs: Vec<VariableId>,
}

impl RawStatement {
    pub fn new(
        uses: impl IntoIterator<Item = VariableId>,
        defs: impl IntoIterator<Item = VariableId>,
    ) -> Self {
        Self {
            uses: uses.into_iter().collect(),
            defs: defs.into_iter().collect(),
        }
    }
}

/// Raw, pre-SSA input. `blocks[node]` is the ordered statement list of graph node
/// `node`; every graph node needs an entry, even when it is empty.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RawProgram {
    /// Entry state of each variable, indexed by `VariableId`.
    pub variables: Vec<EntryState>,
    pub blocks: Vec<Vec<RawStatement>>,
}

/// Stable statement identity: graph node plus index in that node's statement list.
/// It is identical in the raw program and the renamed output.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct StatementId {
    pub node: NodeId,
    pub index: usize,
}

/// Position of a definition: statement plus index into its `defs`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct DefinitionSite {
    pub statement: StatementId,
    pub slot: usize,
}

/// Position of a use: statement plus index into its `uses`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct UseSite {
    pub statement: StatementId,
    pub slot: usize,
}

/// A raw operand location, reported by input validation errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum OperandSite {
    Use(UseSite),
    Definition(DefinitionSite),
}

/// Phi identity: node plus index in that node's phi list. Within a node, phis
/// are sorted by strictly ascending variable, so there is at most one per variable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PhiId {
    pub node: NodeId,
    pub index: usize,
}

/// One incoming operand of a phi, aligned with `RenamedBlock::incoming()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PhiOperandSite {
    pub phi: PhiId,
    pub operand: usize,
}

/// Where control enters a reachable block.
///
/// `Entry` is the virtual function-entry edge. It exists only for the entry
/// node, and is listed even when the entry also has real (back) edges. The
/// derived order puts `Entry` before every `Node`, so incoming lists are sorted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum Predecessor {
    Entry,
    Node(NodeId),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ValueOrigin {
    /// The variable's value on function entry, with its declared state.
    Entry(EntryState),
    Phi(PhiId),
    Definition(DefinitionSite),
}

/// An SSA value: one static definition of one variable.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct Value {
    pub variable: VariableId,
    pub origin: ValueOrigin,
}

/// A phi of one variable at the top of a reachable block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Phi {
    pub(crate) variable: VariableId,
    pub(crate) value: ValueId,
    pub(crate) operands: Vec<ValueId>,
}

impl Phi {
    pub fn variable(&self) -> VariableId {
        self.variable
    }

    /// The value this phi defines.
    pub fn value(&self) -> ValueId {
        self.value
    }

    /// One operand per incoming edge, aligned with `RenamedBlock::incoming()`.
    pub fn operands(&self) -> &[ValueId] {
        &self.operands
    }
}

/// A raw statement with every operand replaced by an SSA value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenamedStatement {
    pub(crate) uses: Vec<ValueId>,
    pub(crate) defs: Vec<ValueId>,
}

impl RenamedStatement {
    /// Same length and order as the raw `uses`.
    pub fn uses(&self) -> &[ValueId] {
        &self.uses
    }

    /// Same length and order as the raw `defs`; each is a fresh value.
    pub fn defs(&self) -> &[ValueId] {
        &self.defs
    }
}

/// Renamed contents of an entry-reachable block.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RenamedBlock {
    pub(crate) incoming: Vec<Predecessor>,
    pub(crate) phis: Vec<Phi>,
    pub(crate) statements: Vec<RenamedStatement>,
}

impl RenamedBlock {
    /// `Entry` first for the entry node, then reachable graph predecessors in
    /// ascending order. Entry-unreachable predecessors are omitted.
    pub fn incoming(&self) -> &[Predecessor] {
        &self.incoming
    }

    /// Operand index of an incoming edge, or `None` if it does not enter here.
    pub fn incoming_index(&self, predecessor: Predecessor) -> Option<usize> {
        self.incoming.binary_search(&predecessor).ok()
    }

    pub fn phis(&self) -> &[Phi] {
        &self.phis
    }

    /// The phi of a variable, if this block has one, with its index.
    pub fn phi_for(&self, variable: VariableId) -> Option<(usize, &Phi)> {
        let index = self
            .phis
            .binary_search_by_key(&variable, |phi| phi.variable)
            .ok()?;
        Some((index, &self.phis[index]))
    }

    pub fn statements(&self) -> &[RenamedStatement] {
        &self.statements
    }
}

/// Per-node output. Unreachable nodes are explicit and never renamed: they
/// have no phis, renamed statements, incoming list, or SSA values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Block {
    /// Not reachable from the entry. `statement_count` is the validated number
    /// of raw statements, which remain only in the caller's `RawProgram`.
    Unreachable {
        statement_count: usize,
    },
    Reachable(RenamedBlock),
}

impl Block {
    pub fn is_reachable(&self) -> bool {
        matches!(self, Self::Reachable(_))
    }

    pub fn renamed(&self) -> Option<&RenamedBlock> {
        match self {
            Self::Reachable(block) => Some(block),
            Self::Unreachable { .. } => None,
        }
    }
}
