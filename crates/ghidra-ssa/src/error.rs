use std::fmt;

use ghidra_graph::NodeId;

use crate::model::{
    DefinitionSite, OperandSite, PhiId, PhiOperandSite, StatementId, UseSite, ValueId, VariableId,
};

pub type Result<T> = std::result::Result<T, Error>;

/// SSA limits. Graph analyses use the graph's own `ghidra_graph::Limits`.
///
/// `max_work` is a fresh budget for each construction (`Ssa::construct`,
/// `Ssa::construct_pruned`, `Ssa::construct_with`) or `Ssa::verify` call. Each
/// of those calls also runs two graph analyses with their own per-call graph
/// budgets; see the crate documentation for the aggregate bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    /// Declared variables, including variables that are never referenced.
    pub max_variables: usize,
    /// Raw statements across all nodes, including unreachable nodes.
    pub max_statements: usize,
    /// Raw use plus def operand references across all nodes.
    pub max_operands: usize,
    /// SSA values: one entry value per variable, plus phis and reachable defs.
    pub max_values: usize,
    pub max_phis: usize,
    /// Sum of phi arities (incoming operands) across all phis.
    pub max_phi_operands: usize,
    /// Pruned placement only: live-in (reachable block, variable) pairs
    /// computed, counted per call. Liveness is computed only for variables
    /// whose definitions have a non-empty dominance frontier. Unpruned
    /// construction and verification never use it.
    pub max_live_ins: usize,
    pub max_work: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_variables: 1_000_000,
            max_statements: 4_000_000,
            max_operands: 16_000_000,
            max_values: 16_000_000,
            max_phis: 4_000_000,
            max_phi_operands: 16_000_000,
            max_live_ins: 16_000_000,
            max_work: 200_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resource {
    Variables,
    Statements,
    Operands,
    Values,
    Phis,
    PhiOperands,
    LiveIns,
    Work,
}

/// A structural invariant that `Ssa::verify` found broken.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Violation {
    /// The raw program, block table, or a statement arity disagrees with the
    /// SSA result. `node` is `None` for whole-program mismatches.
    InputShape {
        node: Option<NodeId>,
    },
    ImmediateDominator {
        node: NodeId,
    },
    /// Reachable/unreachable status disagrees with recomputed dominance.
    Reachability {
        node: NodeId,
    },
    /// The incoming list is not the canonical reachable-predecessor order.
    Incoming {
        node: NodeId,
    },
    /// Phis are not strictly ascending by valid variable.
    PhiOrder {
        phi: PhiId,
    },
    PhiArity {
        phi: PhiId,
    },
    UnknownValue {
        value: ValueId,
    },
    /// A value's origin does not round-trip to the one slot that defines it.
    ValueOrigin {
        value: ValueId,
    },
    EntryValue {
        variable: VariableId,
    },
    DefinitionVariable {
        site: DefinitionSite,
    },
    UseVariable {
        site: UseSite,
    },
    /// The used value's definition does not dominate the use.
    UseNotDominated {
        site: UseSite,
    },
    PhiOperandVariable {
        site: PhiOperandSite,
    },
    /// The operand's definition does not dominate the end of its predecessor.
    PhiOperandNotDominating {
        site: PhiOperandSite,
    },
    /// A virtual entry operand is not the variable's entry value.
    EntryOperand {
        site: PhiOperandSite,
    },
    /// A use does not read the nearest reaching definition.
    StaleUse {
        site: UseSite,
        expected: ValueId,
        actual: ValueId,
    },
    /// A phi operand is not the value live at the end of its predecessor.
    StalePhiOperand {
        site: PhiOperandSite,
        expected: ValueId,
        actual: ValueId,
    },
    /// A definition (or phi) of `variable` reaches `node` through a dominance
    /// frontier edge, but `node` has no phi for it. With pruned placement this
    /// is reported only when `variable` is live on entry to `node`.
    MissingPhi {
        node: NodeId,
        variable: VariableId,
    },
    /// Pruned placement only: a phi of a variable that is not live on entry
    /// to its block.
    DeadPhi {
        phi: PhiId,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// A graph analysis failed, including its own per-call work budget.
    Graph(ghidra_graph::Error),
    InvalidNode {
        node: NodeId,
        node_count: usize,
    },
    /// The raw program must have exactly one statement list per graph node.
    BlockCount {
        node_count: usize,
        blocks: usize,
    },
    InvalidVariable {
        variable: VariableId,
        variable_count: usize,
    },
    /// A raw operand names an undeclared variable.
    InvalidOperand {
        site: OperandSite,
        variable: VariableId,
        variable_count: usize,
    },
    /// A statement defines the same variable more than once.
    DuplicateDefinition {
        statement: StatementId,
        variable: VariableId,
    },
    InvalidValue {
        value: ValueId,
        value_count: usize,
    },
    InvalidStatement {
        statement: StatementId,
    },
    InvalidPhi {
        phi: PhiId,
    },
    /// No partial result is produced.
    LimitExceeded {
        resource: Resource,
    },
    Verification(Violation),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Graph(error) => write!(f, "graph analysis failed: {error}"),
            Self::InvalidNode { node, node_count } => {
                write!(f, "node {node} is outside 0..{node_count}")
            }
            Self::BlockCount { node_count, blocks } => write!(
                f,
                "raw program has {blocks} statement lists for {node_count} graph nodes"
            ),
            Self::InvalidVariable {
                variable,
                variable_count,
            } => write!(f, "variable {} is outside 0..{variable_count}", variable.0),
            Self::InvalidOperand {
                site,
                variable,
                variable_count,
            } => write!(
                f,
                "operand {site:?} names variable {} outside 0..{variable_count}",
                variable.0
            ),
            Self::DuplicateDefinition {
                statement,
                variable,
            } => write!(
                f,
                "statement {statement:?} defines variable {} more than once",
                variable.0
            ),
            Self::InvalidValue { value, value_count } => {
                write!(f, "value {} is outside 0..{value_count}", value.0)
            }
            Self::InvalidStatement { statement } => {
                write!(f, "no renamed statement {statement:?}")
            }
            Self::InvalidPhi { phi } => write!(f, "no phi {phi:?}"),
            Self::LimitExceeded { resource } => write!(f, "{resource:?} limit exceeded"),
            Self::Verification(violation) => write!(f, "SSA verification failed: {violation:?}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Graph(error) => Some(error),
            _ => None,
        }
    }
}

impl From<ghidra_graph::Error> for Error {
    fn from(error: ghidra_graph::Error) -> Self {
        Self::Graph(error)
    }
}

pub(crate) fn limit(resource: Resource) -> Error {
    Error::LimitExceeded { resource }
}

pub(crate) fn violation(violation: Violation) -> Error {
    Error::Verification(violation)
}

/// Add `amount` to a running total, failing before it would exceed `maximum`.
pub(crate) fn account(
    total: &mut usize,
    amount: usize,
    maximum: usize,
    resource: Resource,
) -> Result<()> {
    let next = total.checked_add(amount).ok_or_else(|| limit(resource))?;
    if next > maximum {
        return Err(limit(resource));
    }
    *total = next;
    Ok(())
}

/// Deterministic abstract work units for one public call.
pub(crate) struct Budget {
    remaining: u64,
    used: u64,
}

impl Budget {
    pub(crate) fn new(maximum: u64) -> Self {
        Self {
            remaining: maximum,
            used: 0,
        }
    }

    pub(crate) fn used(&self) -> u64 {
        self.used
    }

    pub(crate) fn charge(&mut self, amount: usize) -> Result<()> {
        let amount = u64::try_from(amount).map_err(|_| limit(Resource::Work))?;
        self.remaining = self
            .remaining
            .checked_sub(amount)
            .ok_or_else(|| limit(Resource::Work))?;
        // used + remaining is invariant and equals the original maximum.
        self.used += amount;
        Ok(())
    }

    pub(crate) fn tick(&mut self) -> Result<()> {
        self.charge(1)
    }

    /// `ceil(log2(n + 1)) + 1`: one binary search over `n` items.
    pub(crate) fn search(&mut self, n: usize) -> Result<()> {
        self.charge((usize::BITS - n.leading_zeros()) as usize + 1)
    }

    /// Precharge a conservative `n * (ceil(log2(n)) + 1)` sorting allowance.
    pub(crate) fn sorting(&mut self, n: usize) -> Result<()> {
        if n > 1 {
            let levels = (usize::BITS - (n - 1).leading_zeros()) as usize + 1;
            self.charge(n.checked_mul(levels).ok_or_else(|| limit(Resource::Work))?)?;
        }
        Ok(())
    }
}
