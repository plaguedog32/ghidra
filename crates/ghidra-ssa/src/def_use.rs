use std::fmt;

use crate::construct::Ssa;
use crate::error::Budget;
use crate::model::{Block, PhiId, PhiOperandSite, PhiPlacement, StatementId, UseSite, ValueId};

/// Limits for building one `DefUseIndex`. They are separate from the SSA
/// construction `Limits`, so an index can be refused for an SSA result that
/// fit its own limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DefUseLimits {
    /// SSA values indexed, `Ssa::values().len()`. Two offset arrays of
    /// `values + 1` entries are allocated only after this check.
    pub max_values: usize,
    /// Use records stored: ordinary statement uses plus phi operands. The site
    /// arrays are allocated only after the whole count fits.
    pub max_uses: usize,
    /// Fresh deterministic work budget for one `DefUseIndex::new` call.
    pub max_work: u64,
}

impl Default for DefUseLimits {
    fn default() -> Self {
        Self {
            max_values: 16_000_000,
            max_uses: 32_000_000,
            max_work: 200_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum DefUseResource {
    Values,
    Uses,
    Work,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DefUseError {
    /// A `DefUseLimits` cap was reached. No partial index is produced.
    LimitExceeded { resource: DefUseResource },
    /// A lookup named a value outside `0..value_count`. Building also reports
    /// this for an operand outside the value table, which a result made by
    /// `Ssa::construct*` never contains.
    InvalidValue { value: ValueId, value_count: usize },
}

pub type DefUseResult<T> = std::result::Result<T, DefUseError>;

impl fmt::Display for DefUseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded { resource } => {
                write!(f, "def-use {resource:?} limit exceeded")
            }
            Self::InvalidValue { value, value_count } => {
                write!(f, "value {} is outside 0..{value_count}", value.0)
            }
        }
    }
}

impl std::error::Error for DefUseError {}

/// Owned def-use index of one `Ssa` snapshot: for every `ValueId`, every
/// renamed statement operand and every phi operand that reads it.
///
/// Built by `DefUseIndex::new` in two linear passes over reachable blocks
/// (count, then fill) into compressed sparse rows: two offset arrays of
/// `value_count + 1` entries and two flat site arrays, one entry per operand
/// reference. Nothing borrows the `Ssa`; the index is `Send + Sync`, `Clone`,
/// and may outlive its source.
///
/// **Coverage.** Every slot is listed separately, so a statement that reads
/// a value twice yields two `UseSite`s and a phi with the same value on two
/// edges yields two `PhiOperandSite`s. Phi operands along the virtual
/// `Predecessor::Entry` edge are included. Unreachable blocks hold no renamed
/// statements or phis, so their raw statements contribute nothing.
///
/// **Order.** `statement_uses(v)` is strictly ascending in `UseSite`'s derived
/// order (node, statement index, slot), and `phi_uses(v)` strictly ascending
/// in `PhiOperandSite`'s derived order (node, phi index, operand index).
/// Equal SSA results give equal indexes.
///
/// **Snapshot.** The index describes exactly the `Ssa` it was built from (or
/// an equal clone). It holds no link to it and cannot detect a different
/// result: lookups only check `ValueId` bounds, so pairing it with another
/// `Ssa` gives meaningless but memory-safe answers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DefUseIndex {
    node_count: usize,
    placement: PhiPlacement,
    limits: DefUseLimits,
    /// `use_start[v]..use_start[v + 1]` indexes `use_sites` for value `v`.
    use_start: Vec<usize>,
    use_sites: Vec<UseSite>,
    /// `phi_start[v]..phi_start[v + 1]` indexes `phi_sites` for value `v`.
    phi_start: Vec<usize>,
    phi_sites: Vec<PhiOperandSite>,
    work: u64,
}

const NO_USE: UseSite = UseSite {
    statement: StatementId { node: 0, index: 0 },
    slot: 0,
};

const NO_PHI_USE: PhiOperandSite = PhiOperandSite {
    phi: PhiId { node: 0, index: 0 },
    operand: 0,
};

fn limit(resource: DefUseResource) -> DefUseError {
    DefUseError::LimitExceeded { resource }
}

/// `Budget` only fails on work, so any error it returns is the work limit.
fn charge(budget: &mut Budget, amount: usize) -> DefUseResult<()> {
    budget
        .charge(amount)
        .map_err(|_| limit(DefUseResource::Work))
}

/// One record per item, plus one for the item itself.
fn charge_item(budget: &mut Budget, operands: usize) -> DefUseResult<()> {
    charge(
        budget,
        operands
            .checked_add(1)
            .ok_or_else(|| limit(DefUseResource::Work))?,
    )
}

/// Count one reference to `value` in `counts[value]`.
fn count(counts: &mut [usize], value: ValueId) -> DefUseResult<()> {
    // `counts` has `value_count + 1` entries; the last is not a value.
    let value_count = counts.len() - 1;
    match counts.get_mut(value.0).filter(|_| value.0 < value_count) {
        // Bounded by the use total, which was already accounted.
        Some(slot) => {
            *slot += 1;
            Ok(())
        }
        None => Err(DefUseError::InvalidValue { value, value_count }),
    }
}

/// Inclusive prefix sum in place: afterwards `counts[v]` is the end of `v`'s
/// row, and `counts[value_count]` (zero before) becomes the total.
fn prefix(counts: &mut [usize], budget: &mut Budget) -> DefUseResult<()> {
    let value_count = counts.len() - 1;
    charge(budget, value_count)?;
    let mut sum = 0usize;
    for slot in &mut counts[..value_count] {
        // Cannot overflow: the sum equals an already-accounted total.
        sum += *slot;
        *slot = sum;
    }
    counts[value_count] = sum;
    Ok(())
}

impl DefUseIndex {
    /// Index every use of every value of `ssa`, within `limits`.
    ///
    /// Checks, in order, before the matching allocation: the value count
    /// against `max_values`; work for the two offset arrays; during the
    /// counting pass, each statement's or phi's operands against `max_uses`
    /// and work; then work for the site arrays and for the fill pass. Any
    /// failure is `DefUseError::LimitExceeded` with no partial index. The
    /// exact work is documented on `work()`. Runs no graph analysis.
    pub fn new(ssa: &Ssa, limits: DefUseLimits) -> DefUseResult<Self> {
        let blocks = ssa.blocks();
        let value_count = ssa.values().len();
        if value_count > limits.max_values {
            return Err(limit(DefUseResource::Values));
        }
        let rows = value_count
            .checked_add(1)
            .ok_or_else(|| limit(DefUseResource::Values))?;
        let mut budget = Budget::new(limits.max_work);
        charge(
            &mut budget,
            rows.checked_mul(2)
                .ok_or_else(|| limit(DefUseResource::Work))?,
        )?;
        let mut use_start = vec![0usize; rows];
        let mut phi_start = vec![0usize; rows];

        // Pass 1: count references per value, accounting every record first.
        let mut total = 0usize;
        let mut account = |amount: usize| -> DefUseResult<()> {
            let next = total
                .checked_add(amount)
                .filter(|&next| next <= limits.max_uses)
                .ok_or_else(|| limit(DefUseResource::Uses))?;
            total = next;
            Ok(())
        };
        charge(&mut budget, blocks.len())?;
        for block in blocks {
            let Block::Reachable(block) = block else {
                continue;
            };
            for phi in &block.phis {
                charge_item(&mut budget, phi.operands.len())?;
                account(phi.operands.len())?;
                for &value in &phi.operands {
                    count(&mut phi_start, value)?;
                }
            }
            for statement in &block.statements {
                charge_item(&mut budget, statement.uses.len())?;
                account(statement.uses.len())?;
                for &value in &statement.uses {
                    count(&mut use_start, value)?;
                }
            }
        }
        prefix(&mut use_start, &mut budget)?;
        prefix(&mut phi_start, &mut budget)?;
        let statement_total = use_start[value_count];
        let phi_total = phi_start[value_count];

        // `total` fit `max_uses`; charge it as the site allocation.
        charge(&mut budget, statement_total + phi_total)?;
        let mut use_sites = vec![NO_USE; statement_total];
        let mut phi_sites = vec![NO_PHI_USE; phi_total];

        // Pass 2: fill in reverse, moving each row end down to its start, so
        // every row comes out in ascending site order.
        charge(&mut budget, blocks.len())?;
        for (node, block) in blocks.iter().enumerate().rev() {
            let Block::Reachable(block) = block else {
                continue;
            };
            for (index, statement) in block.statements.iter().enumerate().rev() {
                charge_item(&mut budget, statement.uses.len())?;
                let statement_id = StatementId { node, index };
                for (slot, value) in statement.uses.iter().enumerate().rev() {
                    // Pass 1 validated `value` and counted this slot.
                    let end = &mut use_start[value.0];
                    *end -= 1;
                    use_sites[*end] = UseSite {
                        statement: statement_id,
                        slot,
                    };
                }
            }
            for (index, phi) in block.phis.iter().enumerate().rev() {
                charge_item(&mut budget, phi.operands.len())?;
                let phi_id = PhiId { node, index };
                for (operand, value) in phi.operands.iter().enumerate().rev() {
                    let end = &mut phi_start[value.0];
                    *end -= 1;
                    phi_sites[*end] = PhiOperandSite {
                        phi: phi_id,
                        operand,
                    };
                }
            }
        }

        Ok(Self {
            node_count: blocks.len(),
            placement: ssa.placement(),
            limits,
            use_start,
            use_sites,
            phi_start,
            phi_sites,
            work: budget.used(),
        })
    }

    /// Number of values indexed; valid lookups are `ValueId(0..value_count)`.
    pub fn value_count(&self) -> usize {
        self.use_start.len() - 1
    }

    /// Node count of the source `Ssa`, for cheap snapshot sanity checks.
    pub fn node_count(&self) -> usize {
        self.node_count
    }

    /// Placement mode of the source `Ssa`.
    pub fn placement(&self) -> PhiPlacement {
        self.placement
    }

    pub fn limits(&self) -> DefUseLimits {
        self.limits
    }

    /// Work units spent by `new`. With `V` values, `N` nodes, and over
    /// reachable blocks `P` phis, `A` phi operands, `S` statements, and `U`
    /// statement uses, it is exactly
    /// `2 + 4V + 2N + 2P + 2S + 3U + 3A`: offset arrays `2(V + 1)`, two
    /// passes of `N + P + A + S + U` each, two prefix sums `2V`, and site
    /// allocation `U + A`.
    pub fn work(&self) -> u64 {
        self.work
    }

    /// Ordinary statement uses stored, `U`.
    pub fn total_statement_uses(&self) -> usize {
        self.use_sites.len()
    }

    /// Phi operands stored, `A`; equals `Ssa::phi_operand_count()`.
    pub fn total_phi_uses(&self) -> usize {
        self.phi_sites.len()
    }

    /// All use records stored, `U + A`; this is what `max_uses` bounds.
    pub fn total_uses(&self) -> usize {
        self.use_sites.len() + self.phi_sites.len()
    }

    /// Every renamed statement operand slot that reads `value`, ascending.
    pub fn statement_uses(&self, value: ValueId) -> DefUseResult<&[UseSite]> {
        let (start, end) = self.row(&self.use_start, value)?;
        Ok(&self.use_sites[start..end])
    }

    /// Every phi operand slot that reads `value`, ascending. Operand `i` of
    /// a phi at node `n` belongs to edge `incoming()[i]` of block `n`, which
    /// may be the virtual `Predecessor::Entry`.
    pub fn phi_uses(&self, value: ValueId) -> DefUseResult<&[PhiOperandSite]> {
        let (start, end) = self.row(&self.phi_start, value)?;
        Ok(&self.phi_sites[start..end])
    }

    /// Statement uses plus phi uses of `value`. Zero means no operand reads it.
    pub fn use_count(&self, value: ValueId) -> DefUseResult<usize> {
        Ok(self.statement_uses(value)?.len() + self.phi_uses(value)?.len())
    }

    fn row(&self, starts: &[usize], value: ValueId) -> DefUseResult<(usize, usize)> {
        let value_count = self.value_count();
        if value.0 >= value_count {
            return Err(DefUseError::InvalidValue { value, value_count });
        }
        Ok((starts[value.0], starts[value.0 + 1]))
    }
}
