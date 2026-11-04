use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// A caller-defined storage slot in `0..ParallelCopySchedule::slot_count()`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CopySlot(pub usize);

/// One assignment in a simultaneous copy of the original slot values.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ParallelCopy {
    pub destination: CopySlot,
    pub source: CopySlot,
}

/// A location used by a sequential copy schedule.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CopyLocation {
    Slot(CopySlot),
    /// One reusable scratch location, initialized by a preceding move.
    Temporary,
}

/// Copy `source` to `destination`, preserving the source value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CopyMove {
    pub source: CopyLocation,
    pub destination: CopyLocation,
}

/// Independent caps for constructing one parallel-copy schedule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CopyLimits {
    /// Size of the caller's slot domain. Storage is sparse in this domain.
    pub max_slots: usize,
    /// Input copies, including identities.
    pub max_copies: usize,
    /// Sequential moves, including saves to the temporary.
    pub max_moves: usize,
    /// Scratch locations; a schedule needs either zero or one.
    pub max_temporaries: usize,
    /// Deterministic abstract work, documented by `ParallelCopySchedule::work`.
    pub max_work: u64,
}

impl Default for CopyLimits {
    fn default() -> Self {
        Self {
            max_slots: 16_000_000,
            max_copies: 16_000_000,
            max_moves: 32_000_000,
            max_temporaries: 1,
            max_work: 200_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum CopyResource {
    Slots,
    Copies,
    Moves,
    Temporaries,
    Work,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CopyError {
    /// No partial schedule is returned when a cap is exceeded.
    LimitExceeded {
        resource: CopyResource,
    },
    InvalidSlot {
        slot: CopySlot,
        slot_count: usize,
    },
    /// Identities also participate in the distinct-destination requirement.
    DuplicateDestination {
        slot: CopySlot,
    },
}

impl fmt::Display for CopyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LimitExceeded { resource } => {
                write!(f, "parallel-copy {resource:?} limit exceeded")
            }
            Self::InvalidSlot { slot, slot_count } => {
                write!(f, "copy slot {} is outside 0..{slot_count}", slot.0)
            }
            Self::DuplicateDestination { slot } => {
                write!(f, "copy slot {} is assigned more than once", slot.0)
            }
        }
    }
}

impl std::error::Error for CopyError {}

fn limit(resource: CopyResource) -> CopyError {
    CopyError::LimitExceeded { resource }
}

struct Work {
    used: u64,
    maximum: u64,
}

impl Work {
    fn charge(&mut self, amount: usize) -> Result<(), CopyError> {
        let amount = u64::try_from(amount).map_err(|_| limit(CopyResource::Work))?;
        self.used = self
            .used
            .checked_add(amount)
            .filter(|&next| next <= self.maximum)
            .ok_or_else(|| limit(CopyResource::Work))?;
        Ok(())
    }
}

fn emit(
    moves: &mut Vec<CopyMove>,
    source: CopyLocation,
    destination: CopyLocation,
    limits: CopyLimits,
    work: &mut Work,
) -> Result<(), CopyError> {
    if moves.len() >= limits.max_moves {
        return Err(limit(CopyResource::Moves));
    }
    work.charge(1)?;
    moves.push(CopyMove {
        source,
        destination,
    });
    Ok(())
}

/// An owned sequential implementation of simultaneous slot assignment.
///
/// Each destination receives its source's value from before the entire
/// schedule; other slots keep their values. Input destinations must be
/// distinct, including identity copies, which produce no moves. No value is
/// invented: every read of `Temporary` follows a save of an original slot.
///
/// Ready destinations (whose original values have no remaining readers) are
/// processed in ascending slot order. The remaining components are disjoint
/// cycles, each started at its smallest destination and broken with the same
/// scratch location. Input reordering therefore does not change the moves or
/// work. There are `nonidentity copies + cycles` moves and at most one scratch
/// location. Construction is iterative, takes `O(C log(C + 1))` time and `O(C)`
/// space for `C` input copies, and never allocates by slot-domain size.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ParallelCopySchedule {
    slot_count: usize,
    input_copy_count: usize,
    limits: CopyLimits,
    moves: Vec<CopyMove>,
    temporary_count: usize,
    work: u64,
}

impl ParallelCopySchedule {
    /// Build a schedule within `limits`, returning no partial result on error.
    ///
    /// Slot and input-copy caps are checked first. Input validation is charged
    /// before its scan, and every slot is checked before graph storage is
    /// allocated. Destination insertion detects duplicates before identities
    /// are discarded. Each later scan, ordered-container operation, and move
    /// is charged before execution or growth. Move and temporary caps are
    /// checked before the corresponding move's work charge.
    pub fn new(
        slot_count: usize,
        copies: &[ParallelCopy],
        limits: CopyLimits,
    ) -> Result<Self, CopyError> {
        if slot_count > limits.max_slots {
            return Err(limit(CopyResource::Slots));
        }
        if copies.len() > limits.max_copies {
            return Err(limit(CopyResource::Copies));
        }
        let mut work = Work {
            used: 0,
            maximum: limits.max_work,
        };
        work.charge(copies.len())?;
        for copy in copies {
            for slot in [copy.destination, copy.source] {
                if slot.0 >= slot_count {
                    return Err(CopyError::InvalidSlot { slot, slot_count });
                }
            }
        }

        let mut pending = BTreeMap::new();
        for copy in copies {
            work.charge(1)?;
            if pending.insert(copy.destination, copy.source).is_some() {
                return Err(CopyError::DuplicateDestination {
                    slot: copy.destination,
                });
            }
        }
        work.charge(pending.len())?;
        pending.retain(|destination, source| destination != source);

        let mut source_uses = BTreeMap::<CopySlot, usize>::new();
        for &source in pending.values() {
            // One record visit and one insertion/update.
            work.charge(2)?;
            *source_uses.entry(source).or_default() += 1;
        }
        let mut ready = BTreeSet::new();
        for &destination in pending.keys() {
            // One record visit and one source-count lookup.
            work.charge(2)?;
            if !source_uses.contains_key(&destination) {
                work.charge(1)?;
                ready.insert(destination);
            }
        }

        let mut moves = Vec::new();
        while !ready.is_empty() {
            work.charge(1)?;
            let destination = ready.pop_first().expect("nonempty ready set");
            work.charge(1)?;
            let source = pending.remove(&destination).expect("ready destination");
            emit(
                &mut moves,
                CopyLocation::Slot(source),
                CopyLocation::Slot(destination),
                limits,
                &mut work,
            )?;
            work.charge(1)?;
            let uses = source_uses.get_mut(&source).expect("pending source count");
            *uses -= 1;
            if *uses == 0 {
                work.charge(1)?;
                if pending.contains_key(&source) {
                    work.charge(1)?;
                    ready.insert(source);
                }
            }
        }

        let mut temporary_count = 0;
        while !pending.is_empty() {
            // With no ready destination, every remaining destination is read
            // at least once. There are as many reads as destinations, so each
            // is read exactly once: the remainder consists only of cycles.
            work.charge(1)?;
            let (&first, _) = pending.first_key_value().expect("nonempty pending map");
            if limits.max_temporaries == 0 {
                return Err(limit(CopyResource::Temporaries));
            }
            temporary_count = 1;
            emit(
                &mut moves,
                CopyLocation::Slot(first),
                CopyLocation::Temporary,
                limits,
                &mut work,
            )?;
            let mut destination = first;
            loop {
                work.charge(1)?;
                let source = pending.remove(&destination).expect("cycle destination");
                let closes_cycle = source == first;
                emit(
                    &mut moves,
                    if closes_cycle {
                        CopyLocation::Temporary
                    } else {
                        CopyLocation::Slot(source)
                    },
                    CopyLocation::Slot(destination),
                    limits,
                    &mut work,
                )?;
                if closes_cycle {
                    break;
                }
                destination = source;
            }
        }

        Ok(Self {
            slot_count,
            input_copy_count: copies.len(),
            limits,
            moves,
            temporary_count,
            work: work.used,
        })
    }

    pub fn moves(&self) -> &[CopyMove] {
        &self.moves
    }

    pub fn temporary_count(&self) -> usize {
        self.temporary_count
    }

    /// Exact deterministic abstract work consumed by construction.
    ///
    /// One unit pays for each input validation, destination insertion, and
    /// identity-filter visit; each active-copy scan and source-count operation;
    /// each ready-set operation; each pending-map lookup/removal; each cycle
    /// selection; and each emitted move. Tree comparison counts are excluded.
    /// If `C` is input copies, `N` nonidentity copies, `A` copies processed
    /// without a temporary, `Z` distinct sources whose pending reader count
    /// reaches zero in that phase, and `K` cycles, the total is
    /// `3*C + 6*N + 3*A + Z + 2*K`. Empty input costs zero.
    pub fn work(&self) -> u64 {
        self.work
    }

    pub fn limits(&self) -> CopyLimits {
        self.limits
    }

    pub fn slot_count(&self) -> usize {
        self.slot_count
    }

    pub fn input_copy_count(&self) -> usize {
        self.input_copy_count
    }
}
