//! The retained declaration-ordered *fallback* primitive over one input or
//! output list: `ParamListStandard::assignAddressFallback` applied to a batch
//! of explicit requests. This is not prototype or signature allocation; model
//! rules, `pointermax`, hidden returns, implicit parameters and injections are
//! never executed here.
use std::collections::BTreeMap;
use std::sync::Arc;

use ghidra_languages::{AssignStrategy, StackGrowth, StorageClass};
use ghidra_pcode::SpaceKind;
use serde::Serialize;
use thiserror::Error;

use crate::{
    AbiSpace, BindingSite, CompilerResources, CompilerStorage, EntryResources, Justification,
    NoFit, ParameterDirection, PlacedStorage, PlacedValue, PlacementError, PlacementLimits,
    PlacementOutcome, PlacementRequest, ResolvedStorage, ResourceId, StorageRange, place_parameter,
};

/// One value to place. The caller has already chosen its storage width and
/// class; no datatype graph or rule is consulted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct FallbackRequest {
    /// Storage width in bytes: the datatype's aligned size (`getAlignSize`).
    pub size: u32,
    /// Datatype alignment in bytes, relative to each aligned pool's origin.
    pub alignment: u32,
    pub storage_class: StorageClass,
}

impl FallbackRequest {
    pub fn new(size: u32, alignment: u32, storage_class: StorageClass) -> Self {
        Self {
            size,
            alignment,
            storage_class,
        }
    }
}

/// The retained `matchExact` argument.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub enum ClassMatch {
    /// `matchExact == false`, as in `ParamListStandard::assignAddress`: an
    /// entry of the requested class matches, and a `General` entry matches
    /// every class.
    #[default]
    GeneralAcceptsAny,
    /// `matchExact == true`: only entries of the requested class match.
    Exact,
}

/// What to do when the list declares behavior this primitive does not run.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub enum DeclaredRules {
    /// Refuse a list that declares `<rule>` elements or `pointermax`.
    #[default]
    Reject,
    /// Run the bare primitive anyway, as upstream rule actions do. The batch
    /// records every skipped declaration in [`FallbackBatch::unexecuted`].
    /// Its result can then differ from full prototype assignment.
    BypassUnexecuted,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct FallbackPolicy {
    pub class_match: ClassMatch,
    pub declared_rules: DeclaredRules,
}

/// One budget per call. Nested placement queries receive only the remaining
/// work and output-piece budget, so their cost is part of these totals.
#[derive(Clone, Copy, Debug)]
pub struct FallbackLimits {
    pub max_requests: usize,
    /// Size of the list-local group state created by [`AllocationState::new`].
    pub max_groups: usize,
    /// Entries visited, including ones skipped as consumed or wrong class.
    pub max_examined_entries: u64,
    pub max_group_references: u64,
    pub max_group_updates: u64,
    pub max_placements: usize,
    /// Output pieces in this batch: concatenation slices, padding and float
    /// containers each count once.
    pub max_pieces: usize,
    /// Occupied extents held by the state after the batch, across batches.
    pub max_occupied_extents: usize,
    /// Per-candidate structural cap passed to each nested placement query.
    pub max_source_pieces: usize,
    pub max_work: u64,
}

impl Default for FallbackLimits {
    fn default() -> Self {
        Self {
            max_requests: 4096,
            max_groups: 100_000,
            max_examined_entries: 4_000_000,
            max_group_references: 8_000_000,
            max_group_updates: 1_000_000,
            max_placements: 4096,
            max_pieces: 65_536,
            max_occupied_extents: 65_536,
            max_source_pieces: 1024,
            max_work: 64_000_000,
        }
    }
}

/// The retained per-group status value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum GroupState {
    /// A nonnegative status: slots used by aligned pools whose first group
    /// this is, including skipped alignment holes. Zero means untouched.
    Available { used_slots: u64 },
    /// Status `-1`: consumed by an exclusion assignment.
    Consumed,
}

/// Storage held by an earlier assignment, in mathematical byte coordinates.
/// Stack offsets are signed; other spaces are unsigned. Nothing wraps.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct OccupiedExtent {
    pub space: AbiSpace,
    pub first: i128,
    pub last: i128,
    pub site: BindingSite,
}

/// Owned list-local resource state for one model's input or output list.
///
/// It owns the retained group status array and the extents occupied by
/// earlier assignments. A failed call leaves it unchanged. Clone it to
/// stage tentative assignments and commit by replacing the original.
#[derive(Clone, Debug)]
pub struct AllocationState {
    storage: Arc<CompilerStorage>,
    model: usize,
    direction: ParameterDirection,
    groups: Vec<GroupState>,
    occupied: BTreeMap<(AbiSpace, i128), (i128, BindingSite)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct SlotRange {
    /// First slot after alignment holes.
    pub first: u64,
    pub next: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FallbackAssignment {
    pub site: BindingSite,
    /// The first group: the retained status index that was tested.
    pub group: ResourceId,
    /// Exclusion entries consume every group in their list; aligned pools
    /// advance only `group`'s slot cursor.
    pub exclusion: bool,
    pub slots: Option<SlotRange>,
    pub value: PlacedValue,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum FallbackOutcome {
    Assigned(FallbackAssignment),
    /// No entry fit. `candidates` passed the group and class filters and
    /// were tried. Cursor advances past alignment holes made while trying
    /// them remain in the state, as in the retained status array. A slice
    /// outside its address domain is an error, not a no-fit.
    NoFit {
        candidates: usize,
    },
    /// After the first `NoFit`, like Java `ParamListStandard.assignMap`.
    NotAttempted,
}

/// Declarations of the selected list and model that this primitive did not
/// execute. Nonzero values mean the batch differs from full assignment.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct UnexecutedDeclarations {
    pub rules: usize,
    pub pointer_max: Option<u32>,
    pub this_before_return_pointer: bool,
    /// `strategy="register"` on an output list (no hidden-return fallback).
    pub register_output_strategy: bool,
    pub has_this: bool,
    pub injections: usize,
    pub share_stack: bool,
}

impl UnexecutedDeclarations {
    /// True when the list declares rules or `pointermax`, which can choose
    /// different storage for the same request.
    pub fn changes_assignment(&self) -> bool {
        self.rules != 0 || self.pointer_max.is_some()
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct FallbackUsage {
    pub requests: usize,
    pub examined_entries: u64,
    pub group_references: u64,
    pub group_updates: u64,
    pub placements: usize,
    pub pieces: usize,
    /// Held by the state after this batch.
    pub occupied_extents: usize,
    /// Largest source-piece count among nested placement queries.
    pub source_pieces: usize,
    /// Includes nested placement work.
    pub work: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct FallbackBatch {
    pub model: usize,
    pub direction: ParameterDirection,
    pub policy: FallbackPolicy,
    /// One per request, in request order.
    pub outcomes: Vec<FallbackOutcome>,
    pub first_no_fit: Option<usize>,
    pub unexecuted: UnexecutedDeclarations,
    pub usage: FallbackUsage,
}

#[derive(Debug, Error)]
pub enum FallbackError {
    #[error("fallback allocation limit exceeded: {0}")]
    Limit(&'static str),
    #[error("model {model} has no {direction:?} parameter list")]
    UnknownList {
        model: usize,
        direction: ParameterDirection,
    },
    #[error("allocation state belongs to another compiler overlay or list")]
    StateMismatch,
    #[error(
        "model {model} {direction:?} list declares {rules} rule(s) and pointermax {pointer_max:?}; fallback does not execute them"
    )]
    RulesNotExecuted {
        model: usize,
        direction: ParameterDirection,
        rules: usize,
        pointer_max: Option<u32>,
    },
    #[error("invalid fallback request {request}: {reason}")]
    InvalidRequest {
        request: usize,
        reason: &'static str,
    },
    /// The retained status test reads only the first group, so it would
    /// select this entry although another of its groups is already used.
    #[error("request {request} at {site:?}: resource group {group:?} is already in use")]
    GroupInUse {
        request: usize,
        site: BindingSite,
        group: ResourceId,
    },
    /// The retained status model would return storage that physically
    /// overlaps an earlier assignment.
    #[error("request {request} at {site:?} overlaps storage held by {previous:?}")]
    Overlap {
        request: usize,
        site: BindingSite,
        previous: BindingSite,
    },
    #[error("unsupported fallback assignment for request {request} at {site:?}: {reason}")]
    Unsupported {
        request: usize,
        site: BindingSite,
        reason: &'static str,
    },
    #[error("placement for request {request} at {site:?}: {source}")]
    Placement {
        request: usize,
        site: BindingSite,
        source: PlacementError,
    },
}

struct Budget {
    limits: FallbackLimits,
    usage: FallbackUsage,
}

fn bump(
    value: &mut u64,
    amount: u64,
    maximum: u64,
    name: &'static str,
) -> Result<(), FallbackError> {
    *value = value
        .checked_add(amount)
        .filter(|n| *n <= maximum)
        .ok_or(FallbackError::Limit(name))?;
    Ok(())
}

fn bump_count(
    value: &mut usize,
    amount: usize,
    maximum: usize,
    name: &'static str,
) -> Result<(), FallbackError> {
    *value = value
        .checked_add(amount)
        .filter(|n| *n <= maximum)
        .ok_or(FallbackError::Limit(name))?;
    Ok(())
}

fn as_u64(amount: usize) -> Result<u64, FallbackError> {
    u64::try_from(amount).map_err(|_| FallbackError::Limit("work"))
}

impl Budget {
    fn work(&mut self, amount: usize) -> Result<(), FallbackError> {
        self.work_u64(as_u64(amount)?)
    }
    fn work_u64(&mut self, amount: u64) -> Result<(), FallbackError> {
        bump(&mut self.usage.work, amount, self.limits.max_work, "work")
    }
    fn lookup(&mut self, length: usize) -> Result<(), FallbackError> {
        self.work((usize::BITS - length.leading_zeros()) as usize + 1)
    }
    fn examine(&mut self) -> Result<(), FallbackError> {
        bump(
            &mut self.usage.examined_entries,
            1,
            self.limits.max_examined_entries,
            "examined entries",
        )?;
        self.work(1)
    }
    fn references(&mut self, amount: usize) -> Result<(), FallbackError> {
        bump(
            &mut self.usage.group_references,
            as_u64(amount)?,
            self.limits.max_group_references,
            "group references",
        )?;
        self.work(amount)
    }
    fn update(&mut self) -> Result<(), FallbackError> {
        bump(
            &mut self.usage.group_updates,
            1,
            self.limits.max_group_updates,
            "group updates",
        )?;
        self.work(1)
    }
    fn nested_limits(&self) -> PlacementLimits {
        PlacementLimits {
            max_source_pieces: self.limits.max_source_pieces,
            max_output_pieces: self.limits.max_pieces - self.usage.pieces,
            max_work: self.limits.max_work - self.usage.work,
        }
    }
}

enum Undo {
    Group(usize, GroupState),
    Extent((AbiSpace, i128)),
}

struct Span {
    space: AbiSpace,
    first: i128,
    last: i128,
}

fn coordinate(range: &StorageRange) -> i128 {
    if range.address.space == AbiSpace::Stack {
        i128::from(range.address.offset as i64)
    } else {
        i128::from(range.address.offset)
    }
}

impl AllocationState {
    /// Fresh state (`allocateStatus`): every group untouched, nothing occupied.
    pub fn new(
        resources: &CompilerResources,
        model: usize,
        direction: ParameterDirection,
        limits: FallbackLimits,
    ) -> Result<Self, FallbackError> {
        let list = resources
            .list(model, direction)
            .ok_or(FallbackError::UnknownList { model, direction })?;
        if list.group_count > limits.max_groups {
            return Err(FallbackError::Limit("groups"));
        }
        let mut work = 0;
        bump(
            &mut work,
            as_u64(list.group_count)?
                .checked_add(1)
                .ok_or(FallbackError::Limit("work"))?,
            limits.max_work,
            "work",
        )?;
        Ok(Self {
            storage: resources.storage().clone(),
            model,
            direction,
            groups: vec![GroupState::Available { used_slots: 0 }; list.group_count],
            occupied: BTreeMap::new(),
        })
    }
    pub fn model(&self) -> usize {
        self.model
    }
    pub fn direction(&self) -> ParameterDirection {
        self.direction
    }
    /// Indexed by the list-local [`ResourceId`].
    pub fn groups(&self) -> &[GroupState] {
        &self.groups
    }
    pub fn occupied_count(&self) -> usize {
        self.occupied.len()
    }
    /// Occupied extents ordered by space and first byte.
    pub fn occupied(&self) -> impl Iterator<Item = OccupiedExtent> + '_ {
        self.occupied
            .iter()
            .map(|(&(space, first), &(last, site))| OccupiedExtent {
                space,
                first,
                last,
                site,
            })
    }

    /// Assign each request in order with the retained fallback loop, stopping
    /// at the first `NoFit`. An error leaves the state unchanged and returns
    /// no partial batch.
    pub fn assign_fallback(
        &mut self,
        resources: &CompilerResources,
        requests: &[FallbackRequest],
        policy: FallbackPolicy,
        limits: FallbackLimits,
    ) -> Result<FallbackBatch, FallbackError> {
        let mut journal = Vec::new();
        let result = self.run(resources, requests, policy, limits, &mut journal);
        if result.is_err() {
            for undo in journal.into_iter().rev() {
                match undo {
                    Undo::Group(index, old) => self.groups[index] = old,
                    Undo::Extent(key) => {
                        self.occupied.remove(&key);
                    }
                }
            }
        }
        result
    }

    fn run(
        &mut self,
        resources: &CompilerResources,
        requests: &[FallbackRequest],
        policy: FallbackPolicy,
        limits: FallbackLimits,
        journal: &mut Vec<Undo>,
    ) -> Result<FallbackBatch, FallbackError> {
        if !Arc::ptr_eq(resources.storage(), &self.storage) {
            return Err(FallbackError::StateMismatch);
        }
        let list = resources
            .list(self.model, self.direction)
            .ok_or(FallbackError::StateMismatch)?;
        let storage = self.storage.clone();
        let prototype = storage
            .source()
            .prototypes
            .get(self.model)
            .ok_or(FallbackError::StateMismatch)?;
        let source = match self.direction {
            ParameterDirection::Input => &prototype.input,
            ParameterDirection::Output => &prototype.output,
        };
        if list.group_count != self.groups.len() || source.entries.len() != list.entries.len() {
            return Err(FallbackError::StateMismatch);
        }
        if requests.len() > limits.max_requests {
            return Err(FallbackError::Limit("requests"));
        }
        if self.occupied.len() > limits.max_occupied_extents {
            return Err(FallbackError::Limit("occupied extents"));
        }
        let mut budget = Budget {
            limits,
            usage: FallbackUsage {
                requests: requests.len(),
                occupied_extents: self.occupied.len(),
                ..Default::default()
            },
        };
        budget.work(1)?;
        let unexecuted = UnexecutedDeclarations {
            rules: source.rules.len(),
            pointer_max: source.pointer_max,
            this_before_return_pointer: source.this_before_return_pointer,
            register_output_strategy: self.direction == ParameterDirection::Output
                && prototype.strategy == AssignStrategy::Register,
            has_this: prototype.has_this,
            injections: prototype.injections.len(),
            share_stack: prototype.share_stack.is_some(),
        };
        if policy.declared_rules == DeclaredRules::Reject && unexecuted.changes_assignment() {
            return Err(FallbackError::RulesNotExecuted {
                model: self.model,
                direction: self.direction,
                rules: unexecuted.rules,
                pointer_max: unexecuted.pointer_max,
            });
        }
        budget.work(requests.len())?;
        for (request, r) in requests.iter().enumerate() {
            if r.size == 0 || r.alignment == 0 {
                return Err(FallbackError::InvalidRequest {
                    request,
                    reason: "size and alignment must be positive",
                });
            }
        }
        let mut outcomes = Vec::with_capacity(requests.len());
        let mut first_no_fit = None;
        for (index, request) in requests.iter().enumerate() {
            if first_no_fit.is_some() {
                outcomes.push(FallbackOutcome::NotAttempted);
                continue;
            }
            let outcome = self.assign_one(
                index,
                *request,
                policy.class_match,
                &list.entries,
                source,
                &mut budget,
                journal,
            )?;
            if matches!(outcome, FallbackOutcome::NoFit { .. }) {
                first_no_fit = Some(index);
            }
            outcomes.push(outcome);
        }
        budget.usage.occupied_extents = self.occupied.len();
        Ok(FallbackBatch {
            model: self.model,
            direction: self.direction,
            policy,
            outcomes,
            first_no_fit,
            unexecuted,
            usage: budget.usage,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn assign_one(
        &mut self,
        request: usize,
        r: FallbackRequest,
        class_match: ClassMatch,
        entries: &[EntryResources],
        source: &ghidra_languages::ParamList,
        budget: &mut Budget,
        journal: &mut Vec<Undo>,
    ) -> Result<FallbackOutcome, FallbackError> {
        let storage = self.storage.clone();
        let mut candidates = 0;
        for (index, entry) in entries.iter().enumerate() {
            budget.examine()?;
            budget.references(1)?;
            let site = entry.site;
            let unsupported = |reason| FallbackError::Unsupported {
                request,
                site,
                reason,
            };
            let first = *entry
                .groups
                .first()
                .ok_or_else(|| unsupported("entry has no resource group"))?;
            let cursor = match self.groups.get(first.0) {
                None => return Err(FallbackError::StateMismatch),
                Some(GroupState::Consumed) => continue,
                Some(GroupState::Available { used_slots }) => *used_slots,
            };
            let declared = &source.entries[index];
            let class = declared.storage_class;
            if r.storage_class != class
                && (class_match == ClassMatch::Exact || class != StorageClass::General)
            {
                continue;
            }
            candidates += 1;
            let placement = place_parameter(
                &storage,
                site,
                PlacementRequest {
                    size: r.size,
                    used_slots: cursor,
                    type_alignment: r.alignment,
                    justification: Justification::Default,
                },
                budget.nested_limits(),
            )
            .map_err(|error| match error {
                PlacementError::Limit("work") => FallbackError::Limit("work"),
                PlacementError::Limit("output pieces") => FallbackError::Limit("pieces"),
                PlacementError::Limit("source pieces") => FallbackError::Limit("source pieces"),
                source => FallbackError::Placement {
                    request,
                    site,
                    source,
                },
            })?;
            budget.work_u64(placement.work)?;
            budget.usage.source_pieces = budget.usage.source_pieces.max(placement.source_pieces);
            let value = match placement.outcome {
                // Retained code would build a wrapped address here, not try
                // the next entry. Neither is a valid fallback result.
                PlacementOutcome::NoFit(NoFit::AddressDomain) => {
                    return Err(unsupported("selected storage leaves its address domain"));
                }
                PlacementOutcome::NoFit(_) => {
                    // Retained getAddrBySlot writes skipped alignment holes
                    // back into the status even when the value does not fit.
                    if placement.next_slot != cursor {
                        self.set(
                            first.0,
                            GroupState::Available {
                                used_slots: placement.next_slot,
                            },
                            budget,
                            journal,
                        )?;
                    }
                    continue;
                }
                PlacementOutcome::Placed(value) => value,
            };
            bump_count(
                &mut budget.usage.placements,
                1,
                budget.limits.max_placements,
                "placements",
            )?;
            let pieces = match &value.storage {
                PlacedStorage::Bits { pieces } => pieces.len(),
                PlacedStorage::FloatConversion { .. } => 1,
            };
            bump_count(
                &mut budget.usage.pieces,
                pieces,
                budget.limits.max_pieces,
                "pieces",
            )?;
            // The retained test reads only the first group. Refuse instead of
            // silently reusing a later group that is already in use.
            budget.references(entry.groups.len())?;
            for &group in &entry.groups {
                let state = self
                    .groups
                    .get(group.0)
                    .ok_or(FallbackError::StateMismatch)?;
                if group != first && *state != (GroupState::Available { used_slots: 0 }) {
                    return Err(FallbackError::GroupInUse {
                        request,
                        site,
                        group,
                    });
                }
            }
            let exclusion = declared.alignment() == 0;
            let (spans, slots) = self
                .spans(entry, declared, r.size, placement.next_slot, budget)
                .map_err(|reason| match reason {
                    SpanError::Budget(error) => error,
                    SpanError::Unsupported(reason) => unsupported(reason),
                })?;
            for span in spans {
                self.occupy(span, request, site, budget, journal)?;
            }
            if exclusion {
                for &group in &entry.groups {
                    self.set(group.0, GroupState::Consumed, budget, journal)?;
                }
            } else {
                self.set(
                    first.0,
                    GroupState::Available {
                        used_slots: placement.next_slot,
                    },
                    budget,
                    journal,
                )?;
            }
            return Ok(FallbackOutcome::Assigned(FallbackAssignment {
                site,
                group: first,
                exclusion,
                slots,
                value,
            }));
        }
        Ok(FallbackOutcome::NoFit { candidates })
    }

    fn set(
        &mut self,
        index: usize,
        value: GroupState,
        budget: &mut Budget,
        journal: &mut Vec<Undo>,
    ) -> Result<(), FallbackError> {
        budget.update()?;
        let slot = self
            .groups
            .get_mut(index)
            .ok_or(FallbackError::StateMismatch)?;
        journal.push(Undo::Group(index, *slot));
        *slot = value;
        Ok(())
    }

    fn occupy(
        &mut self,
        span: Span,
        request: usize,
        site: BindingSite,
        budget: &mut Budget,
        journal: &mut Vec<Undo>,
    ) -> Result<(), FallbackError> {
        budget.lookup(self.occupied.len())?;
        // Stored extents are disjoint, so only the last one starting at or
        // before this span's end can intersect it.
        if let Some((&(space, _), &(last, previous))) =
            self.occupied.range(..=(span.space, span.last)).next_back()
            && space == span.space
            && last >= span.first
        {
            return Err(FallbackError::Overlap {
                request,
                site,
                previous,
            });
        }
        if self.occupied.len() >= budget.limits.max_occupied_extents {
            return Err(FallbackError::Limit("occupied extents"));
        }
        let key = (span.space, span.first);
        journal.push(Undo::Extent(key));
        self.occupied.insert(key, (span.last, site));
        Ok(())
    }

    /// Physical storage held by an assignment: a whole exclusion entry (every
    /// nonconstant join piece, or its pool capacity), or the aligned slots.
    fn spans(
        &self,
        entry: &EntryResources,
        declared: &ghidra_languages::ParamEntry,
        size: u32,
        next_slot: u64,
        budget: &mut Budget,
    ) -> Result<(Vec<Span>, Option<SlotRange>), SpanError> {
        let storage = &self.storage;
        budget.lookup(storage.bindings().len())?;
        let binding = storage
            .binding(entry.site)
            .ok_or(SpanError::Unsupported("missing resolved binding"))?;
        let alignment = declared.alignment();
        let mut spans = Vec::new();
        match &binding.storage {
            ResolvedStorage::Single(range) => {
                budget.work(1)?;
                let constant = self.constant(range.address.space, budget)?;
                let base = coordinate(range);
                if alignment == 0 {
                    if !constant {
                        spans.push(Span {
                            space: range.address.space,
                            first: base,
                            last: base + i128::from(declared.max_size) - 1,
                        });
                    }
                    return Ok((spans, None));
                }
                // The placement succeeded, so these slots are within capacity.
                let align = u64::from(alignment);
                let used = u64::from(size).div_ceil(align);
                let first = next_slot - used;
                let capacity = u64::from(declared.max_size / alignment);
                let index = if storage.stack().growth == StackGrowth::Positive {
                    capacity - next_slot
                } else {
                    first
                };
                if !constant {
                    let start = base + i128::from(index) * i128::from(align);
                    spans.push(Span {
                        space: range.address.space,
                        first: start,
                        last: start + i128::from(used) * i128::from(align) - 1,
                    });
                }
                Ok((
                    spans,
                    Some(SlotRange {
                        first,
                        next: next_slot,
                    }),
                ))
            }
            ResolvedStorage::Join { pieces, .. } => {
                if alignment != 0 {
                    return Err(SpanError::Unsupported(
                        "aligned join pools have no supported slot-to-piece occupancy",
                    ));
                }
                budget.work(pieces.len())?;
                spans.reserve(pieces.len());
                for piece in pieces {
                    if self.constant(piece.storage.address.space, budget)? {
                        continue;
                    }
                    let size = piece
                        .storage
                        .size
                        .ok_or(SpanError::Unsupported("unsized join piece"))?;
                    let base = coordinate(&piece.storage);
                    spans.push(Span {
                        space: piece.storage.address.space,
                        first: base,
                        last: base + i128::from(size) - 1,
                    });
                }
                Ok((spans, None))
            }
        }
    }

    fn constant(&self, space: AbiSpace, budget: &mut Budget) -> Result<bool, SpanError> {
        let AbiSpace::Language(id) = space else {
            return Ok(false);
        };
        let file = self.storage.register_file();
        budget.lookup(file.spaces().len())?;
        Ok(file
            .space(id)
            .ok_or(SpanError::Unsupported("unknown address space"))?
            .kind
            == SpaceKind::Constant)
    }
}

enum SpanError {
    Budget(FallbackError),
    Unsupported(&'static str),
}

impl From<FallbackError> for SpanError {
    fn from(error: FallbackError) -> Self {
        Self::Budget(error)
    }
}
