//! Native `ParamListStandard::assignAddressFallback` (fspec.cc:731-758) for
//! one value, with `ParamEntry::getAddrBySlot` (fspec.cc:453-494) evaluated by
//! its source arithmetic: floor-division alignment waste and refused `int4`
//! overflow. This is the explicit fallback primitive. It never runs model
//! rules or `pointermax`, so it is not `ParamListStandard::assignAddress`.
//!
//! The private kernel shares a caller's `Budget` and undo journal so that a
//! later rule action (`MultiMemberAssign`) can run it once per member and roll
//! back every member, and every failed candidate's alignment waste, together.
use crate::native_types::{NATIVE_INT_MAX, NativeType};

use super::*;

/// One value for [`AllocationState::assign_native_fallback`].
///
/// Both widths are the caller's: no datatype graph, metatype or rule is read
/// here. `aligned_size` is native `Datatype::getAlignSize()`, the width the
/// source passes as `sz`; it is *not* the raw `getSize()`. A raw three-byte
/// value with alignment four is requested as four bytes. A caller that later
/// emits only the raw bytes must keep this placement's address, not
/// re-justify a narrower request.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct NativeFallbackRequest {
    /// Native `getAlignSize()`, in `1..=i32::MAX`.
    pub aligned_size: u32,
    /// Native `getAlignment()` (`typeAlign`), in `1..=i32::MAX`.
    pub alignment: u32,
    /// The `resource` class the caller selected.
    pub storage_class: StorageClass,
}

impl NativeFallbackRequest {
    pub fn new(aligned_size: u32, alignment: u32, storage_class: StorageClass) -> Self {
        Self {
            aligned_size,
            alignment,
            storage_class,
        }
    }

    /// The geometry `assignAddressFallback` reads from a native datatype:
    /// `getAlignSize()` and `getAlignment()`. The class stays explicit; it is
    /// not derived from the metatype.
    pub fn for_type(ty: &NativeType, storage_class: StorageClass) -> Self {
        Self::new(ty.aligned_size, ty.alignment, storage_class)
    }
}

/// One budget per call. The nested placement of the selected candidate gets
/// only the remaining work and output-piece budget; its work is included.
#[derive(Clone, Copy, Debug)]
pub struct NativeFallbackLimits {
    /// Entries visited in declaration order, including consumed and
    /// wrong-class entries. Tried candidates are a subset.
    pub max_examined_entries: u64,
    pub max_group_references: u64,
    /// Journaled status writes: failed-candidate waste plus the commit.
    pub max_group_updates: u64,
    /// Nested placement queries (at most one per call).
    pub max_placements: usize,
    /// Output pieces; a floating conversion counts once.
    pub max_pieces: usize,
    /// Occupied extents held by the state after the call.
    pub max_occupied_extents: usize,
    /// Structural cap passed to the nested placement query.
    pub max_source_pieces: usize,
    pub max_work: u64,
}

impl Default for NativeFallbackLimits {
    fn default() -> Self {
        Self {
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

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct NativeFallbackUsage {
    pub examined_entries: u64,
    /// Entries that passed the status and class gates: `getAddrBySlot` calls.
    pub candidates: usize,
    pub group_references: u64,
    pub group_updates: u64,
    pub placements: usize,
    pub pieces: usize,
    /// Held by the state after the call.
    pub occupied_extents: usize,
    pub source_pieces: usize,
    /// Includes nested placement work.
    pub work: u64,
}

/// The `int4` operation of `getAddrBySlot`'s aligned branch that the source
/// would overflow (undefined behavior). It is refused, never wrapped and
/// never reported as a capacity `NoFit`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum NativeSlotOverflow {
    /// The status cursor itself exceeds `i32::MAX`: no native status holds
    /// it, so the first aligned-branch operation would overflow.
    Cursor,
    /// `slotnum * alignment` (fspec.cc:471).
    CursorBytes,
    /// `slotnum += (typeAlign - tmp) / alignment` (fspec.cc:473).
    AlignedCursor,
    /// `slotnum + slotsused`, evaluated before the capacity test (fspec.cc:478).
    CursorPlusSlots,
}

/// `getAddrBySlot`'s aligned-pool arithmetic before its capacity test
/// (fspec.cc:470-478), in source order. Returns the cursor after native
/// floor-division alignment waste and that cursor plus the value's slots.
/// Every operand and result is checked against `i32::MAX`; wide arithmetic
/// never turns a source overflow into a later capacity rejection.
///
/// Requires `pool_alignment`, `type_alignment` and `size` in `1..=i32::MAX`.
pub(super) fn native_slot_cursor(
    cursor: u64,
    pool_alignment: u32,
    type_alignment: u32,
    size: u32,
) -> Result<(u64, u64), NativeSlotOverflow> {
    let int = u64::from(NATIVE_INT_MAX);
    if cursor > int {
        return Err(NativeSlotOverflow::Cursor);
    }
    let pool = u64::from(pool_alignment);
    let mut slot = cursor;
    if type_alignment > pool_alignment {
        let bytes = slot
            .checked_mul(pool)
            .filter(|n| *n <= int)
            .ok_or(NativeSlotOverflow::CursorBytes)?;
        let remainder = bytes % u64::from(type_alignment);
        if remainder != 0 {
            // Floor division: a nondividing alignment can waste zero slots.
            slot += (u64::from(type_alignment) - remainder) / pool;
            if slot > int {
                return Err(NativeSlotOverflow::AlignedCursor);
            }
        }
    }
    let slots = u64::from(size).div_ceil(pool);
    let end = slot + slots;
    if end > int {
        return Err(NativeSlotOverflow::CursorPlusSlots);
    }
    Ok((slot, end))
}

/// A candidate that `getAddrBySlot` rejected, so the scan continued.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct NativeCandidate {
    /// Declaration index in the list.
    pub entry: usize,
    pub site: BindingSite,
    /// The first group: the status index the source tested.
    pub group: ResourceId,
    /// `status[grp]` before the call.
    pub cursor: u64,
    /// `status[grp]` after it: the cursor plus native alignment waste for a
    /// slot rejection, otherwise unchanged. The state keeps this value.
    pub next_cursor: u64,
    /// `BelowMinimum`, `ExclusionUsed`, `AboveCapacity` or `SlotsExhausted`.
    /// An address-domain escape is an error, never a rejection.
    pub rejection: NoFit,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NativeFallbackAllocation {
    pub entry: usize,
    pub site: BindingSite,
    /// The first group, whose status was tested.
    pub group: ResourceId,
    /// Exclusion entries consume every group; aligned pools advance only
    /// `group`'s cursor.
    pub exclusion: bool,
    /// `status[grp]` before the call.
    pub cursor: u64,
    /// Aligned pools: the first slot after native alignment waste and the new
    /// cursor. `None` for an exclusion entry.
    pub slots: Option<SlotRange>,
    /// Slots skipped by floor-division alignment for this entry.
    pub alignment_waste: u64,
    /// The physical storage or floating conversion, with the request's
    /// aligned width as its size.
    pub value: PlacedValue,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum NativeFallbackOutcome {
    Assigned(NativeFallbackAllocation),
    /// `AssignAction::fail`: no entry fit. This is the bare primitive's
    /// result, not a void return or hidden-return decision.
    NoFit,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct NativeFallbackAssignment {
    pub model: usize,
    pub direction: ParameterDirection,
    pub request: NativeFallbackRequest,
    pub policy: FallbackPolicy,
    /// Candidates tried and rejected before the outcome, in declaration order.
    pub rejected: Vec<NativeCandidate>,
    pub outcome: NativeFallbackOutcome,
    /// Declarations of the list and model this primitive did not execute.
    pub unexecuted: UnexecutedDeclarations,
    pub usage: NativeFallbackUsage,
}

#[derive(Debug, Error)]
pub enum NativeFallbackError {
    /// Every budget exhaustion, including nested placement work and pieces.
    #[error("native fallback limit exceeded: {0}")]
    Limit(&'static str),
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
    #[error("invalid native fallback request: {0}")]
    InvalidRequest(&'static str),
    /// A tried candidate's declaration has no native `int4` geometry.
    #[error("invalid native fallback declaration at {site:?}: {reason}")]
    InvalidDeclaration {
        site: BindingSite,
        reason: &'static str,
    },
    /// The source would overflow a native `int4` in this candidate's slot
    /// arithmetic.
    #[error(
        "native fallback slot arithmetic at {site:?} exceeds the native int range: {operation:?}"
    )]
    NativeIntRange {
        site: BindingSite,
        operation: NativeSlotOverflow,
    },
    /// The source tests only the first group and would reuse this one.
    #[error("native fallback entry {site:?}: resource group {group:?} is already in use")]
    GroupInUse {
        site: BindingSite,
        group: ResourceId,
    },
    /// The source would return storage overlapping an earlier assignment.
    #[error("native fallback storage at {site:?} overlaps storage held by {previous:?}")]
    Overlap {
        site: BindingSite,
        previous: BindingSite,
    },
    /// A selection the source would build invalidly, or one not modeled here.
    #[error("unsupported native fallback assignment at {site:?}: {reason}")]
    Unsupported {
        site: BindingSite,
        reason: &'static str,
    },
    /// The selected entry's placement declaration is invalid.
    #[error("native fallback placement at {site:?}: {source}")]
    Placement {
        site: BindingSite,
        source: PlacementError,
    },
    #[error(transparent)]
    Allocation(FallbackError),
}

impl From<FallbackError> for NativeFallbackError {
    fn from(error: FallbackError) -> Self {
        match error {
            FallbackError::Limit(resource) => Self::Limit(resource),
            FallbackError::StateMismatch => Self::StateMismatch,
            FallbackError::Overlap { site, previous, .. } => Self::Overlap { site, previous },
            FallbackError::GroupInUse { site, group, .. } => Self::GroupInUse { site, group },
            FallbackError::Unsupported { site, reason, .. } => Self::Unsupported { site, reason },
            other => Self::Allocation(other),
        }
    }
}

fn placement_error(site: BindingSite) -> impl FnOnce(PlacementError) -> NativeFallbackError {
    move |error| match error {
        PlacementError::Limit("output pieces") => NativeFallbackError::Limit("pieces"),
        PlacementError::Limit(resource) => NativeFallbackError::Limit(resource),
        source => NativeFallbackError::Placement { site, source },
    }
}

/// The source's answer for one tried candidate.
enum Slot {
    Fit { first: u64, next: u64 },
    Reject { next: u64, reason: NoFit },
}

impl AllocationState {
    /// Run native `assignAddressFallback` for one value. Declared rules and
    /// `pointermax` are never executed: `DeclaredRules::Reject` (the default)
    /// refuses a list that declares them, and `BypassUnexecuted` runs the
    /// bare primitive and reports them in `unexecuted`.
    ///
    /// `Assigned` commits the selected storage and every earlier candidate's
    /// alignment waste. `NoFit` keeps the failed candidates' waste, as the
    /// source's status array does. Every error restores the state exactly.
    pub fn assign_native_fallback(
        &mut self,
        resources: &CompilerResources,
        request: NativeFallbackRequest,
        policy: FallbackPolicy,
        limits: NativeFallbackLimits,
    ) -> Result<NativeFallbackAssignment, NativeFallbackError> {
        let mut journal = Vec::new();
        let result = self.run_native_fallback(resources, request, policy, limits, &mut journal);
        if result.is_err() {
            self.rollback(journal);
        }
        result
    }

    fn run_native_fallback(
        &mut self,
        resources: &CompilerResources,
        request: NativeFallbackRequest,
        policy: FallbackPolicy,
        limits: NativeFallbackLimits,
        journal: &mut Vec<Undo>,
    ) -> Result<NativeFallbackAssignment, NativeFallbackError> {
        let (list, source) = self.source_list(resources)?;
        let prototype = resources
            .storage()
            .source()
            .prototypes
            .get(self.model)
            .ok_or(NativeFallbackError::StateMismatch)?;
        if self.occupied.len() > limits.max_occupied_extents {
            return Err(NativeFallbackError::Limit("occupied extents"));
        }
        let mut budget = Budget {
            limits: FallbackLimits {
                max_requests: 1,
                max_groups: usize::MAX,
                max_examined_entries: limits.max_examined_entries,
                max_group_references: limits.max_group_references,
                max_group_updates: limits.max_group_updates,
                max_placements: limits.max_placements,
                max_pieces: limits.max_pieces,
                max_occupied_extents: limits.max_occupied_extents,
                max_source_pieces: limits.max_source_pieces,
                max_work: limits.max_work,
            },
            usage: FallbackUsage {
                occupied_extents: self.occupied.len(),
                ..Default::default()
            },
        };
        budget.work(1)?;
        let unexecuted = unexecuted_declarations(self.direction, prototype, source);
        if policy.declared_rules == DeclaredRules::Reject && unexecuted.changes_assignment() {
            return Err(NativeFallbackError::RulesNotExecuted {
                model: self.model,
                direction: self.direction,
                rules: unexecuted.rules,
                pointer_max: unexecuted.pointer_max,
            });
        }
        let mut rejected = Vec::new();
        let outcome = self.native_fallback_kernel(
            &list.entries,
            source,
            request,
            policy.class_match,
            &mut budget,
            journal,
            &mut rejected,
        )?;
        let assigned = usize::from(matches!(outcome, NativeFallbackOutcome::Assigned(_)));
        let usage = NativeFallbackUsage {
            examined_entries: budget.usage.examined_entries,
            candidates: rejected.len() + assigned,
            group_references: budget.usage.group_references,
            group_updates: budget.usage.group_updates,
            placements: budget.usage.placements,
            pieces: budget.usage.pieces,
            occupied_extents: self.occupied.len(),
            source_pieces: budget.usage.source_pieces,
            work: budget.usage.work,
        };
        Ok(NativeFallbackAssignment {
            model: self.model,
            direction: self.direction,
            request,
            policy,
            rejected,
            outcome,
            unexecuted,
            usage,
        })
    }

    /// The reusable native fallback kernel, for rule actions that call
    /// `assignAddressFallback` internally. It neither reads nor gates on
    /// declared rules or `pointermax`, and it never rolls back by itself:
    ///
    /// - Every status write and occupied extent is journaled in `journal`.
    ///   `Assigned` and `NoFit` leave their writes (failed candidates'
    ///   alignment waste included); an `Err` can leave partial writes. The
    ///   owner of the journal restores whatever its action requires: a public
    ///   fallback keeps a `NoFit`, a compound action rolls back everything.
    /// - One request is charged to `budget.usage.requests`; all other counts
    ///   and work accumulate in the shared budget, and the nested placement
    ///   gets only its remaining work and pieces.
    /// - Rejected candidates are appended to `rejected` (bounded by examined
    ///   entries); the caller can reuse one vector across members.
    ///
    /// `entries` and `source` must come from `source_list`.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn native_fallback_kernel(
        &mut self,
        entries: &[EntryResources],
        source: &ghidra_languages::ParamList,
        request: NativeFallbackRequest,
        class_match: ClassMatch,
        budget: &mut Budget,
        journal: &mut Vec<Undo>,
        rejected: &mut Vec<NativeCandidate>,
    ) -> Result<NativeFallbackOutcome, NativeFallbackError> {
        bump_count(
            &mut budget.usage.requests,
            1,
            budget.limits.max_requests,
            "requests",
        )?;
        budget.work(1)?;
        if request.aligned_size == 0 || request.aligned_size > NATIVE_INT_MAX {
            return Err(NativeFallbackError::InvalidRequest(
                "aligned size must be a positive native int",
            ));
        }
        if request.alignment == 0 || request.alignment > NATIVE_INT_MAX {
            return Err(NativeFallbackError::InvalidRequest(
                "alignment must be a positive native int",
            ));
        }
        if source.entries.len() != entries.len() {
            return Err(NativeFallbackError::StateMismatch);
        }
        let positive = self.storage.stack().growth == StackGrowth::Positive;
        let size = request.aligned_size;
        for (index, (entry, declared)) in entries.iter().zip(&source.entries).enumerate() {
            budget.examine()?;
            budget.references(1)?;
            let site = entry.site;
            let first = *entry
                .groups
                .first()
                .ok_or(NativeFallbackError::StateMismatch)?;
            // The consumed test comes before the class test (fspec.cc:738-742).
            let cursor = match self.groups.get(first.0) {
                None => return Err(NativeFallbackError::StateMismatch),
                Some(GroupState::Consumed) => continue,
                Some(GroupState::Available { used_slots }) => *used_slots,
            };
            let class = declared.storage_class;
            if request.storage_class != class
                && (class_match == ClassMatch::Exact || class != StorageClass::General)
            {
                continue;
            }
            // getAddrBySlot(status[grp], getAlignSize(), getAlignment()).
            budget.work(1)?;
            let invalid = |reason| NativeFallbackError::InvalidDeclaration { site, reason };
            let alignment = declared.alignment();
            if declared.min_size > NATIVE_INT_MAX
                || declared.max_size > NATIVE_INT_MAX
                || alignment > NATIVE_INT_MAX
            {
                return Err(invalid("pool geometry exceeds the native int range"));
            }
            if positive && alignment != 0 && declared.max_size % alignment != 0 {
                return Err(invalid(
                    "positive growth requires a whole number of pool slots",
                ));
            }
            let slot = if size < declared.min_size {
                Slot::Reject {
                    next: cursor,
                    reason: NoFit::BelowMinimum,
                }
            } else if alignment == 0 {
                if cursor != 0 {
                    Slot::Reject {
                        next: cursor,
                        reason: NoFit::ExclusionUsed,
                    }
                } else if size > declared.max_size {
                    Slot::Reject {
                        next: cursor,
                        reason: NoFit::AboveCapacity,
                    }
                } else {
                    Slot::Fit { first: 0, next: 0 }
                }
            } else {
                let (aligned, end) = native_slot_cursor(cursor, alignment, request.alignment, size)
                    .map_err(|operation| NativeFallbackError::NativeIntRange { site, operation })?;
                if end > u64::from(declared.max_size / alignment) {
                    Slot::Reject {
                        next: aligned,
                        reason: NoFit::SlotsExhausted,
                    }
                } else {
                    Slot::Fit {
                        first: aligned,
                        next: end,
                    }
                }
            };
            let (aligned, next) = match slot {
                Slot::Reject { next, reason } => {
                    // The source writes the wasted slots through its status
                    // reference even though the value does not fit.
                    if next != cursor {
                        self.set(
                            first.0,
                            GroupState::Available { used_slots: next },
                            budget,
                            journal,
                        )?;
                    }
                    rejected.push(NativeCandidate {
                        entry: index,
                        site,
                        group: first,
                        cursor,
                        next_cursor: next,
                        rejection: reason,
                    });
                    continue;
                }
                Slot::Fit { first, next } => (first, next),
            };

            // Only now: physical storage, justification and conversion.
            bump_count(
                &mut budget.usage.placements,
                1,
                budget.limits.max_placements,
                "placements",
            )?;
            let storage = self.storage.clone();
            let placement = place_parameter(
                &storage,
                site,
                PlacementRequest {
                    size,
                    // The native waste is already in the cursor, so placement's
                    // own alignment step must be the identity.
                    used_slots: aligned,
                    type_alignment: 1,
                    justification: Justification::Default,
                },
                budget.nested_limits(),
            )
            .map_err(placement_error(site))?;
            budget.work_u64(placement.work)?;
            budget.usage.source_pieces = budget.usage.source_pieces.max(placement.source_pieces);
            let unsupported = |reason| NativeFallbackError::Unsupported { site, reason };
            let value = match placement.outcome {
                // The source would build a wrapped address here.
                PlacementOutcome::NoFit(NoFit::AddressDomain) => {
                    return Err(unsupported("selected storage leaves its address domain"));
                }
                PlacementOutcome::Placed(value) if placement.next_slot == next => value,
                _ => {
                    return Err(unsupported(
                        "placement disagrees with native slot arithmetic",
                    ));
                }
            };
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
            budget.references(entry.groups.len())?;
            let untouched = GroupState::Available { used_slots: 0 };
            for &group in &entry.groups {
                let state = self
                    .groups
                    .get(group.0)
                    .ok_or(NativeFallbackError::StateMismatch)?;
                if group != first && *state != untouched {
                    return Err(NativeFallbackError::GroupInUse { site, group });
                }
            }
            let exclusion = alignment == 0;
            let (spans, slots) =
                self.spans(entry, declared, size, next, budget)
                    .map_err(|error| match error {
                        SpanError::Budget(error) => error.into(),
                        SpanError::Unsupported(reason) => unsupported(reason),
                    })?;
            for span in spans {
                self.occupy(span, 0, site, budget, journal)?;
            }
            if exclusion {
                for &group in &entry.groups {
                    self.set(group.0, GroupState::Consumed, budget, journal)?;
                }
            } else {
                self.set(
                    first.0,
                    GroupState::Available { used_slots: next },
                    budget,
                    journal,
                )?;
            }
            return Ok(NativeFallbackOutcome::Assigned(NativeFallbackAllocation {
                entry: index,
                site,
                group: first,
                exclusion,
                cursor,
                slots,
                alignment_waste: aligned - cursor,
                value,
            }));
        }
        Ok(NativeFallbackOutcome::NoFit)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ghidra_languages::CompilerSpec;
    use ghidra_pcode::{AddressSpace, Endianness, SpaceId, SpaceKind};

    use super::*;
    use crate::{RegisterDefinition, RegisterFile};

    /// r0 (exclusion, General) and a stack pool of 4-byte slots. The list
    /// declares `pointermax`, which the kernel must neither run nor gate on.
    fn resources(growth: &str, stack_max: u32) -> CompilerResources {
        let space = |id, name: &str, kind| AddressSpace {
            id: SpaceId(id),
            name: name.into(),
            kind,
            address_size: 4,
            word_size: 1,
            endianness: Endianness::Little,
        };
        let registers = ["r0", "sp"]
            .iter()
            .enumerate()
            .map(|(i, name)| RegisterDefinition {
                name: (*name).into(),
                space: SpaceId(1),
                offset: 4 * i as u64,
                size: 4,
            })
            .collect();
        let file = RegisterFile::new(
            vec![
                space(0, "ram", SpaceKind::Ram),
                space(1, "register", SpaceKind::Register),
            ],
            SpaceId(0),
            registers,
            Default::default(),
        )
        .unwrap();
        let text = format!(
            r#"<compiler_spec><stackpointer register="sp" space="ram" {growth}/>
<default_proto><prototype name="p" extrapop="0" stackshift="0"><input pointermax="4">
<pentry minsize="1" maxsize="4"><register name="r0"/></pentry>
<pentry minsize="1" maxsize="{stack_max}" align="4"><addr space="stack" offset="0"/></pentry>
</input><output/></prototype></default_proto></compiler_spec>"#
        );
        let spec = CompilerSpec::parse_str(&text, None, &Default::default()).unwrap();
        let storage =
            CompilerStorage::new(Arc::new(spec), Arc::new(file), Default::default()).unwrap();
        CompilerResources::new(Arc::new(storage), Default::default()).unwrap()
    }

    fn budget(max_requests: usize) -> Budget {
        Budget {
            limits: FallbackLimits {
                max_requests,
                ..Default::default()
            },
            usage: FallbackUsage::default(),
        }
    }

    fn snapshot(state: &AllocationState) -> (Vec<GroupState>, Vec<OccupiedExtent>) {
        (state.groups.clone(), state.occupied().collect())
    }

    fn input(resources: &CompilerResources) -> AllocationState {
        AllocationState::new(resources, 0, ParameterDirection::Input, Default::default()).unwrap()
    }

    #[test]
    fn members_share_one_budget_and_journal_and_roll_back_together() {
        let resources = resources("", 16);
        let mut state = input(&resources);
        let initial = snapshot(&state);
        let (list, source) = state.source_list(&resources).unwrap();
        assert_eq!(source.pointer_max, Some(4));
        let mut budget = budget(3);
        let mut journal = Vec::new();
        let mut rejected = Vec::new();
        let mut member = |state: &mut AllocationState,
                          budget: &mut Budget,
                          journal: &mut Vec<Undo>,
                          size,
                          alignment| {
            state.native_fallback_kernel(
                &list.entries,
                source,
                NativeFallbackRequest::new(size, alignment, StorageClass::General),
                ClassMatch::Exact,
                budget,
                journal,
                &mut rejected,
            )
        };
        // pointermax 4 would pass an 8-byte value by pointer; the kernel
        // places the value itself.
        let first = member(&mut state, &mut budget, &mut journal, 4, 4).unwrap();
        let second = member(&mut state, &mut budget, &mut journal, 8, 8).unwrap();
        // Cursor 2: 8 % 16 = 8 wastes two slots; 4 + 1 > 4 does not fit.
        let third = member(&mut state, &mut budget, &mut journal, 4, 16).unwrap();
        assert!(matches!(first, NativeFallbackOutcome::Assigned(ref a) if a.entry == 0));
        assert!(matches!(second, NativeFallbackOutcome::Assigned(ref a)
            if a.slots == Some(SlotRange { first: 0, next: 2 })));
        assert_eq!(third, NativeFallbackOutcome::NoFit);
        assert_eq!(
            state.groups,
            [
                GroupState::Consumed,
                GroupState::Available { used_slots: 4 }
            ]
        );
        assert_eq!(state.occupied.len(), 2);
        // One budget: three requests and every scan, write and placement.
        assert_eq!(budget.usage.requests, 3);
        assert_eq!(budget.usage.examined_entries, 1 + 2 + 2);
        assert_eq!(budget.usage.placements, 2);
        assert_eq!(budget.usage.group_updates, 3);
        // The outer action owns the journal: one rollback restores every
        // member and the failed member's waste.
        state.rollback(std::mem::take(&mut journal));
        assert_eq!(snapshot(&state), initial);
        // The shared request cap applies across calls.
        let error = member(&mut state, &mut budget, &mut journal, 4, 4).unwrap_err();
        assert!(matches!(error, NativeFallbackError::Limit("requests")));
        // Rejections accumulate in the caller's vector: only the third
        // member's stack candidate was tried and rejected (r0 was consumed).
        assert_eq!(rejected.len(), 1);
        assert_eq!(rejected[0].rejection, NoFit::SlotsExhausted);
        assert_eq!((rejected[0].cursor, rejected[0].next_cursor), (2, 4));
    }

    #[test]
    fn declaration_checks_run_only_for_tried_candidates() {
        let resources = resources("", 16);
        let mut state = input(&resources);
        let (list, source) = state.source_list(&resources).unwrap();
        // Resource construction refuses non-int geometry; hand the kernel an
        // edited declaration list to check its defensive order.
        let mut edited = source.clone();
        edited.entries[0].max_size = NATIVE_INT_MAX + 1;
        edited.entries[1].max_size = NATIVE_INT_MAX + 1;
        let run =
            |state: &mut AllocationState, source: &ghidra_languages::ParamList, class, size| {
                state.native_fallback_kernel(
                    &list.entries,
                    source,
                    NativeFallbackRequest::new(size, 4, class),
                    ClassMatch::Exact,
                    &mut budget(1),
                    &mut Vec::new(),
                    &mut Vec::new(),
                )
            };
        // Wrong class: neither entry is tried.
        let skipped = run(&mut state, &edited, StorageClass::Float, 4).unwrap();
        assert_eq!(skipped, NativeFallbackOutcome::NoFit);
        // Consume r0 with the real declarations; then only the stack is tried.
        run(&mut state, source, StorageClass::General, 4).unwrap();
        let error = run(&mut state, &edited, StorageClass::General, 4).unwrap_err();
        assert!(matches!(
            error,
            NativeFallbackError::InvalidDeclaration {
                site: BindingSite::Input { entry: 1, .. },
                reason: "pool geometry exceeds the native int range",
            }
        ));

        let resources = super::tests::resources(r#"growth="positive""#, 16);
        let mut state = input(&resources);
        let (list, source) = state.source_list(&resources).unwrap();
        let mut edited = source.clone();
        edited.entries[1].max_size = 18;
        let error = state
            .native_fallback_kernel(
                &list.entries,
                &edited,
                NativeFallbackRequest::new(8, 4, StorageClass::General),
                ClassMatch::Exact,
                &mut budget(1),
                &mut Vec::new(),
                &mut Vec::new(),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            NativeFallbackError::InvalidDeclaration {
                reason: "positive growth requires a whole number of pool slots",
                ..
            }
        ));
    }

    #[test]
    fn slot_arithmetic_follows_the_source_order() {
        let max = u64::from(NATIVE_INT_MAX);
        // Floor division: pool 8, type 12, cursor 1 stays 1.
        assert_eq!(native_slot_cursor(1, 8, 12, 12), Ok((1, 3)));
        // Pool 4, type 6: cursor 2 wastes one slot.
        assert_eq!(native_slot_cursor(2, 4, 6, 6), Ok((3, 5)));
        // No multiplication when the type alignment is not larger.
        assert_eq!(native_slot_cursor(max - 1, 4, 4, 4), Ok((max - 1, max)));
        assert_eq!(
            native_slot_cursor(max, 4, 4, 4),
            Err(NativeSlotOverflow::CursorPlusSlots)
        );
        assert_eq!(
            native_slot_cursor(max + 1, 4, 4, 4),
            Err(NativeSlotOverflow::Cursor)
        );
        // Bytes of exactly i32::MAX are allowed (pool 1); the waste of one
        // slot then overflows the cursor instead.
        assert_eq!(
            native_slot_cursor(max, 1, 2, 1),
            Err(NativeSlotOverflow::AlignedCursor)
        );
        // Multiplication one above the bound: 2^29 * 4 = 2^31 overflows.
        assert_eq!(
            native_slot_cursor(1 << 29, 4, 8, 4),
            Err(NativeSlotOverflow::CursorBytes)
        );
        assert_eq!(
            native_slot_cursor((1 << 29) - 1, 4, 8, 4),
            Ok(((1 << 29) - 1 + 1, (1 << 29) + 1))
        );
        // The wasted cursor may be exactly i32::MAX, then the addition fails.
        assert_eq!(
            native_slot_cursor(1, 1, NATIVE_INT_MAX, 1),
            Err(NativeSlotOverflow::CursorPlusSlots)
        );
        // One above i32::MAX after waste.
        assert_eq!(
            native_slot_cursor(max - 10, 1, 16, 1),
            Err(NativeSlotOverflow::AlignedCursor)
        );
    }
}
