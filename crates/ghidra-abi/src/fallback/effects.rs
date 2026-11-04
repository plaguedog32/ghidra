//! Resource-only rule effects. These never create a parameter value.
use ghidra_languages::RuleSideEffect;

use super::*;

/// The retained Java threshold loop indexes status by pentry index; native
/// C++ indexes by the pentry's first resource group. Grouped alternatives make
/// these different. Callers must choose the source contract explicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum StackThresholdIndexing {
    JavaEntry,
    NativeGroup,
}

#[derive(Clone, Copy, Debug)]
pub struct EffectContext {
    /// getLength/getSize, not aligned length. Nonpositive sizes consume no
    /// extra registers; they cannot be passed to the checked stack placer.
    pub raw_size: i128,
    pub alignment: u32,
    /// Space of the assignment's representative address. None denotes a join
    /// address, not "any piece is on the stack". Already collapsed contiguous
    /// stack storage has Some(Stack).
    pub result_space: Option<AbiSpace>,
}

#[derive(Clone, Copy, Debug)]
pub struct EffectLimits {
    pub max_effects: usize,
    pub max_examined_entries: u64,
    pub max_group_references: u64,
    pub max_group_updates: u64,
    pub max_work: u64,
}

impl Default for EffectLimits {
    fn default() -> Self {
        Self {
            max_effects: 4096,
            max_examined_entries: 4_000_000,
            max_group_references: 8_000_000,
            max_group_updates: 1_000_000,
            max_work: 64_000_000,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum EffectOutcome {
    /// Exhaustion is success, even if fewer bytes than requested were consumed.
    Consumed {
        groups: usize,
    },
    AlreadyOnStack,
    BelowThreshold,
    /// A checked stack placement may fail to fit but still advance alignment
    /// holes. Its address is ignored, as in ExtraStack.
    StackReserved {
        previous_slot: u64,
        next_slot: u64,
        fit: bool,
    },
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct EffectUsage {
    pub effects: usize,
    pub examined_entries: u64,
    pub group_references: u64,
    pub group_updates: u64,
    /// Includes nested stack placement work.
    pub work: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EffectBatch {
    pub outcomes: Vec<EffectOutcome>,
    pub threshold_indexing: StackThresholdIndexing,
    pub usage: EffectUsage,
}

#[derive(Debug, thiserror::Error)]
pub enum EffectError {
    #[error("rule-effect limit exceeded: {0}")]
    Limit(&'static str),
    #[error("effect {effect}: no exclusion, single-group tiles of class {class:?}")]
    MissingTiles { effect: usize, class: StorageClass },
    #[error("effect {0}: the last parameter entry is not an aligned stack pool")]
    MissingStack(usize),
    #[error("effect {effect}: Java threshold status index {index} is outside {groups} groups")]
    ThresholdIndex {
        effect: usize,
        index: usize,
        groups: usize,
    },
    #[error("effect {effect}: {reason}")]
    InvalidContext { effect: usize, reason: &'static str },
    #[error("effect {effect}: {source}")]
    Placement {
        effect: usize,
        source: PlacementError,
    },
    #[error(transparent)]
    Allocation(#[from] FallbackError),
}

impl AllocationState {
    /// Execute preconditions or side effects in declaration order on this state.
    /// An Err restores every status change; successful exhaustion is not Err.
    /// Effects reserve logical resources, not writable bytes, and leave occupied
    /// value extents unchanged. The caller supplies the raw datatype geometry
    /// and representative result address; no datatype or rule is guessed here.
    pub fn apply_effects(
        &mut self,
        resources: &CompilerResources,
        effects: &[RuleSideEffect],
        context: EffectContext,
        indexing: StackThresholdIndexing,
        limits: EffectLimits,
    ) -> Result<EffectBatch, EffectError> {
        let mut journal = Vec::new();
        let result = self.run_effects(resources, effects, context, indexing, limits, &mut journal);
        if result.is_err() {
            self.rollback(journal);
        }
        result
    }

    #[allow(clippy::too_many_arguments)]
    fn run_effects(
        &mut self,
        resources: &CompilerResources,
        effects: &[RuleSideEffect],
        context: EffectContext,
        indexing: StackThresholdIndexing,
        limits: EffectLimits,
        journal: &mut Vec<Undo>,
    ) -> Result<EffectBatch, EffectError> {
        let (list, source) = self.source_list(resources)?;
        if effects.len() > limits.max_effects {
            return Err(EffectError::Limit("effects"));
        }
        let mut budget = Budget {
            limits: FallbackLimits {
                max_examined_entries: limits.max_examined_entries,
                max_group_references: limits.max_group_references,
                max_group_updates: limits.max_group_updates,
                max_work: limits.max_work,
                ..Default::default()
            },
            usage: FallbackUsage::default(),
        };
        budget.work(1)?;
        budget.work(effects.len())?;
        let mut outcomes = Vec::with_capacity(effects.len());
        for (effect, action) in effects.iter().enumerate() {
            let outcome = match *action {
                RuleSideEffect::ConsumeExtra {
                    storage,
                    match_size,
                } => self.consume_tiles(
                    effect,
                    storage,
                    Some((context.raw_size, match_size.unwrap_or(true))),
                    list,
                    source,
                    &mut budget,
                    journal,
                )?,
                RuleSideEffect::ConsumeRemaining { storage } => {
                    self.consume_tiles(effect, storage, None, list, source, &mut budget, journal)?
                }
                RuleSideEffect::ExtraStack {
                    after_bytes,
                    after_storage,
                } => self.extra_stack(
                    effect,
                    after_bytes.unwrap_or(-1),
                    after_storage.unwrap_or(StorageClass::General),
                    context,
                    indexing,
                    list,
                    source,
                    &mut budget,
                    journal,
                )?,
            };
            outcomes.push(outcome);
        }
        let u = budget.usage;
        Ok(EffectBatch {
            outcomes,
            threshold_indexing: indexing,
            usage: EffectUsage {
                effects: effects.len(),
                examined_entries: u.examined_entries,
                group_references: u.group_references,
                group_updates: u.group_updates,
                work: u.work,
            },
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn consume_tiles(
        &mut self,
        effect: usize,
        class: StorageClass,
        count: Option<(i128, bool)>,
        list: &crate::ListResources,
        source: &ghidra_languages::ParamList,
        budget: &mut Budget,
        journal: &mut Vec<Undo>,
    ) -> Result<EffectOutcome, EffectError> {
        let mut found = false;
        let mut consumed = 0;
        let mut remaining = count.map_or(1, |(size, _)| size);
        for (entry, declared) in list.entries.iter().zip(&source.entries) {
            budget.examine()?;
            if !entry.exclusion || entry.groups.len() != 1 || declared.storage_class != class {
                continue;
            }
            found = true;
            // The scan also validates that tiles exist when size is zero, as
            // upstream initialization does before assignAddress is called.
            if remaining <= 0 {
                continue;
            }
            budget.references(1)?;
            let group = entry.groups[0].0;
            if self.groups[group] != (GroupState::Available { used_slots: 0 }) {
                continue;
            }
            self.set(group, GroupState::Consumed, budget, journal)?;
            consumed += 1;
            if let Some((_, match_size)) = count {
                remaining -= i128::from(declared.max_size);
                if !match_size {
                    remaining = 0;
                }
            }
        }
        if !found {
            return Err(EffectError::MissingTiles { effect, class });
        }
        Ok(EffectOutcome::Consumed { groups: consumed })
    }

    #[allow(clippy::too_many_arguments)]
    fn extra_stack(
        &mut self,
        effect: usize,
        threshold: i32,
        class: StorageClass,
        context: EffectContext,
        indexing: StackThresholdIndexing,
        list: &crate::ListResources,
        source: &ghidra_languages::ParamList,
        budget: &mut Budget,
        journal: &mut Vec<Undo>,
    ) -> Result<EffectOutcome, EffectError> {
        let invalid = |reason| EffectError::InvalidContext { effect, reason };
        let entry = list
            .entries
            .last()
            .ok_or(EffectError::MissingStack(effect))?;
        budget.examine()?;
        budget.lookup(self.storage.bindings().len())?;
        let binding = self
            .storage
            .binding(entry.site)
            .ok_or(FallbackError::StateMismatch)?;
        if entry.exclusion
            || !matches!(&binding.storage, ResolvedStorage::Single(range) if range.address.space == AbiSpace::Stack)
        {
            return Err(EffectError::MissingStack(effect));
        }
        budget.references(1)?;
        let stack_group = entry.groups.first().ok_or(FallbackError::StateMismatch)?.0;
        if context.result_space == Some(AbiSpace::Stack) {
            return Ok(EffectOutcome::AlreadyOnStack);
        }
        if threshold > 0 {
            let mut consumed_bytes = 0_u64;
            for (i, (resource, declared)) in list.entries.iter().zip(&source.entries).enumerate() {
                budget.examine()?;
                let index = match indexing {
                    StackThresholdIndexing::JavaEntry => i,
                    StackThresholdIndexing::NativeGroup => {
                        budget.references(1)?;
                        resource
                            .groups
                            .first()
                            .ok_or(FallbackError::StateMismatch)?
                            .0
                    }
                };
                if index == stack_group || declared.storage_class != class {
                    continue;
                }
                budget.references(1)?;
                let status = self.groups.get(index).ok_or(EffectError::ThresholdIndex {
                    effect,
                    index,
                    groups: self.groups.len(),
                })?;
                if *status != (GroupState::Available { used_slots: 0 }) {
                    consumed_bytes = consumed_bytes
                        .checked_add(u64::from(declared.max_size))
                        .ok_or_else(|| invalid("consumed byte count overflow"))?;
                }
            }
            if consumed_bytes < threshold as u64 {
                return Ok(EffectOutcome::BelowThreshold);
            }
        }
        let size = u32::try_from(context.raw_size)
            .ok()
            .filter(|&n| n > 0 && n <= i32::MAX as u32)
            .ok_or_else(|| invalid("stack reservation needs a positive signed-int raw size"))?;
        let cursor = match self.groups.get(stack_group) {
            Some(GroupState::Available { used_slots }) => *used_slots,
            Some(GroupState::Consumed) => return Err(invalid("stack group is already consumed")),
            None => return Err(FallbackError::StateMismatch.into()),
        };
        let placement = place_parameter(
            &self.storage,
            entry.site,
            PlacementRequest {
                size,
                used_slots: cursor,
                type_alignment: context.alignment,
                justification: Justification::Default,
            },
            budget.nested_limits(),
        )
        .map_err(|source| EffectError::Placement { effect, source })?;
        budget.work_u64(placement.work)?;
        if matches!(
            placement.outcome,
            PlacementOutcome::NoFit(NoFit::AddressDomain)
        ) {
            return Err(invalid("reserved stack storage leaves its address domain"));
        }
        if placement.next_slot != cursor {
            self.set(
                stack_group,
                GroupState::Available {
                    used_slots: placement.next_slot,
                },
                budget,
                journal,
            )?;
        }
        Ok(EffectOutcome::StackReserved {
            previous_slot: cursor,
            next_slot: placement.next_slot,
            fit: matches!(placement.outcome, PlacementOutcome::Placed(_)),
        })
    }
}
