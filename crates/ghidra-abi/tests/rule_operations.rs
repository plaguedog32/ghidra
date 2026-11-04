//! Hand-derived rule primitive expectations from protorules and modelrules.cc.
mod common;

use ghidra_abi::*;
use ghidra_languages::{RuleSideEffect as E, StorageClass as C};
use ghidra_pcode::Endianness;
use std::sync::Arc;

fn reg(name: &str, class: &str) -> String {
    format!(
        r#"<pentry minsize="1" maxsize="4" storage="{class}"><register name="{name}"/></pentry>"#
    )
}
fn stack(max: u32, align: u32) -> String {
    format!(
        r#"<pentry minsize="1" maxsize="{max}" align="{align}"><addr space="stack" offset="8"/></pentry>"#
    )
}
fn plan(input: &str, big: bool) -> CompilerResources {
    let source = common::parse(&format!(
        r#"<compiler_spec><stackpointer register="sp" space="ram"/>
      <default_proto><prototype name="p" extrapop="0" stackshift="0"><input>{input}</input><output/></prototype></default_proto></compiler_spec>"#
    ));
    let mut spaces = common::spaces(4);
    if big {
        for s in &mut spaces {
            s.endianness = Endianness::Big;
        }
    }
    let file = Arc::new(
        RegisterFile::new(
            spaces,
            common::RAM,
            common::small_registers(),
            Default::default(),
        )
        .unwrap(),
    );
    let storage = common::storage(source, &file, Default::default()).unwrap();
    CompilerResources::new(Arc::new(storage), Default::default()).unwrap()
}
fn fresh(r: &CompilerResources) -> AllocationState {
    AllocationState::new(r, 0, ParameterDirection::Input, Default::default()).unwrap()
}
fn context(size: i128) -> EffectContext {
    EffectContext {
        raw_size: size,
        alignment: 1,
        result_space: None,
    }
}
fn extra() -> E {
    E::ExtraStack {
        after_bytes: None,
        after_storage: None,
    }
}
fn more(class: C, match_size: Option<bool>) -> E {
    E::ConsumeExtra {
        storage: class,
        match_size,
    }
}
fn all(class: C) -> E {
    E::ConsumeRemaining { storage: class }
}
fn apply(
    s: &mut AllocationState,
    r: &CompilerResources,
    effects: &[E],
    c: EffectContext,
) -> EffectBatch {
    s.apply_effects(
        r,
        effects,
        c,
        StackThresholdIndexing::NativeGroup,
        Default::default(),
    )
    .unwrap()
}
fn pool(
    s: &mut AllocationState,
    r: &CompilerResources,
    entry: usize,
    size: u32,
    alignment: u32,
    justification: Justification,
) -> PoolAssignment {
    s.assign_pool(
        r,
        PoolRequest {
            entry,
            size,
            alignment,
            justification,
        },
        Default::default(),
    )
    .unwrap()
}
fn offset(a: &PoolAssignment) -> u64 {
    let FallbackOutcome::Assigned(a) = &a.outcome else {
        panic!("not assigned: {a:?}");
    };
    let PlacedStorage::Bits { pieces } = &a.value.storage else {
        panic!("not bits");
    };
    assert_eq!(pieces.len(), 1);
    pieces[0].storage.address.offset
}
fn statuses(s: &AllocationState) -> (Vec<GroupState>, Vec<OccupiedExtent>) {
    (s.groups().to_vec(), s.occupied().collect())
}

#[test]
fn selected_entry_ignores_class_uses_requested_justification_and_does_not_search() {
    let r = plan(&(reg("f0", "float") + &reg("r0", "general")), true);
    let mut s = fresh(&r);
    let a = pool(&mut s, &r, 0, 2, 1, Justification::Left);
    assert_eq!(offset(&a), 0x100);
    assert_eq!(a.usage.examined_entries, 1);
    assert!(matches!(
        pool(&mut s, &r, 0, 2, 1, Justification::Default).outcome,
        FallbackOutcome::NoFit { candidates: 0 }
    ));
    assert_eq!(s.groups()[1], GroupState::Available { used_slots: 0 });
    let mut s = fresh(&r);
    assert_eq!(
        offset(&pool(&mut s, &r, 0, 2, 1, Justification::Right)),
        0x102
    );
}

#[test]
fn raw_and_aligned_sizes_remain_explicit_and_extra_stack_has_no_value_extent() {
    let r = plan(&stack(64, 1), false);
    let mut s = fresh(&r);
    let a = pool(&mut s, &r, 0, 3, 4, Justification::Default);
    assert_eq!(offset(&a), 8);
    assert_eq!(s.groups(), &[GroupState::Available { used_slots: 3 }]);
    let mut s = fresh(&r);
    s.assign_fallback(
        &r,
        &[FallbackRequest::new(4, 4, C::General)],
        Default::default(),
        Default::default(),
    )
    .unwrap();
    assert_eq!(s.groups(), &[GroupState::Available { used_slots: 4 }]);
    let mut s = fresh(&r);
    let b = apply(
        &mut s,
        &r,
        &[extra()],
        EffectContext {
            alignment: 4,
            ..context(3)
        },
    );
    assert_eq!(
        b.outcomes,
        [EffectOutcome::StackReserved {
            previous_slot: 0,
            next_slot: 3,
            fit: true
        }]
    );
    assert_eq!(s.occupied_count(), 0);
    assert_eq!(s.groups(), &[GroupState::Available { used_slots: 3 }]);
    let direct = place_parameter(
        r.storage(),
        BindingSite::Input { model: 0, entry: 0 },
        PlacementRequest {
            size: 3,
            used_slots: 0,
            type_alignment: 4,
            justification: Justification::Default,
        },
        Default::default(),
    )
    .unwrap();
    // Header/effect 2 + entry 1 + one-binding lookup 2 + group read/write 2.
    assert_eq!(b.usage.work, 7 + direct.work);
}

#[test]
fn no_fit_retains_alignment_holes_but_errors_restore_everything() {
    let r = plan(&stack(8, 1), false);
    let mut s = fresh(&r);
    pool(&mut s, &r, 0, 1, 1, Justification::Default);
    let before = s.occupied().collect::<Vec<_>>();
    let a = pool(&mut s, &r, 0, 6, 4, Justification::Default);
    assert!(matches!(
        a.outcome,
        FallbackOutcome::NoFit { candidates: 1 }
    ));
    assert_eq!(s.groups(), &[GroupState::Available { used_slots: 4 }]);
    assert_eq!(s.occupied().collect::<Vec<_>>(), before);
    let b = apply(
        &mut s,
        &r,
        &[extra()],
        EffectContext {
            alignment: 8,
            ..context(6)
        },
    );
    assert_eq!(
        b.outcomes,
        [EffectOutcome::StackReserved {
            previous_slot: 4,
            next_slot: 8,
            fit: false
        }]
    );
    let before = statuses(&s);
    assert!(
        s.assign_pool(
            &r,
            PoolRequest {
                entry: 5,
                size: 1,
                alignment: 1,
                justification: Justification::Default
            },
            Default::default()
        )
        .is_err()
    );
    assert_eq!(statuses(&s), before);
    assert!(
        s.apply_effects(
            &r,
            &[extra()],
            context(0),
            StackThresholdIndexing::NativeGroup,
            Default::default()
        )
        .is_err()
    );
    assert_eq!(statuses(&s), before);
}

#[test]
fn extra_register_countdown_defaults_to_raw_size_and_exhaustion_succeeds() {
    let r = plan(
        &(reg("r0", "general") + &reg("r1", "general") + &reg("r2", "general")),
        false,
    );
    for (size, single, expected) in [
        (9, None, 3),
        (9, Some(false), 1),
        (0, Some(false), 0),
        (-1, None, 0),
        (99, None, 3),
    ] {
        let mut s = fresh(&r);
        let b = apply(&mut s, &r, &[more(C::General, single)], context(size));
        assert_eq!(b.outcomes, [EffectOutcome::Consumed { groups: expected }]);
        assert_eq!(
            s.groups()
                .iter()
                .filter(|x| **x == GroupState::Consumed)
                .count(),
            expected
        );
        assert_eq!(s.occupied_count(), 0);
        let b = apply(&mut s, &r, &[all(C::General)], context(0));
        assert_eq!(
            b.outcomes,
            [EffectOutcome::Consumed {
                groups: 3 - expected
            }]
        );
    }
}

#[test]
fn tile_selection_is_exact_class_exclusion_and_single_group() {
    let input = reg("f0", "float")
        + &reg("r0", "general")
        + &reg("r1", "general")
        + r#"<pentry minsize="1" maxsize="8"><addr space="join" piece1="r0" piece2="r1"/></pentry>"#
        + &stack(64, 4);
    let r = plan(&input, false);
    let mut s = fresh(&r);
    let b = apply(&mut s, &r, &[all(C::General)], context(100));
    assert_eq!(b.outcomes, [EffectOutcome::Consumed { groups: 2 }]);
    assert_eq!(s.groups()[0], GroupState::Available { used_slots: 0 });
    assert_eq!(
        s.groups().last(),
        Some(&GroupState::Available { used_slots: 0 })
    );
    let before = statuses(&s);
    assert!(matches!(
        s.apply_effects(
            &r,
            &[all(C::Ptr)],
            context(1),
            StackThresholdIndexing::NativeGroup,
            Default::default()
        ),
        Err(EffectError::MissingTiles { .. })
    ));
    assert_eq!(statuses(&s), before);
}

#[test]
fn a_tile_with_a_positive_shared_pool_cursor_is_already_consumed() {
    let r = plan(
        &(r#"<pentry minsize="1" maxsize="8" align="4"><addr space="register" offset="0"/></pentry>"#.to_owned()
            + r#"<pentry minsize="1" maxsize="8"><register name="d0"/></pentry>"#),
        false,
    );
    assert_eq!(
        r.list(0, ParameterDirection::Input).unwrap().entries[1].groups,
        [ResourceId(0)]
    );
    let mut s = fresh(&r);
    pool(&mut s, &r, 0, 1, 1, Justification::Default);
    let before = statuses(&s);
    let b = apply(
        &mut s,
        &r,
        &[more(C::General, None), all(C::General)],
        context(8),
    );
    assert_eq!(
        b.outcomes,
        [
            EffectOutcome::Consumed { groups: 0 },
            EffectOutcome::Consumed { groups: 0 }
        ]
    );
    assert_eq!(statuses(&s), before);
    assert_eq!(s.groups(), &[GroupState::Available { used_slots: 1 }]);
}

#[test]
fn already_on_stack_uses_only_representative_space() {
    let r = plan(&(reg("r0", "general") + &stack(64, 1)), false);
    let mut s = fresh(&r);
    let b = apply(
        &mut s,
        &r,
        &[extra()],
        EffectContext {
            result_space: Some(AbiSpace::Stack),
            ..context(3)
        },
    );
    assert_eq!(b.outcomes, [EffectOutcome::AlreadyOnStack]);
    assert_eq!(
        s.groups().last(),
        Some(&GroupState::Available { used_slots: 0 })
    );
    // None is a join representative, including a mixed register/stack join.
    apply(&mut s, &r, &[extra()], context(3));
    assert_eq!(
        s.groups().last(),
        Some(&GroupState::Available { used_slots: 3 })
    );
}

#[test]
fn thresholds_see_full_declared_sizes_and_ordered_effects() {
    let r = plan(
        &(reg("r0", "general") + &reg("r1", "general") + &stack(64, 1)),
        false,
    );
    let threshold = E::ExtraStack {
        after_bytes: Some(8),
        after_storage: None,
    };
    let mut s = fresh(&r);
    apply(&mut s, &r, &[more(C::General, Some(false))], context(1));
    let b = apply(
        &mut s,
        &r,
        &[threshold.clone(), more(C::General, Some(false))],
        context(1),
    );
    assert_eq!(b.outcomes[0], EffectOutcome::BelowThreshold);
    assert_eq!(
        s.groups().last(),
        Some(&GroupState::Available { used_slots: 0 })
    );
    let b = apply(&mut s, &r, &[threshold], context(1));
    assert_eq!(
        b.outcomes[0],
        EffectOutcome::StackReserved {
            previous_slot: 0,
            next_slot: 1,
            fit: true
        }
    );
    for after_bytes in [None, Some(-1), Some(0)] {
        let mut s = fresh(&r);
        let b = apply(
            &mut s,
            &r,
            &[E::ExtraStack {
                after_bytes,
                after_storage: None,
            }],
            context(1),
        );
        assert!(matches!(b.outcomes[0], EffectOutcome::StackReserved { .. }));
    }
}

#[test]
fn effects_require_final_stack_pool_and_preflight_tile_availability() {
    let r = plan(&(stack(64, 4) + &reg("r0", "general")), false);
    let mut s = fresh(&r);
    assert!(matches!(
        s.apply_effects(
            &r,
            &[extra()],
            context(4),
            StackThresholdIndexing::NativeGroup,
            Default::default()
        ),
        Err(EffectError::MissingStack(0))
    ));
    let r = plan(&stack(64, 4), false);
    assert!(matches!(
        fresh(&r).apply_effects(
            &r,
            &[more(C::General, None)],
            context(0),
            StackThresholdIndexing::NativeGroup,
            Default::default()
        ),
        Err(EffectError::MissingTiles { .. })
    ));
}

#[test]
fn effect_limits_are_absolute_and_every_failure_rolls_back() {
    let r = plan(
        &(reg("r0", "general") + &reg("r1", "general") + &reg("r2", "general")),
        false,
    );
    let effects = [all(C::General), all(C::General)];
    let b = apply(&mut fresh(&r), &r, &effects, context(10));
    // 1 + two effect visits + six entry visits + six group reads + three writes.
    assert_eq!(
        b.usage,
        EffectUsage {
            effects: 2,
            examined_entries: 6,
            group_references: 6,
            group_updates: 3,
            work: 18
        }
    );
    let exact = EffectLimits {
        max_effects: 2,
        max_examined_entries: 6,
        max_group_references: 6,
        max_group_updates: 3,
        max_work: 18,
    };
    let mut s = fresh(&r);
    assert!(
        s.apply_effects(
            &r,
            &effects,
            context(10),
            StackThresholdIndexing::NativeGroup,
            exact
        )
        .is_ok()
    );
    for cap in 0..5 {
        let mut limits = exact;
        match cap {
            0 => limits.max_effects -= 1,
            1 => limits.max_examined_entries -= 1,
            2 => limits.max_group_references -= 1,
            3 => limits.max_group_updates -= 1,
            _ => limits.max_work -= 1,
        }
        let mut s = fresh(&r);
        let before = statuses(&s);
        assert!(
            s.apply_effects(
                &r,
                &effects,
                context(10),
                StackThresholdIndexing::NativeGroup,
                limits
            )
            .is_err()
        );
        assert_eq!(statuses(&s), before);
    }
    for max_work in 0..18 {
        let mut s = fresh(&r);
        assert!(
            s.apply_effects(
                &r,
                &effects,
                context(10),
                StackThresholdIndexing::NativeGroup,
                EffectLimits { max_work, ..exact }
            )
            .is_err()
        );
        assert_eq!(statuses(&s), statuses(&fresh(&r)));
    }
}

#[test]
fn later_effect_error_restores_prior_effects_and_prior_value_extents() {
    let r = plan(
        &(reg("r0", "general") + &reg("r1", "general") + &stack(64, 4)),
        false,
    );
    let mut s = fresh(&r);
    pool(&mut s, &r, 0, 1, 1, Justification::Default);
    let before = statuses(&s);
    assert!(
        s.apply_effects(
            &r,
            &[all(C::General), extra(), all(C::Float)],
            context(4),
            StackThresholdIndexing::NativeGroup,
            Default::default()
        )
        .is_err()
    );
    assert_eq!(statuses(&s), before);
    let other = plan(
        &(reg("r0", "general") + &reg("r1", "general") + &stack(64, 4)),
        false,
    );
    assert!(matches!(
        s.apply_effects(
            &other,
            &[],
            context(1),
            StackThresholdIndexing::NativeGroup,
            Default::default()
        ),
        Err(EffectError::Allocation(FallbackError::StateMismatch))
    ));
    assert!(matches!(
        s.assign_pool(
            &other,
            PoolRequest {
                entry: 1,
                size: 1,
                alignment: 1,
                justification: Justification::Default
            },
            Default::default()
        ),
        Err(FallbackError::StateMismatch)
    ));
}

#[test]
fn selected_assignment_all_lower_work_caps_restore_state() {
    let r = plan(&stack(64, 4), false);
    let request = PoolRequest {
        entry: 0,
        size: 4,
        alignment: 8,
        justification: Justification::Default,
    };
    let mut initial = fresh(&r);
    pool(&mut initial, &r, 0, 4, 4, Justification::Default);
    let b = initial
        .clone()
        .assign_pool(&r, request, Default::default())
        .unwrap();
    assert_eq!(offset(&b), 16);
    for max_work in 0..b.usage.work {
        let mut s = initial.clone();
        assert!(
            s.assign_pool(
                &r,
                request,
                FallbackLimits {
                    max_work,
                    ..Default::default()
                }
            )
            .is_err()
        );
        assert_eq!(statuses(&s), statuses(&initial));
    }
}
