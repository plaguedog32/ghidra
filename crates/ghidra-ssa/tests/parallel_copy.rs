//! Parallel copies are checked against an independent old-snapshot interpreter.

use std::collections::BTreeMap;

use ghidra_ssa::{
    CopyError, CopyLimits, CopyLocation, CopyMove, CopyResource, CopySlot, ParallelCopy,
    ParallelCopySchedule,
};

fn copy(destination: usize, source: usize) -> ParallelCopy {
    ParallelCopy {
        destination: CopySlot(destination),
        source: CopySlot(source),
    }
}

fn slot(index: usize) -> CopyLocation {
    CopyLocation::Slot(CopySlot(index))
}

fn movement(source: CopyLocation, destination: CopyLocation) -> CopyMove {
    CopyMove {
        source,
        destination,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Token {
    Value(usize, u64),
    Undefined(usize),
}

fn token(slot: usize) -> Token {
    match slot % 3 {
        0 => Token::Undefined(slot),
        _ => Token::Value(slot, (slot as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15)),
    }
}

/// Each expected destination reads only the original map. The sequential
/// interpreter starts its temporary uninitialized and uses opaque tokens,
/// including undefined values that cannot be replaced with a concrete zero.
fn check_snapshot(
    copies: &[ParallelCopy],
    schedule: &ParallelCopySchedule,
    old: BTreeMap<CopySlot, Token>,
) {
    let mut expected = old.clone();
    for copy in copies {
        expected.insert(copy.destination, old[&copy.source]);
    }
    let mut actual = old;
    let mut temporary = None;
    let mut saves = 0;
    for movement in schedule.moves() {
        assert_ne!(movement.source, movement.destination);
        let value = match movement.source {
            CopyLocation::Slot(slot) => {
                assert!(slot.0 < schedule.slot_count());
                actual[&slot]
            }
            CopyLocation::Temporary => temporary.expect("temporary read before its first save"),
        };
        match movement.destination {
            CopyLocation::Slot(slot) => {
                assert!(slot.0 < schedule.slot_count());
                assert!(actual.contains_key(&slot), "invented destination");
                actual.insert(slot, value);
            }
            CopyLocation::Temporary => {
                assert!(matches!(movement.source, CopyLocation::Slot(_)));
                temporary = Some(value);
                saves += 1;
            }
        }
    }
    assert_eq!(
        actual, expected,
        "sequential moves changed old-value semantics"
    );
    assert_eq!(schedule.temporary_count(), usize::from(saves != 0));
    assert!(schedule.temporary_count() <= 1);
    let active = copies
        .iter()
        .filter(|copy| copy.destination != copy.source)
        .count();
    assert_eq!(schedule.moves().len(), active + saves);
    assert_eq!(schedule.input_copy_count(), copies.len());
}

fn check(copies: &[ParallelCopy], slots: usize) -> ParallelCopySchedule {
    let schedule = ParallelCopySchedule::new(slots, copies, CopyLimits::default()).unwrap();
    check_snapshot(
        copies,
        &schedule,
        (0..slots)
            .map(|index| (CopySlot(index), token(index)))
            .collect(),
    );
    schedule
}

#[test]
fn swap_and_three_cycle_have_hand_derived_moves() {
    let swap = check(&[copy(0, 1), copy(1, 0)], 4);
    assert_eq!(
        swap.moves(),
        [
            movement(slot(0), CopyLocation::Temporary),
            movement(slot(1), slot(0)),
            movement(CopyLocation::Temporary, slot(1)),
        ]
    );
    assert_eq!(swap.work(), 20);

    let three = check(&[copy(2, 0), copy(0, 1), copy(1, 2)], 5);
    assert_eq!(
        three.moves(),
        [
            movement(slot(0), CopyLocation::Temporary),
            movement(slot(1), slot(0)),
            movement(slot(2), slot(1)),
            movement(CopyLocation::Temporary, slot(2)),
        ]
    );
    assert_eq!(three.work(), 29);
}

#[test]
fn fanout_is_saved_before_overwriting_a_cycle() {
    let schedule = check(&[copy(0, 1), copy(1, 0), copy(2, 0), copy(3, 2)], 6);
    assert_eq!(
        schedule.moves(),
        [
            movement(slot(2), slot(3)),
            movement(slot(0), slot(2)),
            movement(slot(0), CopyLocation::Temporary),
            movement(slot(1), slot(0)),
            movement(CopyLocation::Temporary, slot(1)),
        ]
    );
    assert_eq!(schedule.work(), 45);
}

#[test]
fn chains_and_repeated_sources_need_no_temporary() {
    let chain = check(&[copy(1, 2), copy(0, 1), copy(2, 3)], 5);
    assert_eq!(
        chain.moves(),
        [
            movement(slot(1), slot(0)),
            movement(slot(2), slot(1)),
            movement(slot(3), slot(2)),
        ]
    );
    assert_eq!(chain.temporary_count(), 0);
    assert_eq!(chain.work(), 39);

    let fanout = check(&[copy(1, 2), copy(0, 2)], 4);
    assert_eq!(
        fanout.moves(),
        [movement(slot(2), slot(0)), movement(slot(2), slot(1))]
    );
    assert_eq!(fanout.work(), 25);
    assert_eq!(fanout.temporary_count(), 0);
}

#[test]
fn disjoint_cycles_reuse_one_initialized_temporary() {
    let schedule = check(
        &[copy(5, 4), copy(1, 0), copy(4, 3), copy(0, 1), copy(3, 5)],
        7,
    );
    assert_eq!(schedule.temporary_count(), 1);
    assert_eq!(
        schedule.moves(),
        [
            movement(slot(0), CopyLocation::Temporary),
            movement(slot(1), slot(0)),
            movement(CopyLocation::Temporary, slot(1)),
            movement(slot(3), CopyLocation::Temporary),
            movement(slot(5), slot(3)),
            movement(slot(4), slot(5)),
            movement(CopyLocation::Temporary, slot(4)),
        ]
    );
    assert_eq!(schedule.work(), 49);
}

#[test]
fn identities_zero_slots_and_empty_domain_are_supported() {
    let empty = check(&[], 0);
    assert!(empty.moves().is_empty());
    assert_eq!(empty.work(), 0);
    assert_eq!(empty.temporary_count(), 0);

    let identities = check(&[copy(2, 2), copy(0, 0), copy(1, 1)], 4);
    assert!(identities.moves().is_empty());
    assert_eq!(identities.work(), 9);
    assert_eq!(identities.temporary_count(), 0);

    let with_identity = check(&[copy(1, 1), copy(0, 1)], 3);
    assert_eq!(with_identity.moves(), [movement(slot(1), slot(0))]);
    assert_eq!(with_identity.work(), 16);
}

#[test]
fn duplicate_destinations_include_identity_copies() {
    for copies in [
        [copy(0, 1), copy(0, 2)],
        [copy(0, 0), copy(0, 1)],
        [copy(0, 1), copy(0, 0)],
        [copy(0, 0), copy(0, 0)],
    ] {
        assert_eq!(
            ParallelCopySchedule::new(3, &copies, CopyLimits::default()),
            Err(CopyError::DuplicateDestination { slot: CopySlot(0) })
        );
    }
}

#[test]
fn invalid_source_destination_and_empty_domain_are_rejected() {
    for (slots, copies, invalid) in [
        (3, vec![copy(3, 0)], 3),
        (3, vec![copy(0, 3)], 3),
        (3, vec![copy(0, 1), copy(2, usize::MAX)], usize::MAX),
        (0, vec![copy(0, 0)], 0),
    ] {
        assert_eq!(
            ParallelCopySchedule::new(slots, &copies, CopyLimits::default()),
            Err(CopyError::InvalidSlot {
                slot: CopySlot(invalid),
                slot_count: slots,
            })
        );
    }
}

fn limit_error(resource: CopyResource) -> CopyError {
    CopyError::LimitExceeded { resource }
}

#[test]
fn every_resource_accepts_its_exact_limit_and_rejects_one_below() {
    let copies = [copy(0, 1), copy(1, 0), copy(2, 2)];
    let baseline = check(&copies, 4);
    let exact = CopyLimits {
        max_slots: 4,
        max_copies: copies.len(),
        max_moves: baseline.moves().len(),
        max_temporaries: baseline.temporary_count(),
        max_work: baseline.work(),
    };
    let schedule = ParallelCopySchedule::new(4, &copies, exact).unwrap();
    assert_eq!(schedule.moves(), baseline.moves());
    assert_eq!(schedule.limits(), exact);
    for resource in [
        CopyResource::Slots,
        CopyResource::Copies,
        CopyResource::Moves,
        CopyResource::Temporaries,
        CopyResource::Work,
    ] {
        let mut below = exact;
        match resource {
            CopyResource::Slots => below.max_slots -= 1,
            CopyResource::Copies => below.max_copies -= 1,
            CopyResource::Moves => below.max_moves -= 1,
            CopyResource::Temporaries => below.max_temporaries -= 1,
            CopyResource::Work => below.max_work -= 1,
        }
        assert_eq!(
            ParallelCopySchedule::new(4, &copies, below),
            Err(limit_error(resource)),
            "resource {resource:?}"
        );
    }
}

#[test]
fn zero_limits_fit_empty_and_scratch_free_schedules() {
    let zero = CopyLimits {
        max_slots: 0,
        max_copies: 0,
        max_moves: 0,
        max_temporaries: 0,
        max_work: 0,
    };
    assert!(ParallelCopySchedule::new(0, &[], zero).is_ok());
    let limits = CopyLimits {
        max_slots: 2,
        max_copies: 1,
        max_moves: 0,
        max_temporaries: 0,
        max_work: 3,
    };
    assert!(ParallelCopySchedule::new(2, &[copy(1, 1)], limits).is_ok());
    let limits = CopyLimits {
        max_moves: 1,
        max_work: 13,
        ..limits
    };
    assert!(ParallelCopySchedule::new(2, &[copy(0, 1)], limits).is_ok());
}

#[test]
fn every_lower_work_budget_fails_without_exposing_partial_moves() {
    for copies in [
        vec![],
        vec![copy(0, 0)],
        vec![copy(0, 1)],
        vec![copy(0, 1), copy(1, 2), copy(2, 3)],
        vec![copy(0, 1), copy(1, 0)],
        vec![copy(0, 1), copy(1, 0), copy(2, 0), copy(3, 2)],
        vec![copy(0, 1), copy(1, 0), copy(2, 3), copy(3, 2)],
    ] {
        let baseline = check(&copies, 5);
        for max_work in 0..baseline.work() {
            let limits = CopyLimits {
                max_work,
                ..CopyLimits::default()
            };
            assert_eq!(
                ParallelCopySchedule::new(5, &copies, limits),
                Err(limit_error(CopyResource::Work)),
                "copies {copies:?}, budget {max_work}"
            );
        }
        let limits = CopyLimits {
            max_work: baseline.work(),
            ..CopyLimits::default()
        };
        assert!(ParallelCopySchedule::new(5, &copies, limits).is_ok());
    }
}

#[test]
fn caps_precede_scans_and_invalid_slots_precede_graph_growth() {
    let limits = CopyLimits {
        max_slots: 0,
        max_copies: 0,
        max_work: 0,
        ..CopyLimits::default()
    };
    assert_eq!(
        ParallelCopySchedule::new(1, &[copy(9, 9)], limits),
        Err(limit_error(CopyResource::Slots))
    );
    assert_eq!(
        ParallelCopySchedule::new(0, &[copy(9, 9)], limits),
        Err(limit_error(CopyResource::Copies))
    );
    let limits = CopyLimits {
        max_work: 2,
        ..CopyLimits::default()
    };
    // Two validation records fit; a first map insertion would exceed work.
    assert_eq!(
        ParallelCopySchedule::new(2, &[copy(0, 1), copy(1, 2)], limits),
        Err(CopyError::InvalidSlot {
            slot: CopySlot(2),
            slot_count: 2,
        })
    );
}

#[test]
fn huge_sparse_slot_domains_including_usize_max_need_no_dense_storage() {
    let copies = [
        copy(usize::MAX - 1, usize::MAX - 2),
        copy(usize::MAX - 2, usize::MAX - 1),
        copy(0, usize::MAX - 1),
    ];
    let limits = CopyLimits {
        max_slots: usize::MAX,
        max_copies: 3,
        max_moves: 4,
        max_temporaries: 1,
        max_work: 32,
    };
    let schedule = ParallelCopySchedule::new(usize::MAX, &copies, limits).unwrap();
    check_snapshot(
        &copies,
        &schedule,
        [0, 42, usize::MAX - 2, usize::MAX - 1]
            .into_iter()
            .map(|index| (CopySlot(index), token(index)))
            .collect(),
    );
    assert_eq!(schedule.work(), 32);
    assert_eq!(schedule.slot_count(), usize::MAX);
    assert_eq!(
        ParallelCopySchedule::new(usize::MAX, &[copy(0, usize::MAX)], limits),
        Err(CopyError::InvalidSlot {
            slot: CopySlot(usize::MAX),
            slot_count: usize::MAX,
        })
    );
}

struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn index(&mut self, count: usize) -> usize {
        (self.next() % count as u64) as usize
    }

    fn shuffle<T>(&mut self, values: &mut [T]) {
        for i in (1..values.len()).rev() {
            let j = self.index(i + 1);
            values.swap(i, j);
        }
    }
}

#[test]
fn random_partial_maps_and_permutations_match_original_snapshot() {
    let mut random = Random(0x48bd_1aa5_762c_9001);
    for slots in 1..=48 {
        for iteration in 0..40 {
            let mut destinations: Vec<_> = (0..slots).collect();
            random.shuffle(&mut destinations);
            let count = random.index(slots + 1);
            let mut copies: Vec<_> = destinations[..count]
                .iter()
                .map(|&destination| copy(destination, random.index(slots)))
                .collect();
            if iteration % 2 == 0 {
                let mut sources: Vec<_> = (0..slots).collect();
                random.shuffle(&mut sources);
                copies = (0..slots)
                    .map(|destination| copy(destination, sources[destination]))
                    .collect();
            }
            let baseline = check(&copies, slots + 2);
            for _ in 0..3 {
                random.shuffle(&mut copies);
                let reordered = check(&copies, slots + 2);
                assert_eq!(reordered, baseline);
            }
        }
    }
}

#[test]
fn every_small_total_map_matches_original_snapshot() {
    // Exhaustive maps include all functional components, arbitrary fanout,
    // identities, and mixtures. The oracle does not discover graph cycles.
    for slots in 1usize..=5 {
        let cases = slots.pow(slots as u32);
        for mut encoding in 0..cases {
            let mut copies = Vec::new();
            for destination in 0..slots {
                copies.push(copy(destination, encoding % slots));
                encoding /= slots;
            }
            check(&copies, slots + 1);
        }
    }
}

#[test]
fn hundred_thousand_copy_chain_and_cycles_are_iterative_and_bounded() {
    const COUNT: usize = 100_000;
    let chain: Vec<_> = (0..COUNT).map(|index| copy(index, index + 1)).collect();
    let schedule = check(&chain, COUNT + 2);
    assert_eq!(schedule.moves().len(), COUNT);
    assert_eq!(schedule.temporary_count(), 0);
    assert_eq!(schedule.work(), 13 * COUNT as u64);

    let cycle: Vec<_> = (0..COUNT)
        .map(|index| copy(index, (index + 1) % COUNT))
        .collect();
    let schedule = check(&cycle, COUNT + 2);
    assert_eq!(schedule.moves().len(), COUNT + 1);
    assert_eq!(schedule.temporary_count(), 1);
    assert_eq!(schedule.work(), 9 * COUNT as u64 + 2);

    let swaps: Vec<_> = (0..COUNT).map(|index| copy(index, index ^ 1)).collect();
    let schedule = check(&swaps, COUNT + 2);
    assert_eq!(schedule.moves().len(), COUNT + COUNT / 2);
    assert_eq!(schedule.temporary_count(), 1);
    assert_eq!(schedule.work(), 10 * COUNT as u64);
}

#[test]
fn schedules_are_owned_clone_send_sync_and_errors_are_descriptive() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<ParallelCopySchedule>();
    let schedule = {
        let copies = vec![copy(0, 1), copy(1, 0)];
        ParallelCopySchedule::new(3, &copies, CopyLimits::default()).unwrap()
    };
    assert_eq!(schedule.clone(), schedule);
    assert_eq!(schedule.limits(), CopyLimits::default());
    assert_eq!(schedule.slot_count(), 3);
    assert_eq!(schedule.input_copy_count(), 2);
    assert_eq!(
        CopyError::InvalidSlot {
            slot: CopySlot(9),
            slot_count: 4
        }
        .to_string(),
        "copy slot 9 is outside 0..4"
    );
    assert!(
        CopyError::DuplicateDestination { slot: CopySlot(7) }
            .to_string()
            .contains('7')
    );
    let error: &dyn std::error::Error = &limit_error(CopyResource::Work);
    assert_eq!(error.to_string(), "parallel-copy Work limit exceeded");
}
