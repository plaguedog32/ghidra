//! Independent small-state reference for the retained rule side effects.
//!
//! `extractTiles`, ConsumeExtra/ConsumeRemaining and ExtraStack come from
//! Ghidra's ParamListStandard and protorules (Java), and fspec/modelrules (C++).
//! The fixture owns its group map. The reference caches tiles at initialization
//! and runs the source's integer-status loops; it does not call ABI placement,
//! inspect resolved entries to discover eligible tiles, or execute Java/C++.
mod common;

use std::sync::Arc;

use ghidra_abi::*;
use ghidra_languages::{RuleSideEffect, StorageClass};

const G: StorageClass = StorageClass::General;
const F: StorageClass = StorageClass::Float;
const P: StorageClass = StorageClass::Ptr;
const INPUT: ParameterDirection = ParameterDirection::Input;
const REG: AbiSpace = AbiSpace::Language(common::REGISTER);

#[derive(Clone, Debug)]
struct Entry {
    class: StorageClass,
    min: u32,
    max: u32,
    align: u32,
    groups: Vec<usize>,
    offset: u64,
    stack: bool,
    alternative: Option<usize>,
}

#[derive(Clone, Debug, Default)]
struct Fixture {
    entries: Vec<Entry>,
    group_count: usize,
    positive: bool,
}

impl Fixture {
    fn fresh_group(&mut self) -> usize {
        let group = self.group_count;
        self.group_count += 1;
        group
    }

    fn register(&mut self, class: StorageClass, max: u32, align: u32) -> usize {
        let group = self.fresh_group();
        let index = self.entries.len();
        self.entries.push(Entry {
            class,
            min: 1,
            max,
            align,
            groups: vec![group],
            offset: 0x1000 + index as u64 * 0x100,
            stack: false,
            alternative: None,
        });
        index
    }

    fn alternatives(&mut self, class: StorageClass, max: u32) {
        let first = self.register(if class == G { F } else { class }, max, 0);
        let group = self.entries[first].groups[0];
        self.entries[first].alternative = Some(group);
        let mut second = self.entries[first].clone();
        second.class = G;
        second.offset += 0x40;
        self.entries.push(second);
    }

    fn alias_pair(&mut self, first_class: StorageClass, alias_class: StorageClass) {
        assert!(self.entries.is_empty());
        self.register(first_class, 4, 0);
        self.register(G, 4, 0);
        self.entries[0].offset = 0;
        self.entries[1].offset = 4;
        self.entries.push(Entry {
            class: alias_class,
            min: 1,
            max: 8,
            align: 0,
            groups: vec![0, 1],
            offset: 0,
            stack: false,
            alternative: None,
        });
    }

    fn stack(&mut self, min: u32, max: u32, align: u32) {
        let index = self.register(G, max, align);
        self.entries[index].min = min;
        self.entries[index].offset = 16;
        self.entries[index].stack = true;
    }

    fn build(&self) -> CompilerResources {
        let mut input = String::new();
        let mut open = None;
        for e in &self.entries {
            if open != e.alternative {
                if open.is_some() {
                    input.push_str("</group>");
                }
                if e.alternative.is_some() {
                    input.push_str("<group>");
                }
                open = e.alternative;
            }
            let class = match e.class {
                StorageClass::General => "general",
                StorageClass::Float => "float",
                StorageClass::Ptr => "ptr",
                other => panic!("unexpected fixture class {other:?}"),
            };
            let space = if e.stack { "stack" } else { "register" };
            input.push_str(&format!(
                r#"<pentry minsize="{}" maxsize="{}" align="{}" storage="{class}"><addr space="{space}" offset="0x{:x}"/></pentry>"#,
                e.min, e.max, e.align, e.offset
            ));
        }
        if open.is_some() {
            input.push_str("</group>");
        }
        let growth = if self.positive {
            r#"growth="positive""#
        } else {
            ""
        };
        let source = common::parse(&format!(
            r#"<compiler_spec><stackpointer register="sp" space="ram" {growth}/>
<default_proto><prototype name="p" extrapop="0" stackshift="0"><input separatefloat="false">{input}</input><output/></prototype></default_proto></compiler_spec>"#
        ));
        let storage = common::storage(source, &common::small_file(), Default::default()).unwrap();
        let resources = CompilerResources::new(Arc::new(storage), Default::default()).unwrap();
        let actual = resources.list(0, INPUT).unwrap();
        // Ensure fixture-owned expectations describe the parsed declarations.
        assert_eq!(actual.group_count, self.group_count);
        assert_eq!(
            actual
                .entries
                .iter()
                .map(|e| e.groups.iter().map(|g| g.0).collect::<Vec<_>>())
                .collect::<Vec<_>>(),
            self.entries
                .iter()
                .map(|e| e.groups.clone())
                .collect::<Vec<_>>()
        );
        resources
    }
}

#[derive(Clone, Copy, Debug)]
enum Action {
    Extra(StorageClass, Option<bool>),
    Remaining(StorageClass),
    Stack(Option<i32>, Option<StorageClass>),
}

impl Action {
    fn production(self) -> RuleSideEffect {
        match self {
            Self::Extra(storage, match_size) => RuleSideEffect::ConsumeExtra {
                storage,
                match_size,
            },
            Self::Remaining(storage) => RuleSideEffect::ConsumeRemaining { storage },
            Self::Stack(after_bytes, after_storage) => RuleSideEffect::ExtraStack {
                after_bytes,
                after_storage,
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    Consumed(usize),
    AlreadyStack,
    Below,
    Reserved { previous: u64, next: u64, fit: bool },
}

impl From<&EffectOutcome> for Outcome {
    fn from(outcome: &EffectOutcome) -> Self {
        match *outcome {
            EffectOutcome::Consumed { groups } => Self::Consumed(groups),
            EffectOutcome::AlreadyOnStack => Self::AlreadyStack,
            EffectOutcome::BelowThreshold => Self::Below,
            EffectOutcome::StackReserved {
                previous_slot,
                next_slot,
                fit,
            } => Self::Reserved {
                previous: previous_slot,
                next: next_slot,
                fit,
            },
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Error {
    Tiles(usize, StorageClass),
    Stack(usize),
    Index {
        effect: usize,
        index: usize,
        groups: usize,
    },
    Context(usize),
    Placement(usize),
}

fn error_kind(error: &EffectError) -> Error {
    match *error {
        EffectError::MissingTiles { effect, class } => Error::Tiles(effect, class),
        EffectError::MissingStack(effect) => Error::Stack(effect),
        EffectError::ThresholdIndex {
            effect,
            index,
            groups,
        } => Error::Index {
            effect,
            index,
            groups,
        },
        EffectError::InvalidContext { effect, .. } => Error::Context(effect),
        EffectError::Placement { effect, .. } => Error::Placement(effect),
        ref other => panic!("unexpected semantic error: {other:?}"),
    }
}

struct Reference<'a> {
    fixture: &'a Fixture,
    // This is the source's signed status vector: -1 consumed, 0 untouched,
    // positive values are cursors, including holes from unsuccessful placement.
    status: Vec<i64>,
    tiles: [Vec<usize>; 3],
}

fn class_index(class: StorageClass) -> usize {
    [G, F, P].iter().position(|&c| c == class).unwrap()
}

impl<'a> Reference<'a> {
    fn new(fixture: &'a Fixture, state: &AllocationState) -> Self {
        let tiles = std::array::from_fn(|i| {
            fixture
                .entries
                .iter()
                .enumerate()
                .filter_map(|(index, e)| {
                    (e.class == [G, F, P][i] && e.align == 0 && e.groups.len() == 1)
                        .then_some(index)
                })
                .collect()
        });
        Self {
            fixture,
            status: state
                .groups()
                .iter()
                .map(|g| match *g {
                    GroupState::Consumed => -1,
                    GroupState::Available { used_slots } => used_slots as i64,
                })
                .collect(),
            tiles,
        }
    }

    fn groups(&self) -> Vec<GroupState> {
        self.status
            .iter()
            .map(|&s| {
                if s == -1 {
                    GroupState::Consumed
                } else {
                    GroupState::Available {
                        used_slots: s as u64,
                    }
                }
            })
            .collect()
    }

    fn run(
        &mut self,
        actions: &[Action],
        context: EffectContext,
        policy: StackThresholdIndexing,
    ) -> Result<Vec<Outcome>, Error> {
        let initial = self.status.clone();
        let result: Result<Vec<Outcome>, Error> = actions
            .iter()
            .enumerate()
            .map(|(effect, action)| self.action(effect, *action, context, policy))
            .collect();
        if result.is_err() {
            self.status = initial;
        }
        result
    }

    fn action(
        &mut self,
        effect: usize,
        action: Action,
        context: EffectContext,
        policy: StackThresholdIndexing,
    ) -> Result<Outcome, Error> {
        match action {
            Action::Extra(class, _) | Action::Remaining(class) => {
                let tiles = &self.tiles[class_index(class)];
                if tiles.is_empty() {
                    return Err(Error::Tiles(effect, class));
                }
                let mut consumed = 0;
                let mut size_left = context.raw_size;
                let mut iter = tiles.iter();
                while matches!(action, Action::Remaining(_)) || size_left > 0 {
                    let Some(&index) = iter.next() else { break };
                    let tile = &self.fixture.entries[index];
                    let group = tile.groups[0];
                    if self.status[group] != 0 {
                        continue;
                    }
                    self.status[group] = -1;
                    consumed += 1;
                    if let Action::Extra(_, match_size) = action {
                        size_left -= i128::from(tile.max);
                        if !match_size.unwrap_or(true) {
                            break;
                        }
                    }
                }
                Ok(Outcome::Consumed(consumed))
            }
            Action::Stack(threshold, class) => {
                let stack = self
                    .fixture
                    .entries
                    .last()
                    .filter(|e| e.stack && e.align != 0)
                    .ok_or(Error::Stack(effect))?;
                let group = stack.groups[0];
                if context.result_space == Some(AbiSpace::Stack) {
                    return Ok(Outcome::AlreadyStack);
                }
                let threshold = threshold.unwrap_or(-1);
                if threshold > 0 {
                    let mut bytes = 0;
                    for (entry_index, entry) in self.fixture.entries.iter().enumerate() {
                        let index = match policy {
                            StackThresholdIndexing::JavaEntry => entry_index,
                            StackThresholdIndexing::NativeGroup => entry.groups[0],
                        };
                        if index == group || entry.class != class.unwrap_or(G) {
                            continue;
                        }
                        let status = self.status.get(index).ok_or(Error::Index {
                            effect,
                            index,
                            groups: self.status.len(),
                        })?;
                        if *status != 0 {
                            bytes += entry.max;
                        }
                    }
                    if bytes < threshold as u32 {
                        return Ok(Outcome::Below);
                    }
                }
                if context.raw_size <= 0
                    || context.raw_size > i128::from(i32::MAX)
                    || self.status[group] < 0
                {
                    return Err(Error::Context(effect));
                }
                if context.alignment == 0 {
                    return Err(Error::Placement(effect));
                }
                let old = self.status[group] as u64;
                let mut next = old;
                let mut fit = false;
                if context.raw_size >= i128::from(stack.min) {
                    // Source getAddrBySlot, confined to divisible power-of-two
                    // alignments: align relative bytes, then count whole slots.
                    let quantum = u64::from(stack.align);
                    let alignment = u64::from(context.alignment);
                    if alignment > quantum {
                        let bytes = next * quantum;
                        next += (alignment - bytes % alignment) % alignment / quantum;
                    }
                    let used = (context.raw_size as u64).div_ceil(quantum);
                    if next + used <= u64::from(stack.max / stack.align) {
                        next += used;
                        fit = true;
                    }
                }
                self.status[group] = next as i64;
                Ok(Outcome::Reserved {
                    previous: old,
                    next,
                    fit,
                })
            }
        }
    }
}

fn fresh(resources: &CompilerResources) -> AllocationState {
    AllocationState::new(resources, 0, INPUT, Default::default()).unwrap()
}

fn snapshot(state: &AllocationState) -> (Vec<GroupState>, Vec<OccupiedExtent>) {
    (state.groups().to_vec(), state.occupied().collect())
}

fn seed(fixture: &Fixture, resources: &CompilerResources, indices: &[usize]) -> AllocationState {
    let mut state = fresh(resources);
    let mut expected = vec![GroupState::Available { used_slots: 0 }; fixture.group_count];
    for &index in indices {
        let e = &fixture.entries[index];
        assert!(
            e.groups
                .iter()
                .all(|&g| expected[g] == GroupState::Available { used_slots: 0 })
        );
        let assignment = state
            .assign_pool(
                resources,
                PoolRequest {
                    entry: index,
                    size: e.min,
                    alignment: 1,
                    justification: Justification::Default,
                },
                Default::default(),
            )
            .unwrap();
        assert!(matches!(assignment.outcome, FallbackOutcome::Assigned(_)));
        for &g in &e.groups {
            expected[g] = if e.align == 0 {
                GroupState::Consumed
            } else {
                GroupState::Available {
                    used_slots: u64::from(e.min.div_ceil(e.align)),
                }
            };
        }
    }
    assert_eq!(state.groups(), expected);
    state
}

fn compare(
    fixture: &Fixture,
    resources: &CompilerResources,
    initial: &AllocationState,
    actions: &[Action],
    context: EffectContext,
    policy: StackThresholdIndexing,
) -> Result<Vec<Outcome>, Error> {
    let mut reference = Reference::new(fixture, initial);
    let expected = reference.run(actions, context, policy);
    let mut state = initial.clone();
    let actual = state.apply_effects(
        resources,
        &actions.iter().map(|a| a.production()).collect::<Vec<_>>(),
        context,
        policy,
        Default::default(),
    );
    let label = format!("{fixture:?}; {actions:?}; {context:?}; {policy:?}");
    match (&expected, &actual) {
        (Ok(expected), Ok(actual)) => {
            assert_eq!(actual.threshold_indexing, policy, "{label}");
            assert_eq!(actual.usage.effects, actions.len(), "{label}");
            assert_eq!(
                actual
                    .outcomes
                    .iter()
                    .map(Outcome::from)
                    .collect::<Vec<_>>(),
                *expected,
                "{label}"
            );
        }
        (Err(expected), Err(actual)) => assert_eq!(error_kind(actual), *expected, "{label}"),
        _ => panic!("reference {expected:?}, actual {actual:?}; {label}"),
    }
    assert_eq!(state.groups(), reference.groups(), "{label}");
    assert_eq!(
        state.occupied().collect::<Vec<_>>(),
        initial.occupied().collect::<Vec<_>>(),
        "{label}"
    );
    if actual.is_err() {
        assert_eq!(snapshot(&state), snapshot(initial), "{label}");
    }
    expected
}

fn context(raw_size: i128, alignment: u32) -> EffectContext {
    EffectContext {
        raw_size,
        alignment,
        result_space: Some(REG),
    }
}

#[test]
fn source_examples_use_raw_countdown_exact_classes_and_single_group_tiles() {
    let mut f = Fixture::default();
    f.alias_pair(G, G);
    f.register(G, 16, 4); // Aligned registers are not tiles.
    f.register(G, 8, 0);
    f.register(F, 4, 0);
    f.stack(1, 32, 4);
    let resources = f.build();
    let initial = fresh(&resources);
    for policy in [
        StackThresholdIndexing::JavaEntry,
        StackThresholdIndexing::NativeGroup,
    ] {
        // 5 raw bytes use two 4-byte tiles. The aligned size could be 8 or 16,
        // but ConsumeExtra receives getLength/getSize, not getAlignedLength.
        assert_eq!(
            compare(
                &f,
                &resources,
                &initial,
                &[Action::Extra(G, None)],
                context(5, 16),
                policy
            ),
            Ok(vec![Outcome::Consumed(2)])
        );
        assert_eq!(
            compare(
                &f,
                &resources,
                &initial,
                &[
                    Action::Extra(G, Some(true)),
                    Action::Extra(G, Some(false)),
                    Action::Remaining(F)
                ],
                context(9, 16),
                policy
            ),
            Ok(vec![
                Outcome::Consumed(3),
                Outcome::Consumed(0),
                Outcome::Consumed(1)
            ])
        );
        // A General resource is not a Ptr tile; exhausting real tiles succeeds.
        assert_eq!(
            compare(
                &f,
                &resources,
                &initial,
                &[Action::Extra(P, Some(false))],
                context(1, 1),
                policy
            ),
            Err(Error::Tiles(0, P))
        );
        assert_eq!(
            compare(
                &f,
                &resources,
                &initial,
                &[Action::Extra(G, Some(false))],
                context(65, 1),
                policy
            ),
            Ok(vec![Outcome::Consumed(1)])
        );
        for raw in [-7, 0] {
            assert_eq!(
                compare(
                    &f,
                    &resources,
                    &initial,
                    &[Action::Extra(G, None)],
                    context(raw, 8),
                    policy
                ),
                Ok(vec![Outcome::Consumed(0)])
            );
        }
    }
    // Seed the first tile: skipped occupied registers do not reduce sizeLeft.
    let initial = seed(&f, &resources, &[0]);
    assert_eq!(
        compare(
            &f,
            &resources,
            &initial,
            &[Action::Extra(G, None)],
            context(5, 8),
            StackThresholdIndexing::NativeGroup
        ),
        Ok(vec![Outcome::Consumed(2)])
    );

    let mut no_tiles = Fixture::default();
    no_tiles.register(G, 16, 4);
    no_tiles.stack(1, 32, 4);
    let resources = no_tiles.build();
    // Tile initialization rejects an absent class even for zero raw length.
    assert_eq!(
        compare(
            &no_tiles,
            &resources,
            &fresh(&resources),
            &[Action::Extra(G, None)],
            context(0, 1),
            StackThresholdIndexing::NativeGroup
        ),
        Err(Error::Tiles(0, G))
    );
}

#[test]
fn source_entry_index_and_group_index_have_observable_different_contracts() {
    let mut f = Fixture::default();
    f.alternatives(F, 4); // entry 0 float, entry 1 general share group 0.
    f.register(G, 4, 0); // entry 2 is group 1.
    f.stack(1, 32, 4); // entry 3 is group 2.
    let resources = f.build();
    let initial = seed(&f, &resources, &[0]);
    let actions = [Action::Stack(Some(4), Some(F))];
    // Filtering to Float avoids Java's out-of-range entry 3. Both count entry
    // 0 here, proving the discrepancy is indexing rather than group creation.
    for policy in [
        StackThresholdIndexing::JavaEntry,
        StackThresholdIndexing::NativeGroup,
    ] {
        assert_eq!(
            compare(&f, &resources, &initial, &actions, context(4, 4), policy),
            Ok(vec![Outcome::Reserved {
                previous: 0,
                next: 1,
                fit: true
            }])
        );
    }
    let actions = [Action::Extra(G, Some(false)), Action::Stack(Some(4), None)];
    // Native counts general entry 1's group 0 and entry 2's group 1.
    assert_eq!(
        compare(
            &f,
            &resources,
            &initial,
            &actions,
            context(4, 4),
            StackThresholdIndexing::NativeGroup
        ),
        Ok(vec![
            Outcome::Consumed(1),
            Outcome::Reserved {
                previous: 0,
                next: 1,
                fit: true
            }
        ])
    );
    // Java skips entry index 2 (the stack group number) but attempts status[3]
    // for the actual stack entry. Its checked Rust error restores Extra's write.
    assert_eq!(
        compare(
            &f,
            &resources,
            &initial,
            &actions,
            context(4, 4),
            StackThresholdIndexing::JavaEntry
        ),
        Err(Error::Index {
            effect: 1,
            index: 3,
            groups: 3
        })
    );

    let mut divergence = Fixture::default();
    divergence.alternatives(F, 4);
    divergence.register(F, 4, 0);
    divergence.stack(1, 32, 4);
    let resources = divergence.build();
    let initial = seed(&divergence, &resources, &[2]);
    let actions = [Action::Stack(Some(4), Some(F))];
    // Entry 2 is skipped by Java because 2 is the stack group, although its
    // true resource is group 1. Float filtering also avoids the bounds error.
    assert_eq!(
        compare(
            &divergence,
            &resources,
            &initial,
            &actions,
            context(4, 4),
            StackThresholdIndexing::JavaEntry
        ),
        Ok(vec![Outcome::Below])
    );
    assert_eq!(
        compare(
            &divergence,
            &resources,
            &initial,
            &actions,
            context(4, 4),
            StackThresholdIndexing::NativeGroup
        ),
        Ok(vec![Outcome::Reserved {
            previous: 0,
            next: 1,
            fit: true
        }])
    );
}

#[test]
fn stack_thresholds_order_representative_address_and_failed_fit_follow_source() {
    let mut f = Fixture::default();
    f.register(G, 4, 0);
    f.register(F, 16, 4);
    f.stack(1, 12, 4);
    let resources = f.build();
    let initial = seed(&f, &resources, &[1, 2]);
    for policy in [
        StackThresholdIndexing::JavaEntry,
        StackThresholdIndexing::NativeGroup,
    ] {
        // A positive aligned cursor counts the full pentry maxsize, not the
        // bytes assigned so far. Size 9 then needs 3 slots after a hole to 2;
        // exhaustion preserves that hole, despite not reserving a value.
        assert_eq!(
            compare(
                &f,
                &resources,
                &initial,
                &[Action::Stack(Some(16), Some(F))],
                context(9, 8),
                policy
            ),
            Ok(vec![Outcome::Reserved {
                previous: 1,
                next: 2,
                fit: false
            }])
        );
        let untouched = fresh(&resources);
        assert_eq!(
            compare(
                &f,
                &resources,
                &untouched,
                &[
                    Action::Stack(Some(4), None),
                    Action::Remaining(G),
                    Action::Stack(Some(4), None)
                ],
                context(4, 4),
                policy
            ),
            Ok(vec![
                Outcome::Below,
                Outcome::Consumed(1),
                Outcome::Reserved {
                    previous: 0,
                    next: 1,
                    fit: true
                }
            ])
        );
        let already = EffectContext {
            raw_size: 0,
            alignment: 0,
            result_space: Some(AbiSpace::Stack),
        };
        assert_eq!(
            compare(
                &f,
                &resources,
                &initial,
                &[Action::Stack(Some(100), None)],
                already,
                policy
            ),
            Ok(vec![Outcome::AlreadyStack])
        );
        // None is a join representative; it must still reserve stack storage.
        let joined = EffectContext {
            result_space: None,
            ..context(1, 4)
        };
        assert_eq!(
            compare(
                &f,
                &resources,
                &initial,
                &[Action::Stack(None, None)],
                joined,
                policy
            ),
            Ok(vec![Outcome::Reserved {
                previous: 1,
                next: 2,
                fit: true
            }])
        );
    }
}

fn generated_fixture(case: usize) -> Fixture {
    let mut f = Fixture {
        positive: !case.is_multiple_of(2),
        ..Default::default()
    };
    if case.is_multiple_of(3) {
        f.alias_pair(if case.is_multiple_of(2) { G } else { F }, G);
    }
    if case.is_multiple_of(2) {
        f.alternatives(
            if case.is_multiple_of(4) { G } else { F },
            [2, 4, 8][case % 3],
        );
    }
    f.register([G, F, P][case % 3], [2, 4, 8][(case / 3) % 3], 0);
    f.register(G, 16, [1, 2, 4, 8][case % 4]);
    if !case.is_multiple_of(5) {
        f.register(G, [1, 2, 4, 8][(case / 2) % 4], 0);
    }
    if !case.is_multiple_of(7) {
        f.register(F, 8, 0);
    }
    let quantum = [1, 2, 4, 8][(case / 4) % 4];
    f.stack(
        if case.is_multiple_of(3) { 3 } else { 1 },
        quantum * [3, 4, 8][case % 3],
        quantum,
    );
    f
}

fn generated_actions(case: usize) -> Vec<Action> {
    let class = [G, F, P][case % 3];
    let extra = Action::Extra(class, [None, Some(true), Some(false)][(case / 3) % 3]);
    let stack = Action::Stack(
        [
            None,
            Some(-1),
            Some(0),
            Some(1),
            Some(4),
            Some(12),
            Some(32),
        ][case % 7],
        [None, Some(G), Some(F), Some(P)][(case / 2) % 4],
    );
    match case % 8 {
        0 => vec![extra],
        1 => vec![Action::Remaining(class)],
        2 => vec![stack],
        3 => vec![extra, stack],
        4 => vec![stack, extra, stack],
        5 => vec![Action::Remaining(class), stack, Action::Remaining(G)],
        6 => vec![extra, extra, Action::Remaining(class)],
        _ => vec![stack, Action::Remaining(G), Action::Remaining(F), stack],
    }
}

#[test]
fn bounded_declaration_corpus_matches_both_source_policies() {
    let mut successes = 0;
    let mut errors = 0;
    let mut index_errors = 0;
    let mut divergences = 0;
    let mut reservations = 0;
    let mut nofits = 0;
    let mut consumes = 0;
    let mut grouped = 0;
    let mut aligned_seeded = 0;
    for case in 0..72 {
        let f = generated_fixture(case);
        let resources = f.build();
        let mut seed_indices = Vec::new();
        let mut used = vec![false; f.group_count];
        for (i, e) in f.entries.iter().enumerate() {
            if (case + i) % 4 == 0 && e.groups.iter().all(|&g| !used[g]) {
                seed_indices.push(i);
                for &g in &e.groups {
                    used[g] = true;
                }
                if e.align != 0 {
                    aligned_seeded += 1;
                }
            }
        }
        grouped += usize::from(f.entries.iter().any(|e| e.alternative.is_some()));
        let initial = seed(&f, &resources, &seed_indices);
        for program in 0..36 {
            let actions = generated_actions(case * 11 + program);
            let context = EffectContext {
                raw_size: [-3, 0, 1, 3, 4, 5, 9, 17, 65][(program + case) % 9],
                alignment: [1, 2, 4, 8, 16][(program / 2 + case) % 5],
                result_space: [None, Some(REG), Some(AbiSpace::Stack)][(program / 3 + case) % 3],
            };
            let mut results = Vec::new();
            for policy in [
                StackThresholdIndexing::JavaEntry,
                StackThresholdIndexing::NativeGroup,
            ] {
                let result = compare(&f, &resources, &initial, &actions, context, policy);
                match &result {
                    Ok(outcomes) => {
                        successes += 1;
                        for outcome in outcomes {
                            match outcome {
                                Outcome::Consumed(n) => consumes += n,
                                Outcome::Reserved { fit, .. } => {
                                    reservations += 1;
                                    nofits += usize::from(!fit);
                                }
                                _ => {}
                            }
                        }
                    }
                    Err(error) => {
                        errors += 1;
                        index_errors += usize::from(matches!(error, Error::Index { .. }));
                    }
                }
                results.push(result);
            }
            divergences += usize::from(results[0] != results[1]);
        }
    }
    assert_eq!(successes + errors, 72 * 36 * 2);
    assert!(
        successes > 2000 && errors > 500,
        "successes={successes}, errors={errors}"
    );
    assert!(
        index_errors > 50 && divergences > 50,
        "index_errors={index_errors}, divergences={divergences}"
    );
    assert!(
        consumes > 500 && reservations > 200 && nofits > 50,
        "consumes={consumes}, reservations={reservations}, nofits={nofits}"
    );
    assert!(grouped > 20 && aligned_seeded > 20);
}

#[test]
fn every_actual_error_restores_preexisting_status_and_occupied_extents() {
    let mut f = Fixture::default();
    f.register(G, 4, 0);
    f.register(G, 4, 0);
    f.register(F, 16, 4);
    f.stack(1, 32, 4);
    let resources = f.build();
    let initial = seed(&f, &resources, &[2, 3]);
    let actions = [
        Action::Extra(G, Some(false)),
        Action::Stack(None, None),
        Action::Remaining(G),
    ];
    let effects = actions.map(Action::production);
    let mut complete = initial.clone();
    let batch = complete
        .apply_effects(
            &resources,
            &effects,
            context(4, 8),
            StackThresholdIndexing::NativeGroup,
            Default::default(),
        )
        .unwrap();
    assert_ne!(snapshot(&complete), snapshot(&initial));
    let before = snapshot(&initial);
    let mut failures_after_work = 0;
    // Drive each resource cap across every value up to its measured usage.
    // These are real Rust errors, including ones after earlier effects wrote
    // status. Exact budget bookkeeping is intentionally outside the oracle.
    for dimension in 0..5 {
        let used = match dimension {
            0 => batch.usage.effects as u64,
            1 => batch.usage.examined_entries,
            2 => batch.usage.group_references,
            3 => batch.usage.group_updates,
            _ => batch.usage.work,
        };
        for cap in 0..used {
            let mut limits = EffectLimits::default();
            match dimension {
                0 => limits.max_effects = cap as usize,
                1 => limits.max_examined_entries = cap,
                2 => limits.max_group_references = cap,
                3 => limits.max_group_updates = cap,
                _ => limits.max_work = cap,
            }
            let mut state = initial.clone();
            assert!(
                state
                    .apply_effects(
                        &resources,
                        &effects,
                        context(4, 8),
                        StackThresholdIndexing::NativeGroup,
                        limits
                    )
                    .is_err(),
                "dimension={dimension}, cap={cap}, usage={:?}",
                batch.usage
            );
            assert_eq!(snapshot(&state), before, "dimension={dimension}, cap={cap}");
            failures_after_work += usize::from(cap > 1 && dimension != 0);
        }
    }
    assert!(failures_after_work > 10);

    for invalid in [
        context(0, 4),
        context(-1, 4),
        context(i128::from(i32::MAX) + 1, 4),
        context(4, 0),
    ] {
        assert!(
            compare(
                &f,
                &resources,
                &initial,
                &[Action::Remaining(G), Action::Stack(None, None)],
                invalid,
                StackThresholdIndexing::NativeGroup
            )
            .is_err()
        );
    }
    assert_eq!(
        compare(
            &f,
            &resources,
            &initial,
            &[Action::Remaining(G), Action::Remaining(P)],
            context(4, 4),
            StackThresholdIndexing::NativeGroup
        ),
        Err(Error::Tiles(1, P))
    );

    f.entries.pop();
    f.group_count -= 1;
    let resources = f.build();
    assert_eq!(
        compare(
            &f,
            &resources,
            &fresh(&resources),
            &[Action::Remaining(G), Action::Stack(None, None)],
            context(4, 4),
            StackThresholdIndexing::NativeGroup
        ),
        Err(Error::Stack(1))
    );
}
