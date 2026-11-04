//! Native one-value fallback: `ParamListStandard::assignAddressFallback`
//! (fspec.cc:731-758) with the source's `ParamEntry::getAddrBySlot`
//! arithmetic (fspec.cc:453-494). Every expected status and address below is
//! derived by hand from the declarations and those source lines; the
//! published exact-congruence fallback appears only as a contrast.
mod common;

use std::sync::Arc;

use ghidra_abi::*;
use ghidra_languages::{Extension, MetaType, StorageClass};
use ghidra_pcode::{Endianness, SpaceId};

const G: StorageClass = StorageClass::General;
const F: StorageClass = StorageClass::Float;
const P: StorageClass = StorageClass::Ptr;
const REG: AbiSpace = AbiSpace::Language(SpaceId(2));
const STACK: AbiSpace = AbiSpace::Stack;
const INPUT: ParameterDirection = ParameterDirection::Input;
const OUTPUT: ParameterDirection = ParameterDirection::Output;
const MAX: u32 = i32::MAX as u32;

/// (name, register-space offset, size).
const REGISTERS: &[(&str, u64, u32)] = &[
    ("r0", 0, 4),
    ("r1", 4, 4),
    ("r2", 8, 4),
    ("r3", 12, 4),
    ("wide", 0, 8),
    ("quad", 0, 16),
    ("f0", 0x100, 4),
    ("f1", 0x104, 4),
    ("d0", 0x100, 8),
    ("d1", 0x108, 8),
    ("x0", 0x200, 8),
    ("x1", 0x208, 8),
    ("sp", 0x400, 4),
];

fn file(big: bool) -> Arc<RegisterFile> {
    let mut spaces = common::spaces(4);
    for space in &mut spaces[1..] {
        space.endianness = if big {
            Endianness::Big
        } else {
            Endianness::Little
        };
    }
    let registers = REGISTERS
        .iter()
        .map(|&(name, offset, size)| common::register(name, common::REGISTER, offset, size))
        .collect();
    Arc::new(RegisterFile::new(spaces, common::RAM, registers, Default::default()).unwrap())
}

#[derive(Default)]
struct Spec<'a> {
    input: &'a str,
    output: &'a str,
    stack: &'a str,
    input_attrs: &'a str,
    big: bool,
}

impl Spec<'_> {
    fn text(&self) -> String {
        format!(
            r#"<compiler_spec><stackpointer register="sp" space="ram" {}/>
<default_proto><prototype name="p" extrapop="0" stackshift="0">
<input separatefloat="false" {}>{}</input><output>{}</output></prototype></default_proto></compiler_spec>"#,
            self.stack, self.input_attrs, self.input, self.output
        )
    }
    fn build(&self) -> CompilerResources {
        let spec = common::parse(&self.text());
        let storage = common::storage(spec, &file(self.big), Default::default()).unwrap();
        CompilerResources::new(Arc::new(storage), Default::default()).unwrap()
    }
}

fn plan(input: &str) -> CompilerResources {
    Spec {
        input,
        ..Default::default()
    }
    .build()
}

fn reg(name: &str, min: u32, max: u32, class: &str) -> String {
    format!(
        r#"<pentry minsize="{min}" maxsize="{max}" storage="{class}"><register name="{name}"/></pentry>"#
    )
}

fn aligned_reg(name: &str, max: u32, align: u32) -> String {
    format!(
        r#"<pentry minsize="1" maxsize="{max}" align="{align}"><register name="{name}"/></pentry>"#
    )
}

fn stack(offset: i64, min: u32, max: u32, align: u32) -> String {
    format!(
        r#"<pentry minsize="{min}" maxsize="{max}" align="{align}"><addr space="stack" offset="0x{:x}"/></pentry>"#,
        offset as i32 as u32
    )
}

fn join(pieces: &[&str], min: u32, max: u32, extra: &str) -> String {
    let attrs: String = pieces
        .iter()
        .enumerate()
        .map(|(i, p)| format!(r#" piece{}="{p}""#, i + 1))
        .collect();
    format!(
        r#"<pentry minsize="{min}" maxsize="{max}" {extra}><addr space="join"{attrs}/></pentry>"#
    )
}

fn fresh(resources: &CompilerResources) -> AllocationState {
    AllocationState::new(resources, 0, INPUT, Default::default()).unwrap()
}

fn policy(class_match: ClassMatch) -> FallbackPolicy {
    FallbackPolicy {
        class_match,
        ..Default::default()
    }
}

fn try_native(
    state: &mut AllocationState,
    resources: &CompilerResources,
    size: u32,
    alignment: u32,
    class: StorageClass,
    class_match: ClassMatch,
) -> Result<NativeFallbackAssignment, NativeFallbackError> {
    state.assign_native_fallback(
        resources,
        NativeFallbackRequest::new(size, alignment, class),
        policy(class_match),
        Default::default(),
    )
}

fn native(
    state: &mut AllocationState,
    resources: &CompilerResources,
    size: u32,
    alignment: u32,
    class: StorageClass,
) -> NativeFallbackAssignment {
    try_native(
        state,
        resources,
        size,
        alignment,
        class,
        ClassMatch::GeneralAcceptsAny,
    )
    .unwrap()
}

fn allocation(result: &NativeFallbackAssignment) -> &NativeFallbackAllocation {
    match &result.outcome {
        NativeFallbackOutcome::Assigned(a) => a,
        other => panic!("expected an assignment, got {other:?}"),
    }
}

fn entry(site: BindingSite) -> usize {
    match site {
        BindingSite::Input { entry, .. } | BindingSite::Output { entry, .. } => entry,
        other => panic!("not a parameter site: {other:?}"),
    }
}

/// (space, signed first byte, size, role) of every placed piece, or of the
/// float container.
fn layout(value: &PlacedValue) -> Vec<(AbiSpace, i64, u32, PieceRole)> {
    match &value.storage {
        PlacedStorage::Bits { pieces } => pieces
            .iter()
            .map(|p| {
                (
                    p.storage.address.space,
                    p.storage.address.offset as i64,
                    p.storage.size.unwrap(),
                    p.role,
                )
            })
            .collect(),
        PlacedStorage::FloatConversion { container, .. } => vec![(
            container.address.space,
            container.address.offset as i64,
            container.size.unwrap(),
            PieceRole::Storage,
        )],
    }
}

fn piece(space: AbiSpace, offset: i64, size: u32) -> Vec<(AbiSpace, i64, u32, PieceRole)> {
    vec![(space, offset, size, PieceRole::Storage)]
}

fn snapshot(state: &AllocationState) -> (Vec<GroupState>, Vec<OccupiedExtent>) {
    (state.groups().to_vec(), state.occupied().collect())
}

fn extents(state: &AllocationState) -> Vec<(AbiSpace, i128, i128, usize)> {
    state
        .occupied()
        .map(|e| (e.space, e.first, e.last, entry(e.site)))
        .collect()
}

const USED: GroupState = GroupState::Consumed;
fn slots(used_slots: u64) -> GroupState {
    GroupState::Available { used_slots }
}

fn rejection(
    entry: usize,
    group: usize,
    cursor: u64,
    next_cursor: u64,
    rejection: NoFit,
) -> NativeCandidate {
    NativeCandidate {
        entry,
        site: BindingSite::Input { model: 0, entry },
        group: ResourceId(group),
        cursor,
        next_cursor,
        rejection,
    }
}

/// Run a request expected to fail and check that the state is unchanged.
fn refused(
    state: &mut AllocationState,
    resources: &CompilerResources,
    request: NativeFallbackRequest,
    policy: FallbackPolicy,
) -> NativeFallbackError {
    let before = snapshot(state);
    let error = state
        .assign_native_fallback(resources, request, policy, Default::default())
        .unwrap_err();
    assert_eq!(snapshot(state), before, "{error:?}");
    error
}

fn overflow(error: &NativeFallbackError) -> (usize, NativeSlotOverflow) {
    match error {
        NativeFallbackError::NativeIntRange { site, operation } => (entry(*site), *operation),
        other => panic!("expected a native int refusal, got {other:?}"),
    }
}

#[test]
fn native_floor_division_differs_from_exact_congruence() {
    // One stack pool: alignment 8, 64 bytes, so eight slots at offset 0.
    let resources = plan(&stack(0, 1, 64, 8));
    let mut state = fresh(&resources);
    let first = native(&mut state, &resources, 8, 8, G);
    assert_eq!(
        allocation(&first).slots,
        Some(SlotRange { first: 0, next: 1 })
    );
    // Type alignment 12 at cursor 1: (1*8) % 12 = 8 and (12-8)/8 = 0, so
    // the cursor stays 1; ceil(12/8) = 2 slots end at 3 <= 8.
    let second = native(&mut state, &resources, 12, 12, G);
    let a = allocation(&second);
    assert_eq!((a.cursor, a.alignment_waste), (1, 0));
    assert_eq!(a.slots, Some(SlotRange { first: 1, next: 3 }));
    assert_eq!(layout(&a.value), piece(STACK, 8, 12));
    assert!(second.rejected.is_empty());
    assert_eq!(state.groups(), [slots(3)]);

    // The published exact-congruence fallback skips to slot 3 (byte 24).
    let mut exact = fresh(&resources);
    let batch = exact
        .assign_fallback(
            &resources,
            &[
                FallbackRequest::new(8, 8, G),
                FallbackRequest::new(12, 12, G),
            ],
            Default::default(),
            Default::default(),
        )
        .unwrap();
    let FallbackOutcome::Assigned(contrast) = &batch.outcomes[1] else {
        panic!("{batch:?}")
    };
    assert_eq!(contrast.slots, Some(SlotRange { first: 3, next: 5 }));
    assert_eq!(exact.groups(), [slots(5)]);

    // Pool alignment 4 and type alignment 6, cursors 1, 3, 5:
    //   1: 4 % 6 = 4, (6-4)/4 = 0 -> slots 1..3 at byte 4 (not 6-aligned)
    //   3: 12 % 6 = 0             -> slots 3..5 at byte 12
    //   5: 20 % 6 = 2, (6-2)/4 = 1 -> slots 6..8 at byte 24
    let resources = plan(&stack(0, 1, 64, 4));
    let mut state = fresh(&resources);
    native(&mut state, &resources, 4, 4, G);
    let mut placed = Vec::new();
    for _ in 0..3 {
        let result = native(&mut state, &resources, 6, 6, G);
        let a = allocation(&result);
        placed.push((
            a.cursor,
            a.alignment_waste,
            a.slots.unwrap(),
            layout(&a.value),
        ));
    }
    assert_eq!(
        placed,
        [
            (1, 0, SlotRange { first: 1, next: 3 }, piece(STACK, 4, 6)),
            (3, 0, SlotRange { first: 3, next: 5 }, piece(STACK, 12, 6)),
            (5, 1, SlotRange { first: 6, next: 8 }, piece(STACK, 24, 6)),
        ]
    );
    // Held slots: [0,3], [4,11], [12,19], [24,31]; slot 5 is a hole.
    assert_eq!(
        extents(&state),
        [
            (STACK, 0, 3, 0),
            (STACK, 4, 11, 0),
            (STACK, 12, 19, 0),
            (STACK, 24, 31, 0)
        ]
    );
    // Power-of-two alignment agrees with exact congruence: cursor 8 needs no
    // waste for 8; cursor 1 of a fresh pool wastes one slot for 8.
    let mut state = fresh(&resources);
    native(&mut state, &resources, 4, 4, G);
    let result = native(&mut state, &resources, 8, 8, G);
    assert_eq!(allocation(&result).alignment_waste, 1);
    assert_eq!(layout(&allocation(&result).value), piece(STACK, 8, 8));
}

#[test]
fn failed_candidates_keep_their_holes_on_success_and_no_fit() {
    // d1 is an aligned register pool of two 4-byte slots; the stack pool has
    // four slots. Groups: d1 = 0, stack = 1.
    let input = format!("{}{}", aligned_reg("d1", 8, 4), stack(0, 1, 16, 4));
    let resources = plan(&input);
    let mut state = fresh(&resources);
    let first = native(&mut state, &resources, 4, 4, G);
    assert_eq!(entry(allocation(&first).site), 0);
    assert_eq!(layout(&allocation(&first).value), piece(REG, 0x108, 4));

    // 8 bytes aligned 8: d1 at cursor 1 wastes (8-4)/4 = 1 slot, then 2+2 > 2
    // slots. The hole is written back and the stack takes the value.
    let second = native(&mut state, &resources, 8, 8, G);
    assert_eq!(
        second.rejected,
        [rejection(0, 0, 1, 2, NoFit::SlotsExhausted)]
    );
    let a = allocation(&second);
    assert_eq!((entry(a.site), a.group, a.cursor), (1, ResourceId(1), 0));
    assert_eq!(a.slots, Some(SlotRange { first: 0, next: 2 }));
    assert_eq!(layout(&a.value), piece(STACK, 0, 8));
    assert_eq!(state.groups(), [slots(2), slots(2)]);
    assert_eq!(second.usage.candidates, 2);
    // One waste write and one commit write.
    assert_eq!(second.usage.group_updates, 2);

    // 16 bytes aligned 8 fits neither, without waste (cursors 2 are aligned).
    let third = native(&mut state, &resources, 16, 8, G);
    assert_eq!(third.outcome, NativeFallbackOutcome::NoFit);
    assert_eq!(
        third.rejected,
        [
            rejection(0, 0, 2, 2, NoFit::SlotsExhausted),
            rejection(1, 1, 2, 2, NoFit::SlotsExhausted)
        ]
    );
    assert_eq!(third.usage.group_updates, 0);

    // Alignment 16: 8 % 16 = 8 wastes 2 slots in each pool; neither fits, and
    // NoFit keeps both holes.
    let fourth = native(&mut state, &resources, 4, 16, G);
    assert_eq!(fourth.outcome, NativeFallbackOutcome::NoFit);
    assert_eq!(
        fourth.rejected,
        [
            rejection(0, 0, 2, 4, NoFit::SlotsExhausted),
            rejection(1, 1, 2, 4, NoFit::SlotsExhausted)
        ]
    );
    assert_eq!(fourth.usage.group_updates, 2);
    assert_eq!(state.groups(), [slots(4), slots(4)]);
    assert_eq!(extents(&state), [(REG, 0x108, 0x10b, 0), (STACK, 0, 7, 1)]);
}

#[test]
fn below_minimum_and_gates_win_before_native_int_overflow() {
    // f0 is a float register; the General stack pool has minimum 2 and
    // 0x7ffffffc / 4 = 0x1fffffff slots.
    let input = format!(
        "{}{}",
        reg("f0", 1, 4, "float"),
        stack(0, 2, 0x7fff_fffc, 4)
    );
    let resources = plan(&input);
    let mut state = fresh(&resources);
    // 4 * 0x1ffffffe bytes fill all but one slot.
    let fill = native(&mut state, &resources, 2_147_483_640, 4, G);
    assert_eq!(
        allocation(&fill).slots,
        Some(SlotRange {
            first: 0,
            next: 536_870_910
        })
    );
    // Type alignment 0x60000000 at cursor 536870910: bytes 2147483640 fit an
    // int; remainder 536870904; waste (1610612736 - 536870904) / 4 =
    // 268435458 slots; cursor 805306368 plus one slot exceeds the capacity.
    let wasted = native(&mut state, &resources, 4, 0x6000_0000, G);
    assert_eq!(wasted.outcome, NativeFallbackOutcome::NoFit);
    assert_eq!(
        wasted.rejected,
        [rejection(
            1,
            1,
            536_870_910,
            805_306_368,
            NoFit::SlotsExhausted
        )]
    );
    assert_eq!(state.groups(), [slots(0), slots(805_306_368)]);

    // The next aligned query multiplies 805306368 * 4 > i32::MAX.
    let request = NativeFallbackRequest::new(4, 8, G);
    let error = refused(&mut state, &resources, request, Default::default());
    assert_eq!(overflow(&error), (1, NativeSlotOverflow::CursorBytes));
    // Without a larger type alignment there is no multiplication: the cursor
    // plus one slot is an int and only exceeds the capacity.
    let no_multiply = native(&mut state, &resources, 4, 4, G);
    assert_eq!(
        no_multiply.rejected,
        [rejection(
            1,
            1,
            805_306_368,
            805_306_368,
            NoFit::SlotsExhausted
        )]
    );
    // Below the minimum, getAddrBySlot returns before any arithmetic.
    let small = native(&mut state, &resources, 1, 8, G);
    assert_eq!(
        small.rejected,
        [rejection(
            1,
            1,
            805_306_368,
            805_306_368,
            NoFit::BelowMinimum
        )]
    );
    // An earlier fit hides the later candidate's overflow.
    let float = native(&mut state, &resources, 4, 8, F);
    assert_eq!(entry(allocation(&float).site), 0);
    // With f0 consumed the General stack pool accepts the float and overflows.
    let error = refused(
        &mut state,
        &resources,
        NativeFallbackRequest::new(4, 8, F),
        Default::default(),
    );
    assert_eq!(overflow(&error), (1, NativeSlotOverflow::CursorBytes));
    // Exact class matching never tries the General pool.
    let exact = try_native(&mut state, &resources, 4, 8, F, ClassMatch::Exact).unwrap();
    assert_eq!(exact.outcome, NativeFallbackOutcome::NoFit);
    assert!(exact.rejected.is_empty());
    assert_eq!(exact.usage.candidates, 0);
}

#[test]
fn native_overflow_precedes_capacity_with_inclusive_bounds() {
    // Alignment 1, 1000 slots, minimum 2. Fill cursor 2 first.
    let resources = plan(&stack(0, 2, 1000, 1));
    let primed = || {
        let mut state = fresh(&resources);
        native(&mut state, &resources, 2, 1, G);
        assert_eq!(state.groups(), [slots(2)]);
        state
    };
    // Type alignment T > 1 at cursor 2: remainder 2, waste T - 2, cursor T.
    // T = 2147483645: cursor + 2 slots = i32::MAX exactly -> capacity NoFit.
    let mut state = primed();
    let result = native(&mut state, &resources, 2, 2_147_483_645, G);
    assert_eq!(
        result.rejected,
        [rejection(0, 0, 2, 2_147_483_645, NoFit::SlotsExhausted)]
    );
    assert_eq!(state.groups(), [slots(2_147_483_645)]);
    // T = 2147483646: cursor + 2 = i32::MAX + 1 overflows before capacity.
    let mut state = primed();
    let error = refused(
        &mut state,
        &resources,
        NativeFallbackRequest::new(2, 2_147_483_646, G),
        Default::default(),
    );
    assert_eq!(overflow(&error), (0, NativeSlotOverflow::CursorPlusSlots));
    // T = i32::MAX: the wasted cursor is exactly i32::MAX (allowed); the
    // following addition overflows.
    let error = refused(
        &mut state,
        &resources,
        NativeFallbackRequest::new(2, MAX, G),
        Default::default(),
    );
    assert_eq!(overflow(&error), (0, NativeSlotOverflow::CursorPlusSlots));
    // Below the minimum nothing is evaluated.
    let small = native(&mut state, &resources, 1, MAX, G);
    assert_eq!(small.rejected, [rejection(0, 0, 2, 2, NoFit::BelowMinimum)]);

    // A cursor no native status can hold: the published exact-congruence
    // fallback leaves 2 + (u32::MAX - 2) = u32::MAX after a failed fit.
    let mut state = fresh(&resources);
    state
        .assign_fallback(
            &resources,
            &[
                FallbackRequest::new(2, 1, G),
                FallbackRequest::new(2, u32::MAX, G),
            ],
            Default::default(),
            Default::default(),
        )
        .unwrap();
    assert_eq!(state.groups(), [slots(u64::from(u32::MAX))]);
    let error = refused(
        &mut state,
        &resources,
        NativeFallbackRequest::new(2, 1, G),
        Default::default(),
    );
    assert_eq!(overflow(&error), (0, NativeSlotOverflow::Cursor));
    let small = native(&mut state, &resources, 1, 1, G);
    assert_eq!(small.rejected[0].rejection, NoFit::BelowMinimum);

    // i32::MAX slots of alignment 1: a cursor plus slots of exactly i32::MAX
    // fits, at the last byte of the signed 32-bit stack domain.
    let resources = plan(&stack(0, 1, MAX, 1));
    let mut state = fresh(&resources);
    native(&mut state, &resources, MAX - 1, 1, G);
    let last = native(&mut state, &resources, 1, 1, G);
    assert_eq!(
        allocation(&last).slots,
        Some(SlotRange {
            first: u64::from(MAX - 1),
            next: u64::from(MAX)
        })
    );
    assert_eq!(
        layout(&allocation(&last).value),
        piece(STACK, 0x7fff_fffe, 1)
    );
    let error = refused(
        &mut state,
        &resources,
        NativeFallbackRequest::new(1, 1, G),
        Default::default(),
    );
    assert_eq!(overflow(&error), (0, NativeSlotOverflow::CursorPlusSlots));

    // Waste addition: cursor 2147483637 = 16 * 134217727 + 5 wastes 11
    // slots for alignment 16 (one above i32::MAX), but 3 for alignment 4.
    let mut state = fresh(&resources);
    native(&mut state, &resources, 2_147_483_637, 1, G);
    let error = refused(
        &mut state,
        &resources,
        NativeFallbackRequest::new(1, 16, G),
        Default::default(),
    );
    assert_eq!(overflow(&error), (0, NativeSlotOverflow::AlignedCursor));
    let aligned = native(&mut state, &resources, 1, 4, G);
    assert_eq!(allocation(&aligned).alignment_waste, 3);
    assert_eq!(
        layout(&allocation(&aligned).value),
        piece(STACK, 2_147_483_640, 1)
    );
}

#[test]
fn class_matching_declaration_order_and_status_gates() {
    // f0 float, r0 general, d1 float with minimum 5, General stack pool.
    let input = format!(
        "{}{}{}{}",
        reg("f0", 1, 4, "float"),
        reg("r0", 1, 4, "general"),
        reg("d1", 5, 8, "float"),
        stack(0, 1, 16, 4)
    );
    let resources = plan(&input);
    let mut state = fresh(&resources);
    let float = native(&mut state, &resources, 4, 4, F);
    assert_eq!(entry(allocation(&float).site), 0);
    // A pointer skips the float entries; General accepts it.
    let mut other = fresh(&resources);
    let pointer = native(&mut other, &resources, 4, 4, P);
    assert_eq!(entry(allocation(&pointer).site), 1);
    assert_eq!(pointer.usage.examined_entries, 2);
    assert_eq!(pointer.usage.candidates, 1);
    // Exact matching has no pointer entry at all.
    let exact = try_native(
        &mut fresh(&resources),
        &resources,
        4,
        4,
        P,
        ClassMatch::Exact,
    )
    .unwrap();
    assert_eq!(exact.outcome, NativeFallbackOutcome::NoFit);
    assert_eq!(exact.usage.examined_entries, 4);
    assert_eq!(exact.usage.candidates, 0);
    // A second exact float: f0 is consumed, r0 and the stack are General,
    // and d1 rejects four bytes below its minimum.
    let second = try_native(&mut state, &resources, 4, 4, F, ClassMatch::Exact).unwrap();
    assert_eq!(second.outcome, NativeFallbackOutcome::NoFit);
    assert_eq!(
        second.rejected,
        [rejection(2, 2, 0, 0, NoFit::BelowMinimum)]
    );
    // Without exact matching r0 takes it.
    let third = native(&mut state, &resources, 4, 4, F);
    assert_eq!(entry(allocation(&third).site), 1);

    // Declaration order decides between a General and a float entry.
    let resources = plan(&format!(
        "{}{}",
        reg("r0", 1, 4, "general"),
        reg("f0", 1, 4, "float")
    ));
    let any = native(&mut fresh(&resources), &resources, 4, 4, F);
    assert_eq!(entry(allocation(&any).site), 0);
    let exact = try_native(
        &mut fresh(&resources),
        &resources,
        4,
        4,
        F,
        ClassMatch::Exact,
    )
    .unwrap();
    assert_eq!(entry(allocation(&exact).site), 1);

    // The status gate reads only the first group. r0 (minimum 4); f0 and r1
    // share group 1; the join r1:r0 has groups [0, 1].
    let input = format!(
        "{}<group>{}{}</group>{}{}",
        reg("r0", 4, 4, "general"),
        reg("f0", 1, 4, "float"),
        reg("r1", 1, 4, "general"),
        join(&["r1", "r0"], 5, 8, ""),
        stack(0, 1, 16, 4)
    );
    let resources = plan(&input);
    assert_eq!(
        resources.list(0, INPUT).unwrap().entries[3].groups,
        [ResourceId(0), ResourceId(1)]
    );
    let mut state = fresh(&resources);
    let float = native(&mut state, &resources, 2, 2, F);
    assert_eq!(float.rejected, [rejection(0, 0, 0, 0, NoFit::BelowMinimum)]);
    assert_eq!(entry(allocation(&float).site), 1);
    assert_eq!(state.groups(), [slots(0), USED, slots(0)]);
    // f0 and r1 are skipped as consumed; the join passes the first-group
    // test though group 1 is consumed, which native would reuse.
    let error = refused(
        &mut state,
        &resources,
        NativeFallbackRequest::new(8, 4, G),
        Default::default(),
    );
    assert!(
        matches!(
            error,
            NativeFallbackError::GroupInUse {
                site: BindingSite::Input { entry: 3, .. },
                group: ResourceId(1),
            }
        ),
        "{error:?}"
    );
    // Consuming r0 instead makes the join's first group consumed: it is
    // skipped before any class or size test, although r1 is still free.
    let mut state = fresh(&resources);
    native(&mut state, &resources, 4, 4, G);
    let wide = native(&mut state, &resources, 8, 8, G);
    assert_eq!(wide.rejected, [rejection(2, 1, 0, 0, NoFit::AboveCapacity)]);
    assert_eq!(wide.usage.examined_entries, 5);
    assert_eq!(entry(allocation(&wide).site), 4);

    // A non-int pool geometry never reaches the primitive: resource
    // construction refuses it (the kernel repeats the check defensively, and
    // a unit test pins that it runs only for tried candidates).
    let input = format!(
        r#"<group><pentry minsize="1" maxsize="4" storage="float"><addr space="stack" offset="0x40"/></pentry>{}</group>"#,
        reg("r0", 1, 4, "general")
    );
    let mut spec = common::parse(
        &Spec {
            input: &input,
            ..Default::default()
        }
        .text(),
    );
    spec.prototypes[0].input.entries[0].max_size = MAX + 1;
    let storage = common::storage(spec, &file(false), Default::default()).unwrap();
    assert!(matches!(
        CompilerResources::new(Arc::new(storage), Default::default()),
        Err(ResourceError::Invalid {
            reason: "invalid parameter size/alignment",
            ..
        })
    ));
}

#[test]
fn every_pool_kind_places_physical_storage_by_source_rules() {
    // Exclusion entries consume every group; a join takes both r1 and r0.
    let input = format!(
        "{}{}{}{}",
        reg("r0", 1, 4, "general"),
        reg("r1", 1, 4, "general"),
        join(&["r1", "r0"], 5, 8, ""),
        r#"<pentry minsize="1" maxsize="8"><addr space="stack" offset="0x10"/></pentry>"#,
    );
    let resources = plan(&input);
    assert_eq!(
        resources.list(0, INPUT).unwrap().entries[2].groups,
        [ResourceId(0), ResourceId(1)]
    );
    let mut state = fresh(&resources);
    let joined = native(&mut state, &resources, 8, 4, G);
    let a = allocation(&joined);
    assert_eq!(entry(a.site), 2);
    assert!(a.exclusion && a.slots.is_none());
    assert_eq!(
        layout(&a.value),
        [
            (REG, 4, 4, PieceRole::Storage),
            (REG, 0, 4, PieceRole::Storage)
        ]
    );
    assert_eq!(joined.usage.group_updates, 2);
    // Every register entry is now consumed; the exclusion stack slot takes
    // the next value, left-justified (LE), and holds its whole pool.
    assert_eq!(state.groups(), [USED, USED, slots(0)]);
    let next = native(&mut state, &resources, 2, 2, G);
    assert_eq!(entry(allocation(&next).site), 3);
    assert_eq!(layout(&allocation(&next).value), piece(STACK, 0x10, 2));
    assert_eq!(
        extents(&state),
        [(REG, 0, 3, 2), (REG, 4, 7, 2), (STACK, 16, 23, 3)]
    );

    // An aligned register pool: two values share it by slots.
    let resources = plan(&aligned_reg("quad", 16, 4));
    let mut state = fresh(&resources);
    let a = native(&mut state, &resources, 2, 2, G);
    let b = native(&mut state, &resources, 8, 8, G);
    assert_eq!(layout(&allocation(&a).value), piece(REG, 0, 2));
    // Cursor 1: 4 % 8 = 4 wastes one slot.
    assert_eq!(layout(&allocation(&b).value), piece(REG, 8, 8));
    assert_eq!(state.groups(), [slots(4)]);

    // Big endian: right justification in exclusion registers and stack slots.
    let input = format!("{}{}", reg("x0", 1, 8, "general"), stack(0, 1, 16, 4));
    let resources = Spec {
        input: &input,
        big: true,
        ..Default::default()
    }
    .build();
    let mut state = fresh(&resources);
    let x0 = native(&mut state, &resources, 4, 4, G);
    assert_eq!(layout(&allocation(&x0).value), piece(REG, 0x204, 4));
    let spilled = native(&mut state, &resources, 2, 2, G);
    assert_eq!(layout(&allocation(&spilled).value), piece(STACK, 2, 2));
    let wide = native(&mut state, &resources, 6, 2, G);
    // Cursor 1, two slots: bytes 4..12, right-justified to 6..12.
    assert_eq!(layout(&allocation(&wide).value), piece(STACK, 6, 6));
    // A reverse-justified big-endian stack is left-justified.
    let resources = Spec {
        input: &stack(0, 1, 16, 4),
        stack: r#"reversejustify="true""#,
        big: true,
        ..Default::default()
    }
    .build();
    let left = native(&mut fresh(&resources), &resources, 2, 2, G);
    assert_eq!(layout(&allocation(&left).value), piece(STACK, 0, 2));

    // Positive growth allocates slot indexes from the pool end, after the
    // native waste: 24 bytes of 4-byte slots (six). Value 1 takes index
    // 6-0-1 = 5. Type alignment 6 at cursor 1 wastes (6-4)/4 = 0, so two
    // slots end at 3 and take index 6-1-2 = 3 (byte 12). Exact congruence
    // would use cursor 3 and index 1.
    let resources = Spec {
        input: &stack(0, 1, 24, 4),
        stack: r#"growth="positive""#,
        ..Default::default()
    }
    .build();
    let mut state = fresh(&resources);
    let first = native(&mut state, &resources, 4, 4, G);
    assert_eq!(layout(&allocation(&first).value), piece(STACK, 20, 4));
    let second = native(&mut state, &resources, 6, 6, G);
    assert_eq!(
        allocation(&second).slots,
        Some(SlotRange { first: 1, next: 3 })
    );
    assert_eq!(layout(&allocation(&second).value), piece(STACK, 12, 6));
    assert_eq!(extents(&state), [(STACK, 12, 19, 0), (STACK, 20, 23, 0)]);

    // An output list uses its own state and entries.
    let resources = Spec {
        input: &reg("r0", 1, 4, "general"),
        output: &reg("r1", 1, 4, "general"),
        ..Default::default()
    }
    .build();
    let mut output = AllocationState::new(&resources, 0, OUTPUT, Default::default()).unwrap();
    let result = output
        .assign_native_fallback(
            &resources,
            NativeFallbackRequest::new(4, 4, G),
            Default::default(),
            Default::default(),
        )
        .unwrap();
    assert_eq!(result.direction, OUTPUT);
    assert_eq!(
        allocation(&result).site,
        BindingSite::Output { model: 0, entry: 0 }
    );
    assert_eq!(layout(&allocation(&result).value), piece(REG, 4, 4));
}

#[test]
fn aligned_widths_float_extension_and_raw_size_are_distinct() {
    // A raw three-byte enum of alignment four has aligned size four. In an
    // eight-byte big-endian register it is allocated at base + 8 - 4.
    let enumeration = NativeType {
        origin: NativeOrigin::Source(ghidra_types::TypeId(0)),
        meta: MetaType::Int,
        size: 3,
        aligned_size: 4,
        alignment: 4,
        enumeration: true,
        alias_of: None,
        canonical: NativeTypeId(0),
    };
    let request = NativeFallbackRequest::for_type(&enumeration, G);
    assert_eq!(request, NativeFallbackRequest::new(4, 4, G));
    let resources = Spec {
        input: &reg("x0", 1, 8, "general"),
        big: true,
        ..Default::default()
    }
    .build();
    let result = fresh(&resources)
        .assign_native_fallback(&resources, request, Default::default(), Default::default())
        .unwrap();
    let a = allocation(&result);
    assert_eq!(layout(&a.value), piece(REG, 0x204, 4));
    assert_eq!(a.value.size, 4);
    // Requesting the raw width instead would re-justify to base + 5.
    let raw = native(&mut fresh(&resources), &resources, 3, 4, G);
    assert_eq!(layout(&allocation(&raw).value), piece(REG, 0x205, 3));

    // A float-extension entry converts a smaller value to its full container
    // before (and instead of) justification, in either byte order.
    for big in [false, true] {
        let resources = Spec {
            input: &reg("d0", 1, 8, r#"float" extension="float"#),
            big,
            ..Default::default()
        }
        .build();
        let result = native(&mut fresh(&resources), &resources, 4, 4, F);
        let a = allocation(&result);
        assert_eq!(a.value.extension, Extension::Float);
        let PlacedStorage::FloatConversion {
            container,
            logical_size,
        } = &a.value.storage
        else {
            panic!("{a:?}")
        };
        assert_eq!(*logical_size, 4);
        assert_eq!((container.address.offset, container.size), (0x100, Some(8)));
        // The full width is an ordinary slice.
        let whole = native(&mut fresh(&resources), &resources, 8, 8, F);
        assert_eq!(layout(&allocation(&whole).value), piece(REG, 0x100, 8));
    }
}

#[test]
fn safeguards_refuse_and_restore_the_entire_query() {
    // A late error rolls back earlier candidates' waste: d1 wastes a slot,
    // then the stack value at 0x7ffffffc would leave the 32-bit domain.
    let input = format!(
        "{}{}",
        aligned_reg("d1", 8, 4),
        stack(0x7fff_fffc, 1, 64, 4)
    );
    let resources = plan(&input);
    let mut state = fresh(&resources);
    native(&mut state, &resources, 4, 4, G);
    assert_eq!(state.groups(), [slots(1), slots(0)]);
    let error = refused(
        &mut state,
        &resources,
        NativeFallbackRequest::new(8, 8, G),
        Default::default(),
    );
    assert!(
        matches!(
            error,
            NativeFallbackError::Unsupported {
                site: BindingSite::Input { entry: 1, .. },
                reason: "selected storage leaves its address domain",
            }
        ),
        "{error:?}"
    );
    assert_eq!(state.groups(), [slots(1), slots(0)]);

    // Two joins share r1 though their groups are disjoint.
    let input = format!(
        "{}{}{}{}",
        reg("r0", 1, 4, "general"),
        reg("r2", 1, 4, "general"),
        join(&["r1", "r0"], 5, 8, ""),
        join(&["r1", "r2"], 5, 8, "")
    );
    let resources = plan(&input);
    let mut state = fresh(&resources);
    native(&mut state, &resources, 8, 4, G);
    let error = refused(
        &mut state,
        &resources,
        NativeFallbackRequest::new(8, 4, G),
        Default::default(),
    );
    assert!(
        matches!(
            error,
            NativeFallbackError::Overlap {
                site: BindingSite::Input { entry: 3, .. },
                previous: BindingSite::Input { entry: 2, .. },
            }
        ),
        "{error:?}"
    );

    // Aligned join pools, partial floating joins and little-endian reverse
    // stack justification are explicit unsupported layouts.
    let aligned_join = plan(&format!(
        "{}{}{}",
        reg("r0", 1, 4, "general"),
        reg("r1", 1, 4, "general"),
        join(&["r0", "r1"], 1, 8, r#"align="4""#)
    ));
    // A one-piece join of logical width 4 over the 8-byte d1 is a floating
    // extension; a 2-byte value would be a partial conversion.
    let float_join = plan(&format!(
        "{}{}",
        reg("d1", 5, 8, "float"),
        join(&["d1"], 1, 4, r#"storage="float""#)
            .replace(r#"piece1="d1""#, r#"piece1="d1" size="4""#)
    ));
    let reverse = Spec {
        input: &stack(0, 1, 16, 4),
        stack: r#"reversejustify="true""#,
        ..Default::default()
    }
    .build();
    for (resources, request, expected) in [
        (
            &aligned_join,
            NativeFallbackRequest::new(8, 4, G),
            "aligned join pools have no supported slot-to-piece occupancy",
        ),
        (&float_join, NativeFallbackRequest::new(2, 2, F), ""),
        (
            &reverse,
            NativeFallbackRequest::new(4, 4, G),
            "native little-endian reverse stack justification",
        ),
    ] {
        let mut state = fresh(resources);
        let error = refused(&mut state, resources, request, Default::default());
        match (expected, &error) {
            ("", NativeFallbackError::Placement { source, .. }) => assert!(
                matches!(source, PlacementError::Unsupported { reason, .. }
                    if *reason == "partial or aligned floating join conversion"),
                "{error:?}"
            ),
            (reason, NativeFallbackError::Unsupported { reason: r, .. }) => assert_eq!(*r, reason),
            (reason, NativeFallbackError::Placement { source, .. }) => assert!(
                matches!(source, PlacementError::Unsupported { reason: r, .. } if *r == reason),
                "{error:?}"
            ),
            (_, other) => panic!("{other:?}"),
        }
    }

    // Invalid requests are refused before any entry is read.
    let resources = plan(&stack(0, 1, 16, 4));
    for (size, alignment) in [(0, 4), (MAX + 1, 4), (4, 0), (4, MAX + 1)] {
        let error = refused(
            &mut fresh(&resources),
            &resources,
            NativeFallbackRequest::new(size, alignment, G),
            Default::default(),
        );
        assert!(
            matches!(error, NativeFallbackError::InvalidRequest(_)),
            "{error:?}"
        );
    }
    // A state belongs to one overlay.
    let other = plan(&stack(0, 1, 16, 4));
    let error = refused(
        &mut fresh(&other),
        &resources,
        NativeFallbackRequest::new(4, 4, G),
        Default::default(),
    );
    assert!(matches!(error, NativeFallbackError::StateMismatch));
}

#[test]
fn declared_rules_are_refused_or_explicitly_bypassed_and_reported() {
    let resources = Spec {
        input: &format!("{}{}", reg("r0", 1, 4, "general"), stack(0, 1, 16, 4)),
        input_attrs: r#"pointermax="8""#,
        ..Default::default()
    }
    .build();
    let mut state = fresh(&resources);
    let error = refused(
        &mut state,
        &resources,
        NativeFallbackRequest::new(16, 4, G),
        Default::default(),
    );
    assert!(
        matches!(
            error,
            NativeFallbackError::RulesNotExecuted {
                model: 0,
                direction: ParameterDirection::Input,
                rules: 0,
                pointer_max: Some(8),
            }
        ),
        "{error:?}"
    );
    // Bypass runs the bare primitive: no pointer conversion for 16 bytes.
    let bypass = FallbackPolicy {
        declared_rules: DeclaredRules::BypassUnexecuted,
        ..Default::default()
    };
    let result = state
        .assign_native_fallback(
            &resources,
            NativeFallbackRequest::new(16, 4, G),
            bypass,
            Default::default(),
        )
        .unwrap();
    assert_eq!(layout(&allocation(&result).value), piece(STACK, 0, 16));
    assert_eq!(result.unexecuted.pointer_max, Some(8));
    assert!(result.unexecuted.changes_assignment());
    assert_eq!(result.policy, bypass);
}

/// A prepared state and one measured query: a consumed entry, a class skip,
/// an aligned candidate that writes waste and fails, and a stack success.
fn representative() -> (CompilerResources, AllocationState, NativeFallbackRequest) {
    let input = format!(
        "{}{}{}{}",
        reg("r0", 1, 4, "general"),
        reg("f0", 1, 4, "float"),
        aligned_reg("d1", 8, 4),
        stack(0, 1, 64, 4)
    );
    let resources = plan(&input);
    let mut state = fresh(&resources);
    native(&mut state, &resources, 4, 4, G);
    native(&mut state, &resources, 4, 4, G);
    assert_eq!(state.groups(), [USED, slots(0), slots(1), slots(0)]);
    (resources, state, NativeFallbackRequest::new(8, 8, G))
}

fn with(change: impl FnOnce(&mut NativeFallbackLimits)) -> NativeFallbackLimits {
    let mut limits = NativeFallbackLimits::default();
    change(&mut limits);
    limits
}

#[test]
fn usage_and_work_are_exact_and_every_cap_is_tight() {
    let (resources, prepared, request) = representative();
    let lookup = |n: usize| u64::from(usize::BITS - n.leading_zeros()) + 1;
    let bindings = resources.storage().bindings().len();
    let spaces = resources.storage().register_file().spaces().len();
    // Four input pentries and the three fixture spaces.
    assert_eq!((bindings, spaces), (4, 3));
    // Nested aligned stack placement: header 1, binding lookup, one gcd step
    // with type alignment 1, the stack geometry for byte order, one output
    // piece and its slice geometry.
    let nested = 1 + lookup(bindings) + 1 + lookup(spaces) + 1 + lookup(spaces);
    // Call header 1, request 1, 2 per examined entry (4), 1 per tried
    // candidate (d1, stack), 1 waste write, the nested placement, 1 group
    // reference, the held span (binding lookup + 1; the stack is not a
    // language space), an occupied lookup over 2 held extents, 1 commit.
    let expected_work = 1 + 1 + 2 * 4 + 2 + 1 + nested + 1 + (lookup(bindings) + 1) + lookup(2) + 1;
    assert_eq!(expected_work, 36);
    let mut state = prepared.clone();
    let reference = state
        .assign_native_fallback(&resources, request, Default::default(), Default::default())
        .unwrap();
    assert_eq!(
        reference.rejected,
        [rejection(2, 2, 1, 2, NoFit::SlotsExhausted)]
    );
    assert_eq!(layout(&allocation(&reference).value), piece(STACK, 0, 8));
    assert_eq!(
        reference.usage,
        NativeFallbackUsage {
            examined_entries: 4,
            candidates: 2,
            group_references: 5,
            group_updates: 2,
            placements: 1,
            pieces: 1,
            occupied_extents: 3,
            source_pieces: 1,
            work: 36,
        }
    );
    let committed = snapshot(&state);

    type Setter = fn(&mut NativeFallbackLimits, u64);
    let usage = reference.usage;
    let caps: [(&str, u64, Setter); 8] = [
        ("examined entries", usage.examined_entries, |l, n| {
            l.max_examined_entries = n
        }),
        ("group references", usage.group_references, |l, n| {
            l.max_group_references = n
        }),
        ("group updates", usage.group_updates, |l, n| {
            l.max_group_updates = n
        }),
        ("placements", usage.placements as u64, |l, n| {
            l.max_placements = n as usize
        }),
        ("pieces", usage.pieces as u64, |l, n| {
            l.max_pieces = n as usize
        }),
        ("occupied extents", usage.occupied_extents as u64, |l, n| {
            l.max_occupied_extents = n as usize
        }),
        ("source pieces", usage.source_pieces as u64, |l, n| {
            l.max_source_pieces = n as usize
        }),
        ("work", usage.work, |l, n| l.max_work = n),
    ];
    for (name, exact, set) in caps {
        let mut state = prepared.clone();
        let result = state
            .assign_native_fallback(
                &resources,
                request,
                Default::default(),
                with(|l| set(l, exact)),
            )
            .unwrap();
        assert_eq!(result, reference, "{name} at its exact value");
        assert_eq!(snapshot(&state), committed, "{name}");
        let mut state = prepared.clone();
        let error = state
            .assign_native_fallback(
                &resources,
                request,
                Default::default(),
                with(|l| set(l, exact - 1)),
            )
            .unwrap_err();
        assert!(
            matches!(error, NativeFallbackError::Limit(n) if n == name),
            "{name}: {error:?}"
        );
        // The waste write of the failed d1 candidate is undone as well.
        assert_eq!(snapshot(&state), snapshot(&prepared), "{name}");
    }
    // Every smaller work budget fails, including inside the nested placement.
    for work in 0..usage.work {
        let mut state = prepared.clone();
        let error = state
            .assign_native_fallback(
                &resources,
                request,
                Default::default(),
                with(|l| l.max_work = work),
            )
            .unwrap_err();
        assert!(
            matches!(error, NativeFallbackError::Limit("work")),
            "{work}: {error:?}"
        );
        assert_eq!(snapshot(&state), snapshot(&prepared));
    }
    // A NoFit charges the same scan and keeps its waste, without placement:
    // d1 at cursor 1 wastes (16-4)/4 = 3 slots; the stack needs 20 of 16.
    let mut state = prepared.clone();
    let no_fit = state
        .assign_native_fallback(
            &resources,
            NativeFallbackRequest::new(80, 16, G),
            Default::default(),
            Default::default(),
        )
        .unwrap();
    assert_eq!(no_fit.outcome, NativeFallbackOutcome::NoFit);
    assert_eq!(
        no_fit.rejected,
        [
            rejection(2, 2, 1, 4, NoFit::SlotsExhausted),
            rejection(3, 3, 0, 0, NoFit::SlotsExhausted)
        ]
    );
    assert_eq!(
        no_fit.usage,
        NativeFallbackUsage {
            examined_entries: 4,
            candidates: 2,
            group_references: 4,
            group_updates: 1,
            placements: 0,
            pieces: 0,
            occupied_extents: 2,
            source_pieces: 0,
            work: 1 + 1 + 2 * 4 + 2 + 1,
        }
    );
    assert_eq!(state.groups(), [USED, slots(0), slots(4), slots(0)]);
}

#[test]
fn already_held_extents_are_bounded_on_entry() {
    let (resources, prepared, _) = representative();
    let held = prepared.occupied_count();
    assert_eq!(held, 2);
    for (cap, ok) in [(held, true), (held - 1, false)] {
        let mut state = prepared.clone();
        // A request below every minimum makes no new extent.
        let result = state.assign_native_fallback(
            &resources,
            NativeFallbackRequest::new(1, 1, StorageClass::Vector),
            policy(ClassMatch::Exact),
            with(|l| l.max_occupied_extents = cap),
        );
        assert_eq!(result.is_ok(), ok, "{cap}: {result:?}");
        assert_eq!(snapshot(&state), snapshot(&prepared));
    }
}

#[test]
fn work_scales_linearly_with_declared_entries() {
    let mut works = Vec::new();
    for count in [256_usize, 1024] {
        let mut registers: Vec<_> = (0..count)
            .map(|i| common::register(&format!("v{i}"), common::REGISTER, 8 * i as u64, 8))
            .collect();
        registers.push(common::register("sp", common::REGISTER, 0x10_0000, 4));
        let file = Arc::new(
            RegisterFile::new(
                common::spaces(4),
                common::RAM,
                registers,
                Default::default(),
            )
            .unwrap(),
        );
        let entries: String = (0..count)
            .map(|i| reg(&format!("v{i}"), 1, 8, "float"))
            .collect();
        let text = Spec {
            input: &format!("{entries}{}", stack(0, 1, 64, 4)),
            ..Default::default()
        }
        .text();
        let storage = common::storage(common::parse(&text), &file, Default::default()).unwrap();
        let resources = CompilerResources::new(Arc::new(storage), Default::default()).unwrap();
        let mut state = fresh(&resources);
        let result = try_native(&mut state, &resources, 4, 4, G, ClassMatch::Exact).unwrap();
        assert_eq!(entry(allocation(&result).site), count);
        assert_eq!(result.usage.examined_entries, count as u64 + 1);
        assert_eq!(result.usage.candidates, 1);
        // Same derivation as the representative pin, with no waste write.
        let lookup = |n: usize| u64::from(usize::BITS - n.leading_zeros()) + 1;
        let bindings = resources.storage().bindings().len();
        let nested = 3 + lookup(bindings) + 2 * lookup(3);
        let expected =
            2 + 2 * (count as u64 + 1) + 1 + nested + 1 + lookup(bindings) + 1 + lookup(0) + 1;
        assert_eq!(result.usage.work, expected, "{count}");
        // Two units per scanned entry plus a logarithmic constant.
        assert!(result.usage.work - 2 * result.usage.examined_entries < 64);
        works.push(result.usage.work);
    }
    assert_eq!(works[1] - works[0], 2 * 768 + 4, "{works:?}");
}

#[test]
fn results_are_owned_send_sync_and_deterministic() {
    fn check<T: Send + Sync + 'static>() {}
    check::<NativeFallbackAssignment>();
    check::<NativeFallbackError>();
    check::<NativeFallbackRequest>();
    check::<AllocationState>();
    let (resources, prepared, request) = representative();
    let resources = Arc::new(resources);
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let resources = resources.clone();
            let mut state = prepared.clone();
            std::thread::spawn(move || {
                let result = state
                    .assign_native_fallback(
                        &resources,
                        request,
                        Default::default(),
                        Default::default(),
                    )
                    .unwrap();
                (result, snapshot(&state))
            })
        })
        .collect();
    let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
    assert!(results.windows(2).all(|w| w[0] == w[1]));
    // The result outlives the state and resources that produced it.
    drop(resources);
    let (owned, _) = results.into_iter().next().unwrap();
    assert_eq!(layout(&allocation(&owned).value), piece(STACK, 0, 8));
    assert!(
        serde_json::to_string(&owned)
            .unwrap()
            .contains("SlotsExhausted")
    );
}
