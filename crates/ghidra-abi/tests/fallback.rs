//! Retained fallback allocation (`ParamListStandard::assignAddressFallback`
//! with `ParamEntry::getAddrBySlot`). Expected placements are derived by hand
//! from the declarations and the retained loop, or from the independent
//! reference model in `generated_layouts_match_an_independent_reference`.
mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use ghidra_abi::*;
use ghidra_languages::{Extension, StorageClass};
use ghidra_pcode::{Endianness, SpaceId};

const G: StorageClass = StorageClass::General;
const F: StorageClass = StorageClass::Float;
const REG: AbiSpace = AbiSpace::Language(SpaceId(2));
const STACK: AbiSpace = AbiSpace::Stack;
const INPUT: ParameterDirection = ParameterDirection::Input;
const OUTPUT: ParameterDirection = ParameterDirection::Output;

/// (name, register-space offset, size). r0..r3 tile `quad`; f0/f1 tile `d0`.
const REGISTERS: &[(&str, u64, u32)] = &[
    ("r0", 0, 4),
    ("r1", 4, 4),
    ("r2", 8, 4),
    ("r3", 12, 4),
    ("wide", 0, 8),
    ("wide2", 8, 8),
    ("quad", 0, 16),
    ("f0", 0x100, 4),
    ("f1", 0x104, 4),
    ("d0", 0x100, 8),
    ("d1", 0x108, 8),
    ("x0", 0x200, 8),
    ("x1", 0x208, 8),
    ("x2", 0x210, 8),
    ("x3", 0x218, 8),
    ("xmm0", 0x300, 8),
    ("xmm1", 0x308, 8),
    ("xmm2", 0x310, 8),
    ("xmm3", 0x318, 8),
    ("sp", 0x400, 4),
    // Odd extents that touch r0/r1 in exactly one byte.
    ("b1", 1, 4),
    ("b3", 3, 4),
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
    output_attrs: &'a str,
    prototype_attrs: &'a str,
    prototype_body: &'a str,
    big: bool,
}

impl Spec<'_> {
    fn build(&self) -> CompilerResources {
        let spec = common::parse(&format!(
            r#"<compiler_spec><stackpointer register="sp" space="ram" {}/>
<default_proto><prototype name="p" extrapop="0" stackshift="0" {}>
<input {}>{}</input><output {}>{}</output>{}</prototype></default_proto></compiler_spec>"#,
            self.stack,
            self.prototype_attrs,
            self.input_attrs,
            self.input,
            self.output_attrs,
            self.output,
            self.prototype_body
        ));
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

fn stack(offset: i32, max: u32, align: u32) -> String {
    format!(
        r#"<pentry minsize="1" maxsize="{max}" align="{align}"><addr space="stack" offset="0x{:x}"/></pentry>"#,
        offset as u32
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

fn req(size: u32, alignment: u32, class: StorageClass) -> FallbackRequest {
    FallbackRequest::new(size, alignment, class)
}

fn fresh(resources: &CompilerResources, direction: ParameterDirection) -> AllocationState {
    AllocationState::new(resources, 0, direction, Default::default()).unwrap()
}

fn run_policy(
    resources: &CompilerResources,
    direction: ParameterDirection,
    requests: &[FallbackRequest],
    policy: FallbackPolicy,
) -> (AllocationState, FallbackBatch) {
    let mut state = fresh(resources, direction);
    let batch = state
        .assign_fallback(resources, requests, policy, Default::default())
        .unwrap();
    (state, batch)
}

fn run(
    resources: &CompilerResources,
    requests: &[FallbackRequest],
) -> (AllocationState, FallbackBatch) {
    run_policy(resources, INPUT, requests, FallbackPolicy::default())
}

fn assigned(batch: &FallbackBatch, index: usize) -> &FallbackAssignment {
    match &batch.outcomes[index] {
        FallbackOutcome::Assigned(a) => a,
        other => panic!("request {index}: expected an assignment, got {other:?}"),
    }
}

fn entry(site: BindingSite) -> usize {
    match site {
        BindingSite::Input { entry, .. } | BindingSite::Output { entry, .. } => entry,
        other => panic!("not a parameter site: {other:?}"),
    }
}

fn signed(storage: &StorageRange) -> i64 {
    storage.address.offset as i64
}

/// (space, signed first byte, size, role) for each placed piece, or for the
/// float container.
fn layout(a: &FallbackAssignment) -> Vec<(AbiSpace, i64, u32, PieceRole)> {
    match &a.value.storage {
        PlacedStorage::Bits { pieces } => pieces
            .iter()
            .map(|p| {
                (
                    p.storage.address.space,
                    signed(&p.storage),
                    p.storage.size.unwrap(),
                    p.role,
                )
            })
            .collect(),
        PlacedStorage::FloatConversion { container, .. } => vec![(
            container.address.space,
            signed(container),
            container.size.unwrap(),
            PieceRole::Storage,
        )],
    }
}

fn piece(space: AbiSpace, offset: i64, size: u32) -> Vec<(AbiSpace, i64, u32, PieceRole)> {
    vec![(space, offset, size, PieceRole::Storage)]
}

fn extents(state: &AllocationState) -> Vec<(AbiSpace, i128, i128, usize)> {
    state
        .occupied()
        .map(|e| (e.space, e.first, e.last, entry(e.site)))
        .collect()
}

fn snapshot(state: &AllocationState) -> (Vec<GroupState>, Vec<OccupiedExtent>) {
    (state.groups().to_vec(), state.occupied().collect())
}

const USED: GroupState = GroupState::Consumed;
fn slots(used_slots: u64) -> GroupState {
    GroupState::Available { used_slots }
}

fn windows_like() -> CompilerResources {
    let group = |f: &str, g: &str| {
        format!(
            "<group>{}{}</group>",
            reg(f, 4, 8, "float"),
            reg(g, 1, 8, "general")
        )
    };
    plan(&format!(
        "{}{}{}{}{}",
        group("xmm0", "x0"),
        group("xmm1", "x1"),
        group("xmm2", "x2"),
        group("xmm3", "x3"),
        stack(40, 500, 8)
    ))
}

#[test]
fn mixed_classes_share_windows_like_groups_then_continue_on_the_stack() {
    let resources = windows_like();
    let requests = [
        req(4, 4, G),
        req(8, 8, F),
        req(8, 8, StorageClass::Ptr),
        req(4, 4, F),
        req(2, 2, G),
        req(8, 8, F),
        req(16, 8, G),
    ];
    let (state, batch) = run(&resources, &requests);
    // Entries: xmm0,x0 | xmm1,x1 | xmm2,x2 | xmm3,x3 share groups 0..3; the
    // stack pool is group 4. A General entry accepts the Ptr request.
    let expected = [
        (1, piece(REG, 0x200, 4)),
        (2, piece(REG, 0x308, 8)),
        (5, piece(REG, 0x210, 8)),
        (6, piece(REG, 0x318, 4)),
        (8, piece(STACK, 40, 2)),
        (8, piece(STACK, 48, 8)),
        (8, piece(STACK, 56, 16)),
    ];
    for (index, (site, pieces)) in expected.into_iter().enumerate() {
        let a = assigned(&batch, index);
        assert_eq!(
            a.site,
            BindingSite::Input {
                model: 0,
                entry: site
            },
            "{index}"
        );
        assert_eq!(layout(a), pieces, "{index}");
    }
    assert!(assigned(&batch, 0).exclusion && assigned(&batch, 0).slots.is_none());
    assert_eq!(
        assigned(&batch, 6).slots,
        Some(SlotRange { first: 2, next: 4 })
    );
    assert_eq!(batch.first_no_fit, None);
    assert_eq!(state.groups(), [USED, USED, USED, USED, slots(4)]);
    // Exclusion entries hold their whole pool; aligned assignments hold slots.
    assert_eq!(
        extents(&state),
        [
            (REG, 0x200, 0x207, 1),
            (REG, 0x210, 0x217, 5),
            (REG, 0x308, 0x30f, 2),
            (REG, 0x318, 0x31f, 6),
            (STACK, 40, 47, 8),
            (STACK, 48, 55, 8),
            (STACK, 56, 71, 8),
        ]
    );
    // Examined entries per request: 2, 3, 6, 7, 9, 9, 9.
    assert_eq!(batch.usage.examined_entries, 45);
    assert_eq!(batch.usage.group_updates, 7);
    assert_eq!((batch.usage.placements, batch.usage.pieces), (7, 7));
    assert_eq!(batch.unexecuted.rules, 0);
    assert!(!batch.unexecuted.changes_assignment());
}

#[test]
fn exact_class_mode_does_not_fall_back_to_general_entries_and_order_matters() {
    let resources = windows_like();
    let floats = [req(8, 8, F); 6];
    let exact = FallbackPolicy {
        class_match: ClassMatch::Exact,
        ..Default::default()
    };
    let (state, batch) = run_policy(&resources, INPUT, &floats, exact);
    for (index, site) in [0, 2, 4, 6].into_iter().enumerate() {
        assert_eq!(entry(assigned(&batch, index).site), site);
    }
    // Every group is consumed and the General stack pool is not a match.
    assert_eq!(batch.outcomes[4], FallbackOutcome::NoFit { candidates: 0 });
    assert_eq!(batch.outcomes[5], FallbackOutcome::NotAttempted);
    assert_eq!(batch.first_no_fit, Some(4));
    assert_eq!(state.groups()[4], slots(0));
    let (_, batch) = run(&resources, &floats);
    assert_eq!(entry(assigned(&batch, 4).site), 8);
    assert_eq!(entry(assigned(&batch, 5).site), 8);

    // Declaration order decides between a General and a Float entry.
    let resources = Spec {
        input: &format!("{}{}", reg("r0", 1, 4, "general"), reg("f0", 1, 4, "float")),
        input_attrs: r#"separatefloat="false""#,
        ..Default::default()
    }
    .build();
    let (_, batch) = run(&resources, &[req(4, 4, F), req(4, 4, F)]);
    assert_eq!(entry(assigned(&batch, 0).site), 0);
    assert_eq!(entry(assigned(&batch, 1).site), 1);
    let (_, batch) = run_policy(&resources, INPUT, &[req(4, 4, F), req(4, 4, F)], exact);
    assert_eq!(entry(assigned(&batch, 0).site), 1);
    assert_eq!(batch.outcomes[1], FallbackOutcome::NoFit { candidates: 0 });
}

#[test]
fn containing_pools_and_joins_alias_their_contained_resources() {
    let base = format!(
        "{}{}",
        reg("r0", 1, 4, "general"),
        reg("r1", 1, 4, "general")
    );
    let resources = plan(&format!(
        "{base}{}{}",
        reg("wide", 5, 8, "general"),
        stack(0, 16, 4)
    ));
    let (state, batch) = run(&resources, &[req(8, 4, G), req(4, 4, G)]);
    assert_eq!(layout(assigned(&batch, 0)), piece(REG, 0, 8));
    assert_eq!(
        assigned(&batch, 0).value.storage,
        PlacedStorage::Bits {
            pieces: vec![PlacedPiece {
                storage: StorageRange {
                    address: AbiAddress {
                        space: REG,
                        offset: 0
                    },
                    size: Some(8),
                    register: resources.storage().register_file().register_id("wide"),
                },
                lsb_byte: 0,
                source_piece: 0,
                source_byte_offset: 0,
                role: PieceRole::Storage,
            }]
        }
    );
    // Both contained groups are consumed, so r0 and r1 are unavailable.
    assert_eq!(entry(assigned(&batch, 1).site), 3);
    assert_eq!(state.groups(), [USED, USED, slots(1)]);

    // Consuming r0 first blocks the pool through its first group only; r1
    // stays available.
    let (state, batch) = run(&resources, &[req(4, 4, G), req(8, 4, G), req(4, 4, G)]);
    assert_eq!(entry(assigned(&batch, 0).site), 0);
    assert_eq!(entry(assigned(&batch, 1).site), 3);
    assert_eq!(layout(assigned(&batch, 1)), piece(STACK, 0, 8));
    assert_eq!(entry(assigned(&batch, 2).site), 1);
    assert_eq!(state.groups(), [USED, USED, slots(2)]);

    let resources = plan(&format!("{base}{}", join(&["r1", "r0"], 5, 8, "")));
    let (state, batch) = run(&resources, &[req(8, 4, G), req(4, 4, G)]);
    let a = assigned(&batch, 0);
    assert_eq!(entry(a.site), 2);
    let PlacedStorage::Bits { pieces } = &a.value.storage else {
        panic!()
    };
    assert_eq!(
        pieces
            .iter()
            .map(|p| (p.source_piece, p.storage.address.offset, p.lsb_byte))
            .collect::<Vec<_>>(),
        [(0, 4, 4), (1, 0, 0)]
    );
    assert_eq!(batch.outcomes[1], FallbackOutcome::NoFit { candidates: 0 });
    assert_eq!(extents(&state), [(REG, 0, 3, 2), (REG, 4, 7, 2)]);
}

#[test]
fn alignment_holes_survive_no_fit_and_failed_candidates() {
    let resources = plan(&stack(0, 16, 4));
    let (mut state, batch) = run(&resources, &[req(4, 4, G), req(16, 8, G), req(4, 4, G)]);
    assert_eq!(layout(assigned(&batch, 0)), piece(STACK, 0, 4));
    // Slot 1 is skipped for 8-byte alignment; four more slots do not fit.
    assert_eq!(batch.outcomes[1], FallbackOutcome::NoFit { candidates: 1 });
    assert_eq!(batch.outcomes[2], FallbackOutcome::NotAttempted);
    assert_eq!(state.groups(), [slots(2)]);
    assert_eq!(extents(&state), [(STACK, 0, 3, 0)]);
    // The retained hole is not reused by a later batch on this state.
    let batch = state
        .assign_fallback(
            &resources,
            &[req(8, 8, G)],
            Default::default(),
            Default::default(),
        )
        .unwrap();
    assert_eq!(layout(assigned(&batch, 0)), piece(STACK, 8, 8));
    assert_eq!(
        assigned(&batch, 0).slots,
        Some(SlotRange { first: 2, next: 4 })
    );
    assert_eq!(state.groups(), [slots(4)]);

    // A candidate that does not fit keeps its holes even though a later
    // candidate takes the request.
    let resources = plan(&format!(
        r#"<pentry minsize="1" maxsize="8" align="4"><register name="quad"/></pentry>{}"#,
        stack(0, 64, 4)
    ));
    let (state, batch) = run(&resources, &[req(4, 4, G), req(8, 8, G), req(4, 4, G)]);
    assert_eq!(layout(assigned(&batch, 0)), piece(REG, 0, 4));
    assert_eq!(layout(assigned(&batch, 1)), piece(STACK, 0, 8));
    assert_eq!(layout(assigned(&batch, 2)), piece(STACK, 8, 4));
    assert_eq!(state.groups(), [slots(2), slots(3)]);
}

#[test]
fn positive_growth_allocates_aligned_slots_from_the_pool_end() {
    let resources = Spec {
        input: &stack(0, 16, 4),
        stack: r#"growth="positive""#,
        ..Default::default()
    }
    .build();
    let (state, batch) = run(
        &resources,
        &[req(4, 4, G), req(8, 8, G), req(4, 4, G), req(1, 1, G)],
    );
    assert_eq!(layout(assigned(&batch, 0)), piece(STACK, 12, 4));
    assert_eq!(layout(assigned(&batch, 1)), piece(STACK, 0, 8));
    assert_eq!(
        assigned(&batch, 1).slots,
        Some(SlotRange { first: 2, next: 4 })
    );
    assert_eq!(batch.outcomes[2], FallbackOutcome::NoFit { candidates: 1 });
    assert_eq!(batch.outcomes[3], FallbackOutcome::NotAttempted);
    assert_eq!(state.groups(), [slots(4)]);
    assert_eq!(extents(&state), [(STACK, 0, 7, 0), (STACK, 12, 15, 0)]);
}

#[test]
fn signed_stack_containment_across_zero_shares_one_group() {
    let input = format!(
        r#"<pentry minsize="1" maxsize="4" storage="float"><addr space="stack" offset="0xfffffffc"/></pentry>{}"#,
        stack(-8, 16, 4)
    );
    let resources = Spec {
        input: &input,
        input_attrs: r#"separatefloat="false""#,
        ..Default::default()
    }
    .build();
    let list = resources.list(0, INPUT).unwrap();
    assert_eq!(list.entries[1].groups, [ResourceId(0)]);
    let (state, batch) = run(&resources, &[req(4, 4, G), req(4, 4, F), req(4, 4, G)]);
    // The exclusion slot sees a used cursor and is skipped (ExclusionUsed).
    assert_eq!(layout(assigned(&batch, 0)), piece(STACK, -8, 4));
    assert_eq!(entry(assigned(&batch, 1).site), 1);
    assert_eq!(layout(assigned(&batch, 1)), piece(STACK, -4, 4));
    assert_eq!(layout(assigned(&batch, 2)), piece(STACK, 0, 4));
    assert_eq!(
        extents(&state),
        [(STACK, -8, -5, 1), (STACK, -4, -1, 1), (STACK, 0, 3, 1)]
    );
    // Consuming the exclusion entry first consumes the shared group.
    let (state, batch) = run(&resources, &[req(4, 4, F), req(4, 4, G)]);
    assert_eq!(layout(assigned(&batch, 0)), piece(STACK, -4, 4));
    assert_eq!(batch.outcomes[1], FallbackOutcome::NoFit { candidates: 0 });
    assert_eq!(state.groups(), [USED]);
}

#[test]
fn padding_float_conversion_and_provenance_pass_through_unchanged() {
    // d0 converts; d1 is too large for 4 bytes, so the one-piece float
    // join over d1 converts next; the padded join then takes r0.
    let input = format!(
        "{}{}{}{}{}",
        reg("d0", 1, 8, r#"float" extension="float"#),
        reg("d1", 5, 8, "float"),
        join(&["d1"], 1, 4, r#"storage="float""#)
            .replace(r#"piece1="d1""#, r#"piece1="d1" size="4""#),
        reg("r0", 1, 4, "general"),
        join(&["const:0xffffffffffffffff:4", "r0"], 5, 8, "")
    );
    let resources = plan(&input);
    let (state, batch) = run(&resources, &[req(4, 4, F), req(4, 4, F), req(8, 4, G)]);
    let storage = resources.storage();
    for (index, site) in [0, 2, 4].into_iter().enumerate() {
        let a = assigned(&batch, index);
        assert_eq!(entry(a.site), site);
        let direct = place_parameter(
            storage,
            a.site,
            PlacementRequest {
                size: requests_size(index),
                used_slots: 0,
                type_alignment: 4,
                justification: Justification::Default,
            },
            Default::default(),
        )
        .unwrap();
        assert_eq!(direct.outcome, PlacementOutcome::Placed(a.value.clone()));
    }
    assert_eq!(
        assigned(&batch, 0).value.storage,
        PlacedStorage::FloatConversion {
            container: StorageRange {
                address: AbiAddress {
                    space: REG,
                    offset: 0x100
                },
                size: Some(8),
                register: storage.register_file().register_id("d0"),
            },
            logical_size: 4,
        }
    );
    assert_eq!(assigned(&batch, 0).value.extension, Extension::Float);
    assert!(matches!(
        &assigned(&batch, 1).value.storage,
        PlacedStorage::FloatConversion { container, logical_size: 4 } if container.address.offset == 0x108
    ));
    assert_eq!(
        layout(assigned(&batch, 2)),
        [
            (AbiSpace::Language(common::CONST), -1, 4, PieceRole::Padding),
            (REG, 0, 4, PieceRole::Storage),
        ]
    );
    // Padding is provenance only: it occupies nothing. Float containers are
    // held whole.
    assert_eq!(
        extents(&state),
        [
            (REG, 0, 3, 4),
            (REG, 0x100, 0x107, 0),
            (REG, 0x108, 0x10f, 2)
        ]
    );
}

fn requests_size(index: usize) -> u32 {
    [4, 4, 8][index]
}

#[test]
fn big_endian_default_justification_matches_direct_placement() {
    let resources = Spec {
        input: &format!("{}{}", reg("r0", 1, 4, "general"), stack(16, 500, 4)),
        big: true,
        ..Default::default()
    }
    .build();
    let (_, batch) = run(&resources, &[req(2, 2, G), req(1, 1, G), req(2, 2, G)]);
    assert_eq!(layout(assigned(&batch, 0)), piece(REG, 2, 2));
    assert_eq!(layout(assigned(&batch, 1)), piece(STACK, 19, 1));
    assert_eq!(layout(assigned(&batch, 2)), piece(STACK, 22, 2));
}

#[test]
fn input_and_output_lists_have_independent_states() {
    let resources = Spec {
        input: &format!(
            "{}{}",
            reg("r0", 1, 4, "general"),
            reg("r1", 1, 4, "general")
        ),
        output: &reg("r0", 1, 4, "general"),
        ..Default::default()
    }
    .build();
    let mut input = fresh(&resources, INPUT);
    let mut output = fresh(&resources, OUTPUT);
    let a = input
        .assign_fallback(
            &resources,
            &[req(4, 4, G)],
            Default::default(),
            Default::default(),
        )
        .unwrap();
    let b = output
        .assign_fallback(
            &resources,
            &[req(4, 4, G), req(4, 4, G)],
            Default::default(),
            Default::default(),
        )
        .unwrap();
    assert_eq!(
        assigned(&a, 0).site,
        BindingSite::Input { model: 0, entry: 0 }
    );
    assert_eq!(
        assigned(&b, 0).site,
        BindingSite::Output { model: 0, entry: 0 }
    );
    assert_eq!((a.direction, b.direction), (INPUT, OUTPUT));
    assert_eq!(b.outcomes[1], FallbackOutcome::NoFit { candidates: 0 });
    assert_eq!(input.groups(), [USED, slots(0)]);
    assert_eq!(output.groups(), [USED]);
    // Each state belongs to one list; the other list's storage is not occupied.
    let batch = input
        .assign_fallback(
            &resources,
            &[req(4, 4, G)],
            Default::default(),
            Default::default(),
        )
        .unwrap();
    assert_eq!(entry(assigned(&batch, 0).site), 1);
}

/// Each hazard returns a typed error, discards the batch and restores state.
fn hazard(
    resources: &CompilerResources,
    first: &[FallbackRequest],
    second: &[FallbackRequest],
) -> FallbackError {
    let mut state = fresh(resources, INPUT);
    state
        .assign_fallback(resources, first, Default::default(), Default::default())
        .unwrap();
    let before = snapshot(&state);
    let error = state
        .assign_fallback(resources, second, Default::default(), Default::default())
        .unwrap_err();
    assert_eq!(snapshot(&state), before);
    // The same requests in one batch fail identically from a fresh state.
    let mut combined = first.to_vec();
    combined.extend_from_slice(second);
    let mut state = fresh(resources, INPUT);
    let again = state
        .assign_fallback(resources, &combined, Default::default(), Default::default())
        .unwrap_err();
    assert_eq!(snapshot(&state), snapshot(&fresh(resources, INPUT)));
    let (request, site, kind) = located(&error);
    assert_eq!(located(&again), (request + first.len(), site, kind));
    error
}

fn located(error: &FallbackError) -> (usize, BindingSite, &'static str) {
    match error {
        FallbackError::GroupInUse { request, site, .. } => (*request, *site, "group"),
        FallbackError::Overlap { request, site, .. } => (*request, *site, "overlap"),
        FallbackError::Unsupported { request, site, .. } => (*request, *site, "unsupported"),
        other => panic!("not a located refusal: {other:?}"),
    }
}

#[test]
fn retained_first_group_test_is_refused_when_a_later_group_is_in_use() {
    // Minimum-size heterogeneity: the float goes to f0, consuming group 1
    // shared with r1. The join (groups [0, 1]) passes the retained first-group
    // test though r1's group is consumed. There is no physical overlap.
    let input = format!(
        "{}<group>{}{}</group>{}",
        reg("r0", 4, 4, "general"),
        reg("f0", 1, 4, "float"),
        reg("r1", 1, 4, "general"),
        join(&["r1", "r0"], 5, 8, "")
    );
    let resources = plan(&input);
    let list = resources.list(0, INPUT).unwrap();
    assert_eq!(list.entries[3].groups, [ResourceId(0), ResourceId(1)]);
    let (_, batch) = run(&resources, &[req(2, 2, F)]);
    assert_eq!(entry(assigned(&batch, 0).site), 1);
    let error = hazard(&resources, &[req(2, 2, F)], &[req(8, 4, G)]);
    assert!(
        matches!(
            error,
            FallbackError::GroupInUse {
                request: 0,
                site: BindingSite::Input { entry: 3, .. },
                group: ResourceId(1),
            }
        ),
        "{error:?}"
    );

    // The same retained test with physical overlap of r1.
    let input = format!(
        "{}{}{}",
        reg("r0", 1, 4, "float"),
        reg("r1", 1, 4, "general"),
        join(&["r1", "r0"], 5, 8, "")
    );
    let resources = plan(&input);
    let error = hazard(&resources, &[req(4, 4, G)], &[req(8, 4, G)]);
    assert!(matches!(
        error,
        FallbackError::GroupInUse {
            group: ResourceId(1),
            ..
        }
    ));
}

#[test]
fn physical_overlap_outside_the_group_model_is_refused() {
    // A join piece with no exact earlier pool has no group: two joins can
    // share r1 while their groups are disjoint.
    let input = format!(
        "{}{}{}{}",
        reg("r0", 1, 4, "general"),
        reg("r2", 1, 4, "general"),
        join(&["r1", "r0"], 5, 8, ""),
        join(&["r1", "r2"], 5, 8, "")
    );
    let resources = plan(&input);
    let groups: Vec<_> = resources
        .list(0, INPUT)
        .unwrap()
        .entries
        .iter()
        .map(|e| e.groups.clone())
        .collect();
    assert_eq!(groups[2], [ResourceId(0)]);
    assert_eq!(groups[3], [ResourceId(1)]);
    let error = hazard(&resources, &[req(8, 4, G)], &[req(8, 4, G)]);
    assert!(
        matches!(
            error,
            FallbackError::Overlap {
                request: 0,
                site: BindingSite::Input { entry: 3, .. },
                previous: BindingSite::Input { entry: 2, .. },
            }
        ),
        "{error:?}"
    );

    // A join piece that only partially matches an earlier pool. The first
    // join piece (r2) is recorded before r0 collides; the error restores it.
    let input = format!(
        "{}{}{}",
        reg("wide", 1, 8, "general"),
        reg("r2", 1, 4, "general"),
        join(&["r2", "r0"], 5, 8, "")
    );
    let error = hazard(&plan(&input), &[req(8, 4, G)], &[req(8, 4, G)]);
    assert!(matches!(
        error,
        FallbackError::Overlap {
            site: BindingSite::Input { entry: 2, .. },
            previous: BindingSite::Input { entry: 0, .. },
            ..
        }
    ));

    // Extents that share exactly one boundary byte overlap; adjacent ones do
    // not. b3 = [3, 6] meets r0 = [0, 3]; b1 = [1, 4] meets r1 = [4, 7].
    for (held, untracked, refused) in [("r0", "b3", true), ("r1", "b1", true), ("r0", "r1", false)]
    {
        let input = format!(
            "{}{}{}",
            reg(held, 1, 4, "general"),
            reg("r2", 1, 4, "general"),
            join(&["r2", untracked], 5, 8, "")
        );
        let resources = plan(&input);
        if refused {
            let error = hazard(&resources, &[req(4, 4, G)], &[req(8, 4, G)]);
            assert!(
                matches!(
                    error,
                    FallbackError::Overlap {
                        site: BindingSite::Input { entry: 2, .. },
                        previous: BindingSite::Input { entry: 0, .. },
                        ..
                    }
                ),
                "{held}/{untracked}: {error:?}"
            );
        } else {
            let (state, batch) = run(&resources, &[req(4, 4, G), req(8, 4, G)]);
            assert_eq!(entry(assigned(&batch, 1).site), 2);
            assert_eq!(
                extents(&state),
                [(REG, 0, 3, 0), (REG, 4, 7, 2), (REG, 8, 11, 2)]
            );
        }
    }

    // An aligned pool with several inherited groups advances only its first
    // group's cursor, so a contained register remains selectable.
    let input = format!(
        r#"{}{}<pentry minsize="1" maxsize="8" align="4"><register name="wide"/></pentry>"#,
        reg("r0", 1, 4, "general"),
        reg("r1", 1, 4, "general")
    );
    let resources = plan(&input);
    let error = hazard(&resources, &[req(8, 4, G)], &[req(4, 4, G)]);
    assert!(matches!(
        error,
        FallbackError::Overlap {
            site: BindingSite::Input { entry: 1, .. },
            previous: BindingSite::Input { entry: 2, .. },
            ..
        }
    ));
    // In declaration order the same list is safe.
    let (state, batch) = run(&resources, &[req(4, 4, G), req(4, 4, G), req(4, 4, G)]);
    assert_eq!(batch.first_no_fit, Some(2));
    assert_eq!(state.groups(), [USED, USED]);

    // Aligned joins have no supported slot occupancy model.
    let input = format!(
        "{}{}{}",
        reg("r0", 1, 4, "general"),
        reg("r1", 1, 4, "general"),
        join(&["r0", "r1"], 1, 8, r#"align="4""#)
    );
    let resources = plan(&input);
    let error = hazard(&resources, &[], &[req(8, 4, G)]);
    assert!(matches!(
        error,
        FallbackError::Unsupported {
            site: BindingSite::Input { entry: 2, .. },
            reason: "aligned join pools have no supported slot-to-piece occupancy",
            ..
        }
    ));
}

#[test]
fn a_slice_leaving_its_address_domain_is_refused_rather_than_skipped() {
    // Pool capacity may extend past the signed 32-bit stack domain; slots 0
    // and 1 fit, slot 2 would start at 0x80000000. Retained code would wrap;
    // trying r0 instead would invent a policy.
    let input = format!(
        "{}{}",
        stack(0x7fff_fff8, 16, 4),
        reg("r0", 1, 4, "general")
    );
    let resources = Spec {
        input: &input,
        input_attrs: r#"separatefloat="false""#,
        ..Default::default()
    }
    .build();
    let (_, batch) = run(&resources, &[req(4, 4, G), req(4, 4, G)]);
    assert_eq!(layout(assigned(&batch, 1)), piece(STACK, 0x7fff_fffc, 4));
    let error = hazard(&resources, &[req(4, 4, G), req(4, 4, G)], &[req(4, 4, G)]);
    assert!(
        matches!(
            error,
            FallbackError::Unsupported {
                request: 0,
                site: BindingSite::Input { entry: 0, .. },
                reason: "selected storage leaves its address domain",
            }
        ),
        "{error:?}"
    );
}

#[test]
fn rules_must_be_explicitly_bypassed_and_are_reported() {
    let rule = r#"<rule><datatype name="any"/><goto_stack/></rule>"#;
    let input = format!("{}{}{rule}", reg("r0", 1, 4, "general"), stack(0, 16, 4));
    let resources = Spec {
        input: &input,
        input_attrs: r#"pointermax="4""#,
        output: &reg("r0", 1, 4, "general"),
        prototype_attrs: r#"hasthis="true" strategy="register""#,
        ..Default::default()
    }
    .build();
    let mut state = fresh(&resources, INPUT);
    let error = state
        .assign_fallback(
            &resources,
            &[req(4, 4, G)],
            Default::default(),
            Default::default(),
        )
        .unwrap_err();
    assert!(matches!(
        error,
        FallbackError::RulesNotExecuted {
            model: 0,
            direction: ParameterDirection::Input,
            rules: 1,
            pointer_max: Some(4),
        }
    ));
    assert_eq!(snapshot(&state), snapshot(&fresh(&resources, INPUT)));
    let bypass = FallbackPolicy {
        declared_rules: DeclaredRules::BypassUnexecuted,
        ..Default::default()
    };
    let (_, batch) = run_policy(&resources, INPUT, &[req(4, 4, G), req(8, 4, G)], bypass);
    // goto_stack would put the first value on the stack, and pointermax would
    // pass the 8-byte value by reference. The bare primitive does neither.
    assert_eq!(entry(assigned(&batch, 0).site), 0);
    assert_eq!(layout(assigned(&batch, 1)), piece(STACK, 0, 8));
    assert_eq!(
        batch.unexecuted,
        UnexecutedDeclarations {
            rules: 1,
            pointer_max: Some(4),
            this_before_return_pointer: false,
            register_output_strategy: false,
            has_this: true,
            injections: 0,
            share_stack: false,
        }
    );
    assert!(batch.unexecuted.changes_assignment());
    assert_eq!(batch.policy, bypass);
    // The output list has no rules; its register strategy is recorded.
    let (_, batch) = run_policy(&resources, OUTPUT, &[req(4, 4, G)], Default::default());
    assert!(batch.unexecuted.register_output_strategy && !batch.unexecuted.changes_assignment());
}

#[test]
fn invalid_requests_lists_and_states_fail_without_partial_results() {
    let resources = windows_like();
    let mut state = fresh(&resources, INPUT);
    for (bad, reason_index) in [(req(0, 1, G), 2), (req(4, 0, G), 2)] {
        let error = state
            .assign_fallback(
                &resources,
                &[req(4, 4, G), req(4, 4, G), bad, req(4, 4, G)],
                Default::default(),
                Default::default(),
            )
            .unwrap_err();
        assert!(matches!(
            error,
            FallbackError::InvalidRequest { request, .. } if request == reason_index
        ));
        assert_eq!(snapshot(&state), snapshot(&fresh(&resources, INPUT)));
    }
    assert!(matches!(
        AllocationState::new(&resources, 1, INPUT, Default::default()),
        Err(FallbackError::UnknownList {
            model: 1,
            direction: ParameterDirection::Input
        })
    ));
    // A state belongs to one overlay; an identical rebuild is still refused.
    let other = windows_like();
    assert!(matches!(
        state.assign_fallback(
            &other,
            &[req(4, 4, G)],
            Default::default(),
            Default::default()
        ),
        Err(FallbackError::StateMismatch)
    ));
    // An empty batch and an empty list are valid.
    let batch = state
        .assign_fallback(&resources, &[], Default::default(), Default::default())
        .unwrap();
    assert!(batch.outcomes.is_empty() && batch.first_no_fit.is_none());
    let (_, batch) = run_policy(&resources, OUTPUT, &[req(4, 4, G)], Default::default());
    assert_eq!(batch.outcomes, [FallbackOutcome::NoFit { candidates: 0 }]);
}

#[test]
fn results_are_deterministic_owned_and_thread_safe() {
    fn send_sync<T: Send + Sync + 'static>() {}
    send_sync::<AllocationState>();
    send_sync::<FallbackBatch>();
    send_sync::<FallbackError>();
    let resources = windows_like();
    let requests = [req(4, 4, G), req(8, 8, F), req(16, 8, G)];
    let (a, first) = run(&resources, &requests);
    let (b, second) = run(&resources, &requests);
    assert_eq!(first, second);
    assert_eq!(snapshot(&a), snapshot(&b));
    assert_eq!(
        serde_json::to_string(&first).unwrap(),
        serde_json::to_string(&second).unwrap()
    );
    let moved = std::thread::spawn(move || (a, first)).join().unwrap();
    assert_eq!(moved.1, second);
    // A clone stages tentative work without touching the original.
    let mut staged = b.clone();
    staged
        .assign_fallback(
            &resources,
            &[req(4, 4, G)],
            Default::default(),
            Default::default(),
        )
        .unwrap();
    assert_ne!(snapshot(&staged), snapshot(&b));
}

/// Float conversion, a two-piece join, an alignment hole, a no-fit and a
/// not-attempted request.
fn representative() -> (CompilerResources, Vec<FallbackRequest>) {
    let input = format!(
        "{}{}{}{}{}{}{}",
        reg("d0", 1, 8, r#"float" extension="float"#),
        reg("r0", 1, 4, "general"),
        reg("r1", 1, 4, "general"),
        reg("r2", 1, 4, "general"),
        reg("r3", 1, 4, "general"),
        join(&["r3", "r2"], 5, 8, ""),
        stack(0, 32, 4)
    );
    let requests = vec![
        req(4, 4, F),
        req(4, 4, G),
        req(8, 4, G),
        req(4, 4, G),
        req(2, 2, G),
        req(8, 8, G),
        req(32, 4, G),
        req(4, 4, G),
    ];
    (plan(&input), requests)
}

#[test]
fn representative_batch_is_hand_derived() {
    let (resources, requests) = representative();
    let (state, batch) = run(&resources, &requests);
    assert!(matches!(
        assigned(&batch, 0).value.storage,
        PlacedStorage::FloatConversion {
            logical_size: 4,
            ..
        }
    ));
    assert_eq!(entry(assigned(&batch, 1).site), 1);
    assert_eq!(entry(assigned(&batch, 2).site), 5);
    assert_eq!(
        layout(assigned(&batch, 2)),
        [
            (REG, 12, 4, PieceRole::Storage),
            (REG, 8, 4, PieceRole::Storage)
        ]
    );
    assert_eq!(entry(assigned(&batch, 3).site), 2);
    assert_eq!(layout(assigned(&batch, 4)), piece(STACK, 0, 2));
    assert_eq!(layout(assigned(&batch, 5)), piece(STACK, 8, 8));
    assert_eq!(batch.outcomes[6], FallbackOutcome::NoFit { candidates: 1 });
    assert_eq!(batch.outcomes[7], FallbackOutcome::NotAttempted);
    assert_eq!(state.groups(), [USED, USED, USED, USED, USED, slots(4)]);
    assert_eq!(batch.usage.source_pieces, 2);
    assert_eq!(batch.usage.placements, 6);
    assert_eq!(batch.usage.pieces, 7);
    assert_eq!(batch.usage.occupied_extents, 7);
}

fn with(limits: FallbackLimits, change: impl FnOnce(&mut FallbackLimits)) -> FallbackLimits {
    let mut limits = limits;
    change(&mut limits);
    limits
}

#[test]
fn later_batches_bound_existing_occupied_extents_even_without_new_assignments() {
    let resources = plan(&reg("r0", 1, 4, "general"));
    let limits = FallbackLimits::default();
    let mut state = AllocationState::new(&resources, 0, INPUT, limits).unwrap();
    let request = FallbackRequest {
        size: 4,
        alignment: 4,
        storage_class: G,
    };
    state
        .assign_fallback(&resources, &[request], FallbackPolicy::default(), limits)
        .unwrap();
    assert_eq!(state.occupied_count(), 1);
    let before_groups = state.groups().to_vec();
    let before_extents = state.occupied().collect::<Vec<_>>();
    let reduced = with(limits, |l| l.max_occupied_extents = 0);
    for requests in [&[][..], &[request][..]] {
        assert!(matches!(
            state.assign_fallback(&resources, requests, FallbackPolicy::default(), reduced),
            Err(FallbackError::Limit("occupied extents"))
        ));
        assert_eq!(state.groups(), before_groups);
        assert_eq!(state.occupied().collect::<Vec<_>>(), before_extents);
    }
    let exact = with(limits, |l| l.max_occupied_extents = 1);
    assert_eq!(
        state
            .assign_fallback(&resources, &[], FallbackPolicy::default(), exact)
            .unwrap()
            .usage
            .occupied_extents,
        1
    );
    assert!(matches!(
        state
            .assign_fallback(&resources, &[request], FallbackPolicy::default(), exact)
            .unwrap()
            .outcomes[0],
        FallbackOutcome::NoFit { .. }
    ));
}

#[test]
fn every_batch_limit_is_exact_and_one_below_fails_without_side_effects() {
    let (resources, requests) = representative();
    let (_, reference) = run(&resources, &requests);
    let usage = reference.usage;
    let base = FallbackLimits::default();
    type Setter = fn(&mut FallbackLimits, u64);
    let caps: [(&str, u64, Setter); 9] = [
        ("requests", usage.requests as u64, |l, n| {
            l.max_requests = n as usize
        }),
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
        let mut state = fresh(&resources, INPUT);
        let batch = state
            .assign_fallback(
                &resources,
                &requests,
                Default::default(),
                with(base, |l| set(l, exact)),
            )
            .unwrap();
        assert_eq!(batch, reference, "{name} at its exact value");
        let mut state = fresh(&resources, INPUT);
        let error = state
            .assign_fallback(
                &resources,
                &requests,
                Default::default(),
                with(base, |l| set(l, exact - 1)),
            )
            .unwrap_err();
        assert!(
            matches!(error, FallbackError::Limit(n) if n == name),
            "{name}: {error:?}"
        );
        assert_eq!(
            snapshot(&state),
            snapshot(&fresh(&resources, INPUT)),
            "{name}"
        );
    }
    // Every smaller work budget fails, including inside nested placement.
    for work in 0..usage.work {
        let mut state = fresh(&resources, INPUT);
        let error = state
            .assign_fallback(
                &resources,
                &requests,
                Default::default(),
                with(base, |l| l.max_work = work),
            )
            .unwrap_err();
        assert!(
            matches!(error, FallbackError::Limit("work")),
            "{work}: {error:?}"
        );
        assert_eq!(snapshot(&state), snapshot(&fresh(&resources, INPUT)));
    }
    // Nested placement work is included in the total, not reset per value.
    let direct: u64 = [0usize, 1, 5]
        .iter()
        .map(|&site| {
            place_parameter(
                resources.storage(),
                BindingSite::Input {
                    model: 0,
                    entry: site,
                },
                PlacementRequest::new(4),
                Default::default(),
            )
            .unwrap()
            .work
        })
        .sum();
    assert!(usage.work > direct + usage.examined_entries);

    // A failure in a later batch restores the earlier batch's state.
    let mut state = fresh(&resources, INPUT);
    state
        .assign_fallback(
            &resources,
            &requests[..3],
            Default::default(),
            Default::default(),
        )
        .unwrap();
    let before = snapshot(&state);
    let error = state
        .assign_fallback(
            &resources,
            &requests[3..6],
            Default::default(),
            with(base, |l| l.max_occupied_extents = 4),
        )
        .unwrap_err();
    assert!(matches!(error, FallbackError::Limit("occupied extents")));
    assert_eq!(snapshot(&state), before);

    // State creation has its own exact group and work limits.
    let groups = resources.list(0, INPUT).unwrap().group_count;
    for (limits, ok) in [
        (with(base, |l| l.max_groups = groups), true),
        (with(base, |l| l.max_groups = groups - 1), false),
        (with(base, |l| l.max_work = groups as u64 + 1), true),
        (with(base, |l| l.max_work = groups as u64), false),
    ] {
        assert_eq!(
            AllocationState::new(&resources, 0, INPUT, limits).is_ok(),
            ok
        );
    }
}

#[test]
fn long_batches_scale_linearly_with_requests_times_entries() {
    let registers: String = ["r0", "r1", "r2", "r3", "x0", "x1", "x2", "x3"]
        .iter()
        .map(|r| reg(r, 1, 4, "general"))
        .collect();
    let resources = plan(&format!("{registers}{}", stack(0, 400_000, 4)));
    let mut work = Vec::new();
    for count in [1024_usize, 4096] {
        let requests = vec![req(4, 4, G); count];
        let (state, batch) = run(&resources, &requests);
        let last = assigned(&batch, count - 1);
        assert_eq!(layout(last), piece(STACK, (count as i64 - 9) * 4, 4));
        // Requests 0..8 examine 1..=8 entries; every later one examines 9.
        assert_eq!(batch.usage.examined_entries, 36 + 9 * (count as u64 - 8));
        assert_eq!(state.occupied_count(), count);
        work.push(batch.usage.work);
    }
    let ratio = work[1] as f64 / work[0] as f64;
    assert!((3.9..4.6).contains(&ratio), "{work:?}");
    // The request cap is checked before any work or allocation.
    let mut state = fresh(&resources, INPUT);
    assert!(matches!(
        state.assign_fallback(
            &resources,
            &vec![req(4, 4, G); 4097],
            Default::default(),
            Default::default()
        ),
        Err(FallbackError::Limit("requests"))
    ));
}

// ---------------------------------------------------------------------------
// Independent reference: a transcription of Java `assignAddressFallback` and
// `getAddrBySlot` over the generator's own declarations (power-of-two
// alignments, little-endian), plus a byte-set occupancy oracle that does not
// read the group arrays.
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
enum Shape {
    Register(&'static str),
    Join(Vec<&'static str>),
    Stack(i64),
}

#[derive(Clone, Debug)]
struct Declared {
    shape: Shape,
    min: u32,
    max: u32,
    align: u32,
    class: StorageClass,
    group: Option<usize>,
}

const PAD: &str = "const:0xffffffffffffffff:4";

fn register_extent(name: &str) -> Option<(u64, u32)> {
    REGISTERS
        .iter()
        .find(|(n, ..)| *n == name)
        .map(|&(_, offset, size)| (offset, size))
}

fn to_xml(entries: &[Declared]) -> String {
    let mut text = String::new();
    let mut open = None;
    for e in entries {
        if open != e.group {
            if open.is_some() {
                text.push_str("</group>");
            }
            if e.group.is_some() {
                text.push_str("<group>");
            }
            open = e.group;
        }
        let class = if e.class == F { "float" } else { "general" };
        let align = if e.align == 0 {
            String::new()
        } else {
            format!(r#" align="{}""#, e.align)
        };
        let location = match &e.shape {
            Shape::Register(name) => format!(r#"<register name="{name}"/>"#),
            Shape::Stack(offset) => format!(
                r#"<addr space="stack" offset="0x{:x}"/>"#,
                *offset as i32 as u32
            ),
            Shape::Join(pieces) => {
                let attrs: String = pieces
                    .iter()
                    .enumerate()
                    .map(|(i, p)| format!(r#" piece{}="{p}""#, i + 1))
                    .collect();
                format!(r#"<addr space="join"{attrs}/>"#)
            }
        };
        text.push_str(&format!(
            r#"<pentry minsize="{}" maxsize="{}" storage="{class}"{align}>{location}</pentry>"#,
            e.min, e.max
        ));
    }
    if open.is_some() {
        text.push_str("</group>");
    }
    text
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[(self.next() % items.len() as u64) as usize]
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

fn generate(rng: &mut Rng) -> Vec<Declared> {
    let single = |name, min, max, class| Declared {
        shape: Shape::Register(name),
        min,
        max,
        align: 0,
        class,
        group: None,
    };
    let mut entries = Vec::new();
    if rng.chance(50) {
        entries.push(single("f0", rng.pick(&[1, 4]), 4, F));
    }
    if rng.chance(40) {
        entries.push(Declared {
            group: Some(0),
            ..single("f1", 1, 4, F)
        });
        entries.push(Declared {
            group: Some(0),
            ..single("r1", rng.pick(&[1, 2]), 4, G)
        });
    } else if rng.chance(70) {
        entries.push(single("r1", rng.pick(&[1, 2, 4]), 4, rng.pick(&[G, G, F])));
    }
    if rng.chance(70) {
        entries.push(single("r0", rng.pick(&[1, 2, 4]), 4, rng.pick(&[G, G, F])));
    }
    for name in ["r2", "r3"] {
        if rng.chance(60) {
            entries.push(single(name, rng.pick(&[1, 4]), 4, G));
        }
    }
    if rng.chance(35) {
        let aligned = rng.chance(40);
        entries.push(Declared {
            align: if aligned { 4 } else { 0 },
            ..single("wide", if aligned { 1 } else { rng.pick(&[1, 5]) }, 8, G)
        });
    }
    if rng.chance(25) {
        entries.push(single("d0", 5, 8, F));
    }
    if rng.chance(15) {
        let aligned = rng.chance(50);
        entries.push(Declared {
            align: if aligned { rng.pick(&[4, 8]) } else { 0 },
            ..single("quad", if aligned { 1 } else { 9 }, 16, G)
        });
    }
    for pieces in [
        vec!["r1", "r0"],
        vec!["r3", "r2"],
        vec!["r2", "r1"],
        vec![PAD, "r0"],
        vec!["r3", "r2", "r1", "r0"],
    ] {
        if rng.chance(25) {
            let total: u32 = pieces
                .iter()
                .map(|p| register_extent(p).map_or(4, |(_, s)| s))
                .sum();
            entries.push(Declared {
                shape: Shape::Join(pieces),
                min: rng.pick(&[1, 5, total]),
                max: total,
                align: 0,
                class: G,
                group: None,
            });
        }
    }
    let offset = rng.pick(&[0_i64, 8, -16]);
    if rng.chance(25) {
        entries.push(Declared {
            shape: Shape::Stack(offset + 4),
            min: 1,
            max: 4,
            align: 0,
            class: rng.pick(&[G, F]),
            group: None,
        });
    }
    let align = rng.pick(&[4, 8]);
    if rng.chance(15) {
        entries.push(Declared {
            shape: Shape::Stack(offset),
            min: 1,
            max: 8,
            align: 4,
            class: G,
            group: None,
        });
    }
    if rng.chance(90) {
        entries.push(Declared {
            shape: Shape::Stack(offset),
            min: 1,
            max: rng.pick(&[16, 32]),
            align,
            class: G,
            group: None,
        });
    }
    entries
}

type Byte = (u8, i64);
/// (value address, slot range, held span) from `getAddrBySlot`.
type Placed = (i64, Option<(u64, u64)>, i64);

/// Pool span (exclusion) and value bytes in the reference's own coordinates.
fn bytes(shape: &Shape, first: i64, size: u32, whole_join: bool) -> BTreeSet<Byte> {
    let mut set = BTreeSet::new();
    match shape {
        Shape::Register(_) => set.extend((first..first + i64::from(size)).map(|b| (0, b))),
        Shape::Stack(_) => set.extend((first..first + i64::from(size)).map(|b| (1, b))),
        Shape::Join(pieces) => {
            // Little-endian logical coordinates: the last piece is least
            // significant. A value occupies logical bytes [0, size).
            let mut low = 0_i64;
            for piece in pieces.iter().rev() {
                let Some((offset, width)) = register_extent(piece) else {
                    low += 4;
                    continue;
                };
                let width = i64::from(width);
                for b in 0..width {
                    if whole_join || low + b < i64::from(size) {
                        set.insert((0, offset as i64 + b));
                    }
                }
                low += width;
            }
        }
    }
    set
}

#[derive(Debug, PartialEq)]
enum Expected {
    Assigned {
        entry: usize,
        bytes: BTreeSet<Byte>,
        slots: Option<(u64, u64)>,
    },
    NoFit,
    NotAttempted,
}

#[derive(Debug, PartialEq)]
enum Hazard {
    GroupInUse {
        request: usize,
        entry: usize,
        group: usize,
    },
    Overlap {
        request: usize,
        entry: usize,
    },
}

fn reference(
    entries: &[Declared],
    groups: &[Vec<usize>],
    group_count: usize,
    requests: &[FallbackRequest],
    exact: bool,
    positive: bool,
) -> Result<(Vec<Expected>, Vec<i64>), Hazard> {
    let mut status = vec![0_i64; group_count];
    let mut occupied: BTreeSet<Byte> = BTreeSet::new();
    let mut result = Vec::new();
    for (request, r) in requests.iter().enumerate() {
        if result.last() == Some(&Expected::NoFit) || result.contains(&Expected::NotAttempted) {
            result.push(Expected::NotAttempted);
            continue;
        }
        let mut outcome = Expected::NoFit;
        for (index, e) in entries.iter().enumerate() {
            let grp = groups[index][0];
            if status[grp] < 0 {
                continue;
            }
            if r.storage_class != e.class && (exact || e.class != G) {
                continue;
            }
            // getAddrBySlot
            let mut slot = status[grp];
            let base = match &e.shape {
                Shape::Register(name) => register_extent(name).unwrap().0 as i64,
                Shape::Stack(offset) => *offset,
                Shape::Join(_) => 0,
            };
            let size = i64::from(r.size);
            let placed: Option<Placed> = if size < i64::from(e.min) {
                None
            } else if e.align == 0 {
                (slot == 0 && size <= i64::from(e.max)).then_some((base, None, i64::from(e.max)))
            } else {
                let align = i64::from(e.align);
                let type_align = i64::from(r.alignment);
                if type_align > align {
                    let tmp = (slot * align) % type_align;
                    if tmp != 0 {
                        slot += (type_align - tmp) / align;
                    }
                }
                let used = (size + align - 1) / align;
                let numslots = i64::from(e.max) / align;
                if slot + used > numslots {
                    None
                } else {
                    let index = if positive {
                        numslots - slot - used
                    } else {
                        slot
                    };
                    let start = slot;
                    slot += used;
                    Some((
                        base + index * align,
                        Some((start as u64, slot as u64)),
                        used * align,
                    ))
                }
            };
            status[grp] = slot;
            let Some((address, slots, span)) = placed else {
                continue;
            };
            for &g in &groups[index] {
                if g != grp && status[g] != 0 {
                    return Err(Hazard::GroupInUse {
                        request,
                        entry: index,
                        group: g,
                    });
                }
            }
            let held = match e.shape {
                Shape::Join(_) => bytes(&e.shape, 0, 0, true),
                _ => bytes(&e.shape, address, span as u32, false),
            };
            if !held.is_disjoint(&occupied) {
                return Err(Hazard::Overlap {
                    request,
                    entry: index,
                });
            }
            occupied.extend(held);
            if e.align == 0 {
                for &g in &groups[index] {
                    status[g] = -1;
                }
            }
            outcome = Expected::Assigned {
                entry: index,
                bytes: bytes(&e.shape, address, r.size, false),
                slots,
            };
            break;
        }
        result.push(outcome);
    }
    Ok((result, status))
}

fn value_bytes(a: &FallbackAssignment) -> BTreeSet<Byte> {
    let mut set = BTreeSet::new();
    for (space, offset, size, role) in layout(a) {
        if role == PieceRole::Padding {
            continue;
        }
        let tag = if space == STACK { 1 } else { 0 };
        set.extend((offset..offset + i64::from(size)).map(|b| (tag, b)));
    }
    set
}

#[test]
fn generated_layouts_match_an_independent_reference() {
    let mut rng = Rng(0x5eed_fa11_bac4);
    let file = file(false);
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut valid = 0;
    for _ in 0..2500 {
        let entries = generate(&mut rng);
        let positive = rng.chance(30);
        let text = format!(
            r#"<compiler_spec><stackpointer register="sp" space="ram" {}/>
<default_proto><prototype name="p" extrapop="0" stackshift="0">
<input separatefloat="false">{}</input><output/></prototype></default_proto></compiler_spec>"#,
            if positive { r#"growth="positive""# } else { "" },
            to_xml(&entries)
        );
        let spec = common::parse(&text);
        let Ok(storage) = CompilerStorage::new(Arc::new(spec), file.clone(), Default::default())
        else {
            *counts.entry("unresolvable").or_default() += 1;
            continue;
        };
        let Ok(resources) = CompilerResources::new(Arc::new(storage), Default::default()) else {
            *counts.entry("invalid resource layout").or_default() += 1;
            continue;
        };
        valid += 1;
        let list = resources.list(0, INPUT).unwrap();
        let groups: Vec<Vec<usize>> = list
            .entries
            .iter()
            .map(|e| e.groups.iter().map(|g| g.0).collect())
            .collect();
        let count = 1 + (rng.next() % 7) as usize;
        let requests: Vec<_> = (0..count)
            .map(|_| {
                let size = rng.pick(&[1, 2, 3, 4, 5, 8, 12, 16]);
                req(size, rng.pick(&[1, 2, 4, 8]), rng.pick(&[G, G, F]))
            })
            .collect();
        let exact = rng.chance(25);
        let policy = FallbackPolicy {
            class_match: if exact {
                ClassMatch::Exact
            } else {
                ClassMatch::GeneralAcceptsAny
            },
            ..Default::default()
        };
        let expected = reference(
            &entries,
            &groups,
            list.group_count,
            &requests,
            exact,
            positive,
        );
        let mut state = fresh(&resources, INPUT);
        let actual = state.assign_fallback(&resources, &requests, policy, Default::default());
        match (expected, actual) {
            (Ok((steps, status)), Ok(batch)) => {
                *counts.entry("accepted batches").or_default() += 1;
                let mut held: BTreeSet<Byte> = BTreeSet::new();
                for (index, (step, outcome)) in steps.iter().zip(&batch.outcomes).enumerate() {
                    match (step, outcome) {
                        (
                            Expected::Assigned {
                                entry: e,
                                bytes,
                                slots,
                            },
                            FallbackOutcome::Assigned(a),
                        ) => {
                            *counts.entry("assignments").or_default() += 1;
                            assert_eq!(entry(a.site), *e, "{index}: {text}");
                            assert_eq!(&value_bytes(a), bytes, "{index}: {text}");
                            assert_eq!(a.slots.map(|s| (s.first, s.next)), *slots, "{index}");
                            // Independent oracle: no two values share a byte.
                            assert!(held.is_disjoint(bytes), "{index}: {text}");
                            held.extend(bytes.iter().copied());
                        }
                        (Expected::NoFit, FallbackOutcome::NoFit { .. }) => {
                            *counts.entry("no-fit").or_default() += 1;
                        }
                        (Expected::NotAttempted, FallbackOutcome::NotAttempted) => {}
                        (step, outcome) => panic!("{index}: {step:?} vs {outcome:?}\n{text}"),
                    }
                }
                let states: Vec<_> = status
                    .iter()
                    .map(|&s| if s < 0 { USED } else { slots(s as u64) })
                    .collect();
                assert_eq!(state.groups(), states, "{text}");
            }
            (Err(hazard), Err(error)) => {
                let actual = match error {
                    FallbackError::GroupInUse {
                        request,
                        site,
                        group,
                    } => Hazard::GroupInUse {
                        request,
                        entry: entry(site),
                        group: group.0,
                    },
                    FallbackError::Overlap { request, site, .. } => Hazard::Overlap {
                        request,
                        entry: entry(site),
                    },
                    other => panic!("{other:?}\n{text}"),
                };
                assert_eq!(actual, hazard, "{text}");
                *counts
                    .entry(match hazard {
                        Hazard::GroupInUse { .. } => "refused: group in use",
                        Hazard::Overlap { .. } => "refused: overlap",
                    })
                    .or_default() += 1;
                assert_eq!(snapshot(&state), snapshot(&fresh(&resources, INPUT)));
            }
            (expected, actual) => panic!("{expected:?} vs {actual:?}\n{text}"),
        }
    }
    eprintln!("{valid} valid layouts: {counts:?}");
    assert!(valid >= 1000, "{counts:?}");
    assert!(counts["assignments"] >= 3000, "{counts:?}");
    assert!(counts["no-fit"] >= 300, "{counts:?}");
    assert!(counts["refused: overlap"] >= 20, "{counts:?}");
    assert!(counts["refused: group in use"] >= 20, "{counts:?}");
}
