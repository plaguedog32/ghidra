//! Hand-derived expectations for the native `<join>` action
//! (`MultiSlotAssign`, modelrules.cc:856-1072; `justifyPieces` at :742;
//! `getAddrBySlot`, `extractTiles`, `getStackEntry` and
//! `assignAddressFromPieces` in fspec.cc). Registers are fixture-owned:
//! r0..r7 at 4*i (4 bytes), x0..x7 at 0x80+8*i (8 bytes), s0..s7 at
//! 0x100+4*i (4 bytes), d0..d3 at 0x200+8*i (8 bytes), sp at 0x40.
mod common;

use std::sync::Arc;

use ghidra_abi::*;
use ghidra_languages::{RuleAction, StorageClass as C};
use ghidra_pcode::{Endianness, SpaceKind};

const IN: ParameterDirection = ParameterDirection::Input;
const OUT: ParameterDirection = ParameterDirection::Output;
const REG: AbiSpace = AbiSpace::Language(common::REGISTER);
const STACK: AbiSpace = AbiSpace::Stack;

fn registers() -> Vec<RegisterDefinition> {
    let mut out = Vec::new();
    for i in 0..8_u64 {
        out.push(common::register(
            &format!("r{i}"),
            common::REGISTER,
            4 * i,
            4,
        ));
        out.push(common::register(
            &format!("x{i}"),
            common::REGISTER,
            0x80 + 8 * i,
            8,
        ));
        out.push(common::register(
            &format!("s{i}"),
            common::REGISTER,
            0x100 + 4 * i,
            4,
        ));
    }
    for i in 0..4_u64 {
        out.push(common::register(
            &format!("d{i}"),
            common::REGISTER,
            0x200 + 8 * i,
            8,
        ));
    }
    out.push(common::register("sp", common::REGISTER, 0x40, 4));
    out
}

#[derive(Clone, Copy)]
struct Layout {
    register_big: bool,
    ram_big: bool,
    positive: bool,
}

const LE: Layout = Layout {
    register_big: false,
    ram_big: false,
    positive: false,
};
const BE: Layout = Layout {
    register_big: true,
    ram_big: true,
    positive: false,
};

fn plan_with(input: &str, output: &str, layout: Layout) -> CompilerResources {
    let growth = if layout.positive {
        r#" growth="positive""#
    } else {
        ""
    };
    let source = common::parse(&format!(
        r#"<compiler_spec><stackpointer register="sp" space="ram"{growth}/>
<default_proto><prototype name="p" extrapop="0" stackshift="0">
<input separatefloat="false">{input}</input><output separatefloat="false">{output}</output>
</prototype></default_proto></compiler_spec>"#
    ));
    let mut spaces = common::spaces(4);
    for s in &mut spaces {
        let big = match s.kind {
            SpaceKind::Register => layout.register_big,
            _ => layout.ram_big,
        };
        s.endianness = if big {
            Endianness::Big
        } else {
            Endianness::Little
        };
    }
    let file =
        Arc::new(RegisterFile::new(spaces, common::RAM, registers(), Default::default()).unwrap());
    let storage = common::storage(source, &file, Default::default()).unwrap();
    CompilerResources::new(Arc::new(storage), Default::default()).unwrap()
}

fn plan(input: &str, layout: Layout) -> CompilerResources {
    plan_with(input, "", layout)
}

fn reg(name: &str, max: u32, class: &str) -> String {
    format!(
        r#"<pentry minsize="1" maxsize="{max}" storage="{class}"><register name="{name}"/></pentry>"#
    )
}
fn regs(names: &[&str], max: u32, class: &str) -> String {
    names.iter().map(|n| reg(n, max, class)).collect()
}
fn stack(min: u32, max: u32, align: u32, offset: i64) -> String {
    format!(
        r#"<pentry minsize="{min}" maxsize="{max}" align="{align}"><addr space="stack" offset="{offset}"/></pentry>"#
    )
}
fn default_stack() -> String {
    stack(1, 500, 4, 8)
}

fn fresh(r: &CompilerResources, direction: ParameterDirection) -> AllocationState {
    AllocationState::new(r, 0, direction, Default::default()).unwrap()
}

fn attrs() -> JoinAttributes {
    JoinAttributes::default()
}

fn join(
    s: &mut AllocationState,
    r: &CompilerResources,
    a: JoinAttributes,
    size: u32,
    align: u32,
) -> JoinAssignment {
    s.assign_join(r, &a, JoinRequest::new(size, align), Default::default())
        .unwrap()
}

fn assigned(a: &JoinAssignment) -> &JoinAllocation {
    match &a.outcome {
        JoinOutcome::Assigned(allocation) => allocation,
        other => panic!("not assigned: {other:?}"),
    }
}

/// (space, signed offset, size, lsb) most significant first.
type Piece = (AbiSpace, i64, u32, u32);

fn pieces(a: &JoinAssignment) -> Vec<Piece> {
    match &assigned(a).storage {
        JoinStorage::Pieces(pieces) => pieces
            .iter()
            .map(|p| {
                (
                    p.piece.storage.address.space,
                    p.piece.storage.address.offset as i64,
                    p.piece.storage.size.unwrap(),
                    p.piece.lsb_byte,
                )
            })
            .collect(),
        other => panic!("not pieces: {other:?}"),
    }
}

fn snapshot(s: &AllocationState) -> (Vec<GroupState>, Vec<OccupiedExtent>) {
    (s.groups().to_vec(), s.occupied().collect())
}

fn extents(s: &AllocationState) -> Vec<(AbiSpace, i128, i128)> {
    s.occupied().map(|e| (e.space, e.first, e.last)).collect()
}

const FREE: GroupState = GroupState::Available { used_slots: 0 };
const USED: GroupState = GroupState::Consumed;

fn input(i: usize) -> BindingSite {
    BindingSite::Input { model: 0, entry: i }
}

#[test]
fn defaults_follow_list_byte_order_direction_and_true_toggles() {
    let list = regs(&["r0", "r1"], 4, "general") + &default_stack();
    let expected = |big, stack| JoinConfig {
        storage: C::General,
        big_endian: big,
        consume_from_stack: stack,
        consume_most_significant: big,
        enforce_alignment: false,
        justify_right: big,
        backfill: false,
    };
    for (layout, big) in [(LE, false), (BE, true)] {
        let r = plan_with(&list, &regs(&["r0", "r1"], 4, "general"), layout);
        let a = join(&mut fresh(&r, IN), &r, attrs(), 4, 4);
        assert_eq!(a.config, expected(big, true));
        let a = join(&mut fresh(&r, OUT), &r, attrs(), 4, 4);
        assert_eq!(a.config, expected(big, false));
        // Declared false never toggles; declared true toggles the default.
        let a = join(
            &mut fresh(&r, IN),
            &r,
            JoinAttributes {
                reverse_justify: Some(false),
                reverse_significance: Some(false),
                ..attrs()
            },
            4,
            4,
        );
        assert_eq!(a.config, expected(big, true));
        let a = join(
            &mut fresh(&r, IN),
            &r,
            JoinAttributes {
                reverse_justify: Some(true),
                reverse_significance: Some(true),
                align: Some(true),
                stack_spill: Some(false),
                backfill: Some(true),
                storage: Some(C::General),
            },
            4,
            4,
        );
        assert_eq!(
            a.config,
            JoinConfig {
                consume_from_stack: false,
                consume_most_significant: !big,
                enforce_alignment: true,
                justify_right: !big,
                backfill: true,
                ..expected(big, true)
            }
        );
    }
    // The list byte order is the FIRST entry's, not the first tile's: a
    // leading stack pool uses its little-endian backing space even though
    // the register tiles are big endian.
    let mixed = Layout {
        register_big: true,
        ram_big: false,
        positive: false,
    };
    let r = plan(
        &(r#"<pentry minsize="1" maxsize="4" storage="ptr"><addr space="stack" offset="0"/></pentry>"#
            .to_string()
            + &regs(&["r0", "r1"], 4, "general")
            + &default_stack()),
        mixed,
    );
    assert!(
        !join(&mut fresh(&r, IN), &r, attrs(), 4, 4)
            .config
            .big_endian
    );
    let r = plan(&list, mixed);
    assert!(
        join(&mut fresh(&r, IN), &r, attrs(), 4, 4)
            .config
            .big_endian
    );
}

#[test]
fn attributes_come_from_parsed_rule_actions() {
    let source = common::parse(
        r#"<compiler_spec><default_proto><prototype name="p" extrapop="0" stackshift="0">
<input><pentry minsize="1" maxsize="4"><register name="r0"/></pentry>
<rule><datatype name="any"/><join storage="float" align="true" reversejustify="true" reversesignif="false" stackspill="false" backfill="true"/></rule>
<rule><datatype name="any"/><join/></rule>
<rule><datatype name="any"/><goto_stack/></rule>
</input><output/></prototype></default_proto></compiler_spec>"#,
    );
    let rules = &source.prototypes[0].input.rules;
    assert_eq!(
        JoinAttributes::from_action(&rules[0].action),
        Some(JoinAttributes {
            storage: Some(C::Float),
            reverse_justify: Some(true),
            reverse_significance: Some(false),
            align: Some(true),
            stack_spill: Some(false),
            backfill: Some(true),
        })
    );
    assert_eq!(JoinAttributes::from_action(&rules[1].action), Some(attrs()));
    assert_eq!(rules[2].action, RuleAction::GotoStack);
    assert_eq!(JoinAttributes::from_action(&rules[2].action), None);
}

#[test]
fn eight_byte_values_split_most_significant_first_in_both_byte_orders() {
    let list = regs(&["r0", "r1", "r2"], 4, "general") + &default_stack();
    let r = plan(&list, LE);
    let mut s = fresh(&r, IN);
    let a = join(&mut s, &r, attrs(), 8, 4);
    // Consumed r0 then r1; little endian reverses to r1:r0.
    assert_eq!(pieces(&a), [(REG, 4, 4, 4), (REG, 0, 4, 0)]);
    let allocation = assigned(&a);
    assert_eq!(
        allocation
            .steps
            .iter()
            .map(|s| (s.site, s.kind, s.bytes))
            .collect::<Vec<_>>(),
        [
            (input(0), JoinStepKind::Tile, 4),
            (input(1), JoinStepKind::Tile, 4)
        ]
    );
    assert_eq!((allocation.skipped_tiles, allocation.excess), (0, 0));
    let JoinStorage::Pieces(raw) = &allocation.storage else {
        unreachable!()
    };
    assert_eq!(
        raw.iter().map(|p| (p.site, p.step)).collect::<Vec<_>>(),
        [(input(1), 1), (input(0), 0)]
    );
    assert_eq!(s.groups(), [USED, USED, FREE, FREE]);
    assert_eq!(extents(&s), [(REG, 0, 3), (REG, 4, 7)]);
    // Big endian consumes the most significant tile first: r0:r1.
    let r = plan(&list, BE);
    let mut s = fresh(&r, IN);
    assert_eq!(
        pieces(&join(&mut s, &r, attrs(), 8, 4)),
        [(REG, 0, 4, 4), (REG, 4, 4, 0)]
    );
    // A later value continues at the first untouched tile.
    assert_eq!(pieces(&join(&mut s, &r, attrs(), 4, 4)), [(REG, 8, 4, 0)]);
}

#[test]
fn every_byte_order_and_reverse_flag_combination_justifies_the_partial_tile() {
    let list = regs(&["r0", "r1"], 4, "general") + &default_stack();
    // 6 bytes over r0 (0..4) and r1 (4..8): 2 excess bytes. Each row was
    // worked by hand from justifyPieces and assignAddressFromPieces:
    // (big, reverse significance, reverse justify) -> pieces.
    let table: [(bool, bool, bool, [Piece; 2]); 8] = [
        // LE default: truncate the last tile r1 at its start.
        (false, false, false, [(REG, 4, 2, 4), (REG, 0, 4, 0)]),
        // LE reversejustify: first tile r0 loses its low 2 bytes.
        (false, false, true, [(REG, 4, 4, 2), (REG, 2, 2, 0)]),
        // LE reversesignif (AVR): r0 most significant, last tile r1 at +2.
        (false, true, false, [(REG, 0, 4, 2), (REG, 6, 2, 0)]),
        // LE both: first tile r0 at its start.
        (false, true, true, [(REG, 0, 2, 4), (REG, 4, 4, 0)]),
        // BE default: first tile r0, skip its 2 padding bytes.
        (true, false, false, [(REG, 2, 2, 4), (REG, 4, 4, 0)]),
        // BE reversejustify (MIPS struct): last tile r1 at its start.
        (true, false, true, [(REG, 0, 4, 2), (REG, 4, 2, 0)]),
        // BE reversesignif: r1 most significant; first tile r0 at its start.
        (true, true, false, [(REG, 4, 4, 2), (REG, 0, 2, 0)]),
        // BE both: r1 most significant; last tile r1 at +2.
        (true, true, true, [(REG, 6, 2, 4), (REG, 0, 4, 0)]),
    ];
    for (big, signif, justify, expected) in table {
        let r = plan(&list, if big { BE } else { LE });
        let mut s = fresh(&r, IN);
        let a = join(
            &mut s,
            &r,
            JoinAttributes {
                reverse_significance: Some(signif),
                reverse_justify: Some(justify),
                ..attrs()
            },
            6,
            1,
        );
        assert_eq!(
            pieces(&a),
            expected,
            "big {big} signif {signif} justify {justify}"
        );
        assert_eq!(assigned(&a).excess, 2);
        // The full declared tiles are held, not only the value bytes.
        assert_eq!(extents(&s), [(REG, 0, 3), (REG, 4, 7)]);
        let cropped = if big ^ justify { 0 } else { 1 };
        assert_eq!(assigned(&a).steps[cropped].bytes, 2);
        assert_eq!(assigned(&a).steps[1 - cropped].bytes, 4);
    }
}

#[test]
fn alignment_enforcement_skips_and_consumes_unaligned_tiles() {
    let list = regs(&["x0", "x1", "x2", "x3"], 8, "general") + &stack(1, 500, 8, 0);
    let r = plan(&list, LE);
    let aligned = JoinAttributes {
        align: Some(true),
        ..attrs()
    };
    let mut s = fresh(&r, IN);
    // A 4-byte int uses x0's low half; the tile is still consumed whole.
    assert_eq!(
        pieces(&join(&mut s, &r, aligned, 4, 4)),
        [(REG, 0x80, 4, 0)]
    );
    // A 16-byte value aligned to 16: x0 is consumed (8 resource bytes), x1
    // would start at byte 8, so it is skipped and consumed; x2:x3 is used.
    let a = join(&mut s, &r, aligned, 16, 16);
    assert_eq!(pieces(&a), [(REG, 0x98, 8, 8), (REG, 0x90, 8, 0)]);
    assert_eq!(assigned(&a).skipped_tiles, 2);
    assert_eq!(s.groups(), [USED, USED, USED, USED, FREE]);
    // x1 was skipped, not placed: it holds no physical extent.
    assert_eq!(
        extents(&s),
        [(REG, 0x80, 0x87), (REG, 0x90, 0x97), (REG, 0x98, 0x9f)]
    );
    // Without enforcement the same sequence takes x1:x2.
    let mut s = fresh(&r, IN);
    join(&mut s, &r, attrs(), 4, 4);
    assert_eq!(
        pieces(&join(&mut s, &r, attrs(), 16, 16)),
        [(REG, 0x90, 8, 8), (REG, 0x88, 8, 0)]
    );
    // Alignment no larger than the tile never skips.
    let mut s = fresh(&r, IN);
    join(&mut s, &r, aligned, 4, 4);
    assert_eq!(
        pieces(&join(&mut s, &r, aligned, 16, 8)),
        [(REG, 0x90, 8, 8), (REG, 0x88, 8, 0)]
    );
}

#[test]
fn backfill_leaves_skipped_float_tiles_for_later_values() {
    // ARM.cspec: <join storage="float" align="true" backfill="true" stackspill="false"/>.
    let list = regs(&["s0", "s1", "s2", "s3"], 4, "float") + &regs(&["r0"], 4, "general");
    let r = plan(&list, LE);
    let float = |backfill| JoinAttributes {
        storage: Some(C::Float),
        align: Some(true),
        backfill: Some(backfill),
        stack_spill: Some(false),
        ..attrs()
    };
    let mut s = fresh(&r, IN);
    assert_eq!(
        pieces(&join(&mut s, &r, float(true), 4, 4)),
        [(REG, 0x100, 4, 0)]
    );
    let a = join(&mut s, &r, float(true), 8, 8);
    assert_eq!(pieces(&a), [(REG, 0x10c, 4, 4), (REG, 0x108, 4, 0)]);
    assert_eq!(assigned(&a).skipped_tiles, 2);
    assert_eq!(s.groups(), [USED, FREE, USED, USED, FREE]);
    // s1 was skipped for alignment and is reused.
    assert_eq!(
        pieces(&join(&mut s, &r, float(true), 4, 4)),
        [(REG, 0x104, 4, 0)]
    );
    // Without backfill the skipped s1 is consumed, so the third value fails
    // and that NoFit changes nothing.
    let mut s = fresh(&r, IN);
    join(&mut s, &r, float(false), 4, 4);
    join(&mut s, &r, float(false), 8, 8);
    assert_eq!(s.groups(), [USED, USED, USED, USED, FREE]);
    let before = snapshot(&s);
    let a = join(&mut s, &r, float(false), 4, 4);
    assert_eq!(
        a.outcome,
        JoinOutcome::NoFit(JoinNoFit::StackSpillDisabled { uncovered: 4 })
    );
    assert_eq!(snapshot(&s), before);
}

#[test]
fn positive_cursor_tiles_are_never_starts_and_are_consumed_when_skipped() {
    // An aligned pool declared after r0 and r1 inherits both groups, so its
    // slot cursor lives in r0's group.
    let list = regs(&["r0", "r1", "r2"], 4, "general")
        + r#"<pentry minsize="1" maxsize="8" align="4" storage="vector"><addr space="register" offset="0"/></pentry>"#
        + &default_stack();
    let r = plan(&list, LE);
    assert_eq!(
        r.list(0, IN).unwrap().entries[3].groups,
        [ResourceId(0), ResourceId(1)]
    );
    let mut seeded = fresh(&r, IN);
    seeded
        .assign_pool(
            &r,
            PoolRequest {
                entry: 3,
                size: 4,
                alignment: 1,
                justification: Justification::Default,
            },
            Default::default(),
        )
        .unwrap();
    assert_eq!(seeded.groups()[0], GroupState::Available { used_slots: 1 });
    let mut s = seeded.clone();
    let a = join(&mut s, &r, attrs(), 4, 4);
    assert_eq!(pieces(&a), [(REG, 4, 4, 0)]);
    assert_eq!(assigned(&a).skipped_tiles, 1);
    // The skipped r0 cursor becomes consumed, as status[grp] = -1 does.
    assert_eq!(s.groups(), [USED, USED, FREE, FREE]);
    // With backfill its cursor is retained.
    let mut s = seeded.clone();
    join(
        &mut s,
        &r,
        JoinAttributes {
            backfill: Some(true),
            ..attrs()
        },
        4,
        4,
    );
    assert_eq!(
        s.groups(),
        [GroupState::Available { used_slots: 1 }, USED, FREE, FREE]
    );
}

#[test]
fn positive_cursor_tiles_after_the_start_are_passed_over_unchanged() {
    // The aligned pool contains r1 and r2, so its cursor lives in r1's group.
    let list = regs(&["r0", "r1", "r2"], 4, "general")
        + r#"<pentry minsize="1" maxsize="8" align="4" storage="vector"><addr space="register" offset="4"/></pentry>"#
        + &default_stack();
    let r = plan(&list, LE);
    let mut s = fresh(&r, IN);
    s.assign_pool(
        &r,
        PoolRequest {
            entry: 3,
            size: 4,
            alignment: 1,
            justification: Justification::Default,
        },
        Default::default(),
    )
    .unwrap();
    let a = join(&mut s, &r, attrs(), 12, 4);
    // r0 starts; r1's nonzero status is skipped without being consumed.
    assert_eq!(
        pieces(&a),
        [(STACK, 8, 4, 8), (REG, 8, 4, 4), (REG, 0, 4, 0)]
    );
    assert_eq!(
        s.groups(),
        [
            USED,
            GroupState::Available { used_slots: 1 },
            USED,
            GroupState::Available { used_slots: 1 }
        ]
    );
}

#[test]
fn spilled_bytes_after_a_register_use_alignment_one() {
    let r = plan(&(regs(&["r0"], 4, "general") + &default_stack()), LE);
    let mut s = fresh(&r, IN);
    s.assign_pool(
        &r,
        PoolRequest {
            entry: 1,
            size: 4,
            alignment: 1,
            justification: Justification::Default,
        },
        Default::default(),
    )
    .unwrap();
    // Eight-byte alignment applies only until the first register is taken:
    // the four spilled bytes use the next slot (offset 12), not slot 2.
    let a = join(&mut s, &r, attrs(), 8, 8);
    assert_eq!(pieces(&a), [(STACK, 12, 4, 4), (REG, 0, 4, 0)]);
    assert_eq!(s.groups()[1], GroupState::Available { used_slots: 2 });
}

#[test]
fn skipped_byte_counts_beyond_native_int_are_refused_only_when_read() {
    // Two consumed tiles of i32::MAX bytes make resourcesConsumed overflow a
    // native int before the alignment test reads it.
    let huge = |offset: u64| {
        format!(
            r#"<pentry minsize="1" maxsize="2147483647"><addr space="register" offset="{offset:#x}"/></pentry>"#
        )
    };
    let list =
        huge(0x1_0000_0000) + &huge(0x2_0000_0000) + &reg("r0", 4, "general") + &default_stack();
    let r = plan(&list, LE);
    let mut base = fresh(&r, IN);
    for entry in 0..2 {
        base.assign_pool(
            &r,
            PoolRequest {
                entry,
                size: 4,
                alignment: 1,
                justification: Justification::Default,
            },
            Default::default(),
        )
        .unwrap();
    }
    let mut s = base.clone();
    let before = snapshot(&s);
    assert!(matches!(
        s.assign_join(
            &r,
            &JoinAttributes {
                align: Some(true),
                ..attrs()
            },
            JoinRequest::new(4, 8),
            Default::default()
        ),
        Err(JoinError::Unsupported {
            reason: "skipped tile bytes exceed the native int range",
            ..
        })
    ));
    assert_eq!(snapshot(&s), before);
    // Without alignment enforcement the count is never read.
    let mut s = base.clone();
    assert_eq!(pieces(&join(&mut s, &r, attrs(), 4, 8)), [(REG, 0, 4, 0)]);
}

#[test]
fn fit_test_reads_only_the_start_tile_so_allocation_spans_gaps() {
    let list = regs(&["r0", "r1", "r2", "r3"], 4, "general") + &default_stack();
    let r = plan(&list, LE);
    let mut base = fresh(&r, IN);
    base.assign_pool(
        &r,
        PoolRequest {
            entry: 1,
            size: 4,
            alignment: 1,
            justification: Justification::Default,
        },
        Default::default(),
    )
    .unwrap();
    // checkFit's adjacency loop never advances, so the used r1 does not
    // reject r0 as a start; r1 is then passed over.
    let mut s = base.clone();
    let a = join(&mut s, &r, attrs(), 12, 4);
    assert_eq!(
        pieces(&a),
        [(REG, 12, 4, 8), (REG, 8, 4, 4), (REG, 0, 4, 0)]
    );
    assert_eq!(assigned(&a).skipped_tiles, 0);
    // A larger value spills its last four bytes to the stack, across the gap.
    let mut s = base.clone();
    let a = join(&mut s, &r, attrs(), 16, 4);
    assert_eq!(
        pieces(&a),
        [
            (STACK, 8, 4, 12),
            (REG, 12, 4, 8),
            (REG, 8, 4, 4),
            (REG, 0, 4, 0)
        ]
    );
    let stack_step = assigned(&a).steps[3];
    assert_eq!(
        (stack_step.site, stack_step.group, stack_step.bytes),
        (input(4), ResourceId(4), 4)
    );
    assert_eq!(
        stack_step.kind,
        JoinStepKind::Stack {
            slots: SlotRange { first: 0, next: 1 }
        }
    );
    assert_eq!(s.groups()[4], GroupState::Available { used_slots: 1 });
}

#[test]
fn stack_spill_uses_action_justification_and_the_original_alignment() {
    let list = regs(&["r0", "r1"], 4, "general") + &default_stack();
    for (layout, spilled, reversed) in [(LE, 8, 10), (BE, 10, 8)] {
        let r = plan(&list, layout);
        let mut s = fresh(&r, IN);
        let a = join(&mut s, &r, attrs(), 10, 4);
        // Remaining 2 bytes use alignment 1 after the first register.
        let stack_piece = pieces(&a).into_iter().find(|p| p.0 == STACK).unwrap();
        assert_eq!(
            stack_piece,
            (STACK, spilled, 2, if layout.ram_big { 0 } else { 8 })
        );
        assert_eq!(s.groups()[2], GroupState::Available { used_slots: 1 });
        // reversejustify flips only the action's justification.
        let mut s = fresh(&r, IN);
        let a = join(
            &mut s,
            &r,
            JoinAttributes {
                reverse_justify: Some(true),
                ..attrs()
            },
            10,
            4,
        );
        assert!(pieces(&a).iter().any(|p| p.0 == STACK && p.1 == reversed));
    }
    // With every tile used the whole value goes to the stack with the
    // datatype alignment: cursor 1 aligns to slot 2 (offset 16).
    let r = plan(&list, LE);
    let mut s = fresh(&r, IN);
    join(&mut s, &r, attrs(), 8, 4);
    s.assign_pool(
        &r,
        PoolRequest {
            entry: 2,
            size: 4,
            alignment: 1,
            justification: Justification::Default,
        },
        Default::default(),
    )
    .unwrap();
    let a = join(&mut s, &r, attrs(), 6, 8);
    assert_eq!(pieces(&a), [(STACK, 16, 6, 0)]);
    assert_eq!(assigned(&a).skipped_tiles, 2);
    assert_eq!(s.groups()[2], GroupState::Available { used_slots: 4 });
    // Big endian right-justifies the six bytes in their eight-byte slots.
    let r = plan(&list, BE);
    let mut s = fresh(&r, IN);
    join(&mut s, &r, attrs(), 8, 4);
    s.assign_pool(
        &r,
        PoolRequest {
            entry: 2,
            size: 4,
            alignment: 1,
            justification: Justification::Default,
        },
        Default::default(),
    )
    .unwrap();
    assert_eq!(
        pieces(&join(&mut s, &r, attrs(), 6, 8)),
        [(STACK, 18, 6, 0)]
    );
}

#[test]
fn every_no_fit_is_transactional_including_skips_and_stack_holes() {
    let aligned = JoinAttributes {
        align: Some(true),
        ..attrs()
    };
    // Disabled spill after an alignment skip: the skip is undone too.
    let list = regs(&["r0", "r1", "r2"], 4, "general") + &default_stack();
    let r = plan(&list, LE);
    let mut s = fresh(&r, IN);
    join(&mut s, &r, attrs(), 4, 4);
    let before = snapshot(&s);
    let a = join(
        &mut s,
        &r,
        JoinAttributes {
            stack_spill: Some(false),
            ..aligned
        },
        12,
        8,
    );
    assert_eq!(
        a.outcome,
        JoinOutcome::NoFit(JoinNoFit::StackSpillDisabled { uncovered: 8 })
    );
    assert_eq!(snapshot(&s), before);
    // Output lists do not spill by default.
    let r = plan_with("", &regs(&["r0", "r1"], 4, "general"), LE);
    let mut s = fresh(&r, OUT);
    assert_eq!(
        join(&mut s, &r, attrs(), 12, 4).outcome,
        JoinOutcome::NoFit(JoinNoFit::StackSpillDisabled { uncovered: 4 })
    );
    assert_eq!(s.groups(), [FREE, FREE]);
    // The stack rejects a spill below its minimum size.
    let r = plan(
        &(regs(&["r0", "r1"], 4, "general") + &stack(4, 500, 4, 8)),
        LE,
    );
    let mut s = fresh(&r, IN);
    assert_eq!(
        join(&mut s, &r, attrs(), 10, 4).outcome,
        JoinOutcome::NoFit(JoinNoFit::Stack {
            uncovered: 2,
            reason: NoFit::BelowMinimum
        })
    );
    assert_eq!(s.groups(), [FREE, FREE, FREE]);
    // Slots exhausted after an alignment hole: unlike bare fallback, the
    // hole written by getAddrBySlot is discarded with the failed attempt.
    let r = plan(&(regs(&["r0"], 4, "general") + &stack(1, 12, 4, 8)), LE);
    let mut s = fresh(&r, IN);
    join(&mut s, &r, attrs(), 4, 4);
    s.assign_pool(
        &r,
        PoolRequest {
            entry: 1,
            size: 4,
            alignment: 1,
            justification: Justification::Default,
        },
        Default::default(),
    )
    .unwrap();
    let before = snapshot(&s);
    assert_eq!(
        join(&mut s, &r, attrs(), 8, 8).outcome,
        JoinOutcome::NoFit(JoinNoFit::Stack {
            uncovered: 8,
            reason: NoFit::SlotsExhausted
        })
    );
    assert_eq!(snapshot(&s), before);
}

#[test]
fn float_joins_convert_only_a_single_partial_tile() {
    let list = regs(&["d0", "d1"], 8, "float") + &regs(&["r0", "r1"], 4, "general");
    let r = plan(&list, LE);
    let float = JoinAttributes {
        storage: Some(C::Float),
        stack_spill: Some(false),
        ..attrs()
    };
    let mut s = fresh(&r, IN);
    let a = join(&mut s, &r, float, 4, 4);
    match &assigned(&a).storage {
        JoinStorage::FloatConversion {
            container,
            logical_size,
        } => {
            assert_eq!(
                (
                    container.address.space,
                    container.address.offset,
                    container.size
                ),
                (REG, 0x200, Some(8))
            );
            assert_eq!(*logical_size, 4);
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(assigned(&a).excess, 4);
    assert_eq!(assigned(&a).steps[0].bytes, 8);
    assert_eq!(a.usage.pieces, 1);
    assert_eq!(extents(&s), [(REG, 0x200, 0x207)]);
    // Two float tiles truncate instead (little endian: last tile's start).
    let mut s = fresh(&r, IN);
    assert_eq!(
        pieces(&join(&mut s, &r, float, 12, 4)),
        [(REG, 0x208, 4, 8), (REG, 0x200, 8, 0)]
    );
    // An exact float tile is a plain piece.
    let mut s = fresh(&r, IN);
    assert_eq!(pieces(&join(&mut s, &r, float, 8, 8)), [(REG, 0x200, 8, 0)]);
    // A general join never converts.
    let mut s = fresh(&r, IN);
    assert_eq!(
        pieces(&join(
            &mut s,
            &r,
            JoinAttributes {
                stack_spill: Some(false),
                ..attrs()
            },
            2,
            2
        )),
        [(REG, 0, 2, 0)]
    );
}

fn join_tiles() -> String {
    // Pointer pools r0/r1 supply the resource groups; each general join tile
    // inherits exactly one group (r2 and r3 match no earlier pool).
    regs(&["r0", "r1"], 4, "ptr")
        + r#"<pentry minsize="1" maxsize="8"><addr space="join" piece1="r2" piece2="r0"/></pentry>"#
        + r#"<pentry minsize="1" maxsize="8"><addr space="join" piece1="r3" piece2="r1"/></pentry>"#
}

#[test]
fn join_pool_tiles_contribute_their_pieces_and_padding_with_significance() {
    let r = plan(&join_tiles(), LE);
    let list = r.list(0, IN).unwrap();
    assert_eq!(list.entries[2].groups, [ResourceId(0)]);
    assert_eq!(list.entries[3].groups, [ResourceId(1)]);
    let spill = JoinAttributes {
        stack_spill: Some(false),
        ..attrs()
    };
    let mut s = fresh(&r, IN);
    let a = join(&mut s, &r, spill, 16, 4);
    // Consumed J0 (r2:r0) then J1 (r3:r1); little endian reverses the two
    // tiles but keeps each tile's own most-significant-first pieces.
    assert_eq!(
        pieces(&a),
        [
            (REG, 12, 4, 12),
            (REG, 4, 4, 8),
            (REG, 8, 4, 4),
            (REG, 0, 4, 0)
        ]
    );
    let JoinStorage::Pieces(raw) = &assigned(&a).storage else {
        unreachable!()
    };
    assert_eq!(
        raw.iter()
            .map(|p| (p.site, p.piece.source_piece))
            .collect::<Vec<_>>(),
        [(input(3), 0), (input(3), 1), (input(2), 0), (input(2), 1)]
    );
    assert_eq!(s.groups(), [USED, USED]);
    assert_eq!(
        extents(&s),
        [(REG, 0, 3), (REG, 4, 7), (REG, 8, 11), (REG, 12, 15)]
    );
    let r = plan(&join_tiles(), BE);
    let mut s = fresh(&r, IN);
    assert_eq!(
        pieces(&join(&mut s, &r, spill, 16, 4)),
        [
            (REG, 8, 4, 12),
            (REG, 0, 4, 8),
            (REG, 12, 4, 4),
            (REG, 4, 4, 0)
        ]
    );
    // Constant padding stays padding, is not held, and keeps its offset.
    let r = plan(
        &(regs(&["r0"], 4, "ptr")
            + r#"<pentry minsize="1" maxsize="8"><addr space="join" piece1="const:0x7:4" piece2="r0"/></pentry>"#),
        LE,
    );
    let mut s = fresh(&r, IN);
    let a = join(&mut s, &r, spill, 8, 4);
    let JoinStorage::Pieces(raw) = &assigned(&a).storage else {
        unreachable!()
    };
    assert_eq!(raw[0].piece.role, PieceRole::Padding);
    assert_eq!(
        (raw[0].piece.storage.address.offset, raw[0].piece.lsb_byte),
        (7, 4)
    );
    assert_eq!(raw[1].piece.role, PieceRole::Storage);
    assert_eq!(extents(&s), [(REG, 0, 3)]);
}

#[test]
fn unmodeled_join_tile_layouts_are_refused_without_state_changes() {
    let spill = JoinAttributes {
        stack_spill: Some(false),
        ..attrs()
    };
    let refused = |r: &CompilerResources, a: JoinAttributes, size| {
        let mut s = fresh(r, IN);
        let before = snapshot(&s);
        let error = s
            .assign_join(r, &a, JoinRequest::new(size, 1), Default::default())
            .unwrap_err();
        assert_eq!(snapshot(&s), before);
        match error {
            JoinError::Unsupported { reason, .. } => reason,
            other => panic!("{other:?}"),
        }
    };
    let r = plan(&join_tiles(), LE);
    // Truncating a join tile would build a nested partial join address.
    assert_eq!(
        refused(&r, spill, 6),
        "justification would truncate a join tile"
    );
    // So would converting a join tile to a float extension.
    let float_join = join_tiles().replace(
        r#"<pentry minsize="1" maxsize="8"><addr"#,
        r#"<pentry minsize="1" maxsize="8" storage="float"><addr"#,
    );
    let r = plan(&float_join, LE);
    assert_eq!(
        refused(
            &r,
            JoinAttributes {
                storage: Some(C::Float),
                ..spill
            },
            4
        ),
        "floating conversion of a join or padding tile"
    );
    // A tile narrower than its join storage would be a partial nested join.
    let r = plan(
        &(regs(&["r0"], 4, "ptr")
            + r#"<pentry minsize="1" maxsize="6"><addr space="join" piece1="r2" piece2="r0"/></pentry>"#),
        LE,
    );
    assert_eq!(
        refused(&r, spill, 6),
        "join tile narrower than its join storage"
    );
    // A floating-extension pentry tile inside a compound join.
    let r = plan(
        &(regs(&["d0"], 8, "ptr")
            + r#"<pentry minsize="1" maxsize="4" storage="float"><addr space="join" piece1="d0" size="4"/></pentry>"#
            + &regs(&["s1"], 4, "float")),
        LE,
    );
    let float = JoinAttributes {
        storage: Some(C::Float),
        ..spill
    };
    assert_eq!(
        refused(&r, float, 8),
        "floating-extension tile inside a compound or truncated join"
    );
    // ... while an exact single floating-extension tile is that conversion.
    let mut s = fresh(&r, IN);
    let a = join(&mut s, &r, float, 4, 4);
    assert!(matches!(
        &assigned(&a).storage,
        JoinStorage::FloatConversion { container, logical_size: 4 }
            if container.size == Some(8) && container.address.offset == 0x200
    ));
}

#[test]
fn excess_beyond_a_variable_width_first_piece_is_refused() {
    // Big endian justifies the first consumed tile. A 2-byte r0 tile followed
    // by an 8-byte x1 tile leaves up to 7 excess bytes, more than r0 holds.
    let list = reg("r0", 2, "general") + &reg("x1", 8, "general") + &default_stack();
    let r = plan(&list, BE);
    for (size, ok) in [(3, false), (4, false), (8, false), (9, true), (10, true)] {
        let mut s = fresh(&r, IN);
        let before = snapshot(&s);
        let result = s.assign_join(&r, &attrs(), JoinRequest::new(size, 1), Default::default());
        if ok {
            let a = result.unwrap();
            // 10 - size excess bytes leave the low bytes of r0's two-byte piece.
            let excess = 10 - size;
            assert_eq!(
                pieces(&a),
                [(REG, i64::from(excess), 2 - excess, 8), (REG, 0x88, 8, 0)]
            );
        } else {
            assert!(matches!(
                result,
                Err(JoinError::Unsupported {
                    reason: "excess bytes cover the whole justified piece",
                    ..
                })
            ));
            assert_eq!(snapshot(&s), before);
        }
    }
    // Little endian truncates the last tile, which always keeps a byte.
    let r = plan(&list, LE);
    let mut s = fresh(&r, IN);
    assert_eq!(
        pieces(&join(&mut s, &r, attrs(), 3, 1)),
        [(REG, 0x88, 1, 2), (REG, 0, 2, 0)]
    );
}

#[test]
fn initialization_requires_tiles_and_a_final_aligned_stack_pool() {
    let error = |r: &CompilerResources, a: JoinAttributes| {
        fresh(r, IN)
            .assign_join(r, &a, JoinRequest::new(4, 4), Default::default())
            .unwrap_err()
    };
    let r = plan(&(regs(&["r0"], 4, "general") + &default_stack()), LE);
    assert!(matches!(
        error(
            &r,
            JoinAttributes {
                storage: Some(C::Float),
                ..attrs()
            }
        ),
        JoinError::NoTiles { class: C::Float }
    ));
    // A stack-only list has no tiles, even though it could hold the value.
    let r = plan(&default_stack(), LE);
    assert!(matches!(
        error(&r, attrs()),
        JoinError::NoTiles { class: C::General }
    ));
    // The last entry must be an aligned stack pool when spilling.
    let r = plan(&regs(&["r0", "r1"], 4, "general"), LE);
    assert!(matches!(error(&r, attrs()), JoinError::MissingStack));
    let no_spill = JoinAttributes {
        stack_spill: Some(false),
        ..attrs()
    };
    assert_eq!(
        pieces(&join(&mut fresh(&r, IN), &r, no_spill, 4, 4)).len(),
        1
    );
    let r = plan(
        &(regs(&["r0"], 4, "general")
            + r#"<pentry minsize="1" maxsize="8"><addr space="stack" offset="8"/></pentry>"#),
        LE,
    );
    assert!(matches!(error(&r, attrs()), JoinError::MissingStack));
    let r = plan(&(default_stack() + &regs(&["r0"], 4, "general")), LE);
    assert!(matches!(error(&r, attrs()), JoinError::MissingStack));
    // NoTiles takes precedence over a missing stack.
    let r = plan(&regs(&["r0"], 4, "ptr"), LE);
    assert!(matches!(error(&r, attrs()), JoinError::NoTiles { .. }));
    // Eligible tiles are exclusion entries of the exact class with one group:
    // a two-group join, an aligned register pool and other classes are not.
    let r = plan(
        &(regs(&["r0", "r1"], 4, "ptr")
            + r#"<pentry minsize="1" maxsize="8"><addr space="join" piece1="r1" piece2="r0"/></pentry>"#
            + r#"<pentry minsize="1" maxsize="8" align="4"><register name="x2"/></pentry>"#
            + &reg("r4", 4, "general")
            + &reg("s0", 4, "float")
            + &default_stack()),
        LE,
    );
    let a = join(&mut fresh(&r, IN), &r, attrs(), 8, 4);
    assert_eq!(a.usage.tiles, 1);
    assert_eq!(pieces(&a), [(STACK, 8, 4, 4), (REG, 16, 4, 0)]);
    // Grouped alternatives each have exactly one (shared) group, so both are
    // tiles; consuming one makes the other unavailable.
    let r = plan(
        &(r#"<group>"#.to_string()
            + &reg("s0", 4, "float")
            + &reg("r0", 4, "general")
            + "</group>"
            + &reg("r1", 4, "general")
            + &default_stack()),
        LE,
    );
    let mut s = fresh(&r, IN);
    let float = JoinAttributes {
        storage: Some(C::Float),
        ..attrs()
    };
    assert_eq!(pieces(&join(&mut s, &r, float, 4, 4)), [(REG, 0x100, 4, 0)]);
    assert_eq!(pieces(&join(&mut s, &r, attrs(), 4, 4)), [(REG, 4, 4, 0)]);
}

#[test]
fn invalid_requests_and_foreign_states_are_typed_errors() {
    let r = plan(&(regs(&["r0"], 4, "general") + &default_stack()), LE);
    let mut s = fresh(&r, IN);
    join(&mut s, &r, attrs(), 4, 4);
    let before = snapshot(&s);
    for (size, align) in [
        (0, 1),
        (i32::MAX as u32 + 1, 1),
        (4, 0),
        (4, i32::MAX as u32 + 1),
    ] {
        assert!(matches!(
            s.assign_join(
                &r,
                &attrs(),
                JoinRequest::new(size, align),
                Default::default()
            ),
            Err(JoinError::InvalidRequest(_))
        ));
        assert_eq!(snapshot(&s), before);
    }
    // The largest native size is a valid request (it fits nowhere here).
    assert!(matches!(
        s.assign_join(
            &r,
            &attrs(),
            JoinRequest::new(i32::MAX as u32, 1),
            Default::default()
        )
        .unwrap()
        .outcome,
        JoinOutcome::NoFit(JoinNoFit::Stack {
            reason: NoFit::SlotsExhausted,
            ..
        })
    ));
    let other = plan(&(regs(&["r0"], 4, "general") + &default_stack()), LE);
    assert!(matches!(
        s.assign_join(&other, &attrs(), JoinRequest::new(4, 4), Default::default()),
        Err(JoinError::StateMismatch)
    ));
    let mut output = fresh(&r, OUT);
    assert!(matches!(
        output.assign_join(&r, &attrs(), JoinRequest::new(4, 4), Default::default()),
        Err(JoinError::NoTiles { .. })
    ));
}

#[test]
fn signed_stack_coordinates_and_domain_escapes() {
    // A stack pool across zero keeps signed offsets in results and extents.
    let r = plan(&(regs(&["r0"], 4, "general") + &stack(1, 32, 4, -8)), LE);
    let mut s = fresh(&r, IN);
    let a = join(&mut s, &r, attrs(), 10, 4);
    assert_eq!(pieces(&a), [(STACK, -8, 6, 4), (REG, 0, 4, 0)]);
    // Extents order by space (language spaces before the stack), then offset.
    assert_eq!(extents(&s), [(REG, 0, 3), (STACK, -8, -1)]);
    // A pool near the top of the 32-bit signed stack domain: the second slot
    // would leave the domain, which is refused rather than wrapped.
    let r = plan(
        &(regs(&["r0"], 4, "general") + &stack(1, 16, 4, 0x7fff_fffc)),
        LE,
    );
    let mut s = fresh(&r, IN);
    let a = join(&mut s, &r, attrs(), 8, 4);
    assert_eq!(pieces(&a)[0], (STACK, 0x7fff_fffc, 4, 4));
    let before = snapshot(&s);
    let mut after = s.clone();
    assert!(matches!(
        after.assign_join(&r, &attrs(), JoinRequest::new(4, 4), Default::default()),
        Err(JoinError::Unsupported {
            reason: "spilled stack storage leaves its address domain",
            ..
        })
    ));
    assert_eq!(snapshot(&after), before);
}

#[test]
fn aliased_storage_and_later_stack_groups_are_refused() {
    // Two join tiles share r2, which matches no earlier pool.
    let r = plan(
        &(regs(&["r0", "r1"], 4, "ptr")
            + r#"<pentry minsize="1" maxsize="8"><addr space="join" piece1="r2" piece2="r0"/></pentry>"#
            + r#"<pentry minsize="1" maxsize="8"><addr space="join" piece1="r2" piece2="r1"/></pentry>"#),
        LE,
    );
    let mut s = fresh(&r, IN);
    let before = snapshot(&s);
    assert!(matches!(
        s.assign_join(
            &r,
            &JoinAttributes {
                stack_spill: Some(false),
                ..attrs()
            },
            JoinRequest::new(16, 4),
            Default::default()
        ),
        Err(JoinError::Overlap {
            site: BindingSite::Input { entry: 3, .. },
            previous: BindingSite::Input { entry: 2, .. }
        })
    ));
    assert_eq!(snapshot(&s), before);
    // An aligned pool holding r1's bytes through r0's cursor leaves r1's own
    // group untouched; the join must not return the aliased r1.
    let list = regs(&["r0", "r1"], 4, "general")
        + r#"<pentry minsize="1" maxsize="8" align="4" storage="vector"><addr space="register" offset="0"/></pentry>"#
        + &default_stack();
    let r = plan(&list, LE);
    let mut s = fresh(&r, IN);
    for _ in 0..2 {
        s.assign_pool(
            &r,
            PoolRequest {
                entry: 2,
                size: 4,
                alignment: 1,
                justification: Justification::Default,
            },
            Default::default(),
        )
        .unwrap();
    }
    assert_eq!(s.groups()[1], FREE);
    let before = snapshot(&s);
    assert!(matches!(
        s.assign_join(&r, &attrs(), JoinRequest::new(4, 4), Default::default()),
        Err(JoinError::Overlap { .. })
    ));
    assert_eq!(snapshot(&s), before);
    // A stack pool containing earlier stack pools inherits their groups; a
    // used later group refuses the spill, a consumed first group too.
    let list = regs(&["r0", "r1"], 4, "general")
        + r#"<pentry minsize="1" maxsize="4" storage="ptr"><addr space="stack" offset="8"/></pentry>"#
        + r#"<pentry minsize="1" maxsize="4" storage="ptr"><addr space="stack" offset="12"/></pentry>"#
        + &stack(1, 16, 4, 8);
    let r = plan(&list, LE);
    assert_eq!(
        r.list(0, IN).unwrap().entries[4].groups,
        [ResourceId(2), ResourceId(3)]
    );
    let seeded = |entry| {
        let mut s = fresh(&r, IN);
        s.assign_pool(
            &r,
            PoolRequest {
                entry,
                size: 4,
                alignment: 1,
                justification: Justification::Default,
            },
            Default::default(),
        )
        .unwrap();
        s
    };
    let mut s = seeded(3);
    let before = snapshot(&s);
    assert!(matches!(
        s.assign_join(&r, &attrs(), JoinRequest::new(12, 4), Default::default()),
        Err(JoinError::GroupInUse {
            group: ResourceId(3),
            ..
        })
    ));
    assert_eq!(snapshot(&s), before);
    let mut s = seeded(2);
    let before = snapshot(&s);
    assert!(matches!(
        s.assign_join(&r, &attrs(), JoinRequest::new(12, 4), Default::default()),
        Err(JoinError::Unsupported {
            reason: "the stack pool's resource group is consumed",
            ..
        })
    ));
    assert_eq!(snapshot(&s), before);
}

/// r0, r1 and a stack pool: three bindings and three spaces, so every binding
/// or space lookup costs bits(3)+1 = 3 and an occupied lookup bits(n)+1.
fn absolute_fixture() -> CompilerResources {
    plan(&(regs(&["r0", "r1"], 4, "general") + &default_stack()), LE)
}

#[test]
fn absolute_work_charges_follow_the_documented_cost_model() {
    let r = absolute_fixture();
    assert_eq!(r.storage().bindings().len(), 3);
    assert_eq!(r.storage().register_file().spaces().len(), 3);
    // Direct full-width register query: 1 + binding 3 + pool space 3 +
    // output 1 + slice space 3 = 11. Stack two-byte query adds one gcd step.
    let direct = |entry, size| {
        place_parameter(
            r.storage(),
            input(entry),
            PlacementRequest {
                size,
                used_slots: 0,
                type_alignment: 1,
                justification: Justification::Left,
            },
            Default::default(),
        )
        .unwrap()
        .work
    };
    assert_eq!((direct(0, 4), direct(2, 2)), (11, 12));
    // 8 bytes in r0:r1. Header 1, list byte order 3+3, scan 3 entries + 2
    // tiles, stack check 3, start search 2, two consumptions 2*(2+1) = 23.
    // Each tile: placement 11 + binding 3 + span 1+3 + occupied lookup
    // (1 then 2) -> 19 and 20. Final ordering 2 pieces. Total 64.
    let mut s = fresh(&r, IN);
    let a = join(&mut s, &r, attrs(), 8, 4);
    assert_eq!(
        a.usage,
        JoinUsage {
            tiles: 2,
            examined_entries: 6,
            group_references: 3,
            group_updates: 2,
            placements: 2,
            pieces: 2,
            occupied_extents: 2,
            source_pieces: 1,
            work: 64,
        }
    );
    // 10 bytes: as above to 23, spill read 1 + stack placement 12 + write 1,
    // tiles 19 + 20, stack groups 1 + binding 3 + span 1 (the stack is not a
    // language space, so no constant-space lookup) + occupied lookup 3, final
    // 3 pieces. Total 87.
    let mut s = fresh(&r, IN);
    let a = join(&mut s, &r, attrs(), 10, 4);
    assert_eq!(
        (
            a.usage.work,
            a.usage.examined_entries,
            a.usage.group_references,
            a.usage.group_updates,
            a.usage.placements,
            a.usage.pieces
        ),
        (87, 6, 5, 3, 3, 3)
    );
    // NoFit without a spill: 1 + 6 + 5 (no stack check) + 2 + 6 = 20.
    let mut s = fresh(&r, IN);
    let a = join(
        &mut s,
        &r,
        JoinAttributes {
            stack_spill: Some(false),
            ..attrs()
        },
        10,
        4,
    );
    assert_eq!((a.usage.work, a.usage.group_updates), (20, 2));
    assert_eq!(s.groups(), [FREE, FREE, FREE]);
}

fn budget_fixture() -> (CompilerResources, AllocationState) {
    // A skipped tile, a join tile with two pieces, a cropped tile and a spill.
    let list = regs(&["r0", "r1"], 4, "ptr")
        + &reg("x4", 8, "general")
        + r#"<pentry minsize="1" maxsize="8"><addr space="join" piece1="r2" piece2="r0"/></pentry>"#
        + &reg("r5", 4, "general")
        + &default_stack();
    let r = plan(&list, LE);
    let mut s = fresh(&r, IN);
    // Hold one unrelated extent so occupied extents start nonzero.
    s.assign_pool(
        &r,
        PoolRequest {
            entry: 1,
            size: 4,
            alignment: 1,
            justification: Justification::Default,
        },
        Default::default(),
    )
    .unwrap();
    (r, s)
}

fn budget_request() -> (JoinAttributes, JoinRequest) {
    (
        JoinAttributes {
            align: Some(true),
            ..attrs()
        },
        // Alignment 16 exceeds x4's width, but zero bytes are consumed, so x4
        // starts; 23 bytes = x4 + J + r5 + 3 bytes on the stack.
        JoinRequest::new(23, 16),
    )
}

#[test]
fn every_limit_is_exact_and_one_below_fails_with_rollback() {
    let (r, base) = budget_fixture();
    let (a, request) = budget_request();
    let mut s = base.clone();
    let full = s.assign_join(&r, &a, request, Default::default()).unwrap();
    let u = full.usage;
    assert!(matches!(full.outcome, JoinOutcome::Assigned(_)));
    assert_eq!(
        (
            u.tiles,
            u.placements,
            u.pieces,
            u.occupied_extents,
            u.source_pieces
        ),
        (3, 4, 5, 6, 2)
    );
    let exact = JoinLimits {
        max_tiles: u.tiles,
        max_examined_entries: u.examined_entries,
        max_group_references: u.group_references,
        max_group_updates: u.group_updates,
        max_placements: u.placements,
        max_pieces: u.pieces,
        max_occupied_extents: u.occupied_extents,
        max_source_pieces: u.source_pieces,
        max_work: u.work,
    };
    let mut s = base.clone();
    assert_eq!(s.assign_join(&r, &a, request, exact).unwrap(), full);
    let lowered: [(&str, JoinLimits); 9] = [
        (
            "tiles",
            JoinLimits {
                max_tiles: u.tiles - 1,
                ..exact
            },
        ),
        (
            "examined entries",
            JoinLimits {
                max_examined_entries: u.examined_entries - 1,
                ..exact
            },
        ),
        (
            "group references",
            JoinLimits {
                max_group_references: u.group_references - 1,
                ..exact
            },
        ),
        (
            "group updates",
            JoinLimits {
                max_group_updates: u.group_updates - 1,
                ..exact
            },
        ),
        (
            "placements",
            JoinLimits {
                max_placements: u.placements - 1,
                ..exact
            },
        ),
        (
            "pieces",
            JoinLimits {
                max_pieces: u.pieces - 1,
                ..exact
            },
        ),
        (
            "occupied extents",
            JoinLimits {
                max_occupied_extents: u.occupied_extents - 1,
                ..exact
            },
        ),
        (
            "source pieces",
            JoinLimits {
                max_source_pieces: u.source_pieces - 1,
                ..exact
            },
        ),
        (
            "work",
            JoinLimits {
                max_work: u.work - 1,
                ..exact
            },
        ),
    ];
    for (name, limits) in lowered {
        let mut s = base.clone();
        let before = snapshot(&s);
        match s.assign_join(&r, &a, request, limits) {
            Err(JoinError::Limit(resource)) => assert_eq!(resource, name),
            other => panic!("{name}: {other:?}"),
        }
        assert_eq!(snapshot(&s), before, "{name}");
    }
    // Every lower work budget fails with the same classification.
    for work in 0..u.work {
        let mut s = base.clone();
        let before = snapshot(&s);
        assert!(
            matches!(
                s.assign_join(
                    &r,
                    &a,
                    request,
                    JoinLimits {
                        max_work: work,
                        ..exact
                    }
                ),
                Err(JoinError::Limit("work"))
            ),
            "work {work}"
        );
        assert_eq!(snapshot(&s), before);
    }
    // Nested placement output exhaustion has the same classification.
    let r2 = plan(&join_tiles(), LE);
    let mut s = fresh(&r2, IN);
    assert!(matches!(
        s.assign_join(
            &r2,
            &JoinAttributes {
                stack_spill: Some(false),
                ..attrs()
            },
            JoinRequest::new(8, 4),
            JoinLimits {
                max_pieces: 1,
                ..Default::default()
            }
        ),
        Err(JoinError::Limit("pieces"))
    ));
    assert_eq!(s.groups(), [FREE, FREE]);
    // Held extents equal to the limit are accepted on entry (here a NoFit).
    let mut s = base.clone();
    assert!(matches!(
        s.assign_join(
            &r,
            &JoinAttributes {
                stack_spill: Some(false),
                ..attrs()
            },
            JoinRequest::new(64, 4),
            JoinLimits {
                max_occupied_extents: 1,
                ..Default::default()
            }
        )
        .unwrap()
        .outcome,
        JoinOutcome::NoFit(JoinNoFit::StackSpillDisabled { .. })
    ));
    // Already-held extents are bounded on entry, even for a later NoFit.
    let mut s = base.clone();
    assert!(matches!(
        s.assign_join(
            &r,
            &a,
            request,
            JoinLimits {
                max_occupied_extents: 0,
                ..Default::default()
            }
        ),
        Err(JoinError::Limit("occupied extents"))
    ));
}

#[test]
fn budget_fixture_result_is_the_hand_derived_recipe() {
    let (r, mut s) = budget_fixture();
    let (a, request) = budget_request();
    let result = s.assign_join(&r, &a, request, Default::default()).unwrap();
    // Consumption x4 (8), J = r2:r0 (8), r5 (4), stack 3 bytes; LE reverses
    // the steps to stack, r5, J (r2 then r0), x4.
    assert_eq!(
        pieces(&result),
        [
            (STACK, 8, 3, 20),
            (REG, 20, 4, 16),
            (REG, 8, 4, 12),
            (REG, 0, 4, 8),
            (REG, 0xa0, 8, 0)
        ]
    );
    assert_eq!(assigned(&result).skipped_tiles, 0);
    // Groups: r0 (shared by J), r1 (seeded), x4, r5, stack.
    assert_eq!(
        s.groups(),
        [
            USED,
            USED,
            USED,
            USED,
            GroupState::Available { used_slots: 1 }
        ]
    );
}

#[test]
fn work_scales_linearly_with_large_tile_lists() {
    let measure = |count: u64| {
        let mut list = String::new();
        for i in 0..count {
            list.push_str(&format!(
                r#"<pentry minsize="1" maxsize="4"><addr space="register" offset="{:#x}"/></pentry>"#,
                0x1000 + 4 * i
            ));
        }
        list.push_str(&default_stack());
        let source = common::parse(&format!(
            r#"<compiler_spec><stackpointer register="sp" space="ram"/>
<default_proto><prototype name="p" extrapop="0" stackshift="0"><input>{list}</input><output/></prototype></default_proto></compiler_spec>"#
        ));
        let file = Arc::new(
            RegisterFile::new(
                common::spaces(4),
                common::RAM,
                registers(),
                Default::default(),
            )
            .unwrap(),
        );
        let storage = common::storage(source, &file, Default::default()).unwrap();
        let r = CompilerResources::new(
            Arc::new(storage),
            ResourceLimits {
                max_work: u64::MAX,
                ..Default::default()
            },
        )
        .unwrap();
        // Consume all but the final tile so the start search scans the list.
        let mut s = fresh(&r, IN);
        let all = join(&mut s, &r, attrs(), (4 * (count - 1)) as u32, 1);
        assert_eq!(assigned(&all).steps.len() as u64, count - 1);
        let last = join(&mut s, &r, attrs(), 4, 1);
        assert_eq!(assigned(&last).skipped_tiles as u64, count - 1);
        (all.usage.work, last.usage.work)
    };
    let (small_all, small_last) = measure(1000);
    let (large_all, large_last) = measure(4000);
    let all = large_all as f64 / small_all as f64;
    let last = large_last as f64 / small_last as f64;
    // Logarithmic binding/extent lookups make the consume-all ratio
    // slightly above four.
    assert!((3.9..4.8).contains(&all), "consume all {all}");
    assert!((3.9..4.3).contains(&last), "scan {last}");
}

#[test]
fn results_are_owned_deterministic_and_thread_safe() {
    fn send_sync<T: Send + Sync + Clone>() {}
    send_sync::<JoinAssignment>();
    send_sync::<JoinAttributes>();
    send_sync::<AllocationState>();
    let (r, base) = budget_fixture();
    let (a, request) = budget_request();
    let results: Vec<_> = (0..4)
        .map(|_| {
            let mut s = base.clone();
            (
                s.assign_join(&r, &a, request, Default::default()).unwrap(),
                snapshot(&s),
            )
        })
        .collect();
    assert!(results.windows(2).all(|w| w[0] == w[1]));
    let shared = Arc::new(r);
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let shared = shared.clone();
            let mut s = base.clone();
            std::thread::spawn(move || {
                s.assign_join(&shared, &a, request, Default::default())
                    .unwrap()
            })
        })
        .collect();
    for handle in handles {
        assert_eq!(handle.join().unwrap(), results[0].0);
    }
}
