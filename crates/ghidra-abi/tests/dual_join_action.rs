//! Hand-derived expectations for the native `<join_dual_class>` action
//! (`MultiSlotDualAssign`, modelrules.cc:1213-1470: `initializeEntries`,
//! `getFirstUnused`, `getTileClass`, `assignAddress`, `decode`;
//! `justifyPieces` at :742), `metatype2typeclass` (type.cc:304) and fspec.cc
//! `getAddrBySlot`, `extractTiles`, `getStackEntry` and
//! `assignAddressFromPieces`. Primitives come from the converted native graph
//! (`PrimitiveExtractor(dt,false,false,0,1024)`).
//!
//! Registers are fixture-owned: x0..x7 (general by declaration) at
//! 0x80+8i, d0..d7 at 0x200+8i, p0..p3 at 0x300+8i (8 bytes); r0..r7 at 4i
//! (4 bytes); q0/q1 at 0x400/0x410 and v0/v1 at 0x500/0x510 (16 bytes);
//! e0/n0 at 0x600/0x640 (10 bytes); m0/k0 at 0x620/0x660 (12 bytes); sp at
//! 0x40. The stack is in a 4-byte ram space.
mod common;
mod native_common;

use std::sync::Arc;

use ghidra_abi::*;
use ghidra_languages::{DataOrganization, MetaType, RuleAction, SizeAlignment, StorageClass as C};
use ghidra_pcode::{Endianness, SpaceKind};
use ghidra_types::{Builtin, Field, MinimumAlignment, Packing, TypeId, TypeKind};
use native_common::Source;

const IN: ParameterDirection = ParameterDirection::Input;
const OUT: ParameterDirection = ParameterDirection::Output;
const REG: AbiSpace = AbiSpace::Language(common::REGISTER);
const STACK: AbiSpace = AbiSpace::Stack;
const FREE: GroupState = GroupState::Available { used_slots: 0 };
const USED: GroupState = GroupState::Consumed;

fn registers() -> Vec<RegisterDefinition> {
    let mut out = Vec::new();
    let mut add = |name: String, offset: u64, size: u32| {
        out.push(common::register(&name, common::REGISTER, offset, size));
    };
    for i in 0..8_u64 {
        add(format!("x{i}"), 0x80 + 8 * i, 8);
        add(format!("d{i}"), 0x200 + 8 * i, 8);
        add(format!("r{i}"), 4 * i, 4);
    }
    for i in 0..4_u64 {
        add(format!("p{i}"), 0x300 + 8 * i, 8);
    }
    for i in 0..2_u64 {
        add(format!("q{i}"), 0x400 + 16 * i, 16);
        add(format!("v{i}"), 0x500 + 16 * i, 16);
    }
    add("e0".into(), 0x600, 10);
    add("n0".into(), 0x640, 10);
    add("m0".into(), 0x620, 12);
    add("k0".into(), 0x660, 12);
    add("sp".into(), 0x40, 4);
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

/// d0..d3 (float), x0..x3 (general), an 8-aligned stack at 16: entries 0..8.
fn mixed() -> String {
    regs(&["d0", "d1", "d2", "d3"], 8, "float")
        + &regs(&["x0", "x1", "x2", "x3"], 8, "general")
        + &stack(1, 500, 8, 16)
}

fn fresh(r: &CompilerResources, direction: ParameterDirection) -> AllocationState {
    AllocationState::new(r, 0, direction, Default::default()).unwrap()
}

fn attrs() -> DualJoinAttributes {
    DualJoinAttributes::default()
}
fn spill() -> DualJoinAttributes {
    DualJoinAttributes {
        stack_spill: Some(true),
        ..attrs()
    }
}

fn graph(t: &Source, big: bool) -> Arc<NativeTypeGraph> {
    let order = if big {
        Endianness::Big
    } else {
        Endianness::Little
    };
    native_common::bridge(t.layouts_with(native_common::organization(), order))
}

fn nid(ty: TypeId) -> NativeTypeId {
    native_common::id(ty)
}

fn dual(
    s: &mut AllocationState,
    r: &CompilerResources,
    a: DualJoinAttributes,
    g: &Arc<NativeTypeGraph>,
    ty: TypeId,
) -> DualJoinAssignment {
    s.assign_dual_join(r, &a, g.clone(), nid(ty), Default::default())
        .unwrap()
}

fn assigned(a: &DualJoinAssignment) -> &DualJoinAllocation {
    match &a.outcome {
        DualJoinOutcome::Assigned(allocation) => allocation,
        other => panic!("not assigned: {other:?}"),
    }
}

fn no_fit(a: &DualJoinAssignment) -> DualJoinNoFit {
    match &a.outcome {
        DualJoinOutcome::NoFit(reason) => *reason,
        other => panic!("not a no-fit: {other:?}"),
    }
}

/// (space, signed offset, size, lsb) most significant first.
type Piece = (AbiSpace, i64, u32, u32);

fn pieces(a: &DualJoinAssignment) -> Vec<Piece> {
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

/// (kind, offset, bytes, first primitive, primitive end) per step.
type Step = (DualJoinStepKind, u32, u32, usize, usize);

fn steps(a: &DualJoinAssignment) -> Vec<Step> {
    assigned(a)
        .steps
        .iter()
        .map(|s| {
            (
                s.kind,
                s.offset,
                s.bytes,
                s.first_primitive,
                s.primitive_end,
            )
        })
        .collect()
}

fn tile(class: DualClass, tile: usize) -> DualJoinStepKind {
    DualJoinStepKind::Tile { class, tile }
}
const BASE: DualClass = DualClass::Base;
const ALT: DualClass = DualClass::Alternate;

fn snapshot(s: &AllocationState) -> (Vec<GroupState>, Vec<OccupiedExtent>) {
    (s.groups().to_vec(), s.occupied().collect())
}

fn extents(s: &AllocationState) -> Vec<(AbiSpace, i128, i128)> {
    s.occupied().map(|e| (e.space, e.first, e.last)).collect()
}

#[test]
fn defaults_follow_the_constructor_and_toggle_only_on_true() {
    let mut t = Source::default();
    let long = t.int(8, true);
    let output = reg("d0", 8, "float") + &reg("x0", 8, "general");
    for (layout, big) in [(LE, false), (BE, true)] {
        let r = plan_with(&mixed(), &output, layout);
        let g = graph(&t, big);
        let expected = DualJoinConfig {
            base: C::General,
            alternate: C::Float,
            big_endian: big,
            // Unlike <join>, neither input nor output lists spill by default.
            consume_from_stack: false,
            consume_most_significant: big,
            justify_right: big,
            fill_alternate: false,
            tile_size: 8,
        };
        for direction in [IN, OUT] {
            let a = dual(&mut fresh(&r, direction), &r, attrs(), &g, long);
            assert_eq!(a.config, expected);
        }
        let declared_false = DualJoinAttributes {
            reverse_justify: Some(false),
            reverse_significance: Some(false),
            stack_spill: Some(false),
            fill_alternate: Some(false),
            ..attrs()
        };
        let a = dual(&mut fresh(&r, IN), &r, declared_false, &g, long);
        assert_eq!(a.config, expected);
        let declared_true = DualJoinAttributes {
            storage_a: Some(C::Float),
            storage_b: Some(C::General),
            reverse_justify: Some(true),
            reverse_significance: Some(true),
            stack_spill: Some(true),
            fill_alternate: Some(true),
        };
        let a = dual(&mut fresh(&r, IN), &r, declared_true, &g, long);
        assert_eq!(
            a.config,
            DualJoinConfig {
                base: C::Float,
                alternate: C::General,
                consume_from_stack: true,
                consume_most_significant: !big,
                justify_right: !big,
                fill_alternate: true,
                ..expected
            }
        );
        // The swapped classes put the long (general == alternate) in x0.
        assert_eq!(pieces(&a), [(REG, 0x80, 8, 0)]);
    }
}

#[test]
fn parsed_join_dual_class_attributes_are_adapted() {
    let rules = r#"<rule><datatype name="any"/><join_dual_class a="general" b="float" reversejustify="true" reversesignif="false" stackspill="true" fillalternate="true"/></rule>
<rule><datatype name="any"/><join_dual_class storage="ptr"/></rule>
<rule><datatype name="any"/><join_dual_class/></rule>
<rule><datatype name="any"/><join/></rule>"#;
    let r = plan(&(mixed() + rules), LE);
    let actions: Vec<_> = r.storage().source().prototypes[0]
        .input
        .rules
        .iter()
        .map(|rule| DualJoinAttributes::from_action(&rule.action))
        .collect();
    assert_eq!(
        actions,
        [
            Some(DualJoinAttributes {
                storage_a: Some(C::General),
                storage_b: Some(C::Float),
                reverse_justify: Some(true),
                reverse_significance: Some(false),
                stack_spill: Some(true),
                fill_alternate: Some(true),
            }),
            Some(DualJoinAttributes {
                storage_a: Some(C::Ptr),
                ..attrs()
            }),
            Some(attrs()),
            None,
        ]
    );
    assert_eq!(
        DualJoinAttributes::from_action(&RuleAction::GotoStack),
        None
    );
}

#[test]
fn each_window_chooses_its_class_and_lists_advance_independently() {
    let mut t = Source::default();
    let double = t.float(8);
    let long = t.int(8, true);
    let float = t.float(4);
    let int = t.int(4, true);
    let dl = t.structure(&[double, long]);
    let ld = t.structure(&[long, double]);
    let ffii = t.structure(&[float, float, int, int]);
    let fi = t.structure(&[float, int]);
    let g = graph(&t, false);
    let r = plan(&mixed(), LE);
    let mut s = fresh(&r, IN);
    // {double, long}: window [0,8) holds only the double (float == alt): d0.
    // Window [8,16) holds the long: x0. Little endian reverses: x0 is most
    // significant.
    let a = dual(&mut s, &r, attrs(), &g, dl);
    assert_eq!(pieces(&a), [(REG, 0x80, 8, 8), (REG, 0x200, 8, 0)]);
    assert_eq!(
        steps(&a),
        [(tile(ALT, 0), 0, 8, 0, 1), (tile(BASE, 0), 8, 8, 1, 2)]
    );
    assert_eq!(
        a.primitives
            .iter()
            .map(|p| (p.ty, p.offset, p.meta))
            .collect::<Vec<_>>(),
        [
            (nid(double), 0, MetaType::Float),
            (nid(long), 8, MetaType::Int)
        ]
    );
    assert_eq!(
        s.groups(),
        [USED, FREE, FREE, FREE, USED, FREE, FREE, FREE, FREE]
    );
    // {long, double}: each list resumes after its own consumed tile.
    let a = dual(&mut s, &r, attrs(), &g, ld);
    assert_eq!(pieces(&a), [(REG, 0x208, 8, 8), (REG, 0x88, 8, 0)]);
    assert_eq!(
        steps(&a),
        [(tile(BASE, 1), 0, 8, 0, 1), (tile(ALT, 1), 8, 8, 1, 2)]
    );
    // {float, float, int, int}: two floats share window 0 (d2), two ints
    // window 8 (x2).
    let a = dual(&mut s, &r, attrs(), &g, ffii);
    assert_eq!(pieces(&a), [(REG, 0x90, 8, 8), (REG, 0x210, 8, 0)]);
    assert_eq!(
        steps(&a),
        [(tile(ALT, 2), 0, 8, 0, 2), (tile(BASE, 2), 8, 8, 2, 4)]
    );
    // {float, int}: one general primitive makes the whole window base.
    let a = dual(&mut s, &r, attrs(), &g, fi);
    assert_eq!(pieces(&a), [(REG, 0x98, 8, 0)]);
    assert_eq!(
        s.groups(),
        [USED, USED, USED, FREE, USED, USED, USED, USED, FREE]
    );
    // Whole registers are held, never only the value's bytes.
    assert_eq!(
        extents(&s),
        [
            (REG, 0x80, 0x87),
            (REG, 0x88, 0x8f),
            (REG, 0x90, 0x97),
            (REG, 0x98, 0x9f),
            (REG, 0x200, 0x207),
            (REG, 0x208, 0x20f),
            (REG, 0x210, 0x217)
        ]
    );
    assert_eq!(a.usage.base_tiles, 4);
    assert_eq!(a.usage.alternate_tiles, 4);
}

#[test]
fn metatype_classes_follow_metatype2typeclass() {
    let mut t = Source::default();
    let double = t.float(8);
    let void = t.add(TypeKind::Void);
    let pointer = t.add(TypeKind::Pointer {
        target: double,
        bytes: None,
    });
    let opaque = t.opaque(8);
    let flag = t.add(TypeKind::Builtin(Builtin::Bool));
    let enumeration = t.add(TypeKind::Enum {
        bytes: 4,
        signed: false,
    });
    let code = t.add(TypeKind::Function {
        result: void,
        parameters: vec![],
        variadic: false,
    });
    let pd = t.structure(&[pointer, double]);
    let od = t.structure(&[opaque, double]);
    let fe = t.structure(&[flag, enumeration]);
    let alias = t.alias(double);
    let ad = t.structure(&[alias, double]);
    let g = graph(&t, false);
    // Preconditions from the approved conversion: native meta-types.
    let meta = |ty| g.get(nid(ty)).unwrap().meta;
    assert_eq!(
        [
            meta(pointer),
            meta(opaque),
            meta(flag),
            meta(enumeration),
            meta(code),
            meta(alias)
        ],
        [
            MetaType::Ptr,
            MetaType::Unknown,
            MetaType::Bool,
            MetaType::Uint,
            MetaType::Code,
            MetaType::Float
        ]
    );
    let list = reg("d0", 8, "float") + &reg("p0", 8, "ptr") + &regs(&["x0", "x1"], 8, "general");
    let r = plan(&list, LE);
    let run = |a, ty| {
        let mut s = fresh(&r, IN);
        pieces(&dual(&mut s, &r, a, &g, ty))
    };
    // A pointer is TYPECLASS_PTR: base against a float alternate...
    assert_eq!(run(attrs(), pd), [(REG, 0x200, 8, 8), (REG, 0x80, 8, 0)]);
    // ...and the alternate itself when b="ptr" (the double is then base).
    let ptr_alt = DualJoinAttributes {
        storage_b: Some(C::Ptr),
        ..attrs()
    };
    assert_eq!(run(ptr_alt, pd), [(REG, 0x80, 8, 8), (REG, 0x300, 8, 0)]);
    // Unknown is general, and containsUnknown does not reject the value.
    assert_eq!(run(attrs(), od), [(REG, 0x200, 8, 8), (REG, 0x80, 8, 0)]);
    // Bool and enum (Uint) are general.
    assert_eq!(run(attrs(), fe), [(REG, 0x80, 8, 0)]);
    // An alias keeps its target's Float meta-type and its own identity.
    let mut s = fresh(&r, IN);
    let a = dual(&mut s, &r, attrs(), &g, ad);
    assert_eq!(a.primitives[0].ty, nid(alias));
    // Window [0,8) is the alias (alt), [8,16) the double: d0 then exhausted.
    assert_eq!(
        no_fit(&a),
        DualJoinNoFit::Exhausted {
            class: ALT,
            offset: 8,
            uncovered: 8
        }
    );
    // Code is a one-byte general primitive; the 8-byte tile keeps its first
    // byte (little endian, left justified).
    let mut s = fresh(&r, IN);
    let a = dual(&mut s, &r, attrs(), &g, code);
    assert_eq!(pieces(&a), [(REG, 0x80, 1, 0)]);
    assert_eq!(assigned(&a).excess, 7);
    assert_eq!(extents(&s), [(REG, 0x80, 0x87)]);
}

#[test]
fn union_member_flags_are_dropped_so_unaligned_members_are_accepted() {
    let mut t = Source::default();
    let byte = t.int(1, false);
    let word = t.int(4, false);
    let packed = t.packed(&[byte, word]);
    let union = t.union(&[packed]);
    let double = t.float(8);
    let long = t.int(8, true);
    let dl = t.union(&[double, long]);
    let ld = t.union(&[long, double]);
    let only = t.union(&[double]);
    let g = graph(&t, false);
    let r = plan(&mixed(), LE);
    // Packed {u8, u32} at the root is unaligned with a hole: NoFit.
    let mut s = fresh(&r, IN);
    let a = dual(&mut s, &r, attrs(), &g, packed);
    assert_eq!(no_fit(&a), DualJoinNoFit::Holes);
    assert_eq!(a.primitives.len(), 2);
    // As a union member its flags are dropped (handleUnion); the union's 5
    // bytes go to x0 with 3 excess bytes. Unions are legal here.
    let a = dual(&mut s, &r, attrs(), &g, union);
    assert_eq!(pieces(&a), [(REG, 0x80, 5, 0)]);
    // commonRefinement: a float yields to the overlapping long, a long is
    // kept over the double; both refine to the general long.
    for ty in [dl, ld] {
        let mut s = fresh(&r, IN);
        let a = dual(&mut s, &r, attrs(), &g, ty);
        assert_eq!(a.primitives[0].ty, nid(long));
        assert_eq!(pieces(&a), [(REG, 0x80, 8, 0)]);
    }
    let mut s = fresh(&r, IN);
    assert_eq!(
        pieces(&dual(&mut s, &r, attrs(), &g, only)),
        [(REG, 0x200, 8, 0)]
    );
}

#[test]
fn fill_alternate_needs_one_primitive_of_exactly_the_tile_size() {
    let mut t = Source::default();
    let float = t.float(4);
    let double = t.float(8);
    let ff = t.structure(&[float, float]);
    let dff = t.structure(&[double, float, float]);
    let g = graph(&t, false);
    let r = plan(&mixed(), LE);
    let fill = DualJoinAttributes {
        fill_alternate: Some(true),
        ..attrs()
    };
    let run = |a, ty| {
        let mut s = fresh(&r, IN);
        pieces(&dual(&mut s, &r, a, &g, ty))
    };
    // Two 4-byte floats: alternate without fill, base with it (count 2).
    assert_eq!(run(attrs(), ff), [(REG, 0x200, 8, 0)]);
    assert_eq!(run(fill, ff), [(REG, 0x80, 8, 0)]);
    // One 4-byte float: alternate without fill, base with it (4 != 8). The
    // tile is cropped to the low four bytes either way.
    assert_eq!(run(attrs(), float), [(REG, 0x200, 4, 0)]);
    assert_eq!(run(fill, float), [(REG, 0x80, 4, 0)]);
    // One full-width double is alternate in both modes.
    assert_eq!(run(fill, double), [(REG, 0x200, 8, 0)]);
    // {double, float, float}: d0 then d1 without fill, d0 then x0 with it.
    assert_eq!(run(attrs(), dff), [(REG, 0x208, 8, 8), (REG, 0x200, 8, 0)]);
    assert_eq!(run(fill, dff), [(REG, 0x80, 8, 8), (REG, 0x200, 8, 0)]);
}

#[test]
fn raw_sizes_not_aligned_sizes_drive_windows_fill_and_the_value_size() {
    let mut t = Source::default();
    let f10 = t.float(10);
    let wrapped = t.structure(&[f10]);
    let g = graph(&t, false);
    // Preconditions: a 10-byte float has raw size 10, aligned size 16 and
    // alignment 8 (floor map entry 8); its structure is 16 bytes.
    let native = g.get(nid(f10)).unwrap();
    assert_eq!(
        (native.size, native.aligned_size, native.alignment),
        (10, 16, 8)
    );
    assert_eq!(g.get(nid(wrapped)).unwrap().size, 16);
    let run = |list: &str, a, ty| {
        let r = plan(list, LE);
        let mut s = fresh(&r, IN);
        dual(&mut s, &r, a, &g, ty)
    };
    let fill = DualJoinAttributes {
        fill_alternate: Some(true),
        ..attrs()
    };
    // 16-byte tiles: the value is 10 raw bytes, so v0 is cropped by 6.
    let a = run(
        &(reg("v0", 16, "float") + &reg("q0", 16, "general")),
        attrs(),
        f10,
    );
    assert_eq!(pieces(&a), [(REG, 0x500, 10, 0)]);
    assert_eq!((assigned(&a).size, assigned(&a).excess), (10, 6));
    // 10-byte tiles with fill: the raw size equals the tile size.
    let a = run(
        &(reg("e0", 10, "float") + &reg("n0", 10, "general")),
        fill,
        f10,
    );
    assert_eq!(pieces(&a), [(REG, 0x600, 10, 0)]);
    // 12-byte tiles: the raw extent ends at 10 <= 12 (the aligned one at 16
    // would cross). Without fill it is alternate; with fill, base (10 != 12).
    let list = reg("m0", 12, "float") + &reg("k0", 12, "general");
    assert_eq!(pieces(&run(&list, attrs(), f10)), [(REG, 0x620, 10, 0)]);
    assert_eq!(pieces(&run(&list, fill, f10)), [(REG, 0x660, 10, 0)]);
    // 8-byte tiles: the raw extent [0,10) crosses the first window.
    let a = run(&mixed(), attrs(), wrapped);
    assert_eq!(
        no_fit(&a),
        DualJoinNoFit::Window {
            offset: 0,
            rejection: DualTileRejection::CrossesWindow { primitive: 0 }
        }
    );
}

#[test]
fn holes_empty_invalid_and_the_1024_primitive_maximum_are_no_fits() {
    let mut t = Source::default();
    let word = t.int(4, false);
    let float = t.float(4);
    let holey = t.with_fields(
        vec![Field::bitfield("b", word, 3), Field::new("f", float)],
        Packing::Default,
        MinimumAlignment::Default,
        false,
    );
    let opaque16 = t.opaque(16);
    let empty = t.structure(&[]);
    let void = t.add(TypeKind::Void);
    let empty_union = t.union(&[]);
    let half = t.int(2, false);
    let skewed = t.packed(&[half, word]);
    let incompatible = t.union(&[word, skewed]);
    let byte = t.int(1, false);
    let at_max = t.array(byte, 1024);
    let over_max = t.array(byte, 1025);
    let g = graph(&t, false);
    let r = plan(&mixed(), LE);
    let mut s = fresh(&r, IN);
    let before = snapshot(&s);
    let mut check = |ty, expected| {
        let a = dual(&mut s, &r, attrs(), &g, ty);
        assert_eq!(no_fit(&a), expected);
        a
    };
    // A non-byte bitfield is invisible to extraction and leaves a hole.
    let a = check(holey, DualJoinNoFit::Holes);
    assert_eq!(a.primitives.len(), 1);
    check(opaque16, DualJoinNoFit::NoPrimitives);
    check(empty, DualJoinNoFit::NoPrimitives);
    check(
        void,
        DualJoinNoFit::InvalidExtraction(NativeInvalidExtraction::Unsupported {
            ty: nid(void),
            meta: MetaType::Void,
        }),
    );
    check(
        empty_union,
        DualJoinNoFit::InvalidExtraction(NativeInvalidExtraction::EmptyUnion(nid(empty_union))),
    );
    // The packed member's u32 at 2 ends past the other member's u32 at 0.
    check(
        incompatible,
        DualJoinNoFit::InvalidExtraction(NativeInvalidExtraction::IncompatibleUnion {
            union: nid(incompatible),
            big_offset: 0,
            big_aligned_size: 4,
            small_offset: 2,
            small_aligned_size: 4,
        }),
    );
    // 1024 primitives are valid: four 8-byte base windows, then exhausted.
    let a = check(
        at_max,
        DualJoinNoFit::Exhausted {
            class: BASE,
            offset: 32,
            uncovered: 992,
        },
    );
    assert_eq!(a.primitives.len(), 1024);
    check(
        over_max,
        DualJoinNoFit::InvalidExtraction(NativeInvalidExtraction::MaxPrimitives { maximum: 1024 }),
    );
    assert_eq!(snapshot(&s), before);
}

#[test]
fn window_rejections_follow_get_tile_class() {
    let mut t = Source::default();
    let long = t.int(8, true);
    let int = t.int(4, true);
    let opaque16 = t.opaque(16);
    let gap = t.structure(&[long, int, int, opaque16, long]);
    let tail = t.structure(&[long, opaque16]);
    let four = t.structure(&[long, long, long, long]);
    let g = graph(&t, false);
    let r = plan(&mixed(), LE);
    let mut s = fresh(&r, IN);
    let before = snapshot(&s);
    // {long, int, int, opaque16, long}: windows 0 and 8 succeed; the long at
    // 32 does not start in [16,24).
    assert_eq!(
        no_fit(&dual(&mut s, &r, attrs(), &g, gap)),
        DualJoinNoFit::Window {
            offset: 16,
            rejection: DualTileRejection::EmptyWindow
        }
    );
    // {long, opaque16}: nothing is left for window 8.
    assert_eq!(
        no_fit(&dual(&mut s, &r, attrs(), &g, tail)),
        DualJoinNoFit::Window {
            offset: 8,
            rejection: DualTileRejection::NoPrimitiveLeft
        }
    );
    assert_eq!(snapshot(&s), before);
    // A 16-byte second base tile advances the offset to 24, past the third
    // long at 16, which was never classified: it starts before the window.
    let list = reg("x0", 8, "general")
        + &reg("q0", 16, "general")
        + &regs(&["x1", "x2"], 8, "general")
        + &reg("d0", 8, "float");
    let r = plan(&list, LE);
    let mut s = fresh(&r, IN);
    assert_eq!(
        no_fit(&dual(&mut s, &r, attrs(), &g, four)),
        DualJoinNoFit::Window {
            offset: 24,
            rejection: DualTileRejection::StartsBeforeWindow { primitive: 2 }
        }
    );
    assert_eq!(s.groups(), [FREE; 5]);
}

#[test]
fn later_tiles_of_other_widths_advance_by_their_own_width() {
    let mut t = Source::default();
    let long = t.int(8, true);
    let int = t.int(4, true);
    let double = t.float(8);
    let value = t.structure(&[long, int, int, int, int]);
    let three = t.structure(&[double, double, double]);
    let g = graph(&t, false);
    // Base: x0 (8), r1 (4), x2, x3; the first base and alternate are 8 bytes.
    let list = reg("x0", 8, "general")
        + &reg("r1", 4, "general")
        + &regs(&["x2", "x3"], 8, "general")
        + &reg("d0", 8, "float")
        + &reg("v0", 16, "float");
    let r = plan(&list, LE);
    let mut s = fresh(&r, IN);
    // Windows [0,8) long -> x0; [8,16) two ints -> r1 (4 bytes), so the
    // next window is [12,20): the int at 16 (the int at 12 was already
    // classified) -> x2; then [20,28): the int at 20 -> x3. 8+4+8+8 = 28
    // covers 24 bytes with 4 excess, cropped from x3's end.
    let a = dual(&mut s, &r, attrs(), &g, value);
    assert_eq!(
        steps(&a),
        [
            (tile(BASE, 0), 0, 8, 0, 1),
            (tile(BASE, 1), 8, 4, 1, 3),
            (tile(BASE, 2), 12, 8, 3, 4),
            (tile(BASE, 3), 20, 4, 4, 5)
        ]
    );
    assert_eq!(
        pieces(&a),
        [
            (REG, 0x98, 4, 20),
            (REG, 0x90, 8, 12),
            (REG, 0x4, 4, 8),
            (REG, 0x80, 8, 0)
        ]
    );
    assert_eq!(assigned(&a).excess, 4);
    // A wider later alternate: d0 then v0 (16 bytes) covers the second and
    // third doubles; the third is never classified.
    let mut s = fresh(&r, IN);
    let a = dual(&mut s, &r, attrs(), &g, three);
    assert_eq!(
        steps(&a),
        [(tile(ALT, 0), 0, 8, 0, 1), (tile(ALT, 1), 8, 16, 1, 2)]
    );
    assert_eq!(pieces(&a), [(REG, 0x500, 16, 8), (REG, 0x200, 8, 0)]);
}

#[test]
fn byte_order_significance_and_justification_matrix() {
    let mut t = Source::default();
    let int = t.int(4, true);
    let three = t.structure(&[int, int, int]);
    let list = reg("d0", 8, "float") + &regs(&["x0", "x1"], 8, "general");
    // Windows [0,8) and [8,16) are both base: x0 then x1, 4 excess bytes.
    // consume_most_significant = big ^ rs, justify_right = big ^ rj; the
    // crop is x0 when justifying right, else x1, and starts 4 bytes in iff
    // big ^ cms ^ jr. Pieces are consumption order iff cms.
    let cases: [(bool, bool, bool, [Piece; 2]); 8] = [
        (false, false, false, [(REG, 0x88, 4, 8), (REG, 0x80, 8, 0)]),
        (false, false, true, [(REG, 0x88, 8, 4), (REG, 0x84, 4, 0)]),
        (false, true, false, [(REG, 0x80, 8, 4), (REG, 0x8c, 4, 0)]),
        (false, true, true, [(REG, 0x80, 4, 8), (REG, 0x88, 8, 0)]),
        (true, false, false, [(REG, 0x84, 4, 8), (REG, 0x88, 8, 0)]),
        (true, false, true, [(REG, 0x80, 8, 4), (REG, 0x88, 4, 0)]),
        (true, true, false, [(REG, 0x88, 8, 4), (REG, 0x80, 4, 0)]),
        (true, true, true, [(REG, 0x8c, 4, 8), (REG, 0x80, 8, 0)]),
    ];
    for (big, rs, rj, expected) in cases {
        let r = plan(&list, if big { BE } else { LE });
        let g = graph(&t, big);
        let a = DualJoinAttributes {
            reverse_significance: Some(rs),
            reverse_justify: Some(rj),
            ..attrs()
        };
        let mut s = fresh(&r, IN);
        let result = dual(&mut s, &r, a, &g, three);
        assert_eq!(pieces(&result), expected, "big {big} rs {rs} rj {rj}");
        let cropped = if big ^ rj { 0 } else { 1 };
        assert_eq!(assigned(&result).steps[cropped].bytes, 4);
        // Whole tiles are held regardless of the crop.
        assert_eq!(extents(&s), [(REG, 0x80, 0x87), (REG, 0x88, 0x8f)]);
    }
}

#[test]
fn byte_order_is_the_first_entrys_space_and_must_match_the_graph() {
    let mut t = Source::default();
    let int = t.int(4, true);
    let three = t.structure(&[int, int, int]);
    let list = reg("d0", 8, "float") + &regs(&["x0", "x1"], 8, "general");
    let mixed_order = Layout {
        register_big: true,
        ram_big: false,
        positive: false,
    };
    // Big-endian registers in a little-endian (default-space) language: the
    // graph is little endian, but the list's first entry is a register.
    let r = plan(&list, mixed_order);
    let mut s = fresh(&r, IN);
    let a = dual(&mut s, &r, attrs(), &graph(&t, false), three);
    assert!(a.config.big_endian && a.config.consume_most_significant);
    assert_eq!(pieces(&a), [(REG, 0x84, 4, 8), (REG, 0x88, 8, 0)]);
    // A first entry on the (little-endian) stack makes the list little endian.
    let first = r#"<pentry minsize="1" maxsize="8" storage="ptr"><addr space="stack" offset="64"/></pentry>"#;
    let r = plan(&(first.to_string() + &list), mixed_order);
    let mut s = fresh(&r, IN);
    let a = dual(&mut s, &r, attrs(), &graph(&t, false), three);
    assert!(!a.config.big_endian);
    assert_eq!(pieces(&a), [(REG, 0x88, 4, 8), (REG, 0x80, 8, 0)]);
    // A graph laid out big endian does not describe this language.
    let mut s = fresh(&r, IN);
    let before = snapshot(&s);
    assert!(matches!(
        s.assign_dual_join(
            &r,
            &attrs(),
            graph(&t, true),
            nid(three),
            Default::default()
        ),
        Err(DualJoinError::ByteOrderMismatch {
            graph: Endianness::Big,
            language: Endianness::Little
        })
    ));
    assert_eq!(snapshot(&s), before);
}

#[test]
fn an_exhausted_class_spills_the_whole_suffix_or_fails() {
    let mut t = Source::default();
    let double = t.float(8);
    let long = t.int(8, true);
    let f10 = t.float(10);
    let doubles = t.structure(&[double, double, double, double]);
    let longs = t.structure(&[long, long, long, long, long]);
    let crossing = t.structure(&[double, double, f10]);
    let late = t.structure(&[double, double, double, f10]);
    let g = graph(&t, false);
    let list = regs(&["d0", "d1"], 8, "float")
        + &regs(&["x0", "x1", "x2", "x3"], 8, "general")
        + &stack(1, 500, 8, 16);
    let r = plan(&list, LE);
    // Four doubles: d0, d1, then the alternate class is exhausted at 16. The
    // remaining 16 bytes go to the stack (8-aligned, slot 0 at 16), not to
    // the free general registers.
    let mut s = fresh(&r, IN);
    let a = dual(&mut s, &r, spill(), &g, doubles);
    assert_eq!(
        pieces(&a),
        [(STACK, 16, 16, 16), (REG, 0x208, 8, 8), (REG, 0x200, 8, 0)]
    );
    assert_eq!(
        steps(&a)[2],
        (
            DualJoinStepKind::Stack {
                exhausted: ALT,
                slots: SlotRange { first: 0, next: 2 }
            },
            16,
            16,
            2,
            4
        )
    );
    assert_eq!(
        s.groups(),
        [
            USED,
            USED,
            FREE,
            FREE,
            FREE,
            FREE,
            GroupState::Available { used_slots: 2 }
        ]
    );
    assert_eq!(
        extents(&s),
        [(REG, 0x200, 0x207), (REG, 0x208, 0x20f), (STACK, 16, 31)]
    );
    // Without spill the same value fails and restores d0/d1.
    let mut s = fresh(&r, IN);
    let before = snapshot(&s);
    let a = dual(&mut s, &r, attrs(), &g, doubles);
    assert_eq!(
        no_fit(&a),
        DualJoinNoFit::Exhausted {
            class: ALT,
            offset: 16,
            uncovered: 16
        }
    );
    assert_eq!(a.usage.group_updates, 2);
    assert_eq!(snapshot(&s), before);
    // Five longs: x0..x3, then 8 bytes on the stack at slot 0.
    let mut s = fresh(&r, IN);
    let a = dual(&mut s, &r, spill(), &g, longs);
    assert_eq!(pieces(&a)[0], (STACK, 16, 8, 32));
    assert_eq!(pieces(&a).len(), 5);
    // Class checks come first: the third window crosses before exhaustion
    // is tested...
    let mut s = fresh(&r, IN);
    assert_eq!(
        no_fit(&dual(&mut s, &r, spill(), &g, crossing)),
        DualJoinNoFit::Window {
            offset: 16,
            rejection: DualTileRejection::CrossesWindow { primitive: 2 }
        }
    );
    // ...but a window that is classified and exhausted never reaches the
    // later crossing primitive; with spill the stack takes all 24 bytes.
    assert_eq!(
        no_fit(&dual(&mut s, &r, attrs(), &g, late)),
        DualJoinNoFit::Exhausted {
            class: ALT,
            offset: 16,
            uncovered: 24
        }
    );
    let a = dual(&mut s, &r, spill(), &g, late);
    assert_eq!(pieces(&a)[0], (STACK, 16, 24, 16));
}

#[test]
fn statuses_skip_positive_cursors_and_shared_groups_cross_lists() {
    let mut t = Source::default();
    let double = t.float(8);
    let long = t.int(8, true);
    let dl = t.structure(&[double, long]);
    let g = graph(&t, false);
    // MIPS64-style groups: d0/x0 share a group, d1/x1 the next.
    let pair = |f: &str, x: &str| {
        format!(
            r#"<group><pentry minsize="1" maxsize="8" storage="float"><register name="{f}"/></pentry><pentry minsize="1" maxsize="8"><register name="{x}"/></pentry></group>"#
        )
    };
    let list = pair("d0", "x0") + &pair("d1", "x1") + &stack(1, 500, 8, 16);
    let r = plan(&list, LE);
    let mut s = fresh(&r, IN);
    // d0 consumes group 0, so the base list skips x0 and takes x1.
    let a = dual(&mut s, &r, attrs(), &g, dl);
    assert_eq!(pieces(&a), [(REG, 0x88, 8, 8), (REG, 0x200, 8, 0)]);
    assert_eq!(steps(&a)[1].0, tile(BASE, 1));
    assert_eq!(s.groups(), [USED, USED, FREE]);
    // Nothing is left for a second long.
    assert_eq!(
        no_fit(&dual(&mut s, &r, attrs(), &g, long)),
        DualJoinNoFit::Exhausted {
            class: BASE,
            offset: 0,
            uncovered: 8
        }
    );

    // An aligned pool over x0 and x1 inherits both groups; its slot cursor
    // lives in x0's group. A positive cursor is skipped and kept.
    let list = regs(&["x0", "x1", "x2"], 8, "general")
        + &reg("d0", 8, "float")
        + r#"<pentry minsize="1" maxsize="16" align="8" storage="vector"><addr space="register" offset="0x80"/></pentry>"#;
    let r = plan(&list, LE);
    assert_eq!(
        r.list(0, IN).unwrap().entries[4].groups,
        [ResourceId(0), ResourceId(1)]
    );
    let pool = |s: &mut AllocationState| {
        s.assign_pool(
            &r,
            PoolRequest {
                entry: 4,
                size: 8,
                alignment: 1,
                justification: Justification::Default,
            },
            Default::default(),
        )
        .unwrap();
    };
    let mut s = fresh(&r, IN);
    pool(&mut s);
    let a = dual(&mut s, &r, attrs(), &g, long);
    assert_eq!(pieces(&a), [(REG, 0x88, 8, 0)]);
    assert_eq!(
        s.groups(),
        [GroupState::Available { used_slots: 1 }, USED, FREE, FREE]
    );
    // With both pool slots used, x1's own group is still untouched but its
    // bytes are held: returning it would be double ownership.
    let mut s = fresh(&r, IN);
    pool(&mut s);
    pool(&mut s);
    let before = snapshot(&s);
    assert!(matches!(
        s.assign_dual_join(&r, &attrs(), g.clone(), nid(long), Default::default()),
        Err(DualJoinError::Overlap {
            site: BindingSite::Input { entry: 1, .. },
            previous: BindingSite::Input { entry: 4, .. }
        })
    ));
    assert_eq!(snapshot(&s), before);
}

#[test]
fn stack_minimum_capacity_alignment_and_consumed_cursor() {
    let mut t = Source::default();
    let double = t.float(8);
    let three = t.structure(&[double, double, double]);
    let g = graph(&t, false);
    let list = |stack_entry: &str| reg("d0", 8, "float") + &reg("x0", 8, "general") + stack_entry;
    // Three doubles: d0, then 16 bytes must spill.
    let check = |r: &CompilerResources, s: &mut AllocationState, expected| {
        let before = snapshot(s);
        let a = dual(s, r, spill(), &g, three);
        assert_eq!(no_fit(&a), expected);
        assert_eq!(snapshot(s), before);
    };
    let r = plan(&list(&stack(24, 500, 8, 16)), LE);
    check(
        &r,
        &mut fresh(&r, IN),
        DualJoinNoFit::Stack {
            uncovered: 16,
            reason: NoFit::BelowMinimum,
        },
    );
    // Two 4-byte slots cannot hold 16 bytes (align == maxsize would be an
    // exclusion entry rather than a spill pool).
    let r = plan(&list(&stack(1, 8, 4, 16)), LE);
    check(
        &r,
        &mut fresh(&r, IN),
        DualJoinNoFit::Stack {
            uncovered: 16,
            reason: NoFit::SlotsExhausted,
        },
    );
    // A consumed first stack group (an exclusion stack entry overlapping the
    // pool shares its group): native minimum/capacity checks still run with
    // cursor -1 before the allocation is refused.
    let prior = r#"<pentry minsize="1" maxsize="4" storage="ptr"><addr space="stack" offset="16"/></pentry>"#;
    let consumed = |stack_entry: &str| {
        let r = plan(&(list(prior) + stack_entry), LE);
        let mut s = fresh(&r, IN);
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
        assert_eq!(s.groups()[2], USED);
        (r, s)
    };
    let (r, mut s) = consumed(&stack(24, 32, 8, 16));
    check(
        &r,
        &mut s,
        DualJoinNoFit::Stack {
            uncovered: 16,
            reason: NoFit::BelowMinimum,
        },
    );
    // From -1, two 8-byte slots end at slot 1 <= 2 (16/8 slots): native
    // would allocate from status -1, which is refused, not a NoFit.
    let (r, mut s) = consumed(&stack(1, 16, 8, 16));
    let before = snapshot(&s);
    assert!(matches!(
        s.assign_dual_join(&r, &spill(), g.clone(), nid(three), Default::default()),
        Err(DualJoinError::Unsupported {
            reason: "the stack pool's resource group is consumed",
            ..
        })
    ));
    assert_eq!(snapshot(&s), before);
    // Two 4-byte slots (align == maxsize would make an exclusion entry, not
    // getStackEntry's pool): alignment 8 > 4 moves -1 by (8 - (-4 % 8)) / 4
    // = 3 to 2 (C++ remainder truncates toward zero); 2 + 4 slots > 2.
    let (r, mut s) = consumed(&stack(1, 8, 4, 16));
    check(
        &r,
        &mut s,
        DualJoinNoFit::Stack {
            uncovered: 16,
            reason: NoFit::SlotsExhausted,
        },
    );
    // Three 4-byte slots: the type alignment's waste (to 2) makes 2 + 4 > 3
    // a native NoFit, where -1 + 4 <= 3 without it would be a refusal.
    let (r, mut s) = consumed(&stack(1, 12, 4, 16));
    check(
        &r,
        &mut s,
        DualJoinNoFit::Stack {
            uncovered: 16,
            reason: NoFit::SlotsExhausted,
        },
    );
}

#[test]
fn stack_alignment_uses_the_datatype_and_native_floor_division() {
    // A 16-byte integer aligned to 16, and an 8-byte float aligned to 12,
    // through declared size/alignment entries.
    let organization = |entries: &[(u32, u32)]| {
        DataOrganization {
            size_alignment_map: entries
                .iter()
                .map(|&(size, alignment)| SizeAlignment { size, alignment })
                .collect(),
            ..Default::default()
        }
        .resolve(8)
    };
    let list = reg("d0", 8, "float") + &reg("x0", 8, "general") + &stack(1, 500, 8, 16);
    let r = plan(&list, LE);
    let seeded = || {
        let mut s = fresh(&r, IN);
        // One 8-byte slot is already used: cursor 1.
        s.assign_pool(
            &r,
            PoolRequest {
                entry: 2,
                size: 8,
                alignment: 1,
                justification: Justification::Default,
            },
            Default::default(),
        )
        .unwrap();
        s
    };
    let mut t = Source::default();
    let double = t.float(8);
    let wide = t.int(16, false);
    let value = t.structure(&[double, double, wide]);
    let g = native_common::bridge(
        t.layouts_with(organization(&[(16, 16)]), ghidra_types::Endianness::Little),
    );
    let native = g.get(nid(value)).unwrap();
    assert_eq!((native.size, native.alignment), (32, 16));
    // d0, then 24 bytes spill with the type's alignment 16, not 1: from
    // cursor 1, (1*8) % 16 = 8 wastes one slot, so slots 2..5 at 16+16.
    let mut s = seeded();
    let a = dual(&mut s, &r, spill(), &g, value);
    assert_eq!(pieces(&a), [(STACK, 32, 24, 8), (REG, 0x200, 8, 0)]);
    assert_eq!(
        steps(&a)[1].0,
        DualJoinStepKind::Stack {
            exhausted: ALT,
            slots: SlotRange { first: 2, next: 5 }
        }
    );
    // Alignment 12 over 8-byte slots, with d0 already consumed so the only
    // window is exhausted: native (1*8) % 12 = 8 and (12-8)/8 = 0 wastes
    // nothing, so the spill starts at slot 1 (offset 24), although 24 is not
    // a multiple of 12. Exact congruence would choose slot 3 instead.
    let mut t = Source::default();
    let double = t.float(8);
    let g = native_common::bridge(
        t.layouts_with(organization(&[(8, 12)]), ghidra_types::Endianness::Little),
    );
    let native = g.get(nid(double)).unwrap();
    assert_eq!((native.size, native.alignment), (8, 12));
    let mut s = seeded();
    s.assign_pool(
        &r,
        PoolRequest {
            entry: 0,
            size: 8,
            alignment: 1,
            justification: Justification::Default,
        },
        Default::default(),
    )
    .unwrap();
    let a = dual(&mut s, &r, spill(), &g, double);
    assert_eq!(pieces(&a), [(STACK, 24, 8, 0)]);
    assert_eq!(
        steps(&a),
        [(
            DualJoinStepKind::Stack {
                exhausted: ALT,
                slots: SlotRange { first: 1, next: 2 }
            },
            0,
            8,
            0,
            1
        )]
    );
}

#[test]
fn join_pool_tiles_padding_and_floating_extension_tiles() {
    let mut t = Source::default();
    let long = t.int(8, true);
    let int = t.int(4, true);
    let float = t.float(4);
    let two = t.structure(&[long, long]);
    let three = t.structure(&[int, int, int]);
    let fi = t.structure(&[float, int]);
    let g = graph(&t, false);
    // Pointer pools r0/r1 supply groups; each general join tile inherits
    // one (r2 and r3 match no earlier pool).
    let joins = regs(&["r0", "r1"], 4, "ptr")
        + r#"<pentry minsize="1" maxsize="8"><addr space="join" piece1="r2" piece2="r0"/></pentry>"#
        + r#"<pentry minsize="1" maxsize="8"><addr space="join" piece1="r3" piece2="r1"/></pentry>"#
        + &reg("d0", 8, "float");
    let r = plan(&joins, LE);
    let mut s = fresh(&r, IN);
    let a = dual(&mut s, &r, attrs(), &g, two);
    // J0 (r2:r0) then J1 (r3:r1), reversed as tiles but each keeps its own
    // most-significant-first pieces.
    assert_eq!(
        pieces(&a),
        [
            (REG, 12, 4, 12),
            (REG, 4, 4, 8),
            (REG, 8, 4, 4),
            (REG, 0, 4, 0)
        ]
    );
    assert_eq!(
        extents(&s),
        [(REG, 0, 3), (REG, 4, 7), (REG, 8, 11), (REG, 12, 15)]
    );
    // Cropping a join tile would nest a partial join.
    let mut s = fresh(&r, IN);
    let before = snapshot(&s);
    assert!(matches!(
        s.assign_dual_join(&r, &attrs(), g.clone(), nid(three), Default::default()),
        Err(DualJoinError::Unsupported {
            reason: "justification would truncate a join tile",
            ..
        })
    ));
    assert_eq!(snapshot(&s), before);
    // Two join tiles physically sharing r2 have distinct groups: the second
    // overlaps the first and is refused.
    let shared = regs(&["r0", "r1"], 4, "ptr")
        + r#"<pentry minsize="1" maxsize="8"><addr space="join" piece1="r2" piece2="r0"/></pentry>"#
        + r#"<pentry minsize="1" maxsize="8"><addr space="join" piece1="r2" piece2="r1"/></pentry>"#
        + &reg("d0", 8, "float");
    let r = plan(&shared, LE);
    let mut s = fresh(&r, IN);
    let before = snapshot(&s);
    assert!(matches!(
        s.assign_dual_join(&r, &attrs(), g.clone(), nid(two), Default::default()),
        Err(DualJoinError::Overlap {
            site: BindingSite::Input { entry: 3, .. },
            previous: BindingSite::Input { entry: 2, .. }
        })
    ));
    assert_eq!(snapshot(&s), before);
    // Constant padding stays padding and is not held.
    let padded = reg("r0", 4, "ptr")
        + r#"<pentry minsize="1" maxsize="8"><addr space="join" piece1="const:0x7:4" piece2="r0"/></pentry>"#
        + &reg("d0", 8, "float");
    let r = plan(&padded, LE);
    let mut s = fresh(&r, IN);
    let a = dual(&mut s, &r, attrs(), &g, long);
    let JoinStorage::Pieces(raw) = &assigned(&a).storage else {
        unreachable!()
    };
    assert_eq!(raw[0].piece.role, PieceRole::Padding);
    assert_eq!(raw[1].piece.role, PieceRole::Storage);
    assert_eq!(extents(&s), [(REG, 0, 3)]);
    // A floating-extension join tile (4 logical bytes of d1): an exact
    // single tile is the recorded conversion; inside a compound it is refused.
    let extension = reg("d1", 8, "ptr")
        + r#"<pentry minsize="1" maxsize="4" storage="float"><addr space="join" piece1="d1" size="4"/></pentry>"#
        + &reg("r2", 4, "general");
    let r = plan(&extension, LE);
    let mut s = fresh(&r, IN);
    let a = dual(&mut s, &r, attrs(), &g, float);
    assert!(matches!(
        &assigned(&a).storage,
        JoinStorage::FloatConversion { container, logical_size: 4 }
            if container.size == Some(8) && container.address.offset == 0x208
    ));
    let mut s = fresh(&r, IN);
    let before = snapshot(&s);
    assert!(matches!(
        s.assign_dual_join(&r, &attrs(), g.clone(), nid(fi), Default::default()),
        Err(DualJoinError::Unsupported {
            reason: "floating-extension tile inside a compound or truncated join",
            ..
        })
    ));
    assert_eq!(snapshot(&s), before);
}

#[test]
fn initialization_identity_and_state_errors() {
    let mut t = Source::default();
    let long = t.int(8, true);
    let incomplete = t.add(TypeKind::Incomplete);
    let g = graph(&t, false);
    let error = |list: &str, a: DualJoinAttributes| {
        let r = plan(list, LE);
        let mut s = fresh(&r, IN);
        let before = snapshot(&s);
        let e = s
            .assign_dual_join(&r, &a, g.clone(), nid(long), Default::default())
            .unwrap_err();
        assert_eq!(snapshot(&s), before);
        e
    };
    // extractTiles: exclusion entries of exactly the class with one group.
    // An aligned pool and a two-group pool are not tiles.
    let pool = r#"<pentry minsize="1" maxsize="16" align="8"><addr space="register" offset="0x80"/></pentry>"#;
    assert!(matches!(
        error(&(reg("d0", 8, "float") + pool), attrs()),
        DualJoinError::NoTiles { class: C::General }
    ));
    let wide = regs(&["x0", "x1"], 8, "ptr")
        + r#"<pentry minsize="1" maxsize="16"><addr space="register" offset="0x80"/></pentry>"#
        + &reg("d0", 8, "float");
    assert!(matches!(
        error(&wide, attrs()),
        DualJoinError::NoTiles { class: C::General }
    ));
    assert!(matches!(
        error(&reg("x0", 8, "general"), attrs()),
        DualJoinError::NoTiles { class: C::Float }
    ));
    // Neither list: the base class is reported first.
    assert!(matches!(
        error(&reg("p0", 8, "ptr"), attrs()),
        DualJoinError::NoTiles { class: C::General }
    ));
    // Only the first tiles' widths are compared.
    assert!(matches!(
        error(&(reg("d0", 8, "float") + &reg("r0", 4, "general")), attrs()),
        DualJoinError::TileSizeMismatch {
            base: 4,
            alternate: 8
        }
    ));
    // Missing stack after the tile checks; a stack that is not last is not
    // getStackEntry's pool.
    let tiles = reg("d0", 8, "float") + &reg("x0", 8, "general");
    assert!(matches!(
        error(&tiles, spill()),
        DualJoinError::MissingStack
    ));
    assert!(matches!(
        error(&(stack(1, 500, 8, 16) + &tiles), spill()),
        DualJoinError::MissingStack
    ));
    assert!(matches!(
        error(&(reg("d0", 8, "float") + &reg("r0", 4, "general")), spill()),
        DualJoinError::TileSizeMismatch { .. }
    ));
    // Unknown native IDs and failed conversions are datatype errors.
    let r = plan(&tiles, LE);
    let mut s = fresh(&r, IN);
    assert!(matches!(
        s.assign_dual_join(
            &r,
            &attrs(),
            g.clone(),
            NativeTypeId(99),
            Default::default()
        ),
        Err(DualJoinError::Type(NativeTypeError::UnknownNative(
            NativeTypeId(99)
        )))
    ));
    assert!(matches!(
        s.assign_dual_join(&r, &attrs(), g.clone(), nid(incomplete), Default::default()),
        Err(DualJoinError::Type(NativeTypeError::Conversion(
            NativeConversionError::Incomplete(_)
        )))
    ));
    // A state from another overlay is refused before anything else.
    let other = plan(&tiles, LE);
    assert!(matches!(
        fresh(&other, IN).assign_dual_join(
            &r,
            &attrs(),
            g.clone(),
            NativeTypeId(99),
            Default::default()
        ),
        Err(DualJoinError::StateMismatch)
    ));
    assert_eq!(s.groups(), [FREE, FREE]);
}

#[test]
fn no_fit_and_errors_after_partial_success_restore_the_state() {
    let mut t = Source::default();
    let double = t.float(8);
    let long = t.int(8, true);
    let value = t.structure(&[double, long, long, long]);
    let g = graph(&t, false);
    let list = reg("d0", 8, "float") + &regs(&["x0", "x1"], 8, "general") + &stack(16, 500, 8, 16);
    let r = plan(&list, LE);
    let mut s = fresh(&r, IN);
    // Seed earlier, unrelated state that must survive.
    s.assign_pool(
        &r,
        PoolRequest {
            entry: 3,
            size: 16,
            alignment: 1,
            justification: Justification::Default,
        },
        Default::default(),
    )
    .unwrap();
    assert_eq!(s.groups()[3], GroupState::Available { used_slots: 2 });
    let before = snapshot(&s);
    // d0, x0, x1 are consumed, then 8 bytes are below the stack minimum.
    let a = dual(&mut s, &r, spill(), &g, value);
    assert_eq!(
        no_fit(&a),
        DualJoinNoFit::Stack {
            uncovered: 8,
            reason: NoFit::BelowMinimum
        }
    );
    assert_eq!(a.usage.group_updates, 3);
    assert_eq!(snapshot(&s), before);
    // The same tiles remain usable afterwards.
    let a = dual(&mut s, &r, attrs(), &g, long);
    assert_eq!(pieces(&a), [(REG, 0x80, 8, 0)]);
    // An error after tiles were consumed and held also restores.
    let mut s = fresh(&r, IN);
    let before = snapshot(&s);
    let limits = DualJoinLimits {
        max_occupied_extents: 1,
        ..Default::default()
    };
    let three = t.structure(&[double, long]);
    let g = graph(&t, false);
    assert!(matches!(
        s.assign_dual_join(&r, &attrs(), g.clone(), nid(three), limits),
        Err(DualJoinError::Limit("occupied extents"))
    ));
    assert_eq!(snapshot(&s), before);
}

/// The small mixed-register example used by the work pins and caps.
fn mixed_example() -> (CompilerResources, Arc<NativeTypeGraph>, TypeId) {
    let mut t = Source::default();
    let double = t.float(8);
    let long = t.int(8, true);
    let dl = t.structure(&[double, long]);
    let r = plan(&(reg("d0", 8, "float") + &reg("x0", 8, "general")), LE);
    (r, graph(&t, false), dl)
}

/// The spilling example: {double, long, long} over d0, x0 and the stack.
fn spill_example() -> (CompilerResources, Arc<NativeTypeGraph>, TypeId) {
    let mut t = Source::default();
    let double = t.float(8);
    let long = t.int(8, true);
    let value = t.structure(&[double, long, long]);
    let r = plan(
        &(reg("d0", 8, "float") + &reg("x0", 8, "general") + &stack(1, 500, 8, 16)),
        LE,
    );
    (r, graph(&t, false), value)
}

#[test]
fn absolute_work_is_derived_by_hand() {
    // lookup(n) = bits(n) + 1. Two/three bindings and three spaces cost 3.
    //
    // Mixed {double, long} over d0/x0 (2 bindings):
    //   header 1, datatype 1, graph byte order lookup(3) = 3,
    //   list byte order lookup(2) + lookup(3) = 6,
    //   initialization: 2 entries + 2 tiles = 4,
    //   extraction (native extractor charges): root enter 1, structure task 1,
    //     per field (structure step 1, enter 1, leaf task 1, push 1) = 8,
    //     final structure step 1 = 11,
    //   window 0: 1 + 2 visits (double, then the long ends it) + 2 for d0's
    //     status + 1 write = 6; window 8: 1 + 1 visit + 2 + 1 = 5,
    //   each tile placement 11 (header 1, binding lookup 3, endian geometry
    //     3, one output 1, slice geometry 3) + binding lookup 3 + held span 4
    //     (1 + constant-space lookup 3) + occupied lookup (1 for 0 held, 2
    //     for 1 held) = 19 and 20,
    //   ordering 2 pieces = 2.
    //   1+1+3+6+4+11+6+5+19+20+2 = 78.
    let (r, g, ty) = mixed_example();
    assert_eq!(r.storage().bindings().len(), 2);
    assert_eq!(r.storage().register_file().spaces().len(), 3);
    let mut s = fresh(&r, IN);
    let a = s
        .assign_dual_join(&r, &attrs(), g.clone(), nid(ty), Default::default())
        .unwrap();
    assert_eq!(a.usage.extraction.work, 11);
    assert_eq!(a.usage.work, 78);
    assert_eq!(a.usage.primitive_visits, 3);
    assert_eq!(a.usage.examined_entries, 4);
    assert_eq!(a.usage.group_references, 2);
    assert_eq!(a.usage.group_updates, 2);
    assert_eq!(
        (a.usage.placements, a.usage.pieces, a.usage.occupied_extents),
        (2, 2, 2)
    );
    // Spilling {double, long, long} over d0/x0/stack (3 bindings):
    //   header 1, datatype 1, graph order 3, list order 6,
    //   initialization 3 entries + 2 tiles = 5, stack binding lookup 3,
    //   extraction 1 + 1 + 3 fields * 4 + 1 = 15,
    //   window 0: 1 + 2 + 2 + 1 = 6; window 8: 1 + 2 (long, then the long at
    //     16 ends it) + 2 + 1 = 6; window 16: 1 + 1 + x0 revisited 2 = 4,
    //   stack: group read 1, cursor 1, placement 12 (header 1, binding 3,
    //     one gcd step 1, endian geometry 3, output 1, slice geometry 3),
    //     cursor write 1 = 15,
    //   tiles 19 + 20 as above,
    //   spill safeguards: 1 stack group, spans (binding 3 + 1; the stack is
    //     not a language space) 4, occupied lookup(2) 3 = 8,
    //   ordering 3.
    //   1+1+3+6+5+3+15+6+6+4+15+19+20+8+3 = 115.
    let (r, g, ty) = spill_example();
    let mut s = fresh(&r, IN);
    let a = s
        .assign_dual_join(&r, &spill(), g.clone(), nid(ty), Default::default())
        .unwrap();
    assert_eq!(
        pieces(&a),
        [(STACK, 16, 8, 16), (REG, 0x80, 8, 8), (REG, 0x200, 8, 0)]
    );
    assert_eq!(a.usage.extraction.work, 15);
    assert_eq!(a.usage.work, 115);
    for (example, attributes, total) in [
        (mixed_example(), attrs(), 78),
        (spill_example(), spill(), 115),
    ] {
        let (r, g, ty) = example;
        let s = fresh(&r, IN);
        let before = snapshot(&s);
        for work in 0..total {
            let mut trial = s.clone();
            let limits = DualJoinLimits {
                max_work: work,
                ..Default::default()
            };
            assert!(
                matches!(
                    trial.assign_dual_join(&r, &attributes, g.clone(), nid(ty), limits),
                    Err(DualJoinError::Limit("work"))
                ),
                "work {work}"
            );
            assert_eq!(snapshot(&trial), before);
        }
        let mut trial = s.clone();
        let limits = DualJoinLimits {
            max_work: total,
            ..Default::default()
        };
        assert!(
            trial
                .assign_dual_join(&r, &attributes, g.clone(), nid(ty), limits)
                .is_ok()
        );
    }
}

#[test]
fn every_limit_holds_at_its_usage_and_fails_one_below() {
    let (r, g, ty) = spill_example();
    let s = fresh(&r, IN);
    let a = s
        .clone()
        .assign_dual_join(&r, &spill(), g.clone(), nid(ty), Default::default())
        .unwrap();
    let u = a.usage;
    assert_eq!(
        (
            u.base_tiles,
            u.alternate_tiles,
            u.examined_entries,
            u.primitive_visits
        ),
        (1, 1, 6, 5)
    );
    assert_eq!(
        (u.group_references, u.group_updates, u.placements, u.pieces),
        (5, 3, 3, 3)
    );
    assert_eq!((u.occupied_extents, u.source_pieces), (3, 1));
    // Extraction of a three-field structure: four records never coexist
    // beyond the three primitives; depth is root plus one field level.
    assert_eq!(
        (u.extraction.peak_live_primitives, u.extraction.peak_depth),
        (3, 2)
    );
    let base = DualJoinLimits::default();
    type Set = fn(&mut DualJoinLimits, u64);
    let caps: [(&str, u64, Set); 12] = [
        ("tiles", 2, |l, n| l.max_tiles = n as usize),
        ("examined entries", u.examined_entries, |l, n| {
            l.max_examined_entries = n
        }),
        ("primitive visits", u.primitive_visits, |l, n| {
            l.max_primitive_visits = n
        }),
        ("group references", u.group_references, |l, n| {
            l.max_group_references = n
        }),
        ("group updates", u.group_updates, |l, n| {
            l.max_group_updates = n
        }),
        ("placements", u.placements as u64, |l, n| {
            l.max_placements = n as usize
        }),
        ("pieces", u.pieces as u64, |l, n| l.max_pieces = n as usize),
        ("occupied extents", u.occupied_extents as u64, |l, n| {
            l.max_occupied_extents = n as usize
        }),
        ("source pieces", u.source_pieces as u64, |l, n| {
            l.max_source_pieces = n as usize
        }),
        ("extraction live primitives", 3, |l, n| {
            l.max_extraction_live_primitives = n as usize
        }),
        ("extraction depth", 2, |l, n| {
            l.max_extraction_depth = n as usize
        }),
        ("work", u.work, |l, n| l.max_work = n),
    ];
    let before = snapshot(&s);
    for (name, exact, set) in caps {
        let mut limits = base;
        set(&mut limits, exact);
        let mut trial = s.clone();
        let ok = trial
            .assign_dual_join(&r, &spill(), g.clone(), nid(ty), limits)
            .unwrap();
        assert_eq!(ok, a, "{name}");
        set(&mut limits, exact - 1);
        let mut trial = s.clone();
        match trial.assign_dual_join(&r, &spill(), g.clone(), nid(ty), limits) {
            Err(DualJoinError::Limit(resource)) => assert_eq!(resource, name),
            other => panic!("{name}: {other:?}"),
        }
        assert_eq!(snapshot(&trial), before, "{name}");
    }
    // Already-held extents above the cap are refused on entry; exactly at
    // the cap a NoFit (which holds nothing new) is still reported.
    let mut held = s.clone();
    held.assign_pool(
        &r,
        PoolRequest {
            entry: 2,
            size: 8,
            alignment: 1,
            justification: Justification::Default,
        },
        Default::default(),
    )
    .unwrap();
    assert!(matches!(
        held.assign_dual_join(
            &r,
            &spill(),
            g.clone(),
            nid(ty),
            DualJoinLimits {
                max_occupied_extents: 0,
                ..Default::default()
            }
        ),
        Err(DualJoinError::Limit("occupied extents"))
    ));
    let at_cap = held
        .assign_dual_join(
            &r,
            &attrs(),
            g.clone(),
            nid(ty),
            DualJoinLimits {
                max_occupied_extents: 1,
                ..Default::default()
            },
        )
        .unwrap();
    assert_eq!(
        no_fit(&at_cap),
        DualJoinNoFit::Exhausted {
            class: BASE,
            offset: 16,
            uncovered: 8
        }
    );
}

#[test]
fn work_scales_linearly_with_tiles_and_primitives() {
    let measure = |n: usize| {
        let mut list = String::new();
        let mut names = Vec::new();
        for i in 0..n {
            names.push((format!("t{i}"), 0x10000 + 8 * i as u64));
            names.push((format!("u{i}"), 0x40000 + 8 * i as u64));
        }
        for (name, _) in &names {
            let class = if name.starts_with('t') {
                "general"
            } else {
                "float"
            };
            list += &reg(name, 8, class);
        }
        let source = common::parse(&format!(
            r#"<compiler_spec><stackpointer register="sp" space="ram"/>
<default_proto><prototype name="p" extrapop="0" stackshift="0">
<input separatefloat="false">{list}</input><output/>
</prototype></default_proto></compiler_spec>"#
        ));
        let mut defs = registers();
        defs.extend(
            names
                .iter()
                .map(|(name, offset)| common::register(name, common::REGISTER, *offset, 8)),
        );
        let file = Arc::new(
            RegisterFile::new(common::spaces(4), common::RAM, defs, Default::default()).unwrap(),
        );
        let storage = common::storage(source, &file, Default::default()).unwrap();
        let r = CompilerResources::new(Arc::new(storage), Default::default()).unwrap();
        // An array of n doubles: n alternate windows, each one primitive.
        let mut t = Source::default();
        let double = t.float(8);
        let array = t.array(double, n as u64);
        let g = graph(&t, false);
        let mut s = fresh(&r, IN);
        let a = s
            .assign_dual_join(&r, &attrs(), g, nid(array), Default::default())
            .unwrap();
        assert_eq!(assigned(&a).steps.len(), n);
        a.usage.work
    };
    // Four times the tiles and primitives: four times the linear work, plus
    // logarithmic binding and occupied-extent lookups (two more bits each).
    let small = measure(200);
    let large = measure(800);
    assert!(large < small * 5, "{small} -> {large}");
    assert!(large > small * 4, "{small} -> {large}");
}

#[test]
fn results_are_deterministic_thread_safe_and_retain_the_graph() {
    let (r, g, ty) = spill_example();
    let s = fresh(&r, IN);
    let run = || {
        let mut state = s.clone();
        let a = state
            .assign_dual_join(&r, &spill(), g.clone(), nid(ty), Default::default())
            .unwrap();
        (a, snapshot(&state))
    };
    let first = run();
    assert!(Arc::ptr_eq(&first.0.graph, &g));
    assert_eq!(first.0.ty, nid(ty));
    let results: Vec<_> = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..4).map(|_| scope.spawn(run)).collect();
        handles.into_iter().map(|h| h.join().unwrap()).collect()
    });
    for result in results {
        assert_eq!(result, first);
    }
    fn send_sync<T: Send + Sync>() {}
    send_sync::<DualJoinAssignment>();
    send_sync::<DualJoinError>();
    // Another graph Arc with the same content is a different result.
    let (_, other, _) = spill_example();
    let mut state = s.clone();
    let a = state
        .assign_dual_join(&r, &spill(), other, nid(ty), Default::default())
        .unwrap();
    assert_ne!(a, first.0);
    assert_eq!(a.outcome, first.0.outcome);
}

#[test]
fn spill_native_int_overflow_precedes_capacity_rejection_and_rolls_back() {
    let mut t = Source::default();
    let double = t.float(8);
    let value = t.structure(&[double, double, double]);
    let g = graph(&t, false);
    let r = plan(
        &(reg("d0", 8, "float") + &reg("x0", 8, "general") + &stack(1, i32::MAX as u32, 1, 0)),
        LE,
    );
    let mut state = fresh(&r, IN);
    state
        .assign_pool(
            &r,
            PoolRequest {
                entry: 2,
                size: i32::MAX as u32 - 7,
                alignment: 1,
                justification: Justification::Default,
            },
            Default::default(),
        )
        .unwrap();
    let before = snapshot(&state);
    // The first double uses d0. The remaining 16 bytes spill from the
    // aligned cursor 2147483640. fspec.cc evaluates cursor + slotsused
    // before checking capacity, so wide-arithmetic NoFit would hide overflow.
    assert!(matches!(
        state.assign_dual_join(&r, &spill(), g, nid(value), Default::default()),
        Err(DualJoinError::NativeIntRange(
            "stack cursor plus value slots exceeds the native int range"
        ))
    ));
    assert_eq!(snapshot(&state), before);
}

#[test]
fn window_native_int_overflow_precedes_primitive_exhaustion_and_rolls_back() {
    let mut t = Source::default();
    let value = t.int(2_147_483_640, false);
    let g = graph(&t, false);
    assert_eq!(g.get(nid(value)).unwrap().size, 2_147_483_640);
    let list =
        r#"<pentry minsize="1" maxsize="2147483647"><addr space="register" offset="0"/></pentry>"#
            .to_string()
            + r#"<pentry minsize="1" maxsize="1"><addr space="register" offset="0x80000000"/></pentry>"#
            + r#"<pentry minsize="1" maxsize="2147483647" storage="float"><addr space="register" offset="0x100000000"/></pentry>"#;
    let r = plan(&list, LE);
    let mut state = fresh(&r, IN);
    state
        .assign_pool(
            &r,
            PoolRequest {
                entry: 0,
                size: 1,
                alignment: 1,
                justification: Justification::Default,
            },
            Default::default(),
        )
        .unwrap();
    let before = snapshot(&state);
    // The first window ends exactly at i32::MAX, classifies the sole
    // primitive, then takes the later one-byte tile. The next window must
    // check 1 + i32::MAX before returning NoPrimitiveLeft (modelrules.cc:1262).
    assert!(matches!(
        state.assign_dual_join(&r, &attrs(), g, nid(value), Default::default()),
        Err(DualJoinError::NativeIntRange(
            "tile window end exceeds the native int range"
        ))
    ));
    assert_eq!(snapshot(&state), before);
}
