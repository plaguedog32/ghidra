//! Directed native PrimitiveExtractor tests (modelrules.cc:142-249). Offsets,
//! flags and outcomes are derived by hand from the native field/array rules.
mod native_common;

use std::sync::Arc;

use ghidra_abi::*;
use ghidra_languages::MetaType;
use ghidra_types::{Field, MinimumAlignment, Packing, TypeId, TypeKind};
use native_common::*;

fn run(
    graph: &Arc<NativeTypeGraph>,
    ty: TypeId,
    options: NativeExtractionOptions,
) -> NativePrimitiveExtraction {
    NativePrimitiveExtraction::new(graph.clone(), id(ty), options, Default::default()).unwrap()
}

fn at(offset: u32, max: u32) -> NativeExtractionOptions {
    NativeExtractionOptions {
        offset,
        ..NativeExtractionOptions::new(max)
    }
}

/// (offset, origin) pairs plus the root context's three flags.
fn summary(e: &NativePrimitiveExtraction) -> (Vec<(u32, NativeOrigin)>, bool, bool, bool) {
    let NativeExtractionOutcome::Valid {
        primitives,
        contains_unknown,
        aligned,
        contains_holes,
    } = e.outcome()
    else {
        panic!("invalid extraction {:?}", e.outcome());
    };
    (
        primitives.iter().map(|p| (p.offset, p.origin)).collect(),
        *contains_unknown,
        *aligned,
        *contains_holes,
    )
}

fn src(ty: TypeId) -> NativeOrigin {
    NativeOrigin::Source(ty)
}

fn invalid(e: &NativePrimitiveExtraction) -> NativeInvalidExtraction {
    match e.outcome() {
        NativeExtractionOutcome::Invalid(reason) => *reason,
        valid => panic!("expected invalid, got {valid:?}"),
    }
}

#[test]
fn packed_float_with_opaque_tail_emits_one_float() {
    let mut s = Source::default();
    let f = s.float(4);
    let o16 = s.opaque(16);
    let o17 = s.opaque(17);
    let tail16 = s.packed(&[f, o16]);
    let tail17 = s.packed(&[f, o17]);
    let pair = s.array(tail17, 2);
    let graph = s.native();
    assert_eq!(graph.get(id(tail16)).unwrap().size, 20);
    // The fieldless opaque structure emits nothing and its field check passes.
    assert_eq!(
        summary(&run(&graph, tail16, at(0, 4))),
        (vec![(0, src(f))], false, true, false)
    );
    // Java pads the 17-byte opaque component to its aligned length 24 under
    // the default map, so each element is 28 bytes and stays aligned.
    assert_eq!(graph.get(id(tail17)).unwrap().size, 28);
    assert_eq!(
        summary(&run(&graph, pair, at(0, 4))),
        (vec![(0, src(f)), (28, src(f))], false, true, false)
    );

    // A map entry 16 -> 1 gives the opaque component Java aligned length 17,
    // so the element is 21 bytes. The second element's float at 21 is
    // unaligned and expected offset 21 rounds to 24, recording a hole too.
    let mut organization = organization();
    organization
        .size_alignment_map
        .push(ghidra_languages::SizeAlignment {
            size: 16,
            alignment: 1,
        });
    let graph = bridge(s.layouts_with(organization, ghidra_types::Endianness::Little));
    assert_eq!(graph.get(id(tail17)).unwrap().size, 21);
    assert_eq!(
        summary(&run(&graph, tail17, at(0, 4))),
        (vec![(0, src(f))], false, true, false)
    );
    assert_eq!(
        summary(&run(&graph, pair, at(0, 4))),
        (vec![(0, src(f)), (21, src(f))], false, false, true)
    );
}

#[test]
fn structure_checks_use_absolute_offsets_from_the_extraction_start() {
    let mut s = Source::default();
    let u8_ = s.int(1, false);
    let u32_ = s.int(4, false);
    let natural = s.structure(&[u8_, u32_]);
    let packed = s.packed(&[u8_, u32_]);
    let graph = s.native();
    assert_eq!(
        summary(&run(&graph, natural, at(0, 4))),
        (vec![(0, src(u8_)), (4, src(u32_))], false, true, false)
    );
    assert_eq!(
        summary(&run(&graph, natural, at(1, 4))),
        (vec![(1, src(u8_)), (5, src(u32_))], false, false, true)
    );
    assert_eq!(
        summary(&run(&graph, packed, at(0, 4))),
        (vec![(0, src(u8_)), (1, src(u32_))], false, false, true)
    );
    assert_eq!(
        summary(&run(&graph, packed, at(3, 4))),
        (vec![(3, src(u8_)), (4, src(u32_))], false, true, false)
    );
}

#[test]
fn roots_and_array_elements_have_no_direct_alignment_check() {
    let mut s = Source::default();
    let f = s.float(4);
    let floats = s.array(f, 3);
    let graph = s.native();
    assert_eq!(
        summary(&run(&graph, f, at(1, 4))),
        (vec![(1, src(f))], false, true, false)
    );
    assert_eq!(
        summary(&run(&graph, floats, at(1, 4))),
        (
            vec![(1, src(f)), (5, src(f)), (9, src(f))],
            false,
            true,
            false
        )
    );
}

#[test]
fn nested_structure_checks_and_no_trailing_coverage_check() {
    let mut s = Source::default();
    let u8_ = s.int(1, false);
    let u32_ = s.int(4, false);
    let f = s.float(4);
    let inner = s.packed(&[u32_]);
    let outer = s.packed(&[u8_, inner]);
    let min8 = s.composite(&[f], Packing::Default, MinimumAlignment::Explicit(8), false);
    let pair = s.array(min8, 2);
    let graph = s.native();
    // inner@1 passes the outer check; its u32 at absolute 1 fails both checks.
    assert_eq!(
        summary(&run(&graph, outer, at(0, 4))),
        (vec![(0, src(u8_)), (1, src(u32_))], false, false, true)
    );
    // Padding after the float is never checked; each element restarts at 8.
    assert_eq!(
        summary(&run(&graph, pair, at(0, 4))),
        (vec![(0, src(f)), (8, src(f))], false, true, false)
    );
}

#[test]
fn bitfields_outside_the_field_list_are_invisible_but_leave_gaps() {
    let mut s = Source::default();
    let i32_ = s.int(4, true);
    let f = s.float(4);
    let fields = |first_bitfield: bool| {
        let bitfield = Field::bitfield("b", i32_, 3);
        let float = Field::new("f", f);
        if first_bitfield {
            vec![bitfield, float]
        } else {
            vec![float, bitfield]
        }
    };
    let after = s.with_fields(
        fields(false),
        Packing::Default,
        MinimumAlignment::Default,
        false,
    );
    let before = s.with_fields(
        fields(true),
        Packing::Default,
        MinimumAlignment::Default,
        false,
    );
    let packed_before = s.with_fields(
        fields(true),
        Packing::Explicit(1),
        MinimumAlignment::Default,
        false,
    );
    let graph = s.native();
    assert_eq!(
        summary(&run(&graph, after, at(0, 4))),
        (vec![(0, src(f))], false, true, false)
    );
    // The invisible bitfield leaves expected offset 0 before the float at 4.
    assert_eq!(
        summary(&run(&graph, before, at(0, 4))),
        (vec![(4, src(f))], false, true, true)
    );
    assert_eq!(
        summary(&run(&graph, packed_before, at(0, 4))),
        (vec![(1, src(f))], false, false, true)
    );
}

#[test]
fn byte_range_bitfields_extract_their_converted_field_types() {
    let mut s = Source::default();
    let i32_ = s.int(4, true);
    let e4 = s.add(TypeKind::Enum {
        bytes: 4,
        signed: false,
    });
    let u64_ = s.int(8, false);
    let i128_ = s.int(16, true);
    let f = s.float(4);
    let record = s.with_fields(
        vec![
            Field::bitfield("e", e4, 32),
            Field::bitfield("a", i32_, 16),
            Field::bitfield("c", i32_, 3),
            Field::bitfield("z", i32_, 0),
            Field::bitfield("y", u64_, 24),
            Field::bitfield("w", i128_, 96),
            Field::new("f", f),
        ],
        Packing::Default,
        MinimumAlignment::Default,
        false,
    );
    let graph = s.native();
    let unknown = NativeOrigin::SyntheticBase {
        size: 1,
        meta: MetaType::Unknown,
    };
    let mut expected = vec![
        (0, src(e4)),
        (
            4,
            NativeOrigin::SyntheticBase {
                size: 2,
                meta: MetaType::Int,
            },
        ),
        (
            8,
            NativeOrigin::SyntheticBase {
                size: 3,
                meta: MetaType::Uint,
            },
        ),
    ];
    expected.extend((11..23).map(|offset| (offset, unknown)));
    expected.push((24, src(f)));
    // Uint3 has native aligned size 4, so the byte array at 11 follows an
    // expected offset of 12: a native-only hole. Unknown bytes set the flag.
    let e = run(&graph, record, at(0, 16));
    assert_eq!(summary(&e), (expected, true, true, true));
    assert!(e.primitives()[0].meta == MetaType::Uint);
    assert_eq!(
        invalid(&run(&graph, record, at(0, 15))),
        NativeInvalidExtraction::MaxPrimitives { maximum: 15 }
    );
}

#[test]
fn union_refinement_prefers_integers_and_smaller_pieces_under_floats() {
    let mut s = Source::default();
    let f = s.float(4);
    let u32_ = s.int(4, false);
    let u8_ = s.int(1, false);
    let u16_ = s.int(2, false);
    let u64_ = s.int(8, false);
    let d = s.float(8);
    let floats = s.array(f, 2);
    let fi = s.union(&[f, u32_]);
    let if_ = s.union(&[u32_, f]);
    let df = s.union(&[d, floats]);
    let fd = s.union(&[floats, d]);
    let xf = s.union(&[u64_, floats]);
    let shifted = s.packed(&[u8_, u16_]);
    let bad = s.union(&[shifted, u16_]);
    let graph = s.native();
    let pieces = |ty| summary(&run(&graph, ty, at(0, 4))).0;
    assert_eq!(pieces(fi), [(0, src(u32_))]);
    assert_eq!(pieces(if_), [(0, src(u32_))]);
    assert_eq!(pieces(df), [(0, src(f)), (4, src(f))]);
    assert_eq!(pieces(fd), [(0, src(f)), (4, src(f))]);
    assert_eq!(pieces(xf), [(0, src(u64_))]);
    assert_eq!(
        invalid(&run(&graph, bad, at(0, 4))),
        NativeInvalidExtraction::IncompatibleUnion {
            union: id(bad),
            big_offset: 0,
            big_aligned_size: 2,
            small_offset: 1,
            small_aligned_size: 2,
        }
    );
}

#[test]
fn union_member_contexts_drop_flags_and_reset_array_depth() {
    let mut s = Source::default();
    let f = s.float(4);
    let u8_ = s.int(1, false);
    let u32_ = s.int(4, false);
    let o4 = s.opaque(4);
    let packed = s.packed(&[u8_, u32_]);
    let unknown_union = s.union(&[o4]);
    let misaligned_union = s.union(&[packed]);
    let holder = s.structure(&[unknown_union, misaligned_union]);
    let floats = s.array(f, 2);
    let member = s.union(&[floats]);
    let nested = s.structure(&[floats, member]);
    let graph = s.native();
    // Unknown and alignment flags of members are not copied to the parent.
    let e = run(&graph, holder, at(0, 4));
    assert_eq!(
        summary(&e),
        (
            vec![(0, src(o4)), (4, src(u8_)), (5, src(u32_))],
            false,
            true,
            false
        )
    );
    assert_eq!(e.primitives()[0].meta, MetaType::Unknown);
    // With nested arrays as primitives, the field array is one piece but the
    // union member's array is a fresh root and expands.
    let options = NativeExtractionOptions {
        nested_arrays_are_primitives: true,
        ..at(0, 4)
    };
    assert_eq!(
        summary(&run(&graph, nested, options)).0,
        [(0, src(floats)), (8, src(f)), (12, src(f))]
    );
    assert_eq!(
        summary(&run(&graph, nested, at(0, 4))).0,
        [(0, src(f)), (4, src(f)), (8, src(f)), (12, src(f))]
    );
}

#[test]
fn invalid_outcomes_are_semantic_not_errors() {
    let mut s = Source::default();
    let f = s.float(4);
    let void = s.add(TypeKind::Void);
    let function = s.add(TypeKind::Function {
        result: void,
        parameters: vec![],
        variadic: false,
    });
    let empty_union = s.union(&[]);
    let union = s.union(&[f]);
    let holder = s.structure(&[union]);
    let three = s.structure(&[f, f, f]);
    let member = s.union(&[three]);
    let with_member = s.structure(&[f, member]);
    let zero = s.array(f, 0);
    let graph = s.native();
    assert_eq!(
        invalid(&run(&graph, void, at(0, 4))),
        NativeInvalidExtraction::Unsupported {
            ty: id(void),
            meta: MetaType::Void
        }
    );
    // Code is an extractable primitive of native size one.
    let code = run(&graph, function, at(0, 4));
    assert_eq!(
        (code.primitives()[0].meta, code.primitives()[0].aligned_size),
        (MetaType::Code, 1)
    );
    assert_eq!(
        invalid(&run(&graph, empty_union, at(0, 4))),
        NativeInvalidExtraction::EmptyUnion(id(empty_union))
    );
    let reject = NativeExtractionOptions {
        reject_unions: true,
        ..at(0, 4)
    };
    assert_eq!(
        invalid(&run(&graph, holder, reject)),
        NativeInvalidExtraction::UnionRejected(id(union))
    );
    assert!(run(&graph, holder, at(0, 4)).is_valid());
    assert!(run(&graph, three, at(0, 3)).is_valid());
    assert_eq!(
        invalid(&run(&graph, three, at(0, 2))),
        NativeInvalidExtraction::MaxPrimitives { maximum: 2 }
    );
    // The member gets the full maximum; appending to the parent's one float exceeds it.
    assert_eq!(
        invalid(&run(&graph, with_member, at(0, 3))),
        NativeInvalidExtraction::MaxPrimitives { maximum: 3 }
    );
    assert_eq!(run(&graph, with_member, at(0, 4)).primitives().len(), 4);
    // A zero-element array is one unknown byte natively.
    assert_eq!(
        summary(&run(&graph, zero, at(0, 4))),
        (vec![(0, src(zero))], true, true, false)
    );
    assert!(run(&graph, zero, at(0, 0)).outcome() != run(&graph, zero, at(0, 1)).outcome());
}

#[test]
fn arrays_expand_lazily_and_inert_elements_are_skipped_exactly() {
    let mut s = Source::default();
    let f = s.float(4);
    let empty = s.structure(&[]);
    let floats = s.array(f, 500_000_000);
    let empties = s.array(empty, 2_000_000_000);
    let small = s.array(empty, 10);
    let rows = s.array(small, 100_000_000);
    let graph = s.native();
    let e = run(&graph, floats, at(0, 4));
    assert_eq!(
        invalid(&e),
        NativeInvalidExtraction::MaxPrimitives { maximum: 4 }
    );
    assert!(e.stats().work < 100);
    let e = run(&graph, empties, at(0, 4));
    assert_eq!(summary(&e), (vec![], false, true, false));
    assert_eq!(e.stats().skipped_inert_elements, 2_000_000_000);
    let e = run(&graph, rows, at(0, 4));
    assert!(e.is_valid() && e.stats().work < 100);
    assert_eq!(e.stats().peak_depth, 3);
    // Near the int4 limit the skip is refused and exact traversal reports the
    // offset overflow of element 6.
    let max = i32::MAX as u32;
    assert!(run(&graph, small, at(max - 9, 4)).is_valid());
    assert_eq!(
        NativePrimitiveExtraction::new(
            graph.clone(),
            id(small),
            at(max - 5, 4),
            Default::default()
        )
        .unwrap_err(),
        NativeExtractionError::Overflow
    );
}

#[test]
fn native_int_arithmetic_and_options_are_checked() {
    let mut s = Source::default();
    let u8_ = s.int(1, false);
    let pair = s.structure(&[u8_, u8_]);
    let incomplete = s.add(TypeKind::Incomplete);
    let graph = s.native();
    let max = i32::MAX as u32;
    assert!(run(&graph, pair, at(max - 1, 4)).is_valid());
    let new = |ty: TypeId, options| {
        NativePrimitiveExtraction::new(graph.clone(), id(ty), options, Default::default())
    };
    assert_eq!(
        new(pair, at(max, 4)).unwrap_err(),
        NativeExtractionError::Overflow
    );
    assert_eq!(
        new(pair, at(max + 1, 4)).unwrap_err(),
        NativeExtractionError::InvalidOptions("start offset exceeds the native signed-int range")
    );
    assert_eq!(
        new(pair, at(0, max + 1)).unwrap_err(),
        NativeExtractionError::InvalidOptions(
            "primitive maximum exceeds the native signed-int range"
        )
    );
    assert_eq!(
        new(incomplete, at(0, 4)).unwrap_err(),
        NativeExtractionError::Type(NativeTypeError::Conversion(
            NativeConversionError::Incomplete(incomplete)
        ))
    );
    assert!(matches!(
        NativePrimitiveExtraction::new(
            graph.clone(),
            NativeTypeId(99),
            at(0, 4),
            Default::default()
        ),
        Err(NativeExtractionError::Type(NativeTypeError::UnknownNative(
            NativeTypeId(99)
        )))
    ));
}

#[test]
fn resource_limits_are_exact_and_distinct_from_semantic_rejection() {
    let mut s = Source::default();
    let f = s.float(4);
    let d = s.float(8);
    let floats = s.array(f, 2);
    let u = s.union(&[d, floats, d]);
    let record = s.structure(&[f, u, floats]);
    let graph = s.native();
    let options = at(0, 8);
    let full = run(&graph, record, options);
    let stats = full.stats();
    assert_eq!(full.primitives().len(), 5);
    assert!(stats.refinement_steps > 0 && stats.union_contexts == 3);
    let base = NativeExtractionLimits::default();
    type Setter = fn(&mut NativeExtractionLimits, u64);
    let cases: [(&str, Setter); 3] = [
        ("live primitives", |l, n| l.max_live_primitives = n as usize),
        ("depth", |l, n| l.max_depth = n as usize),
        ("work", |l, n| l.max_work = n),
    ];
    let exact = [
        stats.peak_live_primitives as u64,
        stats.peak_depth as u64,
        stats.work,
    ];
    for ((name, set), value) in cases.into_iter().zip(exact) {
        let mut limits = base;
        set(&mut limits, value);
        let e = NativePrimitiveExtraction::new(graph.clone(), id(record), options, limits).unwrap();
        assert_eq!(e.outcome(), full.outcome(), "{name}");
        set(&mut limits, value - 1);
        assert_eq!(
            NativePrimitiveExtraction::new(graph.clone(), id(record), options, limits).unwrap_err(),
            NativeExtractionError::Limit(name)
        );
    }
    for work in 0..stats.work {
        let limits = NativeExtractionLimits {
            max_work: work,
            ..base
        };
        assert_eq!(
            NativePrimitiveExtraction::new(graph.clone(), id(record), options, limits).unwrap_err(),
            NativeExtractionError::Limit("work")
        );
    }
    // A semantic maximum below the output is an invalid outcome, not an error.
    assert_eq!(
        invalid(&run(&graph, record, at(0, 4))),
        NativeInvalidExtraction::MaxPrimitives { maximum: 4 }
    );
}

#[test]
fn deep_nesting_extracts_without_recursion() {
    let mut s = Source::default();
    for index in 0..99_999 {
        s.structure(&[TypeId(index + 1)]);
    }
    let f = s.float(4);
    let graph = s.native();
    let e = run(&graph, TypeId(0), at(0, 4));
    assert_eq!(summary(&e), (vec![(0, src(f))], false, true, false));
    assert_eq!(e.stats().peak_depth, 100_000);
    let limits = NativeExtractionLimits {
        max_depth: 99_999,
        ..Default::default()
    };
    assert_eq!(
        NativePrimitiveExtraction::new(graph.clone(), NativeTypeId(0), at(0, 4), limits)
            .unwrap_err(),
        NativeExtractionError::Limit("depth")
    );
}

#[test]
fn extraction_snapshots_share_their_graph() {
    let mut s = Source::default();
    let f = s.float(4);
    let a = s.alias(f);
    let record = s.structure(&[f, a]);
    let graph = s.native();
    let e = run(&graph, record, at(0, 4));
    assert!(Arc::ptr_eq(e.graph(), &graph));
    assert_eq!(e.root(), id(record));
    // Each primitive keeps the exact native object, including alias identity.
    assert_eq!(
        e.primitives().iter().map(|p| p.ty).collect::<Vec<_>>(),
        [id(f), id(a)]
    );
    let copy = e.clone();
    assert_eq!(copy.outcome(), e.outcome());
}
