//! Directed bitfield layout tests. Expected values are traced by hand through
//! the retained Java sources under
//! Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/data/:
//! AlignedComponentPacker.java, AlignedStructurePacker.java,
//! BitFieldDataType.java, BitFieldPackingImpl.java and UnionDataType.java.
//! Comments name the source branch a case exercises; "policy" marks behavior
//! the source leaves history-dependent.

use std::sync::Arc;

use ghidra_languages::DataOrganization;
use ghidra_types::*;

const CHAR: TypeId = TypeId(0);
const USHORT: TypeId = TypeId(1);
const SHORT: TypeId = TypeId(2);
const INT: TypeId = TypeId(3);
const LONG_LONG: TypeId = TypeId(4);
const BOOL: TypeId = TypeId(5);
const ENUM3: TypeId = TypeId(6);
const INT3: TypeId = TypeId(7);
const EMPTY: TypeId = TypeId(8);
const INT_ZERO_ARRAY: TypeId = TypeId(9);
const EMPTY_ALIGNED: TypeId = TypeId(10);

fn def(kind: TypeKind) -> TypeDefinition {
    TypeDefinition::new("", kind)
}

fn prelude() -> Vec<TypeDefinition> {
    vec![
        def(TypeKind::Builtin(Builtin::Char)),
        def(TypeKind::Builtin(Builtin::UnsignedShort)),
        def(TypeKind::Builtin(Builtin::Short)),
        def(TypeKind::Builtin(Builtin::Int)),
        def(TypeKind::Builtin(Builtin::LongLong)),
        def(TypeKind::Builtin(Builtin::Bool)),
        def(TypeKind::Enum {
            bytes: 3,
            signed: false,
        }),
        def(TypeKind::Integer {
            bytes: 3,
            signed: true,
        }),
        def(TypeKind::Structure(Composite::default())),
        def(TypeKind::Array {
            element: INT,
            count: 0,
        }),
        def(TypeKind::Structure(Composite {
            minimum_alignment: MinimumAlignment::Explicit(8),
            ..Default::default()
        })),
    ]
}

/// The conventional 1/2/4/8 map with 4-byte int and 8-byte long long.
fn org(ms: bool) -> ResolvedDataOrganization {
    let mut org = DataOrganization::default().resolve(8);
    org.use_ms_bitfield_convention = ms;
    org
}

fn ordinary(ty: TypeId) -> Field {
    Field::new("", ty)
}

fn bits(ty: TypeId, width: u32) -> Field {
    Field::bitfield("", ty, width)
}

fn composite(fields: Vec<Field>, packing: Option<u32>) -> Composite {
    Composite {
        fields,
        packing: packing.map_or(Packing::Default, Packing::Explicit),
        minimum_alignment: MinimumAlignment::Default,
    }
}

fn place_kind(
    org: &ResolvedDataOrganization,
    endianness: Endianness,
    kind: TypeKind,
) -> TypeLayout {
    let mut definitions = prelude();
    definitions.push(def(kind));
    let id = TypeId(definitions.len() - 1);
    TypeLayouts::new_with_endianness(
        definitions.into(),
        org.clone(),
        endianness,
        Limits::default(),
    )
    .unwrap()
    .layout(id)
    .unwrap()
    .clone()
}

fn structure(
    org: &ResolvedDataOrganization,
    fields: Vec<Field>,
    packing: Option<u32>,
) -> TypeLayout {
    place_kind(
        org,
        Endianness::Little,
        TypeKind::Structure(composite(fields, packing)),
    )
}

fn union(
    org: &ResolvedDataOrganization,
    endianness: Endianness,
    fields: Vec<Field>,
    packing: Option<u32>,
) -> TypeLayout {
    place_kind(org, endianness, TypeKind::Union(composite(fields, packing)))
}

/// (offset, component bytes, bit offset) per field.
fn rows(layout: &TypeLayout) -> Vec<(u64, u64, Option<u8>)> {
    layout
        .fields
        .iter()
        .map(|f| (f.offset, f.bytes, f.bitfield.map(|b| b.bit_offset)))
        .collect()
}

fn shape(layout: &TypeLayout) -> (u64, u32) {
    (layout.geometry.size.unwrap(), layout.geometry.alignment)
}

#[test]
fn ordinary_graphs_need_no_byte_order_but_bitfields_require_one() {
    let mut definitions = prelude();
    definitions.push(def(TypeKind::Structure(composite(
        vec![ordinary(CHAR), ordinary(INT)],
        None,
    ))));
    let definitions: Arc<[TypeDefinition]> = definitions.into();
    let plain = TypeLayouts::new(definitions.clone(), org(false), Limits::default()).unwrap();
    assert_eq!(plain.endianness(), None);
    for endianness in [Endianness::Little, Endianness::Big] {
        let ordered = TypeLayouts::new_with_endianness(
            definitions.clone(),
            org(false),
            endianness,
            Limits::default(),
        )
        .unwrap();
        assert_eq!(ordered.layouts(), plain.layouts());
        assert_eq!(ordered.stats(), plain.stats());
        assert_eq!(ordered.endianness(), Some(endianness));
    }
    // Even an unreferenced bitfield composite needs the byte order.
    let mut definitions = prelude();
    definitions.push(def(TypeKind::Union(composite(
        vec![ordinary(CHAR), bits(INT, 3)],
        None,
    ))));
    assert_eq!(
        TypeLayouts::new(definitions.into(), org(true), Limits::default()).unwrap_err(),
        Error::EndiannessRequired {
            owner: TypeId(11),
            field: 1
        }
    );
}

#[test]
fn b1_matches_the_retained_gcc_and_msvc_fixtures() {
    // bitfields.h B1: char a; unsigned short b:6; int c:8; short d:4.
    // StructureLittleEndianBitFieldTest.java:129-142,
    // StructureBigEndianBitFieldTest.java:98-110, MSVCStructureBitFieldTest.java:96-109.
    let fields = || {
        vec![
            Field::new("a", CHAR),
            Field::bitfield("b", USHORT, 6),
            Field::bitfield("c", INT, 8),
            Field::bitfield("d", SHORT, 4),
        ]
    };
    let kind = || TypeKind::Structure(composite(fields(), None));
    let gcc_le = place_kind(&org(false), Endianness::Little, kind());
    assert_eq!(
        rows(&gcc_le),
        [
            (0, 1, None),
            (1, 1, Some(0)),
            (1, 2, Some(6)),
            (2, 2, Some(6))
        ]
    );
    assert_eq!(shape(&gcc_le), (4, 4));
    let gcc_be = place_kind(&org(false), Endianness::Big, kind());
    assert_eq!(
        rows(&gcc_be),
        [
            (0, 1, None),
            (1, 1, Some(2)),
            (1, 2, Some(2)),
            (2, 2, Some(6))
        ]
    );
    assert_eq!(shape(&gcc_be), (4, 4));
    let ms_le = place_kind(&org(true), Endianness::Little, kind());
    assert_eq!(
        rows(&ms_le),
        [
            (0, 1, None),
            (2, 1, Some(0)),
            (4, 1, Some(0)),
            (8, 1, Some(0))
        ]
    );
    assert_eq!(shape(&ms_le), (12, 4));
    // No Java fixture: the MS big-endian bits mirror within one-byte storage.
    let ms_be = place_kind(&org(true), Endianness::Big, kind());
    assert_eq!(
        rows(&ms_be),
        [
            (0, 1, None),
            (2, 1, Some(2)),
            (4, 1, Some(0)),
            (8, 1, Some(4))
        ]
    );
    let c = gcc_le.fields[2].bitfield.unwrap();
    assert_eq!(
        c,
        BitfieldLayout {
            declared_bits: 8,
            effective_bits: 8,
            base_bytes: 4,
            storage_bytes: 2,
            bit_offset: 6
        }
    );
    // The bitfield reports its declared base's alignment, not a placement.
    assert_eq!(gcc_le.fields[2].alignment, 4);
    assert_eq!(gcc_le.fields[2].ty, INT);
}

#[test]
fn declared_effective_storage_and_unit_sizes_stay_distinct() {
    // getEffectiveBitSize clamps; storage is minimal from the byte offset.
    let fields = || {
        vec![
            ordinary(CHAR),
            bits(INT, 85),
            bits(LONG_LONG, 255),
            bits(BOOL, 1),
            bits(CHAR, 8),
        ]
    };
    for ms in [false, true] {
        let layout = structure(&org(ms), fields(), None);
        // MS opens a new unit at each base-size change; here both agree.
        assert_eq!(
            rows(&layout),
            [
                (0, 1, None),
                (4, 4, Some(0)),
                (8, 8, Some(0)),
                (16, 1, Some(0)),
                (17, 1, Some(0))
            ],
            "MS={ms}"
        );
        assert_eq!(shape(&layout), (24, 8));
        let details: Vec<_> = layout.fields[1..]
            .iter()
            .map(|f| {
                let b = f.bitfield.unwrap();
                (
                    b.declared_bits,
                    b.effective_bits,
                    b.base_bytes,
                    b.storage_bytes,
                )
            })
            .collect();
        assert_eq!(
            details,
            [(85, 32, 4, 4), (255, 64, 8, 8), (1, 1, 1, 1), (8, 8, 1, 1)]
        );
    }
}

#[test]
fn invalid_widths_and_ineligible_bases_fail_explicitly() {
    let reject = |definitions: Vec<TypeDefinition>, expected: fn(&Error) -> bool| {
        let error = TypeLayouts::new_with_endianness(
            definitions.into(),
            org(false),
            Endianness::Little,
            Limits::default(),
        )
        .unwrap_err();
        assert!(expected(&error), "{error:?}");
    };
    let mut definitions = prelude();
    definitions.push(def(TypeKind::Structure(composite(
        vec![bits(CHAR, 255), bits(CHAR, MAX_BITFIELD_BITS + 1)],
        None,
    ))));
    reject(definitions, |e| {
        matches!(
            e,
            Error::InvalidBitfield {
                owner: TypeId(11),
                field: 1,
                ..
            }
        )
    });
    // WideCharDataType and float types are not AbstractIntegerDataType.
    let ineligible = [
        TypeKind::Builtin(Builtin::WChar),
        TypeKind::Builtin(Builtin::Float),
        TypeKind::Builtin(Builtin::Double),
        TypeKind::Builtin(Builtin::LongDouble),
        TypeKind::Float { bytes: 4 },
        TypeKind::Opaque { bytes: 4 },
        TypeKind::Pointer {
            target: CHAR,
            bytes: None,
        },
        TypeKind::Array {
            element: INT,
            count: 1,
        },
        TypeKind::Structure(Composite::default()),
        TypeKind::Void,
        TypeKind::Incomplete,
        TypeKind::Function {
            result: INT,
            parameters: vec![],
            variadic: false,
        },
    ];
    for kind in ineligible {
        for aliases in 0..3 {
            let mut definitions = prelude();
            definitions.push(def(kind.clone()));
            for _ in 0..aliases {
                let target = TypeId(definitions.len() - 1);
                definitions.push(def(TypeKind::Alias(target)));
            }
            let base = TypeId(definitions.len() - 1);
            definitions.push(def(TypeKind::Union(composite(
                vec![ordinary(CHAR), bits(base, 1)],
                None,
            ))));
            reject(definitions, |e| {
                matches!(e, Error::InvalidBitfield { field: 1, .. })
            });
        }
    }
    let eligible = [
        TypeKind::Builtin(Builtin::Bool),
        TypeKind::Builtin(Builtin::Char),
        TypeKind::Builtin(Builtin::SignedChar),
        TypeKind::Builtin(Builtin::UnsignedChar),
        TypeKind::Builtin(Builtin::UnsignedLongLong),
        TypeKind::Integer {
            bytes: 16,
            signed: false,
        },
        TypeKind::Enum {
            bytes: 8,
            signed: true,
        },
    ];
    for kind in eligible {
        let mut definitions = prelude();
        definitions.push(def(kind));
        definitions.push(def(TypeKind::Alias(TypeId(11))));
        definitions.push(def(TypeKind::Alias(TypeId(12))));
        definitions.push(def(TypeKind::Structure(composite(
            vec![bits(TypeId(11), 0), bits(TypeId(13), 1)],
            None,
        ))));
        TypeLayouts::new_with_endianness(
            definitions.into(),
            org(false),
            Endianness::Big,
            Limits::default(),
        )
        .unwrap();
    }
}

#[test]
fn union_bitfields_follow_the_retained_allocation_rules() {
    // UnionLittleEndianBitFieldTest.java:39-107 and MSVCUnionBitFieldTest.java:37-105.
    for (ms, packing, plain, with_zero) in [
        (false, None, (4, 4), (4, 4)),
        (false, Some(1), (1, 1), (1, 1)),
        (false, Some(2), (2, 2), (2, 2)),
        (true, None, (4, 4), (8, 8)),
        (true, Some(1), (4, 1), (8, 1)),
        (true, Some(2), (4, 2), (8, 2)),
    ] {
        let org = org(ms);
        let u1 = union(
            &org,
            Endianness::Little,
            vec![bits(INT, 4), bits(INT, 2)],
            packing,
        );
        assert_eq!(shape(&u1), plain, "MS={ms}, pack={packing:?}");
        let u1z = union(
            &org,
            Endianness::Little,
            vec![bits(INT, 4), bits(LONG_LONG, 0), bits(INT, 2)],
            packing,
        );
        assert_eq!(shape(&u1z), with_zero, "MS={ms}, pack={packing:?}");
        assert_eq!(
            rows(&u1z),
            [(0, 1, Some(0)), (0, 0, Some(0)), (0, 1, Some(0))]
        );
        assert_eq!(u1z.fields[1].bitfield.unwrap().storage_bytes, 1);
    }
    // GCC pack below the base allocates LCM(minimal storage, pack): 3 and 2.
    for (packing, expected) in [
        (None, (4, 4)),
        (Some(1), (3, 1)),
        (Some(2), (6, 2)),
        (Some(4), (4, 4)),
    ] {
        let u = union(
            &org(false),
            Endianness::Little,
            vec![bits(INT, 17)],
            packing,
        );
        assert_eq!(shape(&u), expected, "pack={packing:?}");
        let ms = union(&org(true), Endianness::Little, vec![bits(INT, 17)], packing);
        assert_eq!(ms.geometry.size, Some(4), "MS pack={packing:?}");
    }
    // Big-endian union bits are right-aligned in minimal storage; :0 uses 7.
    let be = union(
        &org(false),
        Endianness::Big,
        vec![
            bits(INT, 4),
            bits(LONG_LONG, 0),
            bits(INT, 2),
            bits(INT, 17),
        ],
        None,
    );
    assert_eq!(
        rows(&be),
        [
            (0, 1, Some(4)),
            (0, 0, Some(7)),
            (0, 1, Some(6)),
            (0, 3, Some(7))
        ]
    );
    // A GCC zero-only union stays logically empty; MS allocates the base.
    let gcc_zero = union(&org(false), Endianness::Little, vec![bits(INT, 0)], None);
    assert_eq!(
        gcc_zero.geometry,
        Geometry {
            size: Some(0),
            length: Some(1),
            aligned_length: Some(1),
            alignment: 1
        }
    );
    let ms_zero = union(&org(true), Endianness::Little, vec![bits(INT, 0)], None);
    assert_eq!(shape(&ms_zero), (4, 4));
    let mixed = union(
        &org(false),
        Endianness::Little,
        vec![ordinary(CHAR), bits(LONG_LONG, 3)],
        None,
    );
    assert_eq!(shape(&mixed), (8, 8));
    assert_eq!(rows(&mixed), [(0, 1, None), (0, 1, Some(0))]);
}

#[test]
fn zero_width_type_alignment_switch_and_boundary_are_gcc_only() {
    let interior = || vec![ordinary(CHAR), bits(INT, 0), ordinary(CHAR)];
    let trailing = || vec![ordinary(CHAR), bits(INT, 0)];
    // (MS, type alignment enabled, zero boundary, interior rows, interior shape,
    //  trailing zero offset, trailing shape)
    for (ms, enabled, boundary, inner, inner_shape, tail, tail_shape) in [
        // Interior GCC :0 uses natural alignment and conveys nothing to an
        // ordinary successor; a trailing :0 conveys its packed alignment.
        (false, true, 0, [0, 4, 4], (5, 1), 4, (4, 4)),
        // Disabled type alignment uses the positive boundary, else 1. The
        // trailing offset still rounds to natural base alignment.
        (false, false, 0, [0, 1, 1], (2, 1), 4, (4, 1)),
        (false, false, 16, [0, 16, 16], (17, 1), 4, (16, 16)),
        // MS ignores :0 after an ordinary member and ignores both settings.
        (true, true, 0, [0, 1, 1], (2, 1), 4, (4, 1)),
        (true, false, 16, [0, 1, 1], (2, 1), 4, (4, 1)),
    ] {
        let mut org = org(ms);
        org.bitfield_type_alignment_enabled = enabled;
        org.bitfield_zero_length_boundary = boundary;
        let context = format!("MS={ms}, enabled={enabled}, boundary={boundary}");
        let layout = structure(&org, interior(), None);
        let offsets: Vec<_> = layout.fields.iter().map(|f| f.offset).collect();
        assert_eq!(offsets, inner, "{context}");
        assert_eq!(shape(&layout), inner_shape, "{context}");
        let layout = structure(&org, trailing(), None);
        assert_eq!(layout.fields[1].offset, tail, "{context}");
        assert_eq!(shape(&layout), tail_shape, "{context}");
    }
    // MS honors :0 after a bitfield and conveys its alignment.
    let layout = structure(
        &org(true),
        vec![bits(CHAR, 3), bits(INT, 0), ordinary(CHAR)],
        None,
    );
    assert_eq!(
        rows(&layout),
        [(0, 1, Some(0)), (4, 0, Some(0)), (4, 1, None)]
    );
    assert_eq!(shape(&layout), (8, 4));
}

#[test]
fn trailing_zero_width_rounds_naturally_but_conveys_packed_alignment() {
    // StructureLittleEndianBitFieldTest.java:382-394 and MSVCStructureBitFieldTest.java:349-361.
    let fields = || {
        vec![
            ordinary(CHAR),
            bits(USHORT, 6),
            bits(INT, 8),
            bits(INT, 4),
            bits(LONG_LONG, 0),
        ]
    };
    for (ms, packing, zero_offset, expected) in [
        (false, None, 8, (8, 8)),
        (false, Some(1), 8, (8, 1)),
        (false, Some(2), 8, (8, 2)),
        (true, None, 8, (8, 8)),
        (true, Some(1), 8, (8, 1)),
    ] {
        let layout = structure(&org(ms), fields(), packing);
        assert_eq!(
            layout.fields[4].offset, zero_offset,
            "MS={ms}, pack={packing:?}"
        );
        assert_eq!(layout.fields[4].bytes, 0);
        assert_eq!(shape(&layout), expected, "MS={ms}, pack={packing:?}");
    }
}

#[test]
fn repeated_zero_width_bitfields_use_the_declaration_order_policy() {
    // Java never re-places the first of two adjacent :0 members. Policy: it
    // keeps its trailing placement from declaration-order construction.
    let interior = || {
        vec![
            ordinary(CHAR),
            bits(INT, 0),
            bits(LONG_LONG, 0),
            ordinary(CHAR),
        ]
    };
    // GCC reads the second group offset from that policy offset; MS advances
    // it by the first base size even though the first :0 is ignored.
    for (ms, packing, expected_rows, expected_shape) in [
        (false, None, [0, 4, 8, 8], (9, 1)),
        (false, Some(1), [0, 4, 8, 8], (9, 1)),
        (true, None, [0, 4, 8, 8], (16, 8)),
        (true, Some(2), [0, 4, 6, 6], (8, 2)),
    ] {
        let layout = structure(&org(ms), interior(), packing);
        let offsets: Vec<_> = layout.fields.iter().map(|f| f.offset).collect();
        assert_eq!(offsets, expected_rows, "MS={ms}, pack={packing:?}");
        assert_eq!(shape(&layout), expected_shape, "MS={ms}, pack={packing:?}");
    }
    for ms in [false, true] {
        let layout = structure(
            &org(ms),
            vec![bits(CHAR, 3), bits(INT, 0), bits(LONG_LONG, 0)],
            None,
        );
        let offsets: Vec<_> = layout.fields.iter().map(|f| f.offset).collect();
        assert_eq!(offsets, [0, 4, 8], "MS={ms}");
        assert_eq!(shape(&layout), (8, 8), "MS={ms}");
    }
}

#[test]
fn gcc_interior_zero_conveys_alignment_only_through_a_bitfield_successor() {
    // adjustZeroLengthBitField records the successor's minimum alignment;
    // under GCC a bitfield successor's minimum is the :0 alignment itself.
    let gcc = org(false);
    let ordinary_tail = structure(
        &gcc,
        vec![ordinary(CHAR), bits(LONG_LONG, 0), ordinary(CHAR)],
        None,
    );
    assert_eq!(
        rows(&ordinary_tail),
        [(0, 1, None), (8, 0, Some(0)), (8, 1, None)]
    );
    assert_eq!(shape(&ordinary_tail), (9, 1));
    let bitfield_tail = structure(
        &gcc,
        vec![ordinary(CHAR), bits(LONG_LONG, 0), bits(CHAR, 3)],
        None,
    );
    assert_eq!(
        rows(&bitfield_tail),
        [(0, 1, None), (8, 0, Some(0)), (8, 1, Some(0))]
    );
    assert_eq!(shape(&bitfield_tail), (16, 8));
    // Interior placement ignores pack; the conveyed alignment is capped.
    let packed = structure(
        &gcc,
        vec![ordinary(CHAR), bits(LONG_LONG, 0), bits(CHAR, 3)],
        Some(2),
    );
    assert_eq!(packed.fields[2].offset, 8);
    assert_eq!(shape(&packed), (10, 2));
    // An 8-byte base can start at 4 after int:0 and still convey 8 (Z5).
    let z5 = structure(
        &gcc,
        vec![
            ordinary(CHAR),
            bits(INT, 0),
            bits(LONG_LONG, 6),
            bits(INT, 8),
        ],
        None,
    );
    assert_eq!(
        rows(&z5),
        [
            (0, 1, None),
            (4, 0, Some(0)),
            (4, 1, Some(0)),
            (4, 2, Some(6))
        ]
    );
    assert_eq!(shape(&z5), (8, 8));
    // MS ignores this :0 and places the bitfield at its own alignment.
    let ms = structure(
        &org(true),
        vec![ordinary(CHAR), bits(LONG_LONG, 0), bits(CHAR, 3)],
        None,
    );
    assert_eq!(rows(&ms), [(0, 1, None), (1, 0, Some(0)), (1, 1, Some(0))]);
    assert_eq!(shape(&ms), (2, 1));
}

#[test]
fn enum_bases_place_by_enum_alignment_and_convey_unsigned_integer_alignment() {
    // A 3-byte enum aligns as size 3 (2 here). getPrimitiveBaseDataType makes
    // it a 3-byte unsigned integer: aligned length 4, alignment 4.
    let gcc = org(false);
    let fields = |base| vec![ordinary(CHAR), ordinary(CHAR), bits(CHAR, 7), bits(base, 4)];
    let by_enum = structure(&gcc, fields(ENUM3), None);
    assert_eq!(by_enum.fields[3].offset, 2);
    assert_eq!(by_enum.fields[3].bytes, 2);
    assert_eq!(by_enum.fields[3].bitfield.unwrap().bit_offset, 7);
    assert_eq!(by_enum.fields[3].bitfield.unwrap().base_bytes, 3);
    assert_eq!(by_enum.fields[3].alignment, 2);
    assert_eq!(shape(&by_enum), (4, 4));
    // A 3-byte integer places with alignment 4 and skips the straddle.
    let by_integer = structure(&gcc, fields(INT3), None);
    assert_eq!(rows(&by_integer)[3], (4, 1, Some(0)));
    assert_eq!(shape(&by_integer), (8, 4));
    // A first-in-group MS bitfield uses the conveyed integer alignment.
    let ms = structure(&org(true), vec![ordinary(CHAR), bits(ENUM3, 4)], None);
    assert_eq!(rows(&ms), [(0, 1, None), (4, 1, Some(0))]);
    assert_eq!(shape(&ms), (8, 4));
}

#[test]
fn ms_unit_restart_uses_the_tentative_storage_after_a_move() {
    // enum3 c:16 starts with one consumed bit at byte 3 (tentative storage 3),
    // crosses its 2-aligned window and moves to byte 4 with storage 2. The
    // source tests the unit restart with the tentative end, 4 + 3 - 1 = 6,
    // which reaches the unit 3..6, so the unit restarts at 4 and `d` lands at
    // 4 + 3. The final storage end, 5, would have kept the unit at 3.
    let fields = || {
        vec![
            bits(ENUM3, 24),
            bits(ENUM3, 1),
            bits(ENUM3, 16),
            ordinary(CHAR),
        ]
    };
    let little = place_kind(
        &org(true),
        Endianness::Little,
        TypeKind::Structure(composite(fields(), None)),
    );
    assert_eq!(
        rows(&little),
        [
            (0, 3, Some(0)),
            (3, 1, Some(0)),
            (4, 2, Some(0)),
            (7, 1, None)
        ]
    );
    assert_eq!(shape(&little), (8, 4));
    let big = place_kind(
        &org(true),
        Endianness::Big,
        TypeKind::Structure(composite(fields(), None)),
    );
    assert_eq!(
        rows(&big),
        [
            (0, 3, Some(0)),
            (3, 1, Some(7)),
            (4, 2, Some(0)),
            (7, 1, None)
        ]
    );
}

#[test]
fn source_placement_can_straddle_a_base_unit_under_packing() {
    // With pack(1) the placement alignment is 1, so only an oversize
    // tentative storage forces a skip. This is retained-source behavior,
    // not a compiler ABI claim.
    let fields = || vec![bits(INT, 20), bits(INT, 20)];
    for (ms, packing, second, expected) in [
        (true, Some(1), (2, 3, Some(4)), (6, 1)),
        (false, Some(1), (2, 3, Some(4)), (5, 1)),
        (true, None, (4, 3, Some(0)), (8, 4)),
        (false, None, (4, 3, Some(0)), (8, 4)),
    ] {
        let layout = structure(&org(ms), fields(), packing);
        assert_eq!(
            rows(&layout),
            [(0, 3, Some(0)), second],
            "MS={ms}, pack={packing:?}"
        );
        assert_eq!(shape(&layout), expected, "MS={ms}, pack={packing:?}");
    }
    // After a GCC zero-width bitfield there is no straddle check (x3p4).
    let layout = structure(
        &org(false),
        vec![ordinary(CHAR), bits(SHORT, 0), bits(INT, 27)],
        None,
    );
    assert_eq!(
        rows(&layout),
        [(0, 1, None), (2, 0, Some(0)), (2, 4, Some(0))]
    );
    assert_eq!(shape(&layout), (8, 4));
}

#[test]
fn empty_logical_members_beside_bitfields_keep_zero_extent() {
    for ms in [false, true] {
        let org = org(ms);
        let empty = structure(
            &org,
            vec![bits(CHAR, 3), ordinary(EMPTY), bits(CHAR, 3)],
            None,
        );
        assert_eq!(
            rows(&empty),
            [(0, 1, Some(0)), (1, 0, None), (1, 1, Some(0))],
            "MS={ms}"
        );
        assert_eq!(shape(&empty), (2, 1));
        let array = structure(
            &org,
            vec![bits(CHAR, 3), ordinary(INT_ZERO_ARRAY), bits(CHAR, 3)],
            None,
        );
        assert_eq!(
            rows(&array),
            [(0, 1, Some(0)), (4, 0, None), (4, 1, Some(0))],
            "MS={ms}"
        );
        assert_eq!(shape(&array), (8, 4));
        let aligned = structure(
            &org,
            vec![bits(CHAR, 3), ordinary(EMPTY_ALIGNED), bits(CHAR, 3)],
            None,
        );
        assert_eq!(
            rows(&aligned)[1..],
            [(8, 0, None), (8, 1, Some(0))],
            "MS={ms}"
        );
        assert_eq!(shape(&aligned), (16, 8));
    }
    // A bitfield-only GCC structure ending in :0 can be logically empty.
    let empty = structure(&org(false), vec![bits(INT, 0)], None);
    assert_eq!(
        empty.geometry,
        Geometry {
            size: Some(0),
            length: Some(1),
            aligned_length: Some(1),
            alignment: 4
        }
    );
}

#[test]
fn alias_chains_are_classified_once_rather_than_walked_per_bitfield() {
    fn graph(chain: usize, bitfields: usize) -> TypeLayouts {
        let mut definitions: Vec<_> = (0..chain)
            .map(|i| def(TypeKind::Alias(TypeId(i + 1))))
            .collect();
        definitions.push(def(TypeKind::Builtin(Builtin::Int)));
        definitions.push(def(TypeKind::Structure(composite(
            (0..bitfields).map(|_| bits(TypeId(0), 1)).collect(),
            None,
        ))));
        let limits = Limits {
            max_types: chain + 2,
            max_depth: chain + 2,
            ..Default::default()
        };
        TypeLayouts::new_with_endianness(definitions.into(), org(false), Endianness::Little, limits)
            .unwrap()
    }
    // A per-bitfield chain walk would cost 2e9 steps, far above default work.
    let small = graph(50_000, 10_000);
    let large = graph(100_000, 20_000);
    assert!(large.stats().work <= 2 * small.stats().work);
    let record = large.layout(TypeId(100_001)).unwrap();
    assert_eq!(record.fields.len(), 20_000);
    assert_eq!(rows(record)[19_999], (2499, 1, Some(7)));
    assert_eq!(shape(record), (2500, 4));
}

#[test]
fn bitfield_graphs_honor_every_limit_exactly() {
    let definitions: Arc<[TypeDefinition]> = vec![
        TypeDefinition::new("integer", TypeKind::Builtin(Builtin::Int)),
        TypeDefinition::new("alias", TypeKind::Alias(TypeId(0))),
        TypeDefinition::new(
            "struct",
            TypeKind::Structure(Composite {
                fields: vec![
                    Field::bitfield("bits", TypeId(1), 3),
                    Field::bitfield("zero", TypeId(0), 0),
                    Field::new("tail", TypeId(0)),
                ],
                ..Default::default()
            }),
        ),
    ]
    .into();
    let organization = org(false);
    let build = |limits| {
        TypeLayouts::new_with_endianness(
            definitions.clone(),
            organization.clone(),
            Endianness::Big,
            limits,
        )
    };
    let baseline = build(Limits::default()).unwrap();
    assert_eq!(
        rows(baseline.layout(TypeId(2)).unwrap()),
        [(0, 1, Some(5)), (4, 0, Some(7)), (4, 4, None)]
    );
    let stats = baseline.stats();
    let exact = Limits {
        max_types: stats.types,
        max_fields: stats.fields,
        max_references: stats.references,
        max_name_length: 7,
        max_name_bytes: stats.name_bytes,
        max_alignment_entries: 4,
        max_depth: stats.depth,
        max_type_bytes: 8,
        max_work: stats.work,
    };
    assert_eq!(build(exact).unwrap().layouts(), baseline.layouts());
    type LimitCase = (Resource, fn(&mut Limits));
    let cases: &[LimitCase] = &[
        (Resource::Types, |l| l.max_types -= 1),
        (Resource::Fields, |l| l.max_fields -= 1),
        (Resource::References, |l| l.max_references -= 1),
        (Resource::NameLength, |l| l.max_name_length -= 1),
        (Resource::NameBytes, |l| l.max_name_bytes -= 1),
        (Resource::AlignmentEntries, |l| l.max_alignment_entries -= 1),
        (Resource::Depth, |l| l.max_depth -= 1),
        (Resource::TypeBytes, |l| l.max_type_bytes -= 1),
        (Resource::Work, |l| l.max_work -= 1),
    ];
    for (resource, change) in cases {
        let mut limits = exact;
        change(&mut limits);
        assert_eq!(build(limits).unwrap_err(), Error::Limit(*resource));
    }
    for work in 0..stats.work {
        assert_eq!(
            build(Limits {
                max_work: work,
                ..exact
            })
            .unwrap_err(),
            Error::Limit(Resource::Work)
        );
    }
}

#[test]
fn bitfield_arithmetic_is_checked_and_extents_are_capped() {
    let huge = |count: u64| {
        let mut definitions = prelude();
        definitions.push(def(TypeKind::Array {
            element: CHAR,
            count,
        }));
        definitions.push(def(TypeKind::Structure(composite(
            vec![ordinary(TypeId(11)), bits(INT, 3)],
            None,
        ))));
        definitions
    };
    let unlimited = Limits {
        max_type_bytes: u64::MAX,
        ..Default::default()
    };
    for ms in [false, true] {
        assert_eq!(
            TypeLayouts::new_with_endianness(
                huge(u64::MAX - 1).into(),
                org(ms),
                Endianness::Little,
                unlimited
            )
            .unwrap_err(),
            Error::Overflow(TypeId(12)),
            "MS={ms}"
        );
        assert_eq!(
            TypeLayouts::new_with_endianness(
                huge(i32::MAX as u64 - 1).into(),
                org(ms),
                Endianness::Little,
                Limits::default()
            )
            .unwrap_err(),
            Error::Limit(Resource::TypeBytes),
            "MS={ms}"
        );
    }
    // Many maximal declarations need no per-bit or per-byte storage.
    let mut definitions = prelude();
    definitions.push(def(TypeKind::Structure(composite(
        (0..100_000).map(|_| bits(LONG_LONG, 255)).collect(),
        None,
    ))));
    let layouts = TypeLayouts::new_with_endianness(
        definitions.into(),
        org(true),
        Endianness::Big,
        Limits::default(),
    )
    .unwrap();
    assert_eq!(
        layouts.layout(TypeId(11)).unwrap().geometry.size,
        Some(800_000)
    );
}

#[test]
fn bitfield_layouts_are_clone_send_sync_values() {
    let mut definitions = prelude();
    definitions.push(def(TypeKind::Structure(composite(
        vec![bits(INT, 3)],
        None,
    ))));
    let layouts = TypeLayouts::new_with_endianness(
        definitions.into(),
        org(false),
        Endianness::Big,
        Limits::default(),
    )
    .unwrap();
    let clone = layouts.clone();
    drop(layouts);
    assert_eq!(clone.endianness(), Some(Endianness::Big));
    assert_eq!(
        clone.layout(TypeId(11)).unwrap().fields[0]
            .bitfield
            .unwrap()
            .bit_offset,
        5
    );
    fn send_sync<T: Send + Sync + Clone>() {}
    send_sync::<TypeLayouts>();
    send_sync::<BitfieldLayout>();
    send_sync::<Field>();
}
