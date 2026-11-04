//! Directed conversion tests. Each expected value is derived by hand from the
//! Java transport (PcodeDataTypeManager) and the native decoders in type.cc.
mod native_common;

use std::sync::Arc;

use ghidra_abi::*;
use ghidra_languages::MetaType;
use ghidra_types::{
    Builtin, Endianness, Field, MinimumAlignment, Packing, TypeId, TypeKind, TypeLayouts,
};
use native_common::*;

fn geometry(graph: &NativeTypeGraph, ty: TypeId) -> (MetaType, u32, u32, u32) {
    let native = graph.get(graph.native(ty).unwrap()).unwrap();
    (
        native.meta,
        native.size,
        native.aligned_size,
        native.alignment,
    )
}

#[test]
fn every_source_kind_decodes_to_its_transported_native_form() {
    let mut s = Source::default();
    let void = s.add(TypeKind::Void);
    let function = s.add(TypeKind::Function {
        result: void,
        parameters: vec![],
        variadic: false,
    });
    let int3 = s.int(3, true);
    let enum3 = s.add(TypeKind::Enum {
        bytes: 3,
        signed: false,
    });
    let enum2 = s.add(TypeKind::Enum {
        bytes: 2,
        signed: true,
    });
    let pointer3 = s.add(TypeKind::Pointer {
        target: void,
        bytes: Some(3),
    });
    let pointer = s.add(TypeKind::Pointer {
        target: void,
        bytes: None,
    });
    let char_ = s.add(TypeKind::Builtin(Builtin::Char));
    let uchar = s.add(TypeKind::Builtin(Builtin::UnsignedChar));
    let wchar = s.add(TypeKind::Builtin(Builtin::WChar));
    let bool_ = s.add(TypeKind::Builtin(Builtin::Bool));
    let long_double = s.add(TypeKind::Builtin(Builtin::LongDouble));
    let float10 = s.float(10);
    let opaque15 = s.opaque(15);
    let opaque16 = s.opaque(16);
    let opaque17 = s.opaque(17);
    let float = s.float(4);
    let zero = s.array(float, 0);
    let graph = s.native();

    use MetaType::*;
    assert_eq!(geometry(&graph, void), (Void, 0, 0, 1));
    assert_eq!(geometry(&graph, function), (Code, 1, 1, 1));
    assert_eq!(geometry(&graph, int3), (Int, 3, 4, 4));
    // type.cc:1572 normalizes enum transport tags; the enum sub-meta remains.
    assert_eq!(geometry(&graph, enum3), (Uint, 3, 4, 4));
    assert_eq!(geometry(&graph, enum2), (Int, 2, 2, 2));
    assert!(graph.get(id(enum3)).unwrap().enumeration);
    assert!(!graph.get(id(int3)).unwrap().enumeration);
    assert_eq!(geometry(&graph, pointer3), (Ptr, 3, 4, 4));
    assert_eq!(geometry(&graph, pointer), (Ptr, 8, 8, 8));
    assert_eq!(
        graph.shape(id(pointer3)).unwrap(),
        NativeShape::Pointer { target: void }
    );
    assert_eq!(geometry(&graph, char_), (Int, 1, 1, 1)); // Default organization: signed char.
    assert_eq!(geometry(&graph, uchar), (Uint, 1, 1, 1));
    assert_eq!(geometry(&graph, wchar), (Int, 2, 2, 2));
    assert_eq!(geometry(&graph, bool_), (Bool, 1, 1, 1));
    assert_eq!(geometry(&graph, long_double), (Float, 8, 8, 8));
    // floor(10)=8 pads to 16; the second lookup at 16 is 8.
    assert_eq!(geometry(&graph, float10), (Float, 10, 16, 8));
    assert_eq!(geometry(&graph, opaque15), (Unknown, 15, 16, 8));
    assert_eq!(geometry(&graph, opaque16), (Struct, 16, 16, 1));
    assert_eq!(geometry(&graph, opaque17), (Struct, 17, 17, 1));
    assert!(graph.fields(id(opaque17)).unwrap().is_empty());
    // A zero-element array is opaque data of its public length one.
    assert_eq!(geometry(&graph, zero), (Unknown, 1, 1, 1));
    assert_eq!(graph.shape(id(zero)).unwrap(), NativeShape::Leaf);
    assert_eq!(graph.array(id(zero)).unwrap(), None);
    assert!(graph.is_fully_converted());
    assert_eq!(graph.stats().synthetic, 0);
    for index in 0..s.defs.len() {
        assert_eq!(
            graph.get(NativeTypeId(index)).unwrap().origin,
            NativeOrigin::Source(TypeId(index))
        );
        assert_eq!(graph.native(TypeId(index)).unwrap(), NativeTypeId(index));
    }
    assert_eq!(
        graph.native(TypeId(s.defs.len())),
        Err(NativeTypeError::UnknownSource(TypeId(s.defs.len())))
    );
}

#[test]
fn native_geometry_uses_the_decoder_map_with_two_lookups_only() {
    let mut s = Source::default();
    let function = s.add(TypeKind::Function {
        result: TypeId(1),
        parameters: vec![],
        variadic: false,
    });
    let void = s.add(TypeKind::Void);
    let float = s.float(4);
    let zero = s.array(float, 0);
    let int2 = s.int(2, true);
    let int3 = s.int(3, true);
    let int4 = s.int(4, true);
    use MetaType::*;

    let odd = s.native_with_map(&[(1, 2), (3, 1), (4, 8)]);
    assert_eq!(geometry(&odd, function), (Code, 1, 1, 1)); // TypeCode fixes alignment one.
    assert_eq!(geometry(&odd, void), (Void, 0, 0, 1));
    assert_eq!(geometry(&odd, zero), (Unknown, 1, 2, 2));
    assert_eq!(geometry(&odd, int2), (Int, 2, 2, 2));
    assert_eq!(geometry(&odd, int3), (Int, 3, 3, 1));
    assert_eq!(geometry(&odd, int4), (Int, 4, 8, 8));

    // Nonmonotonic: 2 pads to 8, whose floor entry (4) gives alignment 2.
    let nonmonotonic = s.native_with_map(&[(2, 8), (4, 2)]);
    assert_eq!(geometry(&nonmonotonic, int2), (Int, 2, 8, 2));
    assert_eq!(geometry(&nonmonotonic, zero), (Unknown, 1, 1, 1));
    // Java's layout of the same snapshot is unchanged and independent.
    let java = odd.layouts().layout(int4).unwrap().geometry;
    assert_eq!((java.aligned_length, java.alignment), (Some(4), 4));
}

#[test]
fn nonzero_arrays_keep_encoded_size_and_reject_native_mismatch() {
    let mut s = Source::default();
    let float = s.float(4);
    let alias = s.alias(float);
    let floats = s.array(float, 3);
    let aliases = s.array(alias, 2);
    let enum3 = s.add(TypeKind::Enum {
        bytes: 3,
        signed: true,
    });
    let enums = s.array(enum3, 2);
    let void = s.add(TypeKind::Void);
    let pointer3 = s.add(TypeKind::Pointer {
        target: void,
        bytes: Some(3),
    });
    let pointers = s.array(pointer3, 2);
    let empty = s.composite(&[], Packing::Default, MinimumAlignment::Explicit(16), false);
    let empties = s.array(empty, 2);
    let holder = s.structure(&[enums]);
    let pointer_to_bad = s.add(TypeKind::Pointer {
        target: enums,
        bytes: None,
    });
    let graph = s.native();

    assert_eq!(geometry(&graph, floats), (MetaType::Array, 12, 12, 4));
    assert_eq!(
        graph.array(id(floats)).unwrap(),
        Some(NativeArray {
            element: id(float),
            count: 3,
            stride: 4
        })
    );
    // The element is the declared alias object, not its canonical float.
    assert_eq!(
        graph.array(id(aliases)).unwrap().unwrap().element,
        id(alias)
    );
    // Java enum/pointer aligned lengths are their widths; native pads 3 to 4.
    assert_eq!(
        graph.native(enums),
        Err(NativeTypeError::Conversion(
            NativeConversionError::ArraySizeMismatch {
                ty: enums,
                count: 2,
                element_aligned_size: 4,
                encoded_size: 6,
                expected: 8
            }
        ))
    );
    assert_eq!(
        graph.native(pointers),
        Err(NativeTypeError::Conversion(
            NativeConversionError::ArraySizeMismatch {
                ty: pointers,
                count: 2,
                element_aligned_size: 4,
                encoded_size: 6,
                expected: 8
            }
        ))
    );
    // Java's empty minimum-aligned structure has public and aligned length 1;
    // native rounds its public size 1 to alignment 16.
    assert_eq!(geometry(&graph, empty), (MetaType::Struct, 1, 16, 16));
    assert_eq!(
        graph.native(empties),
        Err(NativeTypeError::Conversion(
            NativeConversionError::ArraySizeMismatch {
                ty: empties,
                count: 2,
                element_aligned_size: 16,
                encoded_size: 2,
                expected: 32
            }
        ))
    );
    assert_eq!(
        graph.native(holder),
        Err(NativeTypeError::Conversion(
            NativeConversionError::Dependency {
                ty: holder,
                dependency: enums,
                root: enums
            }
        ))
    );
    // Pointers are not by-value dependencies: queryable, but not loadable.
    assert_eq!(geometry(&graph, pointer_to_bad), (MetaType::Ptr, 8, 8, 8));
    assert_eq!(graph.load_blocker(pointer_to_bad).unwrap(), Some(enums));
    assert_eq!(graph.load_blocker(floats).unwrap(), None);
    assert_eq!(
        graph.failures().map(|(ty, _)| ty).collect::<Vec<_>>(),
        [enums, pointers, empties, holder]
    );
    assert_eq!(graph.stats().failed, 4);
    assert_eq!(graph.stats().unloadable, 5);
}

#[test]
fn composites_keep_public_size_java_alignment_and_offsets() {
    let mut s = Source::default();
    let u8_ = s.int(1, false);
    let u32_ = s.int(4, false);
    let float = s.float(4);
    let natural = s.structure(&[u8_, u32_]);
    let packed = s.packed(&[u8_, u32_]);
    let empty = s.composite(&[], Packing::Default, MinimumAlignment::Explicit(16), false);
    let min8 = s.composite(
        &[float],
        Packing::Default,
        MinimumAlignment::Explicit(8),
        false,
    );
    let union = s.union(&[u8_, u32_]);
    let empty_union = s.union(&[]);
    let graph = s.native();
    use MetaType::*;
    assert_eq!(geometry(&graph, natural), (Struct, 8, 8, 4));
    let offsets = |ty| {
        graph
            .fields(id(ty))
            .unwrap()
            .iter()
            .map(|f| (f.offset, f.ty, f.kind))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        offsets(natural),
        [
            (0, id(u8_), NativeFieldKind::Ordinary),
            (4, id(u32_), NativeFieldKind::Ordinary)
        ]
    );
    assert_eq!(geometry(&graph, packed), (Struct, 5, 5, 1));
    assert_eq!(
        offsets(packed),
        [
            (0, id(u8_), NativeFieldKind::Ordinary),
            (1, id(u32_), NativeFieldKind::Ordinary)
        ]
    );
    assert_eq!(geometry(&graph, empty), (Struct, 1, 16, 16));
    assert_eq!(geometry(&graph, min8), (Struct, 8, 8, 8));
    assert_eq!(geometry(&graph, union), (Union, 4, 4, 4));
    assert_eq!(offsets(union).len(), 2);
    assert_eq!(geometry(&graph, empty_union), (Union, 1, 1, 1));
    assert!(graph.fields(id(empty_union)).unwrap().is_empty());
}

#[test]
fn zero_length_components_are_not_transported() {
    let mut s = Source::default();
    let float = s.float(4);
    let zero = s.array(float, 0);
    let empty = s.structure(&[]);
    let outer = s.structure(&[float, zero, empty, float]);
    let union = s.union(&[zero, float]);
    let graph = s.native();
    let fields = graph.fields(id(outer)).unwrap();
    assert_eq!(
        fields
            .iter()
            .map(|f| (f.offset, f.source_field))
            .collect::<Vec<_>>(),
        [(0, 0), (4, 3)]
    );
    assert_eq!(graph.fields(id(union)).unwrap().len(), 1);
    assert_eq!(graph.fields(id(union)).unwrap()[0].source_field, 1);
}

#[test]
fn aliases_keep_identity_and_share_one_canonical_shape() {
    let mut s = Source::default();
    let float = s.float(4);
    let a = s.alias(float);
    let b = s.alias(a);
    let record = s.structure(&[float, a, b]);
    let typedef = s.alias(record);
    let typedef2 = s.alias(typedef);
    let graph = s.native();
    let f = graph.get(id(float)).unwrap();
    let ta = graph.get(id(a)).unwrap();
    let tb = graph.get(id(b)).unwrap();
    assert_eq!(
        (ta.meta, ta.size, ta.aligned_size, ta.alignment),
        (MetaType::Float, 4, 4, 4)
    );
    assert_eq!((f.alias_of, f.canonical), (None, id(float)));
    assert_eq!((ta.alias_of, ta.canonical), (Some(id(float)), id(float)));
    assert_eq!((tb.alias_of, tb.canonical), (Some(id(a)), id(float)));
    assert_eq!(tb.origin, NativeOrigin::Source(b));
    let t2 = graph.get(id(typedef2)).unwrap();
    assert_eq!(
        (t2.meta, t2.alias_of, t2.canonical),
        (MetaType::Struct, Some(id(typedef)), id(record))
    );
    let base = graph.fields(id(record)).unwrap();
    for alias in [typedef, typedef2] {
        let shared = graph.fields(id(alias)).unwrap();
        assert_eq!(shared.as_ptr(), base.as_ptr());
        assert_eq!(shared.len(), 3);
    }
    // Field types are the declared objects, preserving alias identity.
    assert_eq!(
        base.iter().map(|f| f.ty).collect::<Vec<_>>(),
        [id(float), id(a), id(b)]
    );
    // Shared shape: three native fields total, not three per alias.
    assert_eq!(graph.stats().fields, 3);
}

#[test]
fn incomplete_types_fail_only_where_their_geometry_is_needed() {
    let mut s = Source::default();
    let incomplete = s.add(TypeKind::Incomplete);
    let pointer = s.add(TypeKind::Pointer {
        target: incomplete,
        bytes: None,
    });
    let alias = s.alias(incomplete);
    let holder = s.structure(&[pointer]);
    let float = s.float(4);
    let function = s.add(TypeKind::Function {
        result: float,
        parameters: vec![incomplete],
        variadic: false,
    });
    let unrelated = s.structure(&[float]);
    let graph = s.native();
    assert_eq!(
        graph.native(incomplete),
        Err(NativeTypeError::Conversion(
            NativeConversionError::Incomplete(incomplete)
        ))
    );
    assert_eq!(
        graph.native(alias),
        Err(NativeTypeError::Conversion(
            NativeConversionError::Dependency {
                ty: alias,
                dependency: incomplete,
                root: incomplete
            }
        ))
    );
    assert_eq!(geometry(&graph, pointer), (MetaType::Ptr, 8, 8, 8));
    assert_eq!(geometry(&graph, holder), (MetaType::Struct, 8, 8, 8));
    assert_eq!(geometry(&graph, function), (MetaType::Code, 1, 1, 1));
    for ty in [pointer, holder, function, alias, incomplete] {
        assert_eq!(graph.load_blocker(ty).unwrap(), Some(incomplete), "{ty:?}");
    }
    assert_eq!(graph.load_blocker(unrelated).unwrap(), None);
    assert!(!graph.is_fully_converted());
    assert_eq!(
        graph.load_blocker(TypeId(99)),
        Err(NativeTypeError::UnknownSource(TypeId(99)))
    );
}

/// The probe layout: {enum4 e:32; i32 a:16; i32 c:3; i32 :0; u64 y:24;
/// i128 w:96; float f} and union {i32 a:3; i32 :0; i128 w:128; float f}.
fn bitfield_source() -> (Source, [TypeId; 7]) {
    let mut s = Source::default();
    let i32_ = s.int(4, true);
    let e4 = s.add(TypeKind::Enum {
        bytes: 4,
        signed: false,
    });
    let u64_ = s.int(8, false);
    let i128_ = s.int(16, true);
    let float = s.float(4);
    let record = s.with_fields(
        vec![
            Field::bitfield("e", e4, 32),
            Field::bitfield("a", i32_, 16),
            Field::bitfield("c", i32_, 3),
            Field::bitfield("z", i32_, 0),
            Field::bitfield("y", u64_, 24),
            Field::bitfield("w", i128_, 96),
            Field::new("f", float),
        ],
        Packing::Default,
        MinimumAlignment::Default,
        false,
    );
    let union = s.with_fields(
        vec![
            Field::bitfield("a", i32_, 3),
            Field::bitfield("z", i32_, 0),
            Field::bitfield("w", i128_, 128),
            Field::new("f", float),
        ],
        Packing::Default,
        MinimumAlignment::Default,
        true,
    );
    (s, [i32_, e4, u64_, i128_, float, record, union])
}

#[test]
fn structure_bitfields_follow_decode_bit_field_in_both_byte_orders() {
    let (s, [i32_, e4, _, _, float, record, union]) = bitfield_source();
    for (endianness, least) in [(Endianness::Little, 0), (Endianness::Big, 5)] {
        let layouts = s.layouts_with(organization(), endianness);
        let graph = bridge(layouts);
        let fields = graph.fields(id(record)).unwrap();
        let origin = |ty: NativeTypeId| graph.get(ty).unwrap().origin;
        let summary: Vec<_> = fields
            .iter()
            .map(|f| (f.offset, origin(f.ty), f.source_field, f.kind))
            .collect();
        use NativeFieldKind::{ByteRangeBitfield, Ordinary};
        use NativeOrigin::{Source, SyntheticBase, SyntheticByteArray};
        assert_eq!(
            summary,
            [
                // Same width: the declared enum base object itself.
                (0, Source(e4), 0, ByteRangeBitfield { bits: 32 }),
                (
                    4,
                    SyntheticBase {
                        size: 2,
                        meta: MetaType::Int
                    },
                    1,
                    ByteRangeBitfield { bits: 16 }
                ),
                (
                    8,
                    SyntheticBase {
                        size: 3,
                        meta: MetaType::Uint
                    },
                    4,
                    ByteRangeBitfield { bits: 24 }
                ),
                // 12 > max_basetype_size 10: getTypeArray(12, unknown1).
                (
                    11,
                    SyntheticByteArray { count: 12 },
                    5,
                    ByteRangeBitfield { bits: 96 }
                ),
                (24, Source(float), 6, Ordinary),
            ],
            "{endianness:?}"
        );
        assert_eq!(
            graph.bitfields(id(record)).unwrap(),
            [NativeBitfield {
                source_field: 2,
                byte_offset: 6,
                byte_size: 1,
                least_significant_bit: least,
                bits: 3,
                base: id(i32_),
            }]
        );
        let geometry_of = |ty: NativeTypeId| {
            let t = graph.get(ty).unwrap();
            (t.meta, t.size, t.aligned_size, t.alignment)
        };
        assert_eq!(geometry_of(fields[1].ty), (MetaType::Int, 2, 2, 2));
        assert_eq!(geometry_of(fields[2].ty), (MetaType::Uint, 3, 4, 4));
        assert_eq!(geometry_of(fields[3].ty), (MetaType::Array, 12, 12, 1));
        let array = graph.array(fields[3].ty).unwrap().unwrap();
        assert_eq!(
            origin(array.element),
            SyntheticBase {
                size: 1,
                meta: MetaType::Unknown
            }
        );
        assert!(graph.get(fields[0].ty).unwrap().enumeration);

        // Union bitfields are opaque transport of their storage width.
        let union_fields: Vec<_> = graph
            .fields(id(union))
            .unwrap()
            .iter()
            .map(|f| (origin(f.ty), geometry_of(f.ty), f.kind))
            .collect();
        assert_eq!(
            union_fields,
            [
                (
                    NativeOrigin::UnionBitfield {
                        owner: union,
                        field: 0
                    },
                    (MetaType::Unknown, 1, 1, 1),
                    NativeFieldKind::UnionBitfield { storage_bytes: 1 }
                ),
                (
                    NativeOrigin::UnionBitfield {
                        owner: union,
                        field: 2
                    },
                    (MetaType::Struct, 16, 16, 1),
                    NativeFieldKind::UnionBitfield { storage_bytes: 16 }
                ),
                (Source(float), (MetaType::Float, 4, 4, 4), Ordinary),
            ]
        );
        assert_eq!(graph.stats().synthetic, 6);
        assert!(graph.dropped_fields().is_empty());
    }
}

#[test]
fn synthetic_bases_are_interned_and_byte_arrays_use_native_padding() {
    let (mut s, [i32_, e4, _, i128_, ..]) = bitfield_source();
    let alias_enum = s.alias(e4);
    let enum_signed = s.add(TypeKind::Enum {
        bytes: 4,
        signed: true,
    });
    let second = s.with_fields(
        vec![
            Field::bitfield("x", i32_, 16),
            Field::bitfield("e", alias_enum, 32),
            Field::bitfield("s", enum_signed, 16),
            Field::bitfield("w", i128_, 96),
        ],
        Packing::Default,
        MinimumAlignment::Default,
        false,
    );
    let first = TypeId(5);
    let graph = s.native();
    let a = graph.fields(id(first)).unwrap();
    let b = graph.fields(id(second)).unwrap();
    assert_eq!(b[0].ty, a[1].ty, "getBase(2, Int) is shared");
    assert_eq!(
        b[1].ty,
        id(alias_enum),
        "same-width alias base keeps identity"
    );
    // A resized signed enum keeps Int, not the enum object.
    assert_eq!(
        graph.get(b[2].ty).unwrap().origin,
        NativeOrigin::SyntheticBase {
            size: 2,
            meta: MetaType::Int
        }
    );
    assert_eq!(b[2].ty, a[1].ty);
    assert_eq!(b[3].ty, a[3].ty, "byte arrays are interned by count");

    // An odd map pads the Unknown size-one base to 2: the array doubles.
    let odd = s.native_with_map(&[(1, 2), (2, 2), (4, 4), (8, 8)]);
    let field = odd.fields(id(first)).unwrap()[3];
    let array = odd.get(field.ty).unwrap();
    assert_eq!(
        (array.meta, array.size, array.aligned_size, array.alignment),
        (MetaType::Array, 24, 24, 2)
    );
    assert_eq!(odd.array(field.ty).unwrap().unwrap().stride, 2);
}

#[test]
fn max_basetype_size_is_an_explicit_validated_option() {
    let (s, [.., record, _]) = bitfield_source();
    let layouts = s.layouts();
    let map =
        NativeAlignmentMap::from_organization(layouts.organization(), Default::default()).unwrap();
    let options = |max_basetype_size| NativeTypeOptions { max_basetype_size };
    assert_eq!(
        NativeTypeGraph::new(layouts.clone(), &map, options(7), Default::default()).unwrap_err(),
        NativeTypeError::InvalidOptions("max_basetype_size must be in 8..=i32::MAX")
    );
    NativeTypeGraph::new(layouts.clone(), &map, options(8), Default::default()).unwrap();
    let wide = NativeTypeGraph::new(layouts, &map, options(12), Default::default()).unwrap();
    let field = wide.fields(id(record)).unwrap()[3];
    let t = wide.get(field.ty).unwrap();
    assert_eq!(
        (t.origin, t.size, t.aligned_size, t.alignment),
        (
            NativeOrigin::SyntheticBase {
                size: 12,
                meta: MetaType::Int
            },
            12,
            16,
            8
        )
    );
}

#[test]
fn construction_limits_are_exact() {
    let (s, _) = bitfield_source();
    let layouts = s.layouts();
    let map =
        NativeAlignmentMap::from_organization(layouts.organization(), Default::default()).unwrap();
    let full = NativeTypeGraph::new(
        layouts.clone(),
        &map,
        Default::default(),
        Default::default(),
    )
    .unwrap();
    let stats = full.stats();
    let base = NativeTypeLimits::default();
    type Setter = fn(&mut NativeTypeLimits, u64);
    let cases: [(&str, Setter); 6] = [
        ("types", |l, n| l.max_types = n as usize),
        ("fields", |l, n| l.max_fields = n as usize),
        ("references", |l, n| l.max_references = n as usize),
        ("synthetic types", |l, n| l.max_synthetic = n as usize),
        ("depth", |l, n| l.max_depth = n as usize),
        ("work", |l, n| l.max_work = n),
    ];
    let exact = [
        stats.source_types as u64,
        layouts.stats().fields as u64,
        stats.references as u64,
        stats.synthetic as u64,
        stats.depth as u64,
        stats.work,
    ];
    for ((name, set), value) in cases.into_iter().zip(exact) {
        let mut limits = base;
        set(&mut limits, value);
        let graph = NativeTypeGraph::new(layouts.clone(), &map, Default::default(), limits)
            .unwrap_or_else(|e| panic!("{name} at {value}: {e}"));
        assert_eq!(graph.stats(), stats);
        set(&mut limits, value - 1);
        assert_eq!(
            NativeTypeGraph::new(layouts.clone(), &map, Default::default(), limits).unwrap_err(),
            NativeTypeError::Limit(name)
        );
    }
    // Every lower work budget fails as a work limit, never partially.
    for work in 0..stats.work {
        let limits = NativeTypeLimits {
            max_work: work,
            ..base
        };
        assert_eq!(
            NativeTypeGraph::new(layouts.clone(), &map, Default::default(), limits).unwrap_err(),
            NativeTypeError::Limit("work")
        );
    }
}

/// Forward IDs: `TypeId(0)` is the outermost wrapper, so conversion starting
/// at the first root must descend the whole chain without recursion.
pub fn forward_chain(length: usize, wrap: impl Fn(TypeId) -> TypeKind) -> Source {
    let mut s = Source::default();
    for index in 0..length - 1 {
        s.add(wrap(TypeId(index + 1)));
    }
    s.float(4);
    s
}

#[test]
fn deep_alias_and_structure_chains_convert_iteratively() {
    let s = forward_chain(100_000, TypeKind::Alias);
    let graph = s.native();
    assert_eq!(graph.stats().depth, 100_000);
    let outer = graph.get(NativeTypeId(0)).unwrap();
    assert_eq!(
        (outer.meta, outer.alias_of, outer.canonical),
        (MetaType::Float, Some(NativeTypeId(1)), NativeTypeId(99_999))
    );

    let s = forward_chain(100_000, |inner| {
        TypeKind::Structure(ghidra_types::Composite {
            fields: vec![Field::new("f", inner)],
            ..Default::default()
        })
    });
    let graph = s.native();
    assert_eq!(graph.stats().depth, 100_000);
    assert_eq!(graph.stats().fields, 99_999);
    assert_eq!(geometry(&graph, TypeId(0)), (MetaType::Struct, 4, 4, 4));
}

#[test]
fn graphs_are_owned_shareable_snapshots() {
    fn assert_traits<T: Clone + Send + Sync>() {}
    assert_traits::<NativeTypeGraph>();
    assert_traits::<NativePrimitiveExtraction>();
    let mut s = Source::default();
    let float = s.float(4);
    let layouts: Arc<TypeLayouts> = s.layouts();
    let graph = bridge(layouts.clone());
    assert!(Arc::ptr_eq(graph.layouts(), &layouts));
    assert_eq!(graph.alignments().entries().len(), 5);
    let copy = (*graph).clone();
    assert_eq!(copy.get(id(float)).unwrap(), graph.get(id(float)).unwrap());
}
