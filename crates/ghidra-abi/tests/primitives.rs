use ghidra_abi::*;
use ghidra_languages::{DataOrganization, MetaType};
use ghidra_types::{Composite, Field, Packing, TypeDefinition, TypeId, TypeKind, TypeLayouts};
use std::sync::Arc;

fn def(kind: TypeKind) -> TypeDefinition {
    TypeDefinition::new("", kind)
}
fn int(bytes: u32) -> TypeDefinition {
    def(TypeKind::Integer {
        bytes,
        signed: true,
    })
}
fn float(bytes: u32) -> TypeDefinition {
    def(TypeKind::Float { bytes })
}
fn aggregate(fields: &[usize]) -> Composite {
    Composite {
        fields: fields.iter().map(|i| Field::new("", TypeId(*i))).collect(),
        ..Default::default()
    }
}
fn packed(fields: &[usize]) -> Composite {
    Composite {
        packing: Packing::Explicit(1),
        ..aggregate(fields)
    }
}
fn predicates(definitions: Vec<TypeDefinition>) -> Arc<DatatypePredicates> {
    from_layouts(
        TypeLayouts::new(
            definitions.into(),
            DataOrganization::default().resolve(8),
            Default::default(),
        )
        .unwrap(),
    )
}
fn from_layouts(layouts: TypeLayouts) -> Arc<DatatypePredicates> {
    Arc::new(DatatypePredicates::new(Arc::new(layouts), Default::default()).unwrap())
}
fn extract(p: &Arc<DatatypePredicates>, ty: usize) -> PrimitiveExtraction {
    PrimitiveExtraction::new(
        p.clone(),
        TypeId(ty),
        Default::default(),
        Default::default(),
    )
    .unwrap()
}
fn pieces(extraction: &PrimitiveExtraction) -> Vec<(PrimitiveSource, u64, i128, i128)> {
    extraction
        .primitives()
        .iter()
        .map(|p| (p.source, p.offset, p.length, p.aligned_length))
        .collect()
}

#[test]
fn ordinary_pieces_keep_raw_aligned_lengths_offsets_and_canonical_aliases() {
    let p = predicates(vec![
        int(3),
        float(10),
        def(TypeKind::Alias(TypeId(0))),
        def(TypeKind::Structure(aggregate(&[2, 1]))),
    ]);
    let result = PrimitiveExtraction::new(
        p.clone(),
        TypeId(3),
        ExtractionOptions {
            offset: 32,
            ..Default::default()
        },
        Default::default(),
    )
    .unwrap();
    assert_eq!(
        pieces(&result),
        vec![
            (PrimitiveSource::Type(TypeId(0)), 32, 3, 4),
            (PrimitiveSource::Type(TypeId(1)), 40, 10, 16)
        ]
    );
    assert_eq!(result.primitives()[1].alignment, 8);
    assert!(!result.contains_unknown());
    assert!(!result.output_contains_unknown());
    assert!(result.is_aligned());
    assert!(!result.contains_holes());
}

#[test]
fn root_and_nested_arrays_differ_and_union_members_reset_array_depth() {
    let p = predicates(vec![
        float(4),
        def(TypeKind::Array {
            element: TypeId(0),
            count: 2,
        }),
        def(TypeKind::Structure(aggregate(&[1]))),
        def(TypeKind::Union(aggregate(&[1]))),
        def(TypeKind::Structure(aggregate(&[3]))),
        def(TypeKind::Alias(TypeId(1))),
    ]);
    let options = ExtractionOptions {
        nested_arrays_are_primitives: true,
        ..Default::default()
    };
    for id in [1, 3, 4, 5] {
        let result =
            PrimitiveExtraction::new(p.clone(), TypeId(id), options, Default::default()).unwrap();
        assert_eq!(
            pieces(&result),
            vec![
                (PrimitiveSource::Type(TypeId(0)), 0, 4, 4),
                (PrimitiveSource::Type(TypeId(0)), 4, 4, 4)
            ],
            "root {id}"
        );
    }
    let result = PrimitiveExtraction::new(p, TypeId(2), options, Default::default()).unwrap();
    assert_eq!(
        pieces(&result),
        vec![(PrimitiveSource::Type(TypeId(1)), 0, 8, 8)]
    );
    assert_eq!(result.primitives()[0].meta_type, MetaType::Array);
}

#[test]
fn refinement_identity_ties_and_float_preference_follow_source_order() {
    let p = predicates(vec![
        int(4),
        int(4),
        float(4),
        float(4),
        int(8),
        float(8),
        def(TypeKind::Structure(aggregate(&[2, 2]))),
        def(TypeKind::Structure(aggregate(&[0, 0]))),
        def(TypeKind::Union(aggregate(&[0, 1]))),
        def(TypeKind::Union(aggregate(&[2, 3]))),
        def(TypeKind::Union(aggregate(&[4, 6]))),
        def(TypeKind::Union(aggregate(&[5, 7]))),
    ]);
    assert_eq!(
        pieces(&extract(&p, 8)),
        vec![(PrimitiveSource::Type(TypeId(0)), 0, 4, 4)]
    );
    assert_eq!(
        pieces(&extract(&p, 9)),
        vec![(PrimitiveSource::Type(TypeId(3)), 0, 4, 4)]
    );
    assert_eq!(
        pieces(&extract(&p, 10)),
        vec![(PrimitiveSource::Type(TypeId(4)), 0, 8, 8)]
    );
    assert_eq!(
        pieces(&extract(&p, 11)),
        vec![
            (PrimitiveSource::Type(TypeId(0)), 0, 4, 4),
            (PrimitiveSource::Type(TypeId(0)), 4, 4, 4)
        ]
    );
}

#[test]
fn union_refinement_windows_use_aligned_lengths_instead_of_raw_widths() {
    let p = predicates(vec![
        int(3),
        int(4),
        def(TypeKind::Union(aggregate(&[0, 1]))),
        def(TypeKind::Union(aggregate(&[1, 0]))),
    ]);
    // Both primitives have aligned length4. The first therefore wins the tie;
    // using raw length3 for its end would wrongly reject the second's end4.
    assert_eq!(
        pieces(&extract(&p, 2)),
        vec![(PrimitiveSource::Type(TypeId(0)), 0, 3, 4)]
    );
    assert_eq!(
        pieces(&extract(&p, 3)),
        vec![(PrimitiveSource::Type(TypeId(1)), 0, 4, 4)]
    );
}

#[test]
fn shifted_overlap_is_directional_and_missing_coverage_is_not_invented() {
    let p = predicates(vec![
        def(TypeKind::Structure(Composite::default())),
        def(TypeKind::Array {
            element: TypeId(0),
            count: 2,
        }),
        int(4),
        def(TypeKind::Structure(packed(&[1, 2]))),
        def(TypeKind::Union(aggregate(&[3, 2]))),
        def(TypeKind::Union(aggregate(&[2, 3]))),
    ]);
    // First [2,6) is considered "big" on the length tie. The source checks
    // only the other end, not containment of its start at zero.
    assert_eq!(
        pieces(&extract(&p, 4)),
        vec![(PrimitiveSource::Type(TypeId(2)), 2, 4, 4)]
    );
    assert!(matches!(
        PrimitiveExtraction::new(p, TypeId(5), Default::default(), Default::default()),
        Err(ExtractionError::IncompatibleUnion {
            big_offset: 0,
            small_offset: 2,
            ..
        })
    ));
}

#[test]
fn intermediate_union_lists_may_exceed_semantic_max_then_shrink() {
    let p = predicates(vec![
        def(TypeKind::Structure(Composite::default())),
        def(TypeKind::Array {
            element: TypeId(0),
            count: 4,
        }),
        int(1),
        int(8),
        def(TypeKind::Structure(packed(&[1, 2]))),
        def(TypeKind::Union(aggregate(&[4, 2, 3]))),
    ]);
    let limits = ExtractionLimits {
        max_primitives: 1,
        max_live_primitives: 4,
        ..Default::default()
    };
    let result =
        PrimitiveExtraction::new(p.clone(), TypeId(5), Default::default(), limits).unwrap();
    assert_eq!(
        pieces(&result),
        vec![(PrimitiveSource::Type(TypeId(3)), 0, 8, 8)]
    );
    assert_eq!(result.stats().peak_live_primitives, 4);
    assert_eq!(
        PrimitiveExtraction::new(
            p,
            TypeId(5),
            Default::default(),
            ExtractionLimits {
                max_live_primitives: 3,
                ..limits
            }
        )
        .unwrap_err(),
        ExtractionError::Limit("live primitives")
    );
}

#[test]
fn union_unknown_flags_are_context_local_and_output_flags_are_separate() {
    let p = predicates(vec![
        def(TypeKind::Opaque { bytes: 4 }),
        def(TypeKind::Union(aggregate(&[0]))),
        def(TypeKind::Structure(aggregate(&[0]))),
        def(TypeKind::Array {
            element: TypeId(0),
            count: 2,
        }),
        def(TypeKind::Structure(aggregate(&[3]))),
    ]);
    let union = extract(&p, 1);
    assert!(!union.contains_unknown());
    assert!(union.output_contains_unknown());
    assert!(extract(&p, 2).contains_unknown());
    assert!(extract(&p, 3).contains_unknown());
    let result = PrimitiveExtraction::new(
        p,
        TypeId(4),
        ExtractionOptions {
            nested_arrays_are_primitives: true,
            ..Default::default()
        },
        Default::default(),
    )
    .unwrap();
    assert!(!result.contains_unknown());
    assert!(!result.output_contains_unknown());
    assert_eq!(result.primitives()[0].meta_type, MetaType::Array);
}

#[test]
fn empty_void_code_and_zero_array_modes_remain_distinct() {
    let p = predicates(vec![
        def(TypeKind::Void),
        def(TypeKind::Function {
            result: TypeId(0),
            parameters: vec![],
            variadic: false,
        }),
        def(TypeKind::Structure(Composite::default())),
        def(TypeKind::Array {
            element: TypeId(2),
            count: 0,
        }),
        def(TypeKind::Structure(aggregate(&[3]))),
        def(TypeKind::Union(aggregate(&[2, 2]))),
    ]);
    let void = extract(&p, 0);
    assert!(void.contains_unknown());
    assert_eq!(
        pieces(&void),
        vec![(PrimitiveSource::Type(TypeId(0)), 0, 0, 0)]
    );
    assert_eq!(
        pieces(&extract(&p, 1)),
        vec![(PrimitiveSource::Type(TypeId(1)), 0, -1, -1)]
    );
    for id in [2, 3, 4, 5] {
        assert!(extract(&p, id).primitives().is_empty());
    }
    let result = PrimitiveExtraction::new(
        p,
        TypeId(4),
        ExtractionOptions {
            nested_arrays_are_primitives: true,
            ..Default::default()
        },
        Default::default(),
    )
    .unwrap();
    assert_eq!(
        pieces(&result),
        vec![(PrimitiveSource::Type(TypeId(3)), 0, 1, 1)]
    );
}

#[test]
fn errors_reject_unions_bad_ids_and_incomplete_types_without_partial_results() {
    let p = predicates(vec![
        int(4),
        def(TypeKind::Union(aggregate(&[0]))),
        def(TypeKind::Union(Composite::default())),
        def(TypeKind::Incomplete),
    ]);
    assert_eq!(
        PrimitiveExtraction::new(
            p.clone(),
            TypeId(1),
            ExtractionOptions {
                reject_unions: true,
                ..Default::default()
            },
            Default::default()
        )
        .unwrap_err(),
        ExtractionError::UnionRejected(TypeId(1))
    );
    assert_eq!(
        PrimitiveExtraction::new(p.clone(), TypeId(2), Default::default(), Default::default())
            .unwrap_err(),
        ExtractionError::EmptyUnion(TypeId(2))
    );
    assert_eq!(
        PrimitiveExtraction::new(p.clone(), TypeId(3), Default::default(), Default::default())
            .unwrap_err(),
        ExtractionError::Datatype(PredicateError::IncompleteType(TypeId(3)))
    );
    assert_eq!(
        PrimitiveExtraction::new(
            p,
            TypeId(usize::MAX),
            Default::default(),
            Default::default()
        )
        .unwrap_err(),
        ExtractionError::Datatype(PredicateError::UnknownType(TypeId(usize::MAX)))
    );
}

#[test]
fn output_and_scratch_depth_and_work_limits_hold_at_exact_boundaries() {
    let p = predicates(vec![
        int(4),
        float(8),
        def(TypeKind::Structure(aggregate(&[0, 0]))),
        def(TypeKind::Union(aggregate(&[1, 2]))),
    ]);
    let baseline = extract(&p, 3);
    let stats = baseline.stats();
    let exact = ExtractionLimits {
        max_primitives: baseline.primitives().len(),
        max_live_primitives: stats.peak_live_primitives,
        max_depth: stats.peak_depth,
        max_work: stats.work,
    };
    assert_eq!(
        PrimitiveExtraction::new(p.clone(), TypeId(3), Default::default(), exact)
            .unwrap()
            .primitives(),
        baseline.primitives()
    );
    for (limits, error) in [
        (
            ExtractionLimits {
                max_primitives: exact.max_primitives - 1,
                ..exact
            },
            "primitives",
        ),
        (
            ExtractionLimits {
                max_live_primitives: exact.max_live_primitives - 1,
                ..exact
            },
            "live primitives",
        ),
        (
            ExtractionLimits {
                max_depth: exact.max_depth - 1,
                ..exact
            },
            "depth",
        ),
    ] {
        assert_eq!(
            PrimitiveExtraction::new(p.clone(), TypeId(3), Default::default(), limits).unwrap_err(),
            ExtractionError::Limit(error)
        );
    }
    for work in 0..stats.work {
        assert_eq!(
            PrimitiveExtraction::new(
                p.clone(),
                TypeId(3),
                Default::default(),
                ExtractionLimits {
                    max_work: work,
                    ..exact
                }
            )
            .unwrap_err(),
            ExtractionError::Limit("work")
        );
    }
    let empty = predicates(vec![def(TypeKind::Structure(Composite::default()))]);
    assert!(
        PrimitiveExtraction::new(
            empty,
            TypeId(0),
            Default::default(),
            ExtractionLimits {
                max_primitives: 0,
                max_live_primitives: 0,
                ..Default::default()
            }
        )
        .unwrap()
        .primitives()
        .is_empty()
    );
}

#[test]
fn deep_structures_and_union_contexts_are_iterative_and_drop_without_recursion() {
    fn deep(n: usize, unions: bool) -> PrimitiveExtraction {
        let mut definitions = (0..n - 1)
            .map(|i| {
                def(if unions {
                    TypeKind::Union(aggregate(&[i + 1]))
                } else {
                    TypeKind::Structure(aggregate(&[i + 1]))
                })
            })
            .collect::<Vec<_>>();
        definitions.push(int(4));
        extract(&predicates(definitions), 0)
    }
    let half = deep(50_000, false);
    let full = deep(100_000, false);
    assert_eq!(full.stats().peak_depth, 100_000);
    assert_eq!(full.stats().node_visits, 100_000);
    assert_eq!(half.stats().work, 4 * 50_000);
    assert_eq!(full.stats().work, 2 * half.stats().work);
    assert_eq!(full.primitives().len(), 1);
    let unions = deep(20_000, true);
    assert_eq!(unions.stats().peak_depth, 20_000);
    assert_eq!(unions.stats().work, 5 * 20_000 - 1);
    assert_eq!(unions.stats().peak_live_primitives, 1);
}

#[test]
fn large_arrays_are_lazy_and_empty_subgraphs_do_not_expand_payloads() {
    let definitions = vec![
        int(4),
        def(TypeKind::Array {
            element: TypeId(0),
            count: 1_000_000_000,
        }),
        def(TypeKind::Structure(Composite::default())),
        def(TypeKind::Array {
            element: TypeId(2),
            count: 1_000_000_000,
        }),
    ];
    let layouts = TypeLayouts::new(
        definitions.into(),
        DataOrganization::default().resolve(8),
        ghidra_types::Limits {
            max_type_bytes: u64::MAX,
            ..Default::default()
        },
    )
    .unwrap();
    let p = from_layouts(layouts);
    assert_eq!(
        PrimitiveExtraction::new(
            p.clone(),
            TypeId(1),
            Default::default(),
            ExtractionLimits {
                max_primitives: 3,
                max_live_primitives: 3,
                max_work: 100,
                ..Default::default()
            }
        )
        .unwrap_err(),
        ExtractionError::Limit("primitives")
    );
    let empty = extract(&p, 3);
    assert!(empty.primitives().is_empty());
    assert_eq!(empty.stats().node_visits, 1);
    assert_eq!(empty.stats().work, 2);
    assert_eq!(
        PrimitiveExtraction::new(
            p,
            TypeId(3),
            ExtractionOptions {
                nested_arrays_are_primitives: true,
                ..Default::default()
            },
            ExtractionLimits {
                max_work: 100,
                ..Default::default()
            }
        )
        .unwrap_err(),
        ExtractionError::Limit("work")
    );
}

#[test]
fn unsigned_byte_offsets_allow_exclusive_space_end_and_reject_wrap() {
    let p = predicates(vec![int(1), int(8)]);
    let result = PrimitiveExtraction::new(
        p.clone(),
        TypeId(0),
        ExtractionOptions {
            offset: u64::MAX,
            ..Default::default()
        },
        Default::default(),
    )
    .unwrap();
    assert_eq!(result.primitives()[0].offset, u64::MAX);
    assert!(
        PrimitiveExtraction::new(
            p.clone(),
            TypeId(1),
            ExtractionOptions {
                offset: u64::MAX - 7,
                ..Default::default()
            },
            Default::default()
        )
        .is_ok()
    );
    assert_eq!(
        PrimitiveExtraction::new(
            p,
            TypeId(1),
            ExtractionOptions {
                offset: u64::MAX - 6,
                ..Default::default()
            },
            Default::default()
        )
        .unwrap_err(),
        ExtractionError::Overflow
    );
}

#[test]
fn empty_trailing_members_can_start_at_the_exclusive_address_end() {
    let p = predicates(vec![
        int(4),
        def(TypeKind::Array {
            element: TypeId(0),
            count: 0,
        }),
        def(TypeKind::Structure(Composite::default())),
        def(TypeKind::Structure(aggregate(&[0, 1]))),
        def(TypeKind::Structure(aggregate(&[0, 2]))),
        def(TypeKind::Union(aggregate(&[2]))),
        def(TypeKind::Structure(aggregate(&[0, 5]))),
        def(TypeKind::Alias(TypeId(2))),
        def(TypeKind::Structure(aggregate(&[0, 7]))),
    ]);
    for nested in [false, true] {
        for owner in [3, 4, 6, 8] {
            assert_eq!(
                p.layouts().layout(TypeId(owner)).unwrap().geometry.size,
                Some(4)
            );
            let options = ExtractionOptions {
                offset: u64::MAX - 3,
                nested_arrays_are_primitives: nested,
                ..Default::default()
            };
            let result =
                PrimitiveExtraction::new(p.clone(), TypeId(owner), options, Default::default());
            if owner == 3 && nested {
                // A collapsed nested zero array is a real one-byte wrapper.
                assert_eq!(result.unwrap_err(), ExtractionError::Overflow);
            } else {
                let result = result.unwrap();
                assert_eq!(
                    pieces(&result),
                    [(PrimitiveSource::Type(TypeId(0)), u64::MAX - 3, 4, 4)]
                );
            }
        }
    }
}

#[test]
fn a_real_zero_width_bitfield_wrapper_cannot_start_outside_the_address_domain() {
    let layouts = TypeLayouts::new_with_endianness(
        vec![
            int(4),
            def(TypeKind::Structure(Composite {
                fields: vec![
                    Field::new("value", TypeId(0)),
                    Field::bitfield("zero", TypeId(0), 0),
                ],
                ..Default::default()
            })),
        ]
        .into(),
        DataOrganization::default().resolve(8),
        ghidra_types::Endianness::Little,
        Default::default(),
    )
    .unwrap();
    assert_eq!(layouts.layout(TypeId(1)).unwrap().geometry.size, Some(4));
    let p = from_layouts(layouts);
    for nested in [false, true] {
        assert_eq!(
            PrimitiveExtraction::new(
                p.clone(),
                TypeId(1),
                ExtractionOptions {
                    offset: u64::MAX - 3,
                    nested_arrays_are_primitives: nested,
                    ..Default::default()
                },
                Default::default()
            )
            .unwrap_err(),
            ExtractionError::Overflow
        );
    }
}

#[test]
fn owned_extraction_keeps_its_exact_snapshot_and_is_thread_safe() {
    let p = predicates(vec![int(4)]);
    let result = extract(&p, 0);
    assert!(Arc::ptr_eq(result.predicates(), &p));
    let clone = result.clone();
    drop(result);
    drop(p);
    assert_eq!(clone.primitives().len(), 1);
    fn send_sync<T: Send + Sync>() {}
    send_sync::<PrimitiveExtraction>();
}

#[test]
fn bitfields_extract_wrapper_identity_and_storage_including_zero_width() {
    use ghidra_types::Endianness;
    for endianness in [Endianness::Little, Endianness::Big] {
        let definitions = vec![
            int(4),
            def(TypeKind::Alias(TypeId(0))),
            def(TypeKind::Structure(Composite {
                fields: vec![
                    Field::bitfield("a", TypeId(1), 6),
                    Field::bitfield("b", TypeId(0), 8),
                    Field::bitfield("z", TypeId(0), 0),
                ],
                ..Default::default()
            })),
            def(TypeKind::Union(Composite {
                fields: vec![Field::bitfield("u", TypeId(0), 3)],
                ..Default::default()
            })),
        ];
        let layouts = TypeLayouts::new_with_endianness(
            definitions.into(),
            DataOrganization::default().resolve(8),
            endianness,
            Default::default(),
        )
        .unwrap();
        let p = from_layouts(layouts);
        for owner in [2, 3] {
            let result = extract(&p, owner);
            let fields = &p.layouts().layout(TypeId(owner)).unwrap().fields;
            assert_eq!(result.primitives().len(), fields.len());
            for (index, (primitive, field)) in result.primitives().iter().zip(fields).enumerate() {
                let bits = field.bitfield.unwrap();
                let bytes = u64::from(bits.effective_bits + u32::from(bits.bit_offset))
                    .div_ceil(8)
                    .max(1);
                assert_eq!(
                    primitive.source,
                    PrimitiveSource::BitField {
                        owner: TypeId(owner),
                        field: index,
                        base: field.ty
                    }
                );
                assert_eq!(primitive.meta_type, MetaType::Unknown);
                assert_eq!(primitive.offset, field.offset);
                assert_eq!(
                    (primitive.length, primitive.aligned_length),
                    (i128::from(bytes), i128::from(bytes))
                );
                assert_eq!(primitive.alignment, 4);
            }
            assert_eq!(result.contains_unknown(), owner == 2); // union child flags stay local
            assert!(result.output_contains_unknown());
        }
        let zero = extract(&p, 2).primitives()[2];
        assert_eq!(zero.length, 1);
        assert_eq!(p.layouts().layout(TypeId(2)).unwrap().fields[2].bytes, 0);
    }
}

#[test]
fn bitfield_wrappers_use_base_alignment_and_preserve_overlapping_bytes() {
    use ghidra_types::Endianness;
    let definitions = vec![
        def(TypeKind::Enum {
            bytes: 3,
            signed: false,
        }),
        def(TypeKind::Structure(Composite {
            fields: vec![
                Field::bitfield("a", TypeId(0), 1),
                Field::bitfield("b", TypeId(0), 1),
            ],
            ..Default::default()
        })),
    ];
    let layouts = TypeLayouts::new_with_endianness(
        definitions.into(),
        DataOrganization::default().resolve(8),
        Endianness::Little,
        Default::default(),
    )
    .unwrap();
    let p = from_layouts(layouts);
    let result = extract(&p, 1);
    assert_eq!(result.primitives().len(), 2);
    assert_eq!(result.primitives()[0].offset, result.primitives()[1].offset);
    for primitive in result.primitives() {
        assert_eq!(
            (
                primitive.length,
                primitive.aligned_length,
                primitive.alignment
            ),
            (1, 1, 2)
        );
    }
}
