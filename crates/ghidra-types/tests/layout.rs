use std::sync::Arc;

use ghidra_languages::{DataOrganization, SizeAlignment};
use ghidra_types::*;

fn org() -> ResolvedDataOrganization {
    DataOrganization::default().resolve(8)
}
fn def(kind: TypeKind) -> TypeDefinition {
    TypeDefinition::new("", kind)
}
fn scalar(bytes: u32) -> TypeDefinition {
    def(TypeKind::Integer {
        bytes,
        signed: false,
    })
}
fn build(defs: Vec<TypeDefinition>) -> TypeLayouts {
    TypeLayouts::new(defs.into(), org(), Limits::default()).unwrap()
}
fn composite(fields: &[usize], packing: Packing, minimum_alignment: MinimumAlignment) -> Composite {
    Composite {
        fields: fields.iter().map(|i| Field::new("", TypeId(*i))).collect(),
        packing,
        minimum_alignment,
    }
}

#[test]
fn compiler_builtins_and_explicit_scalars_have_independent_lengths() {
    let mut organization = org();
    organization.long_size = 8;
    organization.long_double_size = 10;
    let defs = vec![
        def(TypeKind::Builtin(Builtin::Long)),
        def(TypeKind::Builtin(Builtin::LongDouble)),
        scalar(3),
        def(TypeKind::Enum {
            bytes: 3,
            signed: true,
        }),
        def(TypeKind::Opaque { bytes: 5 }),
        def(TypeKind::Builtin(Builtin::Bool)),
    ];
    let layouts = TypeLayouts::new(defs.into(), organization, Limits::default()).unwrap();
    let geometries: Vec<_> = layouts.layouts().iter().map(|l| l.geometry).collect();
    let lengths: Vec<_> = geometries
        .iter()
        .map(|g| (g.size, g.aligned_length, g.alignment))
        .collect();
    assert_eq!(
        lengths,
        vec![
            (Some(8), Some(8), 8),
            (Some(10), Some(16), 8),
            (Some(3), Some(4), 4),
            (Some(3), Some(3), 2),
            (Some(5), Some(8), 8),
            (Some(1), Some(1), 1)
        ]
    );
}

#[test]
fn primitive_floor_lookup_is_not_exact_lookup_or_host_alignment() {
    let mut organization = org();
    organization.size_alignment_map = vec![
        SizeAlignment {
            size: 2,
            alignment: 3,
        },
        SizeAlignment {
            size: 6,
            alignment: 5,
        },
    ];
    organization.default_alignment = 2;
    assert_eq!(organization.alignment_for_size(5), None);
    let layouts = TypeLayouts::new(
        vec![scalar(1), scalar(5)].into(),
        organization,
        Limits::default(),
    )
    .unwrap();
    assert_eq!(
        layouts.layout(TypeId(0)).unwrap().geometry,
        Geometry {
            size: Some(1),
            length: Some(1),
            aligned_length: Some(2),
            alignment: 3
        }
    );
    assert_eq!(
        layouts.layout(TypeId(1)).unwrap().geometry,
        Geometry {
            size: Some(5),
            length: Some(5),
            aligned_length: Some(6),
            alignment: 5
        }
    );
}

#[test]
fn pointers_keep_width_and_use_unclamped_fallback_only_on_exact_map_miss() {
    let mut organization = org();
    organization.pointer_size = 3;
    organization.default_pointer_alignment = 16;
    organization.absolute_max_alignment = 2;
    let layouts = TypeLayouts::new(
        vec![
            def(TypeKind::Void),
            def(TypeKind::Pointer {
                target: TypeId(0),
                bytes: None,
            }),
            def(TypeKind::Pointer {
                target: TypeId(0),
                bytes: Some(4),
            }),
        ]
        .into(),
        organization,
        Limits::default(),
    )
    .unwrap();
    let p = layouts.layout(TypeId(1)).unwrap().geometry;
    assert_eq!(
        (p.size, p.aligned_length, p.alignment),
        (Some(3), Some(3), 16)
    );
    assert_eq!(layouts.layout(TypeId(2)).unwrap().geometry.alignment, 2);
}

#[test]
fn ordinary_struct_pack_and_minimum_follow_retained_fixtures() {
    for (packing, minimum, offsets, size, alignment) in [
        (
            Packing::Default,
            MinimumAlignment::Default,
            [0, 4, 8],
            12,
            4,
        ),
        (
            Packing::Explicit(2),
            MinimumAlignment::Default,
            [0, 2, 6],
            8,
            2,
        ),
        (
            Packing::Explicit(1),
            MinimumAlignment::Default,
            [0, 1, 5],
            6,
            1,
        ),
        (
            Packing::Explicit(1),
            MinimumAlignment::Explicit(8),
            [0, 1, 5],
            8,
            8,
        ),
    ] {
        let layouts = build(vec![
            scalar(1),
            scalar(4),
            def(TypeKind::Structure(composite(&[0, 1, 0], packing, minimum))),
        ]);
        let record = layouts.layout(TypeId(2)).unwrap();
        assert_eq!(
            record.fields.iter().map(|f| f.offset).collect::<Vec<_>>(),
            offsets
        );
        assert_eq!(
            (record.geometry.size, record.geometry.alignment),
            (Some(size), alignment)
        );
    }
}

#[test]
fn parent_packing_does_not_repack_nested_aggregate() {
    let layouts = build(vec![
        scalar(1),
        scalar(4),
        def(TypeKind::Structure(composite(
            &[0, 1],
            Packing::Default,
            MinimumAlignment::Default,
        ))),
        def(TypeKind::Structure(composite(
            &[0, 2],
            Packing::Explicit(1),
            MinimumAlignment::Default,
        ))),
    ]);
    let inner = layouts.layout(TypeId(2)).unwrap();
    let outer = layouts.layout(TypeId(3)).unwrap();
    assert_eq!(
        (
            inner.fields[1].offset,
            inner.geometry.size,
            inner.geometry.alignment
        ),
        (4, Some(8), 4)
    );
    assert_eq!(
        (
            outer.fields[1].offset,
            outer.geometry.size,
            outer.geometry.alignment
        ),
        (1, Some(9), 1)
    );
}

#[test]
fn empty_types_arrays_and_zero_fields_keep_semantic_zero_separate() {
    let layouts = build(vec![
        scalar(4),
        def(TypeKind::Array {
            element: TypeId(0),
            count: 0,
        }),
        def(TypeKind::Structure(Composite {
            minimum_alignment: MinimumAlignment::Explicit(16),
            ..Default::default()
        })),
        def(TypeKind::Array {
            element: TypeId(2),
            count: 3,
        }),
        scalar(1),
        def(TypeKind::Structure(composite(
            &[4, 1],
            Packing::Default,
            MinimumAlignment::Default,
        ))),
        def(TypeKind::Union(composite(
            &[1, 2],
            Packing::Default,
            MinimumAlignment::Default,
        ))),
    ]);
    assert_eq!(
        layouts.layout(TypeId(1)).unwrap().geometry,
        Geometry {
            size: Some(0),
            length: Some(1),
            aligned_length: Some(1),
            alignment: 4
        }
    );
    assert_eq!(
        layouts.layout(TypeId(2)).unwrap().geometry,
        Geometry {
            size: Some(0),
            length: Some(1),
            aligned_length: Some(1),
            alignment: 16
        }
    );
    let array = layouts.layout(TypeId(3)).unwrap();
    assert_eq!(
        (
            array.array_stride,
            array.geometry.size,
            array.geometry.alignment
        ),
        (Some(1), Some(3), 16)
    );
    let record = layouts.layout(TypeId(5)).unwrap();
    assert_eq!(
        (
            record.fields[1].offset,
            record.fields[1].bytes,
            record.geometry.size
        ),
        (4, 0, Some(4))
    );
    assert_eq!(layouts.layout(TypeId(6)).unwrap().geometry.size, Some(0));
}

#[test]
fn array_stride_uses_aligned_length_and_alias_does_not_expand_fields() {
    let layouts = build(vec![
        scalar(3),
        def(TypeKind::Alias(TypeId(0))),
        def(TypeKind::Array {
            element: TypeId(1),
            count: 7,
        }),
        def(TypeKind::Structure(composite(
            &[0],
            Packing::Default,
            MinimumAlignment::Default,
        ))),
        def(TypeKind::Alias(TypeId(3))),
    ]);
    assert_eq!(layouts.layout(TypeId(2)).unwrap().array_stride, Some(4));
    assert_eq!(layouts.layout(TypeId(2)).unwrap().geometry.size, Some(28));
    assert_eq!(
        layouts.layout(TypeId(3)).unwrap().geometry,
        layouts.layout(TypeId(4)).unwrap().geometry
    );
    assert!(layouts.layout(TypeId(4)).unwrap().fields.is_empty());
}

#[test]
fn minimum_alignment_and_absolute_max_differ_between_struct_and_union() {
    let mut organization = org();
    organization.absolute_max_alignment = 2;
    organization.machine_alignment = 16;
    let c = composite(&[0], Packing::Default, MinimumAlignment::Machine);
    let layouts = TypeLayouts::new(
        vec![
            scalar(4),
            def(TypeKind::Structure(c.clone())),
            def(TypeKind::Union(c)),
        ]
        .into(),
        organization,
        Limits::default(),
    )
    .unwrap();
    assert_eq!(
        (
            layouts.layout(TypeId(1)).unwrap().geometry.size,
            layouts.layout(TypeId(1)).unwrap().geometry.alignment
        ),
        (Some(16), 16)
    );
    assert_eq!(
        (
            layouts.layout(TypeId(2)).unwrap().geometry.size,
            layouts.layout(TypeId(2)).unwrap().geometry.alignment
        ),
        (Some(4), 2)
    );
}

#[test]
fn pointer_recursion_and_function_references_are_not_by_value_cycles() {
    let definitions: Arc<[TypeDefinition]> = vec![
        def(TypeKind::Structure(composite(
            &[1],
            Packing::Default,
            MinimumAlignment::Default,
        ))),
        def(TypeKind::Pointer {
            target: TypeId(0),
            bytes: None,
        }),
        def(TypeKind::Function {
            result: TypeId(2),
            parameters: vec![TypeId(2), TypeId(0)],
            variadic: true,
        }),
        def(TypeKind::Pointer {
            target: TypeId(2),
            bytes: None,
        }),
    ]
    .into();
    let layouts = TypeLayouts::new(definitions.clone(), org(), Limits::default()).unwrap();
    assert!(Arc::ptr_eq(&definitions, &layouts.shared_definitions()));
    assert_eq!(layouts.layout(TypeId(0)).unwrap().geometry.size, Some(8));
    assert_eq!(layouts.layout(TypeId(2)).unwrap().geometry.size, None);
    let clone = layouts.clone();
    drop(layouts);
    assert_eq!(clone.layout(TypeId(3)).unwrap().geometry.size, Some(8));
    fn send_sync<T: Send + Sync>() {}
    send_sync::<TypeLayouts>();
}

#[test]
fn by_value_cycles_reject_even_zero_arrays_and_unreferenced_components() {
    for definitions in [
        vec![def(TypeKind::Alias(TypeId(0)))],
        vec![def(TypeKind::Array {
            element: TypeId(0),
            count: 0,
        })],
        vec![
            scalar(1),
            def(TypeKind::Structure(composite(
                &[2],
                Packing::Default,
                MinimumAlignment::Default,
            ))),
            def(TypeKind::Alias(TypeId(1))),
        ],
    ] {
        assert!(matches!(
            TypeLayouts::new(definitions.into(), org(), Limits::default()),
            Err(Error::ByValueCycle { .. })
        ));
    }
}

#[test]
fn all_reference_kinds_are_checked_including_pointer_and_signature_refs() {
    for kind in [
        TypeKind::Pointer {
            target: TypeId(9),
            bytes: None,
        },
        TypeKind::Alias(TypeId(9)),
        TypeKind::Array {
            element: TypeId(9),
            count: 0,
        },
        TypeKind::Function {
            result: TypeId(0),
            parameters: vec![TypeId(9)],
            variadic: false,
        },
        TypeKind::Structure(composite(&[9], Packing::Default, MinimumAlignment::Default)),
    ] {
        assert!(matches!(
            TypeLayouts::new(vec![def(kind)].into(), org(), Limits::default()),
            Err(Error::InvalidReference {
                target: TypeId(9),
                ..
            })
        ));
    }
}

#[test]
fn void_and_incomplete_have_no_embeddable_storage() {
    for kind in [
        TypeKind::Void,
        TypeKind::Incomplete,
        TypeKind::Function {
            result: TypeId(0),
            parameters: vec![],
            variadic: false,
        },
    ] {
        let layouts = build(vec![def(kind.clone())]);
        assert_eq!(layouts.layout(TypeId(0)).unwrap().geometry.alignment, 1);
        for count in [0, 1] {
            assert!(matches!(
                TypeLayouts::new(
                    vec![
                        def(kind.clone()),
                        def(TypeKind::Array {
                            element: TypeId(0),
                            count
                        })
                    ]
                    .into(),
                    org(),
                    Limits::default()
                ),
                Err(Error::InvalidElement { .. })
            ));
        }
        assert!(matches!(
            TypeLayouts::new(
                vec![
                    def(kind),
                    def(TypeKind::Structure(composite(
                        &[0],
                        Packing::Default,
                        MinimumAlignment::Default
                    )))
                ]
                .into(),
                org(),
                Limits::default()
            ),
            Err(Error::InvalidField { field: 0, .. })
        ));
    }
}

#[test]
fn malformed_organizations_and_declarations_fail_explicitly() {
    for field in [0, 1, 2, 3] {
        let mut organization = org();
        match field {
            0 => organization.default_pointer_alignment = 0,
            1 => organization.size_alignment_map.swap(0, 1),
            2 => organization.size_alignment_map[1].size = 1,
            _ => organization.size_alignment_map[0].alignment = 0,
        }
        assert!(matches!(
            TypeLayouts::new(vec![scalar(4)].into(), organization, Limits::default()),
            Err(Error::InvalidOrganization(_))
        ));
    }
    for kind in [
        TypeKind::Integer {
            bytes: 0,
            signed: true,
        },
        TypeKind::Enum {
            bytes: 9,
            signed: false,
        },
        TypeKind::Pointer {
            target: TypeId(0),
            bytes: Some(0),
        },
        TypeKind::Structure(Composite {
            packing: Packing::Explicit(0),
            ..Default::default()
        }),
        TypeKind::Union(Composite {
            minimum_alignment: MinimumAlignment::Explicit(0),
            ..Default::default()
        }),
    ] {
        assert!(matches!(
            TypeLayouts::new(vec![def(kind)].into(), org(), Limits::default()),
            Err(Error::InvalidType { .. })
        ));
    }
    let layouts = build(vec![]);
    assert_eq!(
        layouts.layout(TypeId(0)),
        Err(Error::UnknownType(TypeId(0)))
    );
    assert_eq!(
        layouts.definition(TypeId(usize::MAX)),
        Err(Error::UnknownType(TypeId(usize::MAX)))
    );
}

#[test]
fn arrays_never_allocate_by_element_count_and_arithmetic_is_checked() {
    let definitions: Arc<[TypeDefinition]> = vec![
        scalar(8),
        def(TypeKind::Array {
            element: TypeId(0),
            count: 1_000_000_000,
        }),
    ]
    .into();
    assert!(matches!(
        TypeLayouts::new(definitions.clone(), org(), Limits::default()),
        Err(Error::Limit(Resource::TypeBytes))
    ));
    let limits = Limits {
        max_type_bytes: u64::MAX,
        ..Default::default()
    };
    let layouts = TypeLayouts::new(definitions, org(), limits).unwrap();
    assert_eq!(
        layouts.layout(TypeId(1)).unwrap().geometry.size,
        Some(8_000_000_000)
    );
    assert_eq!(layouts.layouts().len(), 2);
    assert!(matches!(
        TypeLayouts::new(
            vec![
                scalar(8),
                def(TypeKind::Array {
                    element: TypeId(0),
                    count: u64::MAX
                })
            ]
            .into(),
            org(),
            limits
        ),
        Err(Error::Overflow(TypeId(1)))
    ));
}

#[test]
fn every_limit_is_exact_and_one_below_fails() {
    let definitions: Arc<[TypeDefinition]> = vec![
        TypeDefinition::new("integer", TypeKind::Builtin(Builtin::Int)),
        TypeDefinition::new(
            "array",
            TypeKind::Array {
                element: TypeId(0),
                count: 3,
            },
        ),
        TypeDefinition::new(
            "struct",
            TypeKind::Structure(Composite {
                fields: vec![Field::new("field", TypeId(1))],
                ..Default::default()
            }),
        ),
    ]
    .into();
    let mut organization = org();
    organization.size_alignment_map = vec![SizeAlignment {
        size: 4,
        alignment: 4,
    }];
    let baseline =
        TypeLayouts::new(definitions.clone(), organization.clone(), Limits::default()).unwrap();
    let stats = baseline.stats();
    let exact = Limits {
        max_types: stats.types,
        max_fields: stats.fields,
        max_references: stats.references,
        max_name_length: 7,
        max_name_bytes: stats.name_bytes,
        max_alignment_entries: 1,
        max_depth: stats.depth,
        max_type_bytes: 12,
        max_work: stats.work,
    };
    assert_eq!(
        TypeLayouts::new(definitions.clone(), organization.clone(), exact)
            .unwrap()
            .layouts(),
        baseline.layouts()
    );
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
        assert_eq!(
            TypeLayouts::new(definitions.clone(), organization.clone(), limits).unwrap_err(),
            Error::Limit(*resource)
        );
    }
    for work in 0..stats.work {
        assert_eq!(
            TypeLayouts::new(
                definitions.clone(),
                organization.clone(),
                Limits {
                    max_work: work,
                    ..exact
                }
            )
            .unwrap_err(),
            Error::Limit(Resource::Work)
        );
    }
}

#[test]
fn deep_alias_chain_is_iterative_linear_and_drops_without_recursion() {
    fn chain(n: usize) -> TypeLayouts {
        let mut definitions = (0..n - 1)
            .map(|i| def(TypeKind::Alias(TypeId(i + 1))))
            .collect::<Vec<_>>();
        definitions.push(scalar(4));
        TypeLayouts::new(definitions.into(), org(), Limits::default()).unwrap()
    }
    let small = chain(50_000);
    let large = chain(100_000);
    assert_eq!(large.stats().depth, 100_000);
    assert!(large.stats().work <= 2 * small.stats().work);
    assert_eq!(large.layout(TypeId(0)).unwrap().geometry.size, Some(4));
    assert!(large.layout(TypeId(0)).unwrap().fields.is_empty());
    let limit = Limits {
        max_depth: 99_999,
        ..Default::default()
    };
    assert_eq!(
        TypeLayouts::new(large.shared_definitions(), org(), limit).unwrap_err(),
        Error::Limit(Resource::Depth)
    );
}
