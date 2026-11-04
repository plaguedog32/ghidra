use ghidra_abi::*;
use ghidra_languages::{
    DataOrganization, DatatypeClass, DatatypeFilter, MetaType, ModelRule, RuleAction,
    RuleQualifier, StorageClass,
};
use ghidra_types::{
    Builtin, Composite, Field, MinimumAlignment, Packing, TypeDefinition, TypeId, TypeKind,
    TypeLayouts,
};
use std::sync::Arc;

fn def(kind: TypeKind) -> TypeDefinition {
    TypeDefinition::new("", kind)
}
fn scalar(bytes: u32) -> TypeDefinition {
    def(TypeKind::Integer {
        bytes,
        signed: true,
    })
}
fn aggregate(fields: &[usize]) -> Composite {
    Composite {
        fields: fields.iter().map(|i| Field::new("", TypeId(*i))).collect(),
        ..Default::default()
    }
}
fn engine(definitions: Vec<TypeDefinition>) -> DatatypePredicates {
    let layouts = Arc::new(
        TypeLayouts::new(
            definitions.into(),
            DataOrganization::default().resolve(8),
            Default::default(),
        )
        .unwrap(),
    );
    DatatypePredicates::new(layouts, Default::default()).unwrap()
}
fn filter(class: DatatypeClass) -> DatatypeFilter {
    DatatypeFilter {
        class,
        min_size: None,
        max_size: None,
        sizes: vec![],
        max_primitives: None,
        min_elements: None,
        max_elements: None,
    }
}
fn matches(e: &DatatypePredicates, f: &DatatypeFilter, id: usize) -> bool {
    e.matches_filter(f, TypeId(id), Default::default())
        .unwrap()
        .matched
}
fn rule(datatype: DatatypeFilter, qualifiers: Vec<RuleQualifier>) -> ModelRule {
    ModelRule {
        datatype,
        qualifiers,
        preconditions: vec![],
        action: RuleAction::Consume {
            storage: StorageClass::General,
        },
        side_effects: vec![],
        line: 0,
    }
}

#[test]
fn size_predicates_use_raw_public_length_and_preserve_empty_placeholders() {
    let e = engine(vec![
        scalar(3),
        def(TypeKind::Array {
            element: TypeId(0),
            count: 0,
        }),
        def(TypeKind::Structure(Composite::default())),
    ]);
    let mut f = filter(DatatypeClass::Any);
    f.sizes = vec![3, 3, 5];
    assert!(matches(&e, &f, 0)); // aligned_length is 4, public length 3
    assert!(!matches(&e, &f, 1));
    f.sizes = vec![1];
    assert!(matches(&e, &f, 1));
    assert!(matches(&e, &f, 2));
    f.sizes.clear();
    f.min_size = Some(2);
    f.max_size = Some(0);
    assert!(matches(&e, &f, 0));
    assert!(!matches(&e, &f, 1));
    f.min_size = Some(5);
    f.max_size = Some(2);
    assert!(!matches(&e, &f, 0)); // source allows an always-false range
}

#[test]
fn metatypes_follow_retained_java_including_enum_void_char_and_function_quirks() {
    let kinds = [
        TypeKind::Void,
        TypeKind::Enum {
            bytes: 4,
            signed: true,
        },
        TypeKind::Enum {
            bytes: 4,
            signed: false,
        },
        TypeKind::Builtin(Builtin::Char),
        TypeKind::Builtin(Builtin::WChar),
        TypeKind::Builtin(Builtin::Bool),
        TypeKind::Opaque { bytes: 4 },
        TypeKind::Function {
            result: TypeId(0),
            parameters: vec![],
            variadic: false,
        },
        TypeKind::Pointer {
            target: TypeId(0),
            bytes: None,
        },
    ];
    let e = engine(kinds.into_iter().map(def).collect());
    for (id, meta) in [
        MetaType::Unknown,
        MetaType::Int,
        MetaType::Uint,
        MetaType::Int,
        MetaType::Int,
        MetaType::Bool,
        MetaType::Unknown,
        MetaType::Code,
        MetaType::Ptr,
    ]
    .into_iter()
    .enumerate()
    {
        assert_eq!(e.fact(TypeId(id)).unwrap().meta_type, Some(meta));
        assert_eq!(matches(&e, &filter(DatatypeClass::Meta(meta)), id), id != 7);
    }
    assert!(!matches(
        &e,
        &filter(DatatypeClass::Meta(MetaType::Void)),
        0
    ));
    assert!(!matches(
        &e,
        &filter(DatatypeClass::Meta(MetaType::EnumInt)),
        1
    ));
    assert!(!matches(
        &e,
        &filter(DatatypeClass::Meta(MetaType::EnumUint)),
        2
    ));
    assert_eq!(e.fact(TypeId(7)).unwrap().length, Some(-1));
    let mut org = DataOrganization::default().resolve(8);
    org.char_signed = false;
    let layouts = Arc::new(
        TypeLayouts::new(
            vec![
                def(TypeKind::Builtin(Builtin::Char)),
                def(TypeKind::Builtin(Builtin::WChar)),
            ]
            .into(),
            org,
            Default::default(),
        )
        .unwrap(),
    );
    let e = DatatypePredicates::new(layouts, Default::default()).unwrap();
    assert!(matches(&e, &filter(DatatypeClass::Meta(MetaType::Uint)), 0));
    assert!(matches(&e, &filter(DatatypeClass::Meta(MetaType::Int)), 1));
}

#[test]
fn parsed_array_filter_is_not_typedef_transparent_but_hfa_is() {
    let e = engine(vec![
        def(TypeKind::Float { bytes: 4 }),
        def(TypeKind::Array {
            element: TypeId(0),
            count: 3,
        }),
        def(TypeKind::Alias(TypeId(1))),
    ]);
    let mut f = filter(DatatypeClass::Meta(MetaType::Array));
    f.min_elements = Some(3);
    f.max_elements = Some(3);
    assert!(matches(&e, &f, 1));
    assert!(!matches(&e, &f, 2));
    assert_eq!(e.fact(TypeId(2)).unwrap().meta_type, Some(MetaType::Array));
    assert!(matches(
        &e,
        &filter(DatatypeClass::HomogeneousFloatAggregate),
        2
    ));
    f.max_elements = Some(2);
    assert!(!matches(&e, &f, 1));
    f.max_elements = Some(0);
    assert!(matches(&e, &f, 1));
}

#[test]
fn hfa_uses_alias_canonical_identity_and_ignores_size_bounds_and_tail_padding() {
    let e = engine(vec![
        def(TypeKind::Float { bytes: 4 }),
        def(TypeKind::Float { bytes: 4 }),
        def(TypeKind::Alias(TypeId(0))),
        def(TypeKind::Alias(TypeId(2))),
        def(TypeKind::Structure(aggregate(&[0, 1]))),
        def(TypeKind::Structure(aggregate(&[2, 3]))),
        def(TypeKind::Structure(Composite {
            fields: vec![Field::new("", TypeId(0))],
            minimum_alignment: MinimumAlignment::Explicit(16),
            packing: Packing::Explicit(1),
        })),
    ]);
    let mut f = filter(DatatypeClass::HomogeneousFloatAggregate);
    assert!(!matches(&e, &f, 0));
    assert!(!matches(&e, &f, 4));
    assert!(matches(&e, &f, 5));
    assert_eq!(
        e.fact(TypeId(5)).unwrap().homogeneous_float,
        HomogeneousFloat::Float {
            primitive: TypeId(0),
            count: 2
        }
    );
    assert!(matches(&e, &f, 6));
    f.min_size = Some(100);
    f.max_size = Some(1);
    assert!(matches(&e, &f, 5));
    f.min_size = None;
    f.max_size = None;
    f.sizes = vec![999];
    assert!(matches(&e, &f, 5));
    f.max_primitives = Some(1);
    assert!(!matches(&e, &f, 5));
}

#[test]
fn hfa_handles_unions_zero_arrays_empty_members_and_default_primitive_limit() {
    let e = engine(vec![
        def(TypeKind::Float { bytes: 4 }),
        def(TypeKind::Array {
            element: TypeId(0),
            count: 0,
        }),
        def(TypeKind::Structure(Composite::default())),
        def(TypeKind::Union(aggregate(&[0]))),
        def(TypeKind::Structure(aggregate(&[0, 1, 2]))),
        def(TypeKind::Structure(aggregate(&[0, 3]))),
        def(TypeKind::Array {
            element: TypeId(0),
            count: 4,
        }),
        def(TypeKind::Array {
            element: TypeId(0),
            count: 5,
        }),
    ]);
    let mut f = filter(DatatypeClass::HomogeneousFloatAggregate);
    for id in [1, 2, 3, 5, 7] {
        assert!(!matches(&e, &f, id), "id={id}");
    }
    for id in [4, 6] {
        assert!(matches(&e, &f, id));
    }
    f.max_primitives = Some(0);
    assert!(!matches(&e, &f, 7));
    f.max_primitives = Some(5);
    assert!(matches(&e, &f, 7));
}

#[test]
fn qualifiers_use_literal_positions_relative_varargs_and_arbitrary_negative_return_indices() {
    let e = engine(vec![scalar(4), def(TypeKind::Float { bytes: 8 })]);
    let inputs = [TypeId(0), TypeId(1), TypeId(0)];
    let context = PrototypeTypes {
        result: TypeId(1),
        parameters: &inputs,
        first_vararg: Some(2),
    };
    let f = filter(DatatypeClass::Any);
    let r = rule(
        f.clone(),
        vec![
            RuleQualifier::Position { index: 2 },
            RuleQualifier::Varargs {
                first: Some(0),
                last: Some(1),
            },
            RuleQualifier::DatatypeAt {
                index: -99,
                datatype: filter(DatatypeClass::Meta(MetaType::Float)),
            },
        ],
    );
    assert!(
        e.matches_rule(&r, TypeId(0), context, 2, Default::default())
            .unwrap()
            .matched
    );
    assert_eq!(
        e.matches_rule(&r, TypeId(0), context, 1, Default::default())
            .unwrap()
            .rejection,
        Some(PredicateRejection::Qualifier(0))
    );
    let r = rule(
        f.clone(),
        vec![RuleQualifier::Varargs {
            first: None,
            last: None,
        }],
    );
    assert!(
        e.matches_rule(&r, TypeId(1), context, -1, Default::default())
            .unwrap()
            .matched
    ); // delta=-3 is unrestricted
    assert!(
        !e.matches_rule(
            &r,
            TypeId(0),
            PrototypeTypes {
                first_vararg: None,
                ..context
            },
            2,
            Default::default()
        )
        .unwrap()
        .matched
    );
    let r = rule(
        f,
        vec![RuleQualifier::DatatypeAt {
            index: 3,
            datatype: filter(DatatypeClass::Any),
        }],
    );
    assert_eq!(
        e.matches_rule(&r, TypeId(0), context, 0, Default::default())
            .unwrap()
            .rejection,
        Some(PredicateRejection::Qualifier(0))
    );
}

#[test]
fn rule_predicates_short_circuit_and_never_execute_actions_or_effects() {
    let e = engine(vec![scalar(4), def(TypeKind::Float { bytes: 8 })]);
    let context = PrototypeTypes {
        result: TypeId(0),
        parameters: &[],
        first_vararg: Some(0),
    };
    let malformed = DatatypeFilter {
        sizes: vec![0],
        ..filter(DatatypeClass::Any)
    };
    let mut r = rule(
        filter(DatatypeClass::Meta(MetaType::Float)),
        vec![RuleQualifier::DatatypeAt {
            index: -1,
            datatype: malformed.clone(),
        }],
    );
    assert_eq!(
        e.matches_rule(&r, TypeId(0), context, 0, Default::default())
            .unwrap()
            .rejection,
        Some(PredicateRejection::Datatype)
    );
    r.datatype = filter(DatatypeClass::Any);
    r.qualifiers.insert(0, RuleQualifier::Position { index: 8 });
    assert_eq!(
        e.matches_rule(&r, TypeId(0), context, 0, Default::default())
            .unwrap()
            .rejection,
        Some(PredicateRejection::Qualifier(0))
    );
    r.qualifiers.remove(0);
    assert!(matches!(
        e.matches_rule(&r, TypeId(0), context, 0, Default::default()),
        Err(PredicateError::InvalidFilter(_))
    ));
    r.qualifiers.clear();
    r.action = RuleAction::ConvertToPointer;
    assert!(
        e.matches_rule(&r, TypeId(0), context, 0, Default::default())
            .unwrap()
            .matched
    );
    assert_eq!(e.fact(TypeId(0)).unwrap().meta_type, Some(MetaType::Int));
}

#[test]
fn invalid_ids_contexts_filters_and_incomplete_types_fail_without_partial_results() {
    let e = engine(vec![
        def(TypeKind::Incomplete),
        def(TypeKind::Pointer {
            target: TypeId(0),
            bytes: None,
        }),
    ]);
    let any = filter(DatatypeClass::Any);
    assert_eq!(
        e.matches_filter(&any, TypeId(0), Default::default())
            .unwrap_err(),
        PredicateError::IncompleteType(TypeId(0))
    );
    assert!(matches(&e, &filter(DatatypeClass::Meta(MetaType::Ptr)), 1));
    assert_eq!(
        e.fact(TypeId(99)).unwrap_err(),
        PredicateError::UnknownType(TypeId(99))
    );
    assert_eq!(
        e.matches_filter(&any, TypeId(99), Default::default())
            .unwrap_err(),
        PredicateError::UnknownType(TypeId(99))
    );
    for f in [
        DatatypeFilter {
            sizes: vec![0],
            ..any.clone()
        },
        DatatypeFilter {
            sizes: vec![4],
            max_size: Some(4),
            ..any.clone()
        },
        DatatypeFilter {
            min_size: Some(u32::MAX),
            ..any.clone()
        },
    ] {
        assert!(matches!(
            e.matches_filter(&f, TypeId(1), Default::default()),
            Err(PredicateError::InvalidFilter(_))
        ));
    }
    let r = rule(any, vec![]);
    for context in [
        PrototypeTypes {
            result: TypeId(99),
            parameters: &[],
            first_vararg: None,
        },
        PrototypeTypes {
            result: TypeId(1),
            parameters: &[TypeId(99)],
            first_vararg: None,
        },
    ] {
        assert!(matches!(
            e.matches_rule(&r, TypeId(1), context, 0, Default::default()),
            Err(PredicateError::UnknownType(TypeId(99)))
        ));
    }
    let context = PrototypeTypes {
        result: TypeId(1),
        parameters: &[],
        first_vararg: Some(1),
    };
    assert!(matches!(
        e.matches_rule(&r, TypeId(1), context, 0, Default::default()),
        Err(PredicateError::InvalidPrototype(_))
    ));
    let context = PrototypeTypes {
        result: TypeId(1),
        parameters: &[TypeId(1)],
        first_vararg: Some(1),
    };
    let r = rule(
        filter(DatatypeClass::Any),
        vec![RuleQualifier::Varargs {
            first: None,
            last: None,
        }],
    );
    assert_eq!(
        e.matches_rule(&r, TypeId(1), context, i32::MIN, Default::default())
            .unwrap_err(),
        PredicateError::PositionOverflow
    );
}

#[test]
fn construction_limits_are_exact_and_work_exhaustion_never_returns_a_partial_snapshot() {
    let layouts = Arc::new(
        TypeLayouts::new(
            vec![
                def(TypeKind::Structure(aggregate(&[1]))),
                def(TypeKind::Alias(TypeId(2))),
                def(TypeKind::Float { bytes: 4 }),
            ]
            .into(),
            DataOrganization::default().resolve(8),
            Default::default(),
        )
        .unwrap(),
    );
    let e = DatatypePredicates::new(layouts.clone(), Default::default()).unwrap();
    let s = e.stats();
    let exact = PredicateLimits {
        max_types: s.types,
        max_references: s.references,
        max_depth: s.depth,
        max_work: s.work,
        ..Default::default()
    };
    assert_eq!(
        DatatypePredicates::new(layouts.clone(), exact)
            .unwrap()
            .facts(),
        e.facts()
    );
    for (limits, resource) in [
        (
            PredicateLimits {
                max_types: s.types - 1,
                ..exact
            },
            "types",
        ),
        (
            PredicateLimits {
                max_references: s.references - 1,
                ..exact
            },
            "references",
        ),
        (
            PredicateLimits {
                max_depth: s.depth - 1,
                ..exact
            },
            "depth",
        ),
    ] {
        assert_eq!(
            DatatypePredicates::new(layouts.clone(), limits).unwrap_err(),
            PredicateError::Limit(resource)
        );
    }
    for work in 0..s.work {
        assert_eq!(
            DatatypePredicates::new(
                layouts.clone(),
                PredicateLimits {
                    max_work: work,
                    ..exact
                }
            )
            .unwrap_err(),
            PredicateError::Limit("work")
        );
    }
}

#[test]
fn query_limits_include_all_reached_filters_and_match_exact_boundaries() {
    let e = engine(vec![scalar(4)]);
    let f = DatatypeFilter {
        sizes: vec![1, 4, 4],
        ..filter(DatatypeClass::Any)
    };
    let r = rule(
        f.clone(),
        vec![
            RuleQualifier::Position { index: 0 },
            RuleQualifier::DatatypeAt {
                index: -1,
                datatype: f,
            },
        ],
    );
    let parameters = [TypeId(0)];
    let context = PrototypeTypes {
        result: TypeId(0),
        parameters: &parameters,
        first_vararg: None,
    };
    let baseline = e
        .matches_rule(&r, TypeId(0), context, 0, Default::default())
        .unwrap();
    assert!(baseline.matched);
    assert_eq!(baseline.usage.size_items, 6);
    let exact = PredicateLimits {
        max_size_items: 6,
        max_qualifiers: 2,
        max_parameters: 1,
        max_work: baseline.usage.work,
        ..Default::default()
    };
    assert_eq!(
        e.matches_rule(&r, TypeId(0), context, 0, exact).unwrap(),
        baseline
    );
    for (limits, resource) in [
        (
            PredicateLimits {
                max_size_items: 5,
                ..exact
            },
            "size items",
        ),
        (
            PredicateLimits {
                max_qualifiers: 1,
                ..exact
            },
            "qualifiers",
        ),
        (
            PredicateLimits {
                max_parameters: 0,
                ..exact
            },
            "parameters",
        ),
    ] {
        assert_eq!(
            e.matches_rule(&r, TypeId(0), context, 0, limits)
                .unwrap_err(),
            PredicateError::Limit(resource)
        );
    }
    for work in 0..baseline.usage.work {
        assert_eq!(
            e.matches_rule(
                &r,
                TypeId(0),
                context,
                0,
                PredicateLimits {
                    max_work: work,
                    ..exact
                }
            )
            .unwrap_err(),
            PredicateError::Limit("work")
        );
    }
}

#[test]
fn large_alias_graphs_and_billion_element_arrays_use_linear_metadata_only() {
    fn chain(n: usize) -> DatatypePredicates {
        let mut defs = (0..n - 1)
            .map(|i| def(TypeKind::Alias(TypeId(i + 1))))
            .collect::<Vec<_>>();
        defs.push(def(TypeKind::Float { bytes: 4 }));
        engine(defs)
    }
    let small = chain(50_000);
    let large = chain(100_000);
    assert_eq!(large.stats().depth, 100_000);
    // This chain costs 6*N-1 units: the single leaf has one dependency-loop
    // visit rather than the two visits of each alias.
    assert_eq!(small.stats().work, 6 * 50_000 - 1);
    assert_eq!(large.stats().work, 2 * small.stats().work + 1);
    assert_eq!(large.fact(TypeId(0)).unwrap().canonical, TypeId(99_999));
    let definitions = vec![
        def(TypeKind::Float { bytes: 4 }),
        def(TypeKind::Array {
            element: TypeId(0),
            count: 1_000_000_000,
        }),
    ];
    let layouts = Arc::new(
        TypeLayouts::new(
            definitions.into(),
            DataOrganization::default().resolve(8),
            ghidra_types::Limits {
                max_type_bytes: u64::MAX,
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let predicates = DatatypePredicates::new(layouts.clone(), Default::default()).unwrap();
    assert!(Arc::ptr_eq(predicates.layouts(), &layouts));
    assert_eq!(
        predicates.fact(TypeId(1)).unwrap().homogeneous_float,
        HomogeneousFloat::Float {
            primitive: TypeId(0),
            count: 1_000_000_000
        }
    );
    assert!(!matches(
        &predicates,
        &filter(DatatypeClass::HomogeneousFloatAggregate),
        1
    ));
    assert_eq!(predicates.facts().len(), 2);
    fn send_sync<T: Send + Sync>() {}
    send_sync::<DatatypePredicates>();
    let clone = predicates.clone();
    drop(predicates);
    assert_eq!(clone.facts().len(), 2);
}
