//! Rule matching on decoded native objects, including types that have no
//! source ID. Expectations follow TypeFactory's bitfield transport and the
//! native filters in modelrules.cc; no rule actions are executed here.
mod native_common;

use std::sync::Arc;

use ghidra_abi::*;
use ghidra_languages::{
    DatatypeClass, DatatypeFilter, MetaType, ModelRule, RuleAction, RuleQualifier,
};
use ghidra_types::{Endianness, Field, MinimumAlignment, Packing, TypeId, TypeKind};
use native_common::*;

struct Fixture {
    graph: Arc<NativeTypeGraph>,
    int: NativeTypeId,
    uint: NativeTypeId,
    array: NativeTypeId,
    unknown: NativeTypeId,
    opaque: NativeTypeId,
    pair: TypeId,
    mixed: TypeId,
    incomplete: TypeId,
}

fn fixture(order: Endianness) -> Fixture {
    let mut source = Source::default();
    let int = source.int(4, true);
    let uint = source.int(8, false);
    let wide = source.int(16, false);
    let float = source.float(4);
    let mut record = |name: &str, base, bits| {
        source.with_fields(
            vec![Field::bitfield(name, base, bits)],
            Packing::Default,
            MinimumAlignment::Default,
            false,
        )
    };
    let int_owner = record("signed", int, 16);
    let uint_owner = record("unsigned", uint, 24);
    let array_owner = record("bytes", wide, 96);
    let union = source.with_fields(
        vec![
            Field::bitfield("small", int, 3),
            Field::bitfield("large", wide, 128),
        ],
        Packing::Default,
        MinimumAlignment::Default,
        true,
    );
    let pair = source.structure(&[float, float]);
    let alias = source.alias(float);
    let mixed = source.structure(&[float, alias]);
    let incomplete = source.add(TypeKind::Incomplete);
    let enum3 = source.add(TypeKind::Enum {
        bytes: 3,
        signed: false,
    });
    source.array(enum3, 2); // Native stride four cannot fit the six-byte transport.
    let graph = bridge(source.layouts_with(organization(), order));
    let member = |owner| graph.fields(id(owner)).unwrap()[0].ty;
    Fixture {
        int: member(int_owner),
        uint: member(uint_owner),
        array: member(array_owner),
        unknown: graph.fields(id(union)).unwrap()[0].ty,
        opaque: graph.fields(id(union)).unwrap()[1].ty,
        graph,
        pair,
        mixed,
        incomplete,
    }
}

fn sized(class: DatatypeClass, sizes: &[u32]) -> DatatypeFilter {
    DatatypeFilter {
        sizes: sizes.to_vec(),
        ..filter(class)
    }
}

fn rule(datatype: DatatypeFilter, qualifiers: Vec<RuleQualifier>) -> ModelRule {
    ModelRule {
        datatype,
        qualifiers,
        preconditions: vec![],
        action: RuleAction::GotoStack,
        side_effects: vec![],
        line: 0,
    }
}

#[test]
fn synthesized_native_objects_match_without_inventing_source_ids() {
    for order in [Endianness::Little, Endianness::Big] {
        let f = fixture(order);
        for (ty, meta, size) in [
            (f.int, MetaType::Int, 2),
            (f.uint, MetaType::Uint, 3),
            (f.array, MetaType::Array, 12),
            (f.unknown, MetaType::Unknown, 1),
            (f.opaque, MetaType::Struct, 16),
        ] {
            assert!(ty.0 >= f.graph.source_count());
            assert_eq!(
                f.graph.matches_filter(
                    &filter(DatatypeClass::Any),
                    TypeId(ty.0),
                    Default::default()
                ),
                Err(NativePredicateError::UnknownType(TypeId(ty.0))),
            );
            let matched = f
                .graph
                .matches_filter_native(
                    &sized(DatatypeClass::Meta(meta), &[size]),
                    ty,
                    Default::default(),
                )
                .unwrap();
            assert!(matched.matched, "{order:?}: {ty:?}");
            assert_eq!(matched.usage.work, 4); // Evaluate + two size-item scans + header.
            assert_eq!(matched.usage.size_items, 1);
            assert!(
                !f.graph
                    .matches_filter_native(
                        &sized(DatatypeClass::Meta(meta), &[size + 1]),
                        ty,
                        Default::default(),
                    )
                    .unwrap()
                    .matched
            );
        }
        let array_filter = DatatypeFilter {
            min_elements: Some(12),
            max_elements: Some(12),
            ..meta(MetaType::Array)
        };
        assert!(
            f.graph
                .matches_filter_native(&array_filter, f.array, Default::default())
                .unwrap()
                .matched
        );
        let unknown_element = f.graph.array(f.array).unwrap().unwrap().element;
        assert!(
            f.graph
                .matches_filter_native(
                    &meta(MetaType::Unknown),
                    unknown_element,
                    Default::default()
                )
                .unwrap()
                .matched
        );
    }
}

#[test]
fn native_prototype_qualifiers_keep_synthetic_ids_and_absolute_work_charges() {
    let f = fixture(Endianness::Little);
    let parameters = [f.array, f.unknown];
    let prototype = NativePrototypeTypes {
        result: f.opaque,
        parameters: &parameters,
        first_vararg: Some(1),
    };
    let rule = rule(
        sized(DatatypeClass::Meta(MetaType::Int), &[2, 4]),
        vec![
            RuleQualifier::Position { index: 1 },
            RuleQualifier::DatatypeAt {
                index: 0,
                datatype: sized(DatatypeClass::Meta(MetaType::Array), &[12]),
            },
            RuleQualifier::DatatypeAt {
                index: -1,
                datatype: sized(DatatypeClass::Meta(MetaType::Struct), &[16]),
            },
            RuleQualifier::Varargs {
                first: Some(0),
                last: Some(0),
            },
        ],
    );
    let result = f
        .graph
        .matches_rule_native(&rule, f.int, prototype, 1, Default::default())
        .unwrap();
    assert!(result.matched);
    // Header + two parameter checks + candidate (1+2*2+1) + position
    // + two datatype_at checks (1+1+2*1+1 each) + varargs.
    assert_eq!(
        result.usage,
        NativePredicateUsage {
            parameters: 2,
            qualifiers: 4,
            size_items: 4,
            extractions: 0,
            work: 21
        }
    );
    let exact = NativePredicateLimits {
        max_parameters: 2,
        max_qualifiers: 4,
        max_size_items: 4,
        max_work: 21,
        ..Default::default()
    };
    assert_eq!(
        f.graph
            .matches_rule_native(&rule, f.int, prototype, 1, exact)
            .unwrap(),
        result
    );
    for (limits, resource) in [
        (
            NativePredicateLimits {
                max_parameters: 1,
                ..exact
            },
            "parameters",
        ),
        (
            NativePredicateLimits {
                max_qualifiers: 3,
                ..exact
            },
            "qualifiers",
        ),
        (
            NativePredicateLimits {
                max_size_items: 3,
                ..exact
            },
            "size items",
        ),
    ] {
        assert_eq!(
            f.graph
                .matches_rule_native(&rule, f.int, prototype, 1, limits),
            Err(NativePredicateError::Limit(resource))
        );
    }
    for work in 0..21 {
        assert_eq!(
            f.graph.matches_rule_native(
                &rule,
                f.int,
                prototype,
                1,
                NativePredicateLimits {
                    max_work: work,
                    ..exact
                }
            ),
            Err(NativePredicateError::Limit("work"))
        );
    }
    let rejected = f
        .graph
        .matches_rule_native(&rule, f.int, prototype, 0, Default::default())
        .unwrap();
    assert_eq!(rejected.rejection, Some(PredicateRejection::Qualifier(0)));
    assert_eq!(rejected.usage.work, 10);
    fn send_sync<T: Send + Sync>() {}
    send_sync::<NativePrototypeTypes<'static>>();
}

#[test]
fn native_ids_preserve_validation_and_short_circuit_order() {
    let f = fixture(Endianness::Little);
    let unknown = NativeTypeId(f.graph.native_count());
    let failed = id(f.incomplete);
    let invalid = DatatypeFilter {
        sizes: vec![0],
        ..filter(DatatypeClass::Any)
    };
    assert_eq!(
        f.graph
            .matches_filter(&invalid, TypeId(f.int.0), Default::default()),
        Err(NativePredicateError::UnknownType(TypeId(f.int.0))),
        "a synthesized slot is not a source ID, even with an invalid filter"
    );
    assert_eq!(
        f.graph
            .matches_filter_native(&invalid, unknown, Default::default()),
        Err(NativePredicateError::Graph(NativeTypeError::UnknownNative(
            unknown
        )))
    );
    assert_eq!(
        f.graph
            .matches_filter_native(&invalid, failed, Default::default()),
        Err(NativePredicateError::InvalidFilter(
            "sizes must be positive signed ints"
        ))
    );
    assert!(
        matches!(f.graph.matches_filter_native(&filter(DatatypeClass::Any), failed, Default::default()), Err(NativePredicateError::Conversion(NativeConversionError::Incomplete(ty))) if ty == f.incomplete)
    );

    let parameters = [f.array];
    let prototype = NativePrototypeTypes {
        result: failed,
        parameters: &parameters,
        first_vararg: None,
    };
    let mismatched = rule(
        meta(MetaType::Float),
        vec![RuleQualifier::DatatypeAt {
            index: -1,
            datatype: invalid.clone(),
        }],
    );
    assert_eq!(
        f.graph
            .matches_rule_native(&mismatched, f.int, prototype, 0, Default::default())
            .unwrap()
            .rejection,
        Some(PredicateRejection::Datatype)
    );
    let stopped = rule(
        filter(DatatypeClass::Any),
        vec![
            RuleQualifier::Position { index: 1 },
            RuleQualifier::DatatypeAt {
                index: -1,
                datatype: invalid,
            },
        ],
    );
    assert_eq!(
        f.graph
            .matches_rule_native(&stopped, f.int, prototype, 0, Default::default())
            .unwrap()
            .rejection,
        Some(PredicateRejection::Qualifier(0))
    );
    assert!(matches!(
        f.graph
            .matches_rule_native(&stopped, f.int, prototype, 1, Default::default()),
        Err(NativePredicateError::InvalidFilter(_))
    ));
    let bad_parameters = [unknown];
    let bad = NativePrototypeTypes {
        parameters: &bad_parameters,
        ..prototype
    };
    assert_eq!(
        f.graph.matches_rule_native(
            &mismatched,
            f.int,
            NativePrototypeTypes {
                result: unknown,
                ..prototype
            },
            0,
            Default::default(),
        ),
        Err(NativePredicateError::Graph(NativeTypeError::UnknownNative(
            unknown
        ))),
    );
    assert_eq!(
        f.graph
            .matches_rule_native(&mismatched, f.int, bad, 0, Default::default()),
        Err(NativePredicateError::Graph(NativeTypeError::UnknownNative(
            unknown
        )))
    );
    assert_eq!(
        f.graph.matches_rule_native(
            &stopped,
            unknown,
            bad,
            0,
            NativePredicateLimits {
                max_qualifiers: 0,
                ..Default::default()
            }
        ),
        Err(NativePredicateError::Limit("qualifiers"))
    );
    assert!(matches!(
        f.graph.matches_rule_native(
            &stopped,
            unknown,
            NativePrototypeTypes {
                first_vararg: Some(2),
                ..bad
            },
            0,
            Default::default()
        ),
        Err(NativePredicateError::InvalidPrototype(_))
    ));
    assert!(matches!(
        f.graph.homogeneous_float_aggregate_native(
            unknown,
            Some(i32::MAX as u32 + 1),
            Default::default()
        ),
        Err(NativePredicateError::InvalidFilter(_))
    ));
}

#[test]
fn native_hfa_queries_inspect_the_actual_synthetic_objects() {
    let f = fixture(Endianness::Little);
    let array = f
        .graph
        .homogeneous_float_aggregate_native(f.array, Some(12), Default::default())
        .unwrap();
    assert_eq!(array.rejection, Some(NativeHfaRejection::ContainsUnknown));
    assert_eq!(array.usage.extractions, 1);
    assert!(matches!(
        f.graph
            .homogeneous_float_aggregate_native(f.array, Some(11), Default::default())
            .unwrap()
            .rejection,
        Some(NativeHfaRejection::Invalid(_))
    ));
    assert_eq!(
        f.graph
            .homogeneous_float_aggregate_native(f.int, None, Default::default())
            .unwrap()
            .rejection,
        Some(NativeHfaRejection::NotAggregate(MetaType::Int))
    );
    assert_eq!(
        f.graph
            .homogeneous_float_aggregate_native(f.opaque, None, Default::default())
            .unwrap()
            .rejection,
        Some(NativeHfaRejection::Empty)
    );
    assert!(
        f.graph
            .homogeneous_float_aggregate_native(id(f.pair), None, Default::default())
            .unwrap()
            .matched
    );
    assert!(matches!(
        f.graph
            .homogeneous_float_aggregate_native(id(f.mixed), None, Default::default())
            .unwrap()
            .rejection,
        Some(NativeHfaRejection::MixedIdentity { .. })
    ));
    for work in 0..array.usage.work {
        assert_eq!(
            f.graph.homogeneous_float_aggregate_native(
                f.array,
                Some(12),
                NativePredicateLimits {
                    max_work: work,
                    ..Default::default()
                }
            ),
            Err(NativePredicateError::Limit("work"))
        );
    }
    for (limits, resource) in [
        (
            NativePredicateLimits {
                max_live_primitives: 11,
                ..Default::default()
            },
            "live primitives",
        ),
        (
            NativePredicateLimits {
                max_depth: 1,
                ..Default::default()
            },
            "depth",
        ),
    ] {
        assert_eq!(
            f.graph
                .homogeneous_float_aggregate_native(f.array, Some(12), limits),
            Err(NativePredicateError::Limit(resource))
        );
    }
}

#[test]
fn source_bridge_queries_keep_the_same_results_errors_and_work() {
    for order in [Endianness::Little, Endianness::Big] {
        let f = fixture(order);
        let filters = [
            filter(DatatypeClass::Any),
            meta(MetaType::Float),
            meta(MetaType::Array),
            sized(DatatypeClass::Any, &[1, 2, 3, 4, 8, 12, 16]),
            hfa(),
            DatatypeFilter {
                min_elements: Some(2),
                ..meta(MetaType::Array)
            },
            meta(MetaType::PartEnum),
        ];
        let parameters = [f.pair, f.incomplete];
        let native_parameters = parameters.map(id);
        let source_proto = PrototypeTypes {
            result: f.pair,
            parameters: &parameters,
            first_vararg: Some(1),
        };
        let native_proto = NativePrototypeTypes {
            result: id(f.pair),
            parameters: &native_parameters,
            first_vararg: Some(1),
        };
        for index in 0..f.graph.source_count() {
            let source = TypeId(index);
            let native = NativeTypeId(index);
            for filter in &filters {
                for max_work in [0, 1, 2, 7, NativePredicateLimits::default().max_work] {
                    let limits = NativePredicateLimits {
                        max_work,
                        ..Default::default()
                    };
                    assert_eq!(
                        f.graph.matches_filter(filter, source, limits),
                        f.graph.matches_filter_native(filter, native, limits)
                    );
                    let rule = rule(
                        filter.clone(),
                        vec![
                            RuleQualifier::DatatypeAt {
                                index: -1,
                                datatype: hfa(),
                            },
                            RuleQualifier::Varargs {
                                first: None,
                                last: None,
                            },
                        ],
                    );
                    assert_eq!(
                        f.graph.matches_rule(&rule, source, source_proto, 1, limits),
                        f.graph
                            .matches_rule_native(&rule, native, native_proto, 1, limits)
                    );
                }
            }
            for maximum in [None, Some(0), Some(1), Some(4)] {
                assert_eq!(
                    f.graph
                        .homogeneous_float_aggregate(source, maximum, Default::default()),
                    f.graph
                        .homogeneous_float_aggregate_native(native, maximum, Default::default())
                );
            }
        }
    }
}
