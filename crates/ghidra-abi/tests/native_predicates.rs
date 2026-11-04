//! Directed native filter/qualifier tests (modelrules.cc). Each case states the
//! native answer and, where they differ, the unchanged Java predicate answer.
mod native_common;

use std::path::PathBuf;
use std::sync::Arc;

use ghidra_abi::*;
use ghidra_languages::{
    CompilerSpec, DatatypeClass, DatatypeFilter, MetaType, ModelRule, RuleQualifier,
};
use ghidra_types::{TypeId, TypeKind, TypeLayouts};
use native_common::*;

struct Both {
    native: Arc<NativeTypeGraph>,
    java: DatatypePredicates,
}

impl Both {
    fn new(source: &Source) -> Self {
        let layouts: Arc<TypeLayouts> = source.layouts();
        Self {
            native: bridge(layouts.clone()),
            java: DatatypePredicates::new(layouts, Default::default()).unwrap(),
        }
    }
    fn native(&self, filter: &DatatypeFilter, ty: TypeId) -> bool {
        self.native
            .matches_filter(filter, ty, Default::default())
            .unwrap()
            .matched
    }
    fn java(&self, filter: &DatatypeFilter, ty: TypeId) -> bool {
        self.java
            .matches_filter(filter, ty, Default::default())
            .unwrap()
            .matched
    }
    fn hfa(&self, ty: TypeId, max: Option<u32>) -> NativeHfa {
        self.native
            .homogeneous_float_aggregate(ty, max, Default::default())
            .unwrap()
    }
}

fn sized(class: DatatypeClass, sizes: &[u32]) -> DatatypeFilter {
    DatatypeFilter {
        sizes: sizes.to_vec(),
        ..filter(class)
    }
}

#[test]
fn float_alias_identity_decides_native_hfa() {
    let mut s = Source::default();
    let f = s.float(4);
    let a = s.alias(f);
    let b = s.alias(a);
    let fa = s.structure(&[f, a]);
    let ab = s.structure(&[a, b]);
    let aa = s.structure(&[a, a]);
    let ff = s.structure(&[f, f]);
    let typedef = s.alias(aa);
    let both = Both::new(&s);
    for (ty, native) in [
        (fa, false),
        (ab, false),
        (aa, true),
        (ff, true),
        (typedef, true),
    ] {
        assert_eq!(both.native(&hfa(), ty), native, "{ty:?}");
        assert!(both.java(&hfa(), ty), "Java strips aliases for {ty:?}");
    }
    assert_eq!(
        both.hfa(fa, None).rejection,
        Some(NativeHfaRejection::MixedIdentity {
            index: 1,
            first: id(f),
            other: id(a)
        })
    );
    let matched = both.hfa(aa, None);
    assert_eq!(
        (matched.matched, matched.primitive, matched.count),
        (true, Some(id(a)), 2)
    );
    assert_eq!(
        both.hfa(a, None).rejection,
        Some(NativeHfaRejection::NotAggregate(MetaType::Float))
    );
}

fn golang_array_rule() -> ModelRule {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../Ghidra/Processors/x86/data/languages/x86-64-golang.cspec");
    let spec = CompilerSpec::from_path(&path).unwrap();
    spec.prototypes
        .iter()
        .flat_map(|p| &p.input.rules)
        .find(|rule| {
            rule.datatype.class == DatatypeClass::Meta(MetaType::Array)
                && rule.datatype.min_elements == Some(2)
        })
        .expect("retained Go array-to-stack rule")
        .clone()
}

#[test]
fn named_go_array_matches_the_native_array_rule_only() {
    let rule = golang_array_rule();
    let mut s = Source::default();
    let f = s.float(4);
    let array = s.array(f, 4);
    let named = s.alias(array);
    let single = s.array(f, 1);
    let both = Both::new(&s);
    let parameters = [named];
    let prototype = PrototypeTypes {
        result: f,
        parameters: &parameters,
        first_vararg: None,
    };
    let native = |ty| {
        both.native
            .matches_rule(&rule, ty, prototype, 0, Default::default())
            .unwrap()
            .matched
    };
    let java = |ty| {
        both.java
            .matches_rule(&rule, ty, prototype, 0, Default::default())
            .unwrap()
            .matched
    };
    assert!(native(named) && !java(named));
    assert!(native(array) && java(array));
    assert!(!native(single) && !java(single));
}

#[test]
fn void_code_and_zero_arrays_use_native_meta_types_and_sizes() {
    let mut s = Source::default();
    let void = s.add(TypeKind::Void);
    let function = s.add(TypeKind::Function {
        result: void,
        parameters: vec![],
        variadic: false,
    });
    let f = s.float(4);
    let zero = s.array(f, 0);
    let both = Both::new(&s);
    use DatatypeClass::{Any, Meta};
    let any = filter(Any);

    assert!(both.native(&meta(MetaType::Void), void));
    assert!(!both.java(&meta(MetaType::Void), void));
    assert!(!both.native(&meta(MetaType::Unknown), void));
    assert!(both.java(&meta(MetaType::Unknown), void));
    assert!(both.native(&any, void) && both.java(&any, void));

    // Native code has size one; Java's -1 fails the default minimum.
    assert!(both.native(&any, function) && !both.java(&any, function));
    assert!(both.native(&meta(MetaType::Code), function));
    assert!(!both.java(&meta(MetaType::Code), function));
    assert!(both.native(&sized(Any, &[1]), function));

    assert!(!both.native(&meta(MetaType::Array), zero));
    assert!(both.java(&meta(MetaType::Array), zero));
    assert!(both.native(&sized(Meta(MetaType::Unknown), &[1]), zero));
    assert_eq!(
        both.hfa(zero, None).rejection,
        Some(NativeHfaRejection::NotAggregate(MetaType::Unknown))
    );
    assert!(!both.java(&hfa(), zero));
}

#[test]
fn enum_transport_tags_never_match_and_partenum_is_not_a_native_name() {
    let mut s = Source::default();
    let signed = s.add(TypeKind::Enum {
        bytes: 4,
        signed: true,
    });
    let unsigned = s.add(TypeKind::Enum {
        bytes: 2,
        signed: false,
    });
    let both = Both::new(&s);
    assert!(both.native(&meta(MetaType::Int), signed));
    assert!(both.native(&meta(MetaType::Uint), unsigned));
    for ty in [signed, unsigned] {
        assert!(!both.native(&meta(MetaType::EnumInt), ty));
        assert!(!both.native(&meta(MetaType::EnumUint), ty));
    }
    assert_eq!(
        both.native
            .matches_filter(&meta(MetaType::PartEnum), signed, Default::default())
            .unwrap_err(),
        NativePredicateError::InvalidFilter("partenum is not a native meta-type name")
    );
    assert!(!both.java(&meta(MetaType::PartEnum), signed));
}

#[test]
fn native_hfa_uses_extraction_checks_and_ignores_size_bounds() {
    let mut s = Source::default();
    let f = s.float(4);
    let d = s.float(8);
    let i = s.int(4, true);
    let o16 = s.opaque(16);
    let o4 = s.opaque(4);
    let four = s.structure(&[f, f, f, f]);
    let five = s.structure(&[f, f, f, f, f]);
    let floats = s.array(f, 4);
    let tail = s.packed(&[f, o16]);
    let unknown = s.structure(&[f, o4]);
    let mixed = s.structure(&[d, f]);
    let integer = s.structure(&[i, i]);
    let union = s.union(&[f]);
    let with_union = s.structure(&[f, union]);
    let empty = s.structure(&[]);
    let i32_ = s.int(4, true);
    let gap = s.with_fields(
        vec![
            ghidra_types::Field::bitfield("b", i32_, 3),
            ghidra_types::Field::new("f", f),
        ],
        ghidra_types::Packing::Default,
        ghidra_types::MinimumAlignment::Default,
        false,
    );
    let after = s.with_fields(
        vec![
            ghidra_types::Field::new("f", f),
            ghidra_types::Field::bitfield("b", i32_, 3),
        ],
        ghidra_types::Packing::Default,
        ghidra_types::MinimumAlignment::Default,
        false,
    );
    let both = Both::new(&s);
    let bounded = DatatypeFilter {
        max_size: Some(8),
        ..hfa()
    };
    assert!(both.native(&bounded, four) && both.java(&bounded, four));
    assert!(!both.native(&hfa(), five));
    assert_eq!(
        both.hfa(five, None).rejection,
        Some(NativeHfaRejection::Invalid(
            NativeInvalidExtraction::MaxPrimitives { maximum: 4 }
        ))
    );
    assert!(both.hfa(five, Some(5)).matched && both.hfa(five, Some(0)).rejection.is_some());
    let three = DatatypeFilter {
        max_primitives: Some(3),
        ..hfa()
    };
    assert!(!both.native(&three, four) && both.native(&hfa(), floats));
    // An opaque tail emits nothing natively; Java sees an unknown leaf.
    assert!(both.native(&hfa(), tail) && !both.java(&hfa(), tail));
    let rejection = |ty| both.hfa(ty, None).rejection;
    assert_eq!(
        rejection(unknown),
        Some(NativeHfaRejection::ContainsUnknown)
    );
    assert_eq!(
        rejection(mixed),
        Some(NativeHfaRejection::MixedIdentity {
            index: 1,
            first: id(d),
            other: id(f)
        })
    );
    assert_eq!(
        rejection(integer),
        Some(NativeHfaRejection::NotFloat(MetaType::Int))
    );
    assert_eq!(
        rejection(with_union),
        Some(NativeHfaRejection::Invalid(
            NativeInvalidExtraction::UnionRejected(id(union))
        ))
    );
    assert_eq!(rejection(empty), Some(NativeHfaRejection::Empty));
    // The invisible bitfield leaves a leading native hole. Java instead sees
    // the bitfield's integer base as a leaf, before or after the float.
    assert_eq!(rejection(gap), Some(NativeHfaRejection::ContainsHoles));
    assert!(!both.java(&hfa(), gap));
    assert!(both.native(&hfa(), after) && !both.java(&hfa(), after));
}

#[test]
fn native_array_filter_accepts_aliases_and_checks_native_sizes() {
    let mut s = Source::default();
    let f = s.float(4);
    let array = s.array(f, 3);
    let named = s.alias(array);
    let both = Both::new(&s);
    let bounded = |min, max| DatatypeFilter {
        min_elements: min,
        max_elements: max,
        ..meta(MetaType::Array)
    };
    assert!(both.native(&bounded(Some(3), Some(3)), named));
    assert!(!both.native(&bounded(Some(4), None), named));
    assert!(!both.native(&bounded(None, Some(2)), named));
    assert!(both.native(&bounded(None, Some(0)), named));
    assert!(both.native(&sized(DatatypeClass::Meta(MetaType::Array), &[12]), named));
    assert!(!both.native(&sized(DatatypeClass::Meta(MetaType::Array), &[4]), named));
}

#[test]
fn qualifiers_short_circuit_and_conversion_errors_appear_when_reached() {
    let mut s = Source::default();
    let f = s.float(4);
    let enum3 = s.add(TypeKind::Enum {
        bytes: 3,
        signed: true,
    });
    let bad = s.array(enum3, 2);
    let graph = bridge(s.layouts());
    let at_bad = RuleQualifier::DatatypeAt {
        index: 1,
        datatype: filter(DatatypeClass::Any),
    };
    let rule = |qualifiers: Vec<RuleQualifier>| ModelRule {
        datatype: filter(DatatypeClass::Any),
        qualifiers,
        preconditions: vec![],
        action: ghidra_languages::RuleAction::GotoStack,
        side_effects: vec![],
        line: 0,
    };
    let parameters = [f, bad];
    let prototype = PrototypeTypes {
        result: f,
        parameters: &parameters,
        first_vararg: Some(1),
    };
    let query = |rule: &ModelRule, ty, position| {
        graph.matches_rule(rule, ty, prototype, position, Default::default())
    };
    let skipped = query(
        &rule(vec![RuleQualifier::Position { index: 1 }, at_bad.clone()]),
        f,
        0,
    )
    .unwrap();
    assert_eq!(
        (skipped.matched, skipped.rejection),
        (false, Some(PredicateRejection::Qualifier(0)))
    );
    let conversion = NativeConversionError::ArraySizeMismatch {
        ty: bad,
        count: 2,
        element_aligned_size: 4,
        encoded_size: 6,
        expected: 8,
    };
    assert_eq!(
        query(&rule(vec![at_bad.clone()]), f, 0).unwrap_err(),
        NativePredicateError::Conversion(conversion)
    );
    assert_eq!(
        query(&rule(vec![]), bad, 0).unwrap_err(),
        NativePredicateError::Conversion(conversion)
    );
    // Varargs positions are relative to the first variable slot.
    let varargs = rule(vec![RuleQualifier::Varargs {
        first: Some(0),
        last: Some(0),
    }]);
    assert!(query(&varargs, f, 1).unwrap().matched);
    assert!(!query(&varargs, f, 2).unwrap().matched);
    assert_eq!(
        query(&varargs, f, i32::MIN).unwrap_err(),
        NativePredicateError::PositionOverflow
    );
    let result_void = rule(vec![RuleQualifier::DatatypeAt {
        index: -1,
        datatype: meta(MetaType::Float),
    }]);
    assert!(query(&result_void, f, 0).unwrap().matched);
    let absent = rule(vec![RuleQualifier::DatatypeAt {
        index: 2,
        datatype: filter(DatatypeClass::Any),
    }]);
    assert_eq!(
        query(&absent, f, 0).unwrap().rejection,
        Some(PredicateRejection::Qualifier(0))
    );
    // Prototype validation precedes evaluation.
    let unknown = [f, TypeId(42)];
    assert_eq!(
        graph
            .matches_rule(
                &rule(vec![]),
                f,
                PrototypeTypes {
                    parameters: &unknown,
                    ..prototype
                },
                0,
                Default::default()
            )
            .unwrap_err(),
        NativePredicateError::UnknownType(TypeId(42))
    );
    assert_eq!(
        graph
            .matches_rule(
                &rule(vec![]),
                f,
                PrototypeTypes {
                    first_vararg: Some(3),
                    ..prototype
                },
                0,
                Default::default()
            )
            .unwrap_err(),
        NativePredicateError::InvalidPrototype(
            "first vararg slot exceeds the input list or signed-int range"
        )
    );
    let limited = NativePredicateLimits {
        max_qualifiers: 1,
        max_parameters: 2,
        ..Default::default()
    };
    let two = rule(vec![
        RuleQualifier::Position { index: 0 },
        RuleQualifier::Position { index: 0 },
    ]);
    assert_eq!(
        graph
            .matches_rule(&two, f, prototype, 0, limited)
            .unwrap_err(),
        NativePredicateError::Limit("qualifiers")
    );
    let limited = NativePredicateLimits {
        max_parameters: 1,
        ..Default::default()
    };
    assert_eq!(
        graph
            .matches_rule(&rule(vec![]), f, prototype, 0, limited)
            .unwrap_err(),
        NativePredicateError::Limit("parameters")
    );
}

#[test]
fn filter_validation_matches_the_decoder_boundaries() {
    let mut s = Source::default();
    let f = s.float(4);
    let graph = bridge(s.layouts());
    let check = |filter: DatatypeFilter| graph.matches_filter(&filter, f, Default::default());
    let invalid = |reason| Err(NativePredicateError::InvalidFilter(reason));
    assert_eq!(
        check(DatatypeFilter {
            min_size: Some(1),
            ..sized(DatatypeClass::Any, &[4])
        }),
        invalid("enumerated sizes mixed with range bounds")
    );
    assert_eq!(
        check(sized(DatatypeClass::Any, &[0])),
        invalid("sizes must be positive signed ints")
    );
    assert_eq!(
        check(DatatypeFilter {
            max_size: Some(i32::MAX as u32 + 1),
            ..filter(DatatypeClass::Any)
        }),
        invalid("size bound exceeds signed int")
    );
    assert_eq!(
        check(DatatypeFilter {
            max_primitives: Some(i32::MAX as u32 + 1),
            ..hfa()
        }),
        invalid("primitive bound exceeds signed int")
    );
    assert_eq!(
        check(DatatypeFilter {
            min_elements: Some(i32::MAX as u32 + 1),
            ..meta(MetaType::Array)
        }),
        invalid("element bound exceeds signed int")
    );
    assert_eq!(
        graph.matches_filter(&filter(DatatypeClass::Any), TypeId(9), Default::default()),
        Err(NativePredicateError::UnknownType(TypeId(9)))
    );
    let limited = NativePredicateLimits {
        max_size_items: 1,
        ..Default::default()
    };
    assert_eq!(
        graph.matches_filter(&sized(DatatypeClass::Any, &[4, 8]), f, limited),
        Err(NativePredicateError::Limit("size items"))
    );
}

#[test]
fn query_budgets_include_nested_hfa_extraction_exactly() {
    let mut s = Source::default();
    let f = s.float(4);
    let d = s.float(8);
    let pair = s.structure(&[f, f]);
    let array = s.array(pair, 2);
    let graph = bridge(s.layouts());
    let rule = ModelRule {
        datatype: hfa(),
        qualifiers: vec![RuleQualifier::DatatypeAt {
            index: -1,
            datatype: hfa(),
        }],
        preconditions: vec![],
        action: ghidra_languages::RuleAction::GotoStack,
        side_effects: vec![],
        line: 0,
    };
    let parameters = [array, d];
    let prototype = PrototypeTypes {
        result: pair,
        parameters: &parameters,
        first_vararg: None,
    };
    let full = graph
        .matches_rule(&rule, array, prototype, 0, Default::default())
        .unwrap();
    assert!(full.matched);
    assert_eq!(full.usage.extractions, 2);
    let work = full.usage.work;
    let limits = |max_work| NativePredicateLimits {
        max_work,
        ..Default::default()
    };
    assert_eq!(
        graph
            .matches_rule(&rule, array, prototype, 0, limits(work))
            .unwrap(),
        full
    );
    for budget in 0..work {
        assert_eq!(
            graph
                .matches_rule(&rule, array, prototype, 0, limits(budget))
                .unwrap_err(),
            NativePredicateError::Limit("work"),
            "budget {budget}"
        );
    }
    // Resource exhaustion inside HFA is an error, unlike the semantic maximum.
    let live = NativePredicateLimits {
        max_live_primitives: 3,
        ..Default::default()
    };
    assert_eq!(
        graph.matches_filter(&hfa(), array, live).unwrap_err(),
        NativePredicateError::Limit("live primitives")
    );
    let depth = NativePredicateLimits {
        max_depth: 2,
        ..Default::default()
    };
    assert_eq!(
        graph.matches_filter(&hfa(), array, depth).unwrap_err(),
        NativePredicateError::Limit("depth")
    );
    let semantic = DatatypeFilter {
        max_primitives: Some(3),
        ..hfa()
    };
    assert!(
        !graph
            .matches_filter(&semantic, array, Default::default())
            .unwrap()
            .matched
    );
}
