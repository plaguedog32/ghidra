//! Small-graph oracle for the retained Java predicate behavior. The reference
//! deliberately expands primitive leaves recursively instead of using the native
//! predicate facts or its aggregate summaries. Layout lengths are inputs to the
//! predicate layer; this is not a second layout oracle or a live Java comparison.

use std::sync::Arc;

use ghidra_abi::{
    DatatypePredicates, PredicateError, PredicateLimits, PredicateRejection, PrototypeTypes,
};
use ghidra_languages::{
    DataOrganization, DatatypeClass, DatatypeFilter, MetaType, ModelRule, RuleAction, RuleQualifier,
};
use ghidra_types::{
    Builtin, Composite, Field, Limits, MinimumAlignment, Packing, TypeDefinition, TypeId, TypeKind,
    TypeLayouts,
};

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

fn meta_filter(meta: MetaType) -> DatatypeFilter {
    filter(DatatypeClass::Meta(meta))
}

fn record(fields: &[TypeId], packing: Packing, minimum: MinimumAlignment) -> Composite {
    Composite {
        fields: fields.iter().map(|id| Field::new("", *id)).collect(),
        packing,
        minimum_alignment: minimum,
    }
}

fn add(definitions: &mut Vec<TypeDefinition>, kind: TypeKind) -> TypeId {
    let id = TypeId(definitions.len());
    // Names intentionally do not distinguish otherwise equal float definitions.
    definitions.push(TypeDefinition::new("same name", kind));
    id
}

#[derive(Clone, Copy)]
struct Fixtures {
    void: TypeId,
    integer: TypeId,
    float: TypeId,
    other_float: TypeId,
    float_alias: TypeId,
    array: TypeId,
    alias_array: TypeId,
    empty: TypeId,
    zero_array: TypeId,
    tail_padded: TypeId,
    empty_members: TypeId,
    mixed_identity: TypeId,
    same_identity: TypeId,
    float_union: TypeId,
    four_floats: TypeId,
    five_floats: TypeId,
    function: TypeId,
    char_type: TypeId,
    wchar: TypeId,
    signed_enum: TypeId,
    unsigned_enum: TypeId,
}

fn graph() -> (Vec<TypeDefinition>, Fixtures) {
    let mut definitions = vec![];
    let void = add(&mut definitions, TypeKind::Void);
    let mut builtins = vec![];
    for builtin in [
        Builtin::Bool,
        Builtin::Char,
        Builtin::SignedChar,
        Builtin::UnsignedChar,
        Builtin::WChar,
        Builtin::Short,
        Builtin::UnsignedShort,
        Builtin::Int,
        Builtin::UnsignedInt,
        Builtin::Long,
        Builtin::UnsignedLong,
        Builtin::LongLong,
        Builtin::UnsignedLongLong,
        Builtin::Float,
        Builtin::Double,
        Builtin::LongDouble,
    ] {
        builtins.push(add(&mut definitions, TypeKind::Builtin(builtin)));
    }
    let integer = add(
        &mut definitions,
        TypeKind::Integer {
            bytes: 3,
            signed: true,
        },
    );
    add(
        &mut definitions,
        TypeKind::Integer {
            bytes: 3,
            signed: false,
        },
    );
    let float = add(&mut definitions, TypeKind::Float { bytes: 4 });
    let other_float = add(&mut definitions, TypeKind::Float { bytes: 4 });
    add(&mut definitions, TypeKind::Float { bytes: 10 });
    add(&mut definitions, TypeKind::Opaque { bytes: 4 });
    let signed_enum = add(
        &mut definitions,
        TypeKind::Enum {
            bytes: 3,
            signed: true,
        },
    );
    let unsigned_enum = add(
        &mut definitions,
        TypeKind::Enum {
            bytes: 3,
            signed: false,
        },
    );
    add(
        &mut definitions,
        TypeKind::Pointer {
            target: void,
            bytes: Some(3),
        },
    );
    let function = add(
        &mut definitions,
        TypeKind::Function {
            result: float,
            parameters: vec![integer, float],
            variadic: true,
        },
    );
    let float_alias = add(&mut definitions, TypeKind::Alias(float));
    let double_alias = add(&mut definitions, TypeKind::Alias(float_alias));
    let array = add(
        &mut definitions,
        TypeKind::Array {
            element: float,
            count: 2,
        },
    );
    let alias_array = add(&mut definitions, TypeKind::Alias(array));
    let zero_array = add(
        &mut definitions,
        TypeKind::Array {
            element: float,
            count: 0,
        },
    );
    let empty = add(&mut definitions, TypeKind::Structure(Composite::default()));
    let tail_padded = add(
        &mut definitions,
        TypeKind::Structure(record(
            &[float],
            Packing::Default,
            MinimumAlignment::Explicit(16),
        )),
    );
    let empty_members = add(
        &mut definitions,
        TypeKind::Structure(record(
            &[empty, float, zero_array],
            Packing::Explicit(1),
            MinimumAlignment::Default,
        )),
    );
    let mixed_identity = add(
        &mut definitions,
        TypeKind::Structure(record(
            &[float, other_float],
            Packing::Default,
            MinimumAlignment::Default,
        )),
    );
    let same_identity = add(
        &mut definitions,
        TypeKind::Structure(record(
            &[float_alias, double_alias],
            Packing::Default,
            MinimumAlignment::Default,
        )),
    );
    let float_union = add(
        &mut definitions,
        TypeKind::Union(record(
            &[float, float_alias],
            Packing::Default,
            MinimumAlignment::Default,
        )),
    );
    let four_floats = add(
        &mut definitions,
        TypeKind::Array {
            element: array,
            count: 2,
        },
    );
    let five_floats = add(
        &mut definitions,
        TypeKind::Array {
            element: float,
            count: 5,
        },
    );
    let seed_types = [
        integer,
        float,
        other_float,
        array,
        empty,
        zero_array,
        float_union,
    ];
    for (index, element) in seed_types.into_iter().enumerate() {
        add(
            &mut definitions,
            TypeKind::Array {
                element,
                count: (index % 4) as u64,
            },
        );
        add(
            &mut definitions,
            TypeKind::Structure(record(
                &[element, float_alias],
                if index % 2 == 0 {
                    Packing::Default
                } else {
                    Packing::Explicit(1)
                },
                if index % 3 == 0 {
                    MinimumAlignment::Explicit(16)
                } else {
                    MinimumAlignment::Default
                },
            )),
        );
    }
    for members in [
        vec![],
        vec![float],
        vec![integer, float],
        vec![empty, array],
    ] {
        let union = add(
            &mut definitions,
            TypeKind::Union(record(
                &members,
                Packing::Default,
                MinimumAlignment::Default,
            )),
        );
        add(
            &mut definitions,
            TypeKind::Structure(record(
                &[union],
                Packing::Default,
                MinimumAlignment::Default,
            )),
        );
    }
    (
        definitions,
        Fixtures {
            void,
            integer,
            float,
            other_float,
            float_alias,
            array,
            alias_array,
            empty,
            zero_array,
            tail_padded,
            empty_members,
            mixed_identity,
            same_identity,
            float_union,
            four_floats,
            five_floats,
            function,
            char_type: builtins[1],
            wchar: builtins[4],
            signed_enum,
            unsigned_enum,
        },
    )
}

fn snapshot(char_signed: bool) -> (Arc<TypeLayouts>, Fixtures) {
    let (definitions, fixtures) = graph();
    let mut organization = DataOrganization::default().resolve(8);
    organization.char_signed = char_signed;
    // The ten-byte long double has a sixteen-byte aligned length. Predicate
    // size restrictions must nevertheless use its raw getLength value of ten.
    organization.long_double_size = 10;
    (
        Arc::new(TypeLayouts::new(definitions.into(), organization, Limits::default()).unwrap()),
        fixtures,
    )
}

fn canonical(layouts: &TypeLayouts, id: TypeId) -> TypeId {
    match layouts.definitions()[id.0].kind {
        TypeKind::Alias(target) => canonical(layouts, target),
        _ => id,
    }
}

fn reference_meta(layouts: &TypeLayouts, id: TypeId) -> MetaType {
    match &layouts.definitions()[canonical(layouts, id).0].kind {
        TypeKind::Void => MetaType::Unknown,
        // Explicit native mapping: opaque storage is an unrecognized Java
        // datatype (Unknown); its width never implies a semantic class.
        TypeKind::Opaque { .. } => MetaType::Unknown,
        TypeKind::Builtin(builtin) => match builtin {
            Builtin::Bool => MetaType::Bool,
            Builtin::Char => {
                if layouts.organization().char_signed {
                    MetaType::Int
                } else {
                    MetaType::Uint
                }
            }
            Builtin::SignedChar
            | Builtin::WChar
            | Builtin::Short
            | Builtin::Int
            | Builtin::Long
            | Builtin::LongLong => MetaType::Int,
            Builtin::UnsignedChar
            | Builtin::UnsignedShort
            | Builtin::UnsignedInt
            | Builtin::UnsignedLong
            | Builtin::UnsignedLongLong => MetaType::Uint,
            Builtin::Float | Builtin::Double | Builtin::LongDouble => MetaType::Float,
        },
        TypeKind::Integer { signed, .. } | TypeKind::Enum { signed, .. } => {
            if *signed {
                MetaType::Int
            } else {
                MetaType::Uint
            }
        }
        TypeKind::Float { .. } => MetaType::Float,
        TypeKind::Pointer { .. } => MetaType::Ptr,
        TypeKind::Array { .. } => MetaType::Array,
        TypeKind::Structure(_) => MetaType::Struct,
        TypeKind::Union(_) => MetaType::Union,
        TypeKind::Function { .. } => MetaType::Code,
        TypeKind::Incomplete => panic!("incomplete types are outside this oracle"),
        TypeKind::Alias(_) => unreachable!(),
    }
}

fn reference_length(layouts: &TypeLayouts, id: TypeId) -> i128 {
    if matches!(
        layouts.definitions()[canonical(layouts, id).0].kind,
        TypeKind::Function { .. }
    ) {
        -1
    } else {
        i128::from(layouts.layout(id).unwrap().geometry.length.unwrap())
    }
}

fn expand_leaves(layouts: &TypeLayouts, id: TypeId, leaves: &mut Vec<TypeId>) -> bool {
    let id = canonical(layouts, id);
    match &layouts.definitions()[id.0].kind {
        TypeKind::Array { element, count } => {
            assert!(
                *count <= 5,
                "only tiny arrays belong in this recursive oracle"
            );
            for _ in 0..*count {
                if !expand_leaves(layouts, *element, leaves) {
                    return false;
                }
            }
        }
        TypeKind::Structure(composite) => {
            // Both modeled packing modes enable Java packing, which skips
            // PrimitiveExtractor's explicit-offset hole/alignment checks.
            for member in &composite.fields {
                if !expand_leaves(layouts, member.ty, leaves) {
                    return false;
                }
            }
        }
        TypeKind::Union(_) => return false,
        _ => leaves.push(id),
    }
    true
}

fn reference_filter(layouts: &TypeLayouts, filter: &DatatypeFilter, id: TypeId) -> bool {
    match filter.class {
        DatatypeClass::HomogeneousFloatAggregate => {
            if !matches!(
                reference_meta(layouts, id),
                MetaType::Array | MetaType::Struct
            ) {
                return false;
            }
            let mut leaves = vec![];
            if !expand_leaves(layouts, id, &mut leaves) {
                return false;
            }
            let Some(first) = leaves.first() else {
                return false;
            };
            let maximum = match filter.max_primitives {
                Some(n) if n > 0 => n,
                _ => 4,
            };
            // HomogeneousAggregate.filter never invokes filterOnSize.
            return leaves.len() <= maximum as usize
                && reference_meta(layouts, *first) == MetaType::Float
                && leaves.iter().all(|leaf| leaf == first);
        }
        DatatypeClass::Meta(MetaType::Array) => {
            let TypeKind::Array { count, .. } = layouts.definitions()[id.0].kind else {
                return false;
            };
            if count < u64::from(filter.min_elements.unwrap_or(0)) {
                return false;
            }
            if let Some(maximum) = filter.max_elements
                && maximum != 0
                && count > u64::from(maximum)
            {
                return false;
            }
        }
        DatatypeClass::Meta(meta) => {
            if reference_meta(layouts, id) != meta {
                return false;
            }
        }
        DatatypeClass::Any => (),
    }
    let length = reference_length(layouts, id);
    if !filter.sizes.is_empty() {
        filter.sizes.iter().any(|size| i128::from(*size) == length)
    } else {
        let maximum = match filter.max_size {
            Some(n) if n > 0 => n,
            _ => i32::MAX as u32,
        };
        length >= i128::from(filter.min_size.unwrap_or(0)) && length <= i128::from(maximum)
    }
}

fn filters() -> Vec<DatatypeFilter> {
    let mut classes = vec![DatatypeClass::Any, DatatypeClass::HomogeneousFloatAggregate];
    for meta in [
        MetaType::Void,
        MetaType::Spacebase,
        MetaType::Unknown,
        MetaType::Int,
        MetaType::Uint,
        MetaType::Bool,
        MetaType::Code,
        MetaType::Float,
        MetaType::Ptr,
        MetaType::PtrRel,
        MetaType::Array,
        MetaType::Struct,
        MetaType::Union,
        MetaType::PartEnum,
        MetaType::PartUnion,
        MetaType::EnumInt,
        MetaType::EnumUint,
    ] {
        classes.push(DatatypeClass::Meta(meta));
    }
    let mut filters = vec![];
    for class in classes {
        filters.push(filter(class));
        let mut bounded = filter(class);
        bounded.min_size = Some(3);
        bounded.max_size = Some(8);
        filters.push(bounded);
    }
    for class in [
        DatatypeClass::Any,
        DatatypeClass::Meta(MetaType::Array),
        DatatypeClass::HomogeneousFloatAggregate,
    ] {
        for sizes in [vec![1], vec![3, 4, 10, 3], vec![16, 32]] {
            let mut enumerated = filter(class);
            enumerated.sizes = sizes;
            filters.push(enumerated);
        }
        let mut zero_maximum = filter(class);
        zero_maximum.min_size = Some(4);
        zero_maximum.max_size = Some(0);
        filters.push(zero_maximum);
    }
    for maximum in [0, 1, 2, 5] {
        let mut homogeneous = filter(DatatypeClass::HomogeneousFloatAggregate);
        homogeneous.max_primitives = Some(maximum);
        filters.push(homogeneous);
    }
    for (minimum, maximum) in [(0, 0), (0, 2), (2, 4), (4, 2)] {
        let mut array = meta_filter(MetaType::Array);
        array.min_elements = Some(minimum);
        array.max_elements = Some(maximum);
        filters.push(array);
    }
    filters
}

#[test]
fn generated_filters_match_direct_recursive_java_reference() {
    let filters = filters();
    let mut comparisons = 0;
    for char_signed in [false, true] {
        let (layouts, _) = snapshot(char_signed);
        let predicates =
            DatatypePredicates::new(layouts.clone(), PredicateLimits::default()).unwrap();
        for index in 0..layouts.definitions().len() {
            for filter in &filters {
                let id = TypeId(index);
                let expected = reference_filter(&layouts, filter, id);
                let actual = predicates
                    .matches_filter(filter, id, PredicateLimits::default())
                    .unwrap();
                assert_eq!(
                    actual.matched,
                    expected,
                    "signed-char={char_signed}, type={id:?} {:?}, filter={filter:?}",
                    layouts.definitions()[index].kind
                );
                assert_eq!(
                    actual.rejection,
                    (!expected).then_some(PredicateRejection::Datatype)
                );
                comparisons += 1;
            }
        }
    }
    assert!(comparisons > 5_000);
    eprintln!("predicate oracle: {comparisons} filter comparisons");
}

#[test]
fn real_catalog_rule_predicates_match_the_independent_reference() {
    use ghidra_languages::{Catalog, CompilerSpec};
    use std::collections::BTreeSet;
    use std::path::Path;
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Ghidra/Processors");
    let catalog = Catalog::discover(&root).unwrap();
    assert!(!catalog.has_errors());
    let paths: BTreeSet<_> = catalog
        .languages
        .iter()
        .flat_map(|l| &l.compilers)
        .map(|c| c.spec.available_path().unwrap().canonicalize().unwrap())
        .collect();
    assert_eq!(paths.len(), 107);
    let mut rule_count = 0;
    let mut filter_comparisons = 0;
    let mut qualifier_comparisons = 0;
    for path in paths {
        let spec = CompilerSpec::from_path(&path).unwrap();
        assert!(spec.diagnostics.is_empty(), "{}", path.display());
        let rules: Vec<_> = spec
            .prototypes
            .iter()
            .flat_map(|p| p.input.rules.iter().chain(&p.output.rules))
            .collect();
        rule_count += rules.len();
        for pointer_size in [2, 4, 8] {
            let (definitions, ids) = graph();
            // Explicit synthetic pointer-size profiles exercise the captured
            // declaration predicates; this is not a processor ABI allocation run.
            let layouts = Arc::new(
                TypeLayouts::new(
                    definitions.into(),
                    spec.resolved_data_organization(pointer_size),
                    Limits::default(),
                )
                .unwrap(),
            );
            let predicates = DatatypePredicates::new(layouts.clone(), Default::default()).unwrap();
            let inputs = [ids.integer, ids.float, ids.array];
            for rule in &rules {
                for id in 0..layouts.definitions().len() {
                    let id = TypeId(id);
                    assert_eq!(
                        predicates
                            .matches_filter(&rule.datatype, id, Default::default())
                            .unwrap()
                            .matched,
                        reference_filter(&layouts, &rule.datatype, id),
                        "{}, rule line {}, type {id:?}",
                        path.display(),
                        rule.line
                    );
                    filter_comparisons += 1;
                }
                for first_vararg in [None, Some(1)] {
                    let context = PrototypeTypes {
                        result: ids.float,
                        parameters: &inputs,
                        first_vararg,
                    };
                    for position in [-1, 0, 1, 2, 3] {
                        let ty = if position < 0 {
                            ids.float
                        } else {
                            inputs[position as usize % inputs.len()]
                        };
                        let expected = reference_rule(&layouts, rule, ty, context, position);
                        let actual = predicates
                            .matches_rule(rule, ty, context, position, Default::default())
                            .unwrap();
                        assert_eq!(
                            (actual.rejection, actual.usage.qualifiers),
                            expected,
                            "{}, line {}",
                            path.display(),
                            rule.line
                        );
                        qualifier_comparisons += 1;
                    }
                }
            }
        }
    }
    assert_eq!(rule_count, 230);
    assert_eq!(filter_comparisons, 42_780);
    assert_eq!(qualifier_comparisons, 6_900);
}

#[test]
fn directed_identity_padding_alias_and_metatype_quirks_are_observable() {
    for char_signed in [false, true] {
        let (layouts, ids) = snapshot(char_signed);
        let predicates =
            DatatypePredicates::new(layouts.clone(), PredicateLimits::default()).unwrap();
        let check = |filter: &DatatypeFilter, id, expected| {
            assert_eq!(reference_filter(&layouts, filter, id), expected);
            assert_eq!(
                predicates
                    .matches_filter(filter, id, PredicateLimits::default())
                    .unwrap()
                    .matched,
                expected
            );
        };
        let hfa = filter(DatatypeClass::HomogeneousFloatAggregate);
        for id in [
            ids.array,
            ids.alias_array,
            ids.tail_padded,
            ids.empty_members,
            ids.same_identity,
            ids.four_floats,
        ] {
            check(&hfa, id, true);
        }
        for id in [
            ids.float,
            ids.other_float,
            ids.float_alias,
            ids.empty,
            ids.zero_array,
            ids.mixed_identity,
            ids.float_union,
            ids.five_floats,
        ] {
            check(&hfa, id, false);
        }
        assert_eq!(
            layouts.layout(ids.tail_padded).unwrap().geometry.length,
            Some(16)
        );
        check(&meta_filter(MetaType::Array), ids.array, true);
        check(&meta_filter(MetaType::Array), ids.alias_array, false);
        let mut impossible_hfa_bounds = hfa.clone();
        impossible_hfa_bounds.min_size = Some(100);
        impossible_hfa_bounds.max_size = Some(1);
        check(&impossible_hfa_bounds, ids.tail_padded, true);
        let mut zero_maximum = hfa.clone();
        zero_maximum.max_primitives = Some(0);
        check(&zero_maximum, ids.four_floats, true);
        check(&zero_maximum, ids.five_floats, false);
        let mut length_one = filter(DatatypeClass::Any);
        length_one.sizes = vec![1];
        check(&length_one, ids.empty, true);
        check(&length_one, ids.zero_array, true);
        check(&meta_filter(MetaType::Unknown), ids.void, true);
        check(&meta_filter(MetaType::Void), ids.void, false);
        check(&meta_filter(MetaType::Code), ids.function, false);
        check(&filter(DatatypeClass::Any), ids.function, false);
        check(&meta_filter(MetaType::Int), ids.signed_enum, true);
        check(&meta_filter(MetaType::EnumInt), ids.signed_enum, false);
        check(&meta_filter(MetaType::Uint), ids.unsigned_enum, true);
        check(&meta_filter(MetaType::EnumUint), ids.unsigned_enum, false);
        check(&meta_filter(MetaType::Int), ids.char_type, char_signed);
        check(&meta_filter(MetaType::Uint), ids.char_type, !char_signed);
        check(&meta_filter(MetaType::Int), ids.wchar, true);
    }
}

fn rule(datatype: DatatypeFilter, qualifiers: Vec<RuleQualifier>) -> ModelRule {
    ModelRule {
        datatype,
        qualifiers,
        preconditions: vec![],
        action: RuleAction::GotoStack,
        side_effects: vec![],
        line: 1,
    }
}

fn reference_rule(
    layouts: &TypeLayouts,
    rule: &ModelRule,
    id: TypeId,
    prototype: PrototypeTypes<'_>,
    position: i32,
) -> (Option<PredicateRejection>, usize) {
    if !reference_filter(layouts, &rule.datatype, id) {
        return (Some(PredicateRejection::Datatype), 0);
    }
    for (index, qualifier) in rule.qualifiers.iter().enumerate() {
        let matched = match qualifier {
            RuleQualifier::Position { index } => position == *index,
            RuleQualifier::Varargs { first, last } => match prototype.first_vararg {
                None => false,
                Some(slot) => {
                    let relative = i64::from(position) - slot as i64;
                    relative >= i64::from(first.unwrap_or(i32::MIN))
                        && relative <= i64::from(last.unwrap_or(i32::MAX))
                }
            },
            RuleQualifier::DatatypeAt { index, datatype } => {
                if *index < 0 {
                    reference_filter(layouts, datatype, prototype.result)
                } else {
                    prototype
                        .parameters
                        .get(*index as usize)
                        .is_some_and(|target| reference_filter(layouts, datatype, *target))
                }
            }
        };
        if !matched {
            return (Some(PredicateRejection::Qualifier(index)), index + 1);
        }
    }
    (None, rule.qualifiers.len())
}

#[test]
fn generated_qualifiers_match_literal_positions_and_ordered_short_circuit() {
    let (layouts, ids) = snapshot(false);
    let predicates = DatatypePredicates::new(layouts.clone(), PredicateLimits::default()).unwrap();
    let any = filter(DatatypeClass::Any);
    let float = meta_filter(MetaType::Float);
    let qualifiers = vec![
        vec![],
        vec![RuleQualifier::Varargs {
            first: None,
            last: None,
        }],
        vec![RuleQualifier::Varargs {
            first: Some(0),
            last: None,
        }],
        vec![RuleQualifier::Varargs {
            first: Some(-1),
            last: Some(0),
        }],
        vec![RuleQualifier::Position { index: -1 }],
        vec![RuleQualifier::Position { index: 0 }],
        vec![RuleQualifier::DatatypeAt {
            index: -2,
            datatype: float.clone(),
        }],
        vec![RuleQualifier::DatatypeAt {
            index: 1,
            datatype: float.clone(),
        }],
        vec![RuleQualifier::DatatypeAt {
            index: 4,
            datatype: any.clone(),
        }],
        vec![
            RuleQualifier::Position { index: 0 },
            RuleQualifier::Varargs {
                first: Some(0),
                last: None,
            },
            RuleQualifier::DatatypeAt {
                index: -1,
                datatype: float.clone(),
            },
        ],
        vec![
            RuleQualifier::Varargs {
                first: None,
                last: None,
            },
            RuleQualifier::Position { index: 2 },
            RuleQualifier::DatatypeAt {
                index: 0,
                datatype: meta_filter(MetaType::Int),
            },
        ],
        vec![
            RuleQualifier::DatatypeAt {
                index: -3,
                datatype: float.clone(),
            },
            RuleQualifier::Position { index: -1 },
        ],
    ];
    let parameters = [ids.integer, ids.float, ids.float, ids.array];
    let mut comparisons = 0;
    for first_vararg in [None, Some(0), Some(2), Some(parameters.len())] {
        let prototype = PrototypeTypes {
            result: ids.float,
            parameters: &parameters,
            first_vararg,
        };
        for position in -2..=4 {
            let id = if position == -1 {
                ids.float
            } else {
                parameters
                    .get(position as usize)
                    .copied()
                    .unwrap_or(ids.float)
            };
            for datatype in [
                any.clone(),
                float.clone(),
                meta_filter(MetaType::Array),
                filter(DatatypeClass::HomogeneousFloatAggregate),
            ] {
                for qualifiers in &qualifiers {
                    let rule = rule(datatype.clone(), qualifiers.clone());
                    let (rejection, evaluated) =
                        reference_rule(&layouts, &rule, id, prototype, position);
                    let actual = predicates
                        .matches_rule(&rule, id, prototype, position, PredicateLimits::default())
                        .unwrap();
                    assert_eq!(
                        actual.rejection, rejection,
                        "first_vararg={first_vararg:?}, position={position}, rule={rule:?}"
                    );
                    assert_eq!(actual.matched, rejection.is_none());
                    assert_eq!(actual.usage.qualifiers, evaluated);
                    comparisons += 1;
                }
            }
        }
    }
    assert_eq!(comparisons, 1_344);
    // Invalid later filters must stay unexamined after a failed datatype or
    // earlier qualifier, while reaching the same filter reports its error.
    let mut invalid = any.clone();
    invalid.sizes = vec![0];
    let later = RuleQualifier::DatatypeAt {
        index: -1,
        datatype: invalid,
    };
    let prototype = PrototypeTypes {
        result: ids.float,
        parameters: &parameters,
        first_vararg: Some(2),
    };
    let rejected = rule(
        any.clone(),
        vec![RuleQualifier::Position { index: 0 }, later.clone()],
    );
    let actual = predicates
        .matches_rule(
            &rejected,
            ids.float,
            prototype,
            1,
            PredicateLimits::default(),
        )
        .unwrap();
    assert_eq!(actual.rejection, Some(PredicateRejection::Qualifier(0)));
    assert_eq!(actual.usage.qualifiers, 1);
    assert!(matches!(
        predicates.matches_rule(
            &rejected,
            ids.float,
            prototype,
            0,
            PredicateLimits::default()
        ),
        Err(PredicateError::InvalidFilter(_))
    ));
    let rejected = rule(meta_filter(MetaType::Int), vec![later]);
    let actual = predicates
        .matches_rule(
            &rejected,
            ids.float,
            prototype,
            0,
            PredicateLimits::default(),
        )
        .unwrap();
    assert_eq!(actual.rejection, Some(PredicateRejection::Datatype));
    assert_eq!(actual.usage.qualifiers, 0);
    eprintln!(
        "predicate oracle: {comparisons} rule comparisons plus three error/short-circuit checks"
    );
}
