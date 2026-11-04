//! Small independent reference for PrimitiveExtractor.java. Layout geometry is
//! input, not something this oracle reimplements. Unlike production's cached
//! facts and iterative contexts, this expands tiny graphs recursively and uses
//! queues for source-ordered refinement. It runs neither Java nor C++.

use std::collections::VecDeque;
use std::sync::Arc;

use ghidra_abi::{
    DatatypePredicates, ExtractionError, ExtractionLimits, ExtractionOptions, PrimitiveExtraction,
    PrimitiveSource,
};
use ghidra_languages::{DataOrganization, MetaType, SizeAlignment};
use ghidra_types::{
    Builtin, Composite, Field, MinimumAlignment, Packing, TypeDefinition, TypeId, TypeKind,
    TypeLayouts,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    Unknown,
    Signed,
    Unsigned,
    Boolean,
    Float,
    Pointer,
    Array,
    Code,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Piece {
    identity: TypeId,
    at: u64,
    class: Class,
    raw: i128,
    aligned: i128,
    alignment: u32,
}

impl Piece {
    fn end(self) -> i128 {
        i128::from(self.at) + self.aligned
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Reference {
    pieces: Vec<Piece>,
    local_unknown: bool,
}

#[derive(Debug, PartialEq, Eq)]
enum Rejection {
    Maximum,
    UnionPolicy(TypeId),
    EmptyUnion(TypeId),
    Overlap(TypeId),
}

// The source unwraps a complete typedef chain but never merges equal-width
// primitive identities. This does not consult DatatypePredicates::fact.
fn canonical(layouts: &TypeLayouts, mut id: TypeId) -> TypeId {
    for _ in 0..=10 {
        if let TypeKind::Alias(target) = layouts.definitions()[id.0].kind {
            id = target;
        } else {
            return id;
        }
    }
    panic!("oracle fixtures contain an excessive alias chain");
}

fn scalar_class(layouts: &TypeLayouts, id: TypeId) -> Class {
    match layouts.definitions()[id.0].kind {
        TypeKind::Void | TypeKind::Opaque { .. } => Class::Unknown,
        TypeKind::Float { .. } => Class::Float,
        TypeKind::Integer { signed: true, .. } | TypeKind::Enum { signed: true, .. } => {
            Class::Signed
        }
        TypeKind::Integer { signed: false, .. } | TypeKind::Enum { signed: false, .. } => {
            Class::Unsigned
        }
        TypeKind::Pointer { .. } => Class::Pointer,
        TypeKind::Array { .. } => Class::Array,
        TypeKind::Function { .. } => Class::Code,
        TypeKind::Builtin(builtin) => match builtin {
            Builtin::Bool => Class::Boolean,
            Builtin::Float | Builtin::Double | Builtin::LongDouble => Class::Float,
            Builtin::UnsignedChar
            | Builtin::UnsignedShort
            | Builtin::UnsignedInt
            | Builtin::UnsignedLong
            | Builtin::UnsignedLongLong => Class::Unsigned,
            Builtin::Char => {
                if layouts.organization().char_signed {
                    Class::Signed
                } else {
                    Class::Unsigned
                }
            }
            Builtin::SignedChar
            | Builtin::WChar
            | Builtin::Short
            | Builtin::Int
            | Builtin::Long
            | Builtin::LongLong => Class::Signed,
        },
        ref kind => panic!("oracle scalar classification requested for {kind:?}"),
    }
}

fn reference(
    layouts: &TypeLayouts,
    root: TypeId,
    options: ExtractionOptions,
    maximum: usize,
) -> Result<Reference, Rejection> {
    let mut remaining = 100_000;
    let mut result = Reference::default();
    visit(
        layouts,
        root,
        options.offset,
        0,
        0,
        options,
        maximum,
        &mut remaining,
        &mut result,
    )?;
    Ok(result)
}

#[allow(clippy::too_many_arguments)]
fn visit(
    layouts: &TypeLayouts,
    input: TypeId,
    at: u64,
    array_depth: usize,
    call_depth: usize,
    options: ExtractionOptions,
    maximum: usize,
    remaining: &mut usize,
    result: &mut Reference,
) -> Result<(), Rejection> {
    assert!(call_depth <= 10, "oracle graph exceeds its recursion bound");
    *remaining = remaining.checked_sub(1).expect("bounded oracle work");
    let id = canonical(layouts, input);
    let layout = layouts.layout(id).unwrap();
    match &layouts.definitions()[id.0].kind {
        TypeKind::Array { element, count }
            if !options.nested_arrays_are_primitives || array_depth == 0 =>
        {
            assert!(*count <= 4, "only the explicit prefix fixture uses count 4");
            // Java advances by the element datatype's aligned length, not its
            // logical size, and does not descend into a zero-count array.
            let step = layouts
                .layout(*element)
                .unwrap()
                .geometry
                .aligned_length
                .unwrap();
            for index in 0..*count {
                visit(
                    layouts,
                    *element,
                    at + index * step,
                    array_depth + 1,
                    call_depth + 1,
                    options,
                    maximum,
                    remaining,
                    result,
                )?;
            }
            Ok(())
        }
        TypeKind::Structure(_) => {
            for field in &layout.fields {
                visit(
                    layouts,
                    field.ty,
                    at + field.offset,
                    array_depth + 1,
                    call_depth + 1,
                    options,
                    maximum,
                    remaining,
                    result,
                )?;
            }
            Ok(())
        }
        TypeKind::Union(_) => {
            if options.reject_unions {
                return Err(Rejection::UnionPolicy(id));
            }
            if layout.fields.is_empty() {
                return Err(Rejection::EmptyUnion(id));
            }
            let mut common = None;
            for field in &layout.fields {
                let mut child = Reference::default();
                // Each member gets a fresh extractor: array depth and unknown
                // flag reset, while it receives the full semantic maximum.
                visit(
                    layouts,
                    field.ty,
                    at + field.offset,
                    0,
                    call_depth + 1,
                    options,
                    maximum,
                    remaining,
                    &mut child,
                )?;
                common = Some(match common {
                    None => child.pieces,
                    Some(previous) => refine_queues(previous, child.pieces, id)?,
                });
            }
            let common = common.unwrap();
            if result.pieces.len() + common.len() > maximum {
                return Err(Rejection::Maximum);
            }
            // Child flags intentionally are not combined with the parent.
            result.pieces.extend(common);
            Ok(())
        }
        _ => {
            let class = scalar_class(layouts, id);
            result.local_unknown |= class == Class::Unknown;
            if result.pieces.len() >= maximum {
                return Err(Rejection::Maximum);
            }
            let (raw, aligned) = if class == Class::Code {
                (-1, -1)
            } else {
                (
                    i128::from(layout.geometry.length.unwrap()),
                    i128::from(layout.geometry.aligned_length.unwrap()),
                )
            };
            result.pieces.push(Piece {
                identity: id,
                at,
                class,
                raw,
                aligned,
                alignment: layout.geometry.alignment,
            });
            Ok(())
        }
    }
}

// PrimitiveExtractor.java:59-142. Queue consumption makes the reference
// independent of production's indexed vector traversal and budget machinery.
fn refine_queues(
    first: Vec<Piece>,
    second: Vec<Piece>,
    union: TypeId,
) -> Result<Vec<Piece>, Rejection> {
    let mut left = VecDeque::from(first);
    let mut right = VecDeque::from(second);
    let mut output = Vec::new();
    while let (Some(a), Some(b)) = (left.front().copied(), right.front().copied()) {
        if a.at < b.at && a.end() <= i128::from(b.at) {
            output.push(left.pop_front().unwrap());
            continue;
        }
        if b.at < a.at && b.end() <= i128::from(a.at) {
            output.push(right.pop_front().unwrap());
            continue;
        }
        let (big, smaller) = if a.aligned >= b.aligned {
            (left.pop_front().unwrap(), &mut right)
        } else {
            (right.pop_front().unwrap(), &mut left)
        };
        while let Some(candidate) = smaller.front().copied() {
            if i128::from(candidate.at) >= big.end() {
                break;
            }
            if candidate.end() > big.end() {
                return Err(Rejection::Overlap(union));
            }
            smaller.pop_front();
            if big.class == Class::Float {
                output.push(candidate);
            }
        }
        if big.class != Class::Float {
            output.push(big);
        }
    }
    output.extend(left);
    output.extend(right);
    Ok(output)
}

fn actual_class(meta: MetaType) -> Class {
    match meta {
        MetaType::Unknown => Class::Unknown,
        MetaType::Int => Class::Signed,
        MetaType::Uint => Class::Unsigned,
        MetaType::Bool => Class::Boolean,
        MetaType::Float => Class::Float,
        MetaType::Ptr => Class::Pointer,
        MetaType::Array => Class::Array,
        MetaType::Code => Class::Code,
        other => panic!("unexpected emitted metatype {other:?}"),
    }
}

fn observed(result: &PrimitiveExtraction) -> Reference {
    Reference {
        pieces: result
            .primitives()
            .iter()
            .map(|piece| Piece {
                identity: match piece.source {
                    PrimitiveSource::Type(id) => id,
                    other => panic!("ordinary fixtures emitted wrapper source {other:?}"),
                },
                at: piece.offset,
                class: actual_class(piece.meta_type),
                raw: piece.length,
                aligned: piece.aligned_length,
                alignment: piece.alignment,
            })
            .collect(),
        local_unknown: result.contains_unknown(),
    }
}

fn semantic_rejection(error: ExtractionError) -> Rejection {
    match error {
        ExtractionError::Limit("primitives") => Rejection::Maximum,
        ExtractionError::UnionRejected(id) => Rejection::UnionPolicy(id),
        ExtractionError::EmptyUnion(id) => Rejection::EmptyUnion(id),
        ExtractionError::IncompatibleUnion { ty, .. } => Rejection::Overlap(ty),
        other => panic!("small oracle fixtures hit unexpected resource/error {other:?}"),
    }
}

fn compare(
    engine: &Arc<DatatypePredicates>,
    root: TypeId,
    options: ExtractionOptions,
    maximum: usize,
) -> bool {
    let expected = reference(engine.layouts(), root, options, maximum);
    let actual = PrimitiveExtraction::new(
        engine.clone(),
        root,
        options,
        ExtractionLimits {
            max_primitives: maximum,
            ..Default::default()
        },
    );
    let context = format!("root={root:?}, options={options:?}, maximum={maximum}");
    match (expected, actual) {
        (Ok(expected), Ok(actual)) => {
            assert_eq!(observed(&actual), expected, "{context}");
            assert_eq!(
                actual.output_contains_unknown(),
                expected
                    .pieces
                    .iter()
                    .any(|piece| piece.class == Class::Unknown),
                "{context}"
            );
            assert!(actual.is_aligned(), "automatic packing: {context}");
            assert!(!actual.contains_holes(), "automatic packing: {context}");
            true
        }
        (Err(expected), Err(actual)) => {
            assert_eq!(semantic_rejection(actual), expected, "{context}");
            false
        }
        (expected, actual) => {
            panic!("oracle disagreed: {context}; expected={expected:?}; actual={actual:?}")
        }
    }
}

fn add(definitions: &mut Vec<TypeDefinition>, kind: TypeKind) -> TypeId {
    let id = TypeId(definitions.len());
    // Duplicate names prevent names from acting as primitive identity.
    definitions.push(TypeDefinition::new("duplicate", kind));
    id
}

fn record(fields: &[TypeId], packing: Packing) -> Composite {
    Composite {
        fields: fields.iter().map(|id| Field::new("", *id)).collect(),
        packing,
        minimum_alignment: MinimumAlignment::Default,
    }
}

fn array(definitions: &mut Vec<TypeDefinition>, element: TypeId, count: u64) -> TypeId {
    add(definitions, TypeKind::Array { element, count })
}

fn structure(definitions: &mut Vec<TypeDefinition>, fields: &[TypeId]) -> TypeId {
    add(
        definitions,
        TypeKind::Structure(record(fields, Packing::Explicit(1))),
    )
}

fn union(definitions: &mut Vec<TypeDefinition>, fields: &[TypeId]) -> TypeId {
    add(
        definitions,
        TypeKind::Union(record(fields, Packing::Default)),
    )
}

#[derive(Clone, Copy)]
struct Cases {
    void: TypeId,
    code: TypeId,
    u8: TypeId,
    u64: TypeId,
    signed4: TypeId,
    float4: TypeId,
    other_float4: TypeId,
    same_size_integer_tie: TypeId,
    same_size_float_tie: TypeId,
    integer_over_float_pair: TypeId,
    float_over_integer_pair: TypeId,
    shifted_first: TypeId,
    shifted_second: TypeId,
    over_max_then_collapse: TypeId,
    unknown_union: TypeId,
    unknown_container: TypeId,
    local_unknown: TypeId,
    union_member_array: TypeId,
    nested_union_member_array: TypeId,
    nested_zero_array: TypeId,
    empty_union: TypeId,
    empty_member_union: TypeId,
    padded_scalar_array: TypeId,
}

fn fixtures() -> (Vec<TypeDefinition>, Cases) {
    let mut definitions = Vec::new();
    let void = add(&mut definitions, TypeKind::Void);
    let code = add(
        &mut definitions,
        TypeKind::Function {
            result: void,
            parameters: vec![],
            variadic: false,
        },
    );
    let u8 = add(
        &mut definitions,
        TypeKind::Integer {
            bytes: 1,
            signed: false,
        },
    );
    let signed4 = add(
        &mut definitions,
        TypeKind::Integer {
            bytes: 4,
            signed: true,
        },
    );
    let unsigned4 = add(
        &mut definitions,
        TypeKind::Integer {
            bytes: 4,
            signed: false,
        },
    );
    let u64 = add(
        &mut definitions,
        TypeKind::Integer {
            bytes: 8,
            signed: false,
        },
    );
    let float4 = add(&mut definitions, TypeKind::Float { bytes: 4 });
    let other_float4 = add(&mut definitions, TypeKind::Float { bytes: 4 });
    let float8 = add(&mut definitions, TypeKind::Float { bytes: 8 });
    let opaque = add(&mut definitions, TypeKind::Opaque { bytes: 4 });
    let enum_signed = add(
        &mut definitions,
        TypeKind::Enum {
            bytes: 4,
            signed: true,
        },
    );
    let enum_unsigned = add(
        &mut definitions,
        TypeKind::Enum {
            bytes: 4,
            signed: false,
        },
    );
    let padded_scalar = add(
        &mut definitions,
        TypeKind::Integer {
            bytes: 3,
            signed: true,
        },
    );
    add(&mut definitions, TypeKind::Float { bytes: 10 });
    let pointer = add(
        &mut definitions,
        TypeKind::Pointer {
            target: void,
            bytes: None,
        },
    );
    let mut builtin_ids = Vec::new();
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
        builtin_ids.push(add(&mut definitions, TypeKind::Builtin(builtin)));
    }
    let alias = add(&mut definitions, TypeKind::Alias(float4));
    let alias_chain = add(&mut definitions, TypeKind::Alias(alias));
    let empty = structure(&mut definitions, &[]);
    let empty_union = union(&mut definitions, &[]);
    let zero_array = array(&mut definitions, opaque, 0);
    let float_pair = array(&mut definitions, alias_chain, 2);
    array(&mut definitions, float_pair, 3);
    let integer_pair = structure(&mut definitions, &[signed4, unsigned4]);
    let same_size_integer_tie = union(&mut definitions, &[signed4, unsigned4]);
    let same_size_float_tie = union(&mut definitions, &[alias_chain, other_float4]);
    let integer_over_float_pair = union(&mut definitions, &[u64, float_pair]);
    let float_over_integer_pair = union(&mut definitions, &[float8, integer_pair]);
    let prefix2 = array(&mut definitions, empty, 2);
    let shifted = structure(&mut definitions, &[prefix2, signed4]);
    let shifted_first = union(&mut definitions, &[shifted, signed4]);
    let shifted_second = union(&mut definitions, &[signed4, shifted]);
    let prefix4 = array(&mut definitions, empty, 4);
    let byte_at4 = structure(&mut definitions, &[prefix4, u8]);
    let over_max_then_collapse = union(&mut definitions, &[byte_at4, u8, u64]);
    let unknown_union = union(&mut definitions, &[opaque, enum_signed]);
    let unknown_container = structure(&mut definitions, &[unknown_union, u8]);
    let local_unknown = structure(&mut definitions, &[unknown_union, opaque]);
    let union_member_array = union(&mut definitions, &[float_pair]);
    let nested_union_member_array = structure(&mut definitions, &[u8, union_member_array]);
    let nested_zero_array = structure(&mut definitions, &[zero_array]);
    let empty_member_union = union(&mut definitions, &[empty, empty]);
    union(&mut definitions, &[empty, unsigned4]);
    let padded_scalar_array = array(&mut definitions, padded_scalar, 2);
    add(
        &mut definitions,
        TypeKind::Structure(Composite {
            fields: vec![Field::new("", float4)],
            minimum_alignment: MinimumAlignment::Explicit(16),
            ..Default::default()
        }),
    );

    // Four deterministic layers, with dependencies only on the preceding
    // layer, keep depth <= 10. Counts are 0..=3 and records have <= 3 fields.
    let mut previous = vec![
        u8,
        signed4,
        unsigned4,
        u64,
        float4,
        other_float4,
        float8,
        opaque,
        enum_signed,
        enum_unsigned,
        pointer,
        empty,
        empty_union,
        zero_array,
    ];
    previous.extend(builtin_ids);
    let mut state = 0x7a31_4529_u32;
    let mut next_random = || {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        state
    };
    for layer in 0..4 {
        let mut next = Vec::new();
        for index in 0..24 {
            let a = previous[next_random() as usize % previous.len()];
            let b = previous[next_random() as usize % previous.len()];
            let c = previous[next_random() as usize % previous.len()];
            let kind = match index % 6 {
                0 => TypeKind::Alias(a),
                1 => TypeKind::Array {
                    element: a,
                    count: u64::from(next_random() % 4),
                },
                2 => TypeKind::Structure(record(&[a, b], Packing::Default)),
                3 => TypeKind::Structure(record(&[a, b, c], Packing::Explicit(1 + layer % 2))),
                4 => TypeKind::Union(record(&[a, b], Packing::Default)),
                _ => TypeKind::Union(record(&[a, b, c], Packing::Explicit(2))),
            };
            next.push(add(&mut definitions, kind));
        }
        previous = next;
    }

    (
        definitions,
        Cases {
            void,
            code,
            u8,
            u64,
            signed4,
            float4,
            other_float4,
            same_size_integer_tie,
            same_size_float_tie,
            integer_over_float_pair,
            float_over_integer_pair,
            shifted_first,
            shifted_second,
            over_max_then_collapse,
            unknown_union,
            unknown_container,
            local_unknown,
            union_member_array,
            nested_union_member_array,
            nested_zero_array,
            empty_union,
            empty_member_union,
            padded_scalar_array,
        },
    )
}

fn engine(definitions: Vec<TypeDefinition>, char_signed: bool) -> Arc<DatatypePredicates> {
    let organization = DataOrganization {
        char_signed: Some(char_signed),
        size_alignment_map: vec![
            SizeAlignment {
                size: 10,
                alignment: 16,
            },
            SizeAlignment {
                size: 16,
                alignment: 16,
            },
        ],
        ..Default::default()
    };
    let layouts = Arc::new(
        TypeLayouts::new(
            definitions.into(),
            organization.resolve(8),
            Default::default(),
        )
        .unwrap(),
    );
    Arc::new(DatatypePredicates::new(layouts, Default::default()).unwrap())
}

#[test]
fn small_graphs_match_recursive_source_reference() {
    let (definitions, _) = fixtures();
    let mut valid = 0;
    let mut rejected = 0;
    for char_signed in [false, true] {
        let engine = engine(definitions.clone(), char_signed);
        for root in 0..definitions.len() {
            for reject_unions in [false, true] {
                for nested_arrays_are_primitives in [false, true] {
                    for offset in [0, 1, 13] {
                        for maximum in [0, 1, 2, 3, 4, 8, 32] {
                            let valid_case = compare(
                                &engine,
                                TypeId(root),
                                ExtractionOptions {
                                    offset,
                                    reject_unions,
                                    nested_arrays_are_primitives,
                                },
                                maximum,
                            );
                            if valid_case {
                                valid += 1;
                            } else {
                                rejected += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    assert!(valid > 5_000 && rejected > 5_000);
    eprintln!(
        "primitive oracle: {} comparisons ({valid} valid, {rejected} semantic rejections)",
        valid + rejected
    );
}

fn extract(
    engine: &Arc<DatatypePredicates>,
    id: TypeId,
    nested: bool,
    maximum: usize,
) -> PrimitiveExtraction {
    PrimitiveExtraction::new(
        engine.clone(),
        id,
        ExtractionOptions {
            nested_arrays_are_primitives: nested,
            ..Default::default()
        },
        ExtractionLimits {
            max_primitives: maximum,
            ..Default::default()
        },
    )
    .unwrap()
}

#[test]
fn source_order_and_context_regressions_have_explicit_expected_results() {
    let (definitions, cases) = fixtures();
    let engine = engine(definitions, true);
    let identity = |root| extract(&engine, root, false, 32).primitives()[0].source;
    assert_eq!(
        identity(cases.same_size_integer_tie),
        PrimitiveSource::Type(cases.signed4)
    );
    assert_eq!(
        identity(cases.same_size_float_tie),
        PrimitiveSource::Type(cases.other_float4)
    );
    assert_eq!(
        identity(cases.integer_over_float_pair),
        PrimitiveSource::Type(cases.u64)
    );
    let integers = extract(&engine, cases.float_over_integer_pair, false, 32);
    assert_eq!(integers.primitives().len(), 2);
    assert_eq!(
        integers.primitives()[0].source,
        PrimitiveSource::Type(cases.signed4)
    );
    assert!(
        integers
            .primitives()
            .iter()
            .all(|p| p.meta_type != MetaType::Float)
    );

    // The source checks only ends. A smaller primitive may begin before big;
    // reversing union member order can therefore change validity.
    let shifted = extract(&engine, cases.shifted_first, false, 32);
    assert_eq!(shifted.primitives().len(), 1);
    assert_eq!(shifted.primitives()[0].offset, 2);
    assert!(matches!(
        PrimitiveExtraction::new(
            engine.clone(),
            cases.shifted_second,
            Default::default(),
            Default::default()
        ),
        Err(ExtractionError::IncompatibleUnion { .. })
    ));

    // After the first two members, [u8@0, u8@4] exceeds max=1; u64 then
    // replaces both. An intermediate semantic-max check would reject this.
    let collapsed = extract(&engine, cases.over_max_then_collapse, false, 1);
    assert_eq!(collapsed.primitives().len(), 1);
    assert_eq!(
        collapsed.primitives()[0].source,
        PrimitiveSource::Type(cases.u64)
    );
    assert!(collapsed.stats().peak_live_primitives > 1);

    for id in [cases.unknown_union, cases.unknown_container] {
        let unknown = extract(&engine, id, false, 32);
        assert!(!unknown.contains_unknown());
        assert!(unknown.output_contains_unknown());
    }
    assert!(extract(&engine, cases.local_unknown, false, 32).contains_unknown());

    for id in [cases.union_member_array, cases.nested_union_member_array] {
        let expanded = extract(&engine, id, true, 32);
        assert_eq!(
            expanded
                .primitives()
                .iter()
                .filter(|p| p.source == PrimitiveSource::Type(cases.float4))
                .count(),
            2
        );
        assert!(
            expanded
                .primitives()
                .iter()
                .all(|p| p.meta_type != MetaType::Array)
        );
    }
    let zero = extract(&engine, cases.nested_zero_array, true, 32);
    assert_eq!(zero.primitives().len(), 1);
    assert_eq!(
        (
            zero.primitives()[0].length,
            zero.primitives()[0].aligned_length
        ),
        (1, 1)
    );
    assert!(!zero.contains_unknown());
    assert!(
        extract(&engine, cases.nested_zero_array, false, 0)
            .primitives()
            .is_empty()
    );
    assert!(
        extract(&engine, cases.empty_member_union, false, 0)
            .primitives()
            .is_empty()
    );
    assert!(matches!(
        PrimitiveExtraction::new(
            engine.clone(),
            cases.empty_union,
            Default::default(),
            Default::default()
        ),
        Err(ExtractionError::EmptyUnion(_))
    ));

    let padded = extract(&engine, cases.padded_scalar_array, false, 32);
    assert_eq!(
        padded
            .primitives()
            .iter()
            .map(|p| (p.offset, p.length, p.aligned_length))
            .collect::<Vec<_>>(),
        [(0, 3, 4), (4, 3, 4)]
    );
    let void = extract(&engine, cases.void, false, 1);
    assert!(void.contains_unknown());
    assert_eq!(
        (
            void.primitives()[0].length,
            void.primitives()[0].aligned_length
        ),
        (0, 0)
    );
    let code = extract(&engine, cases.code, false, 1);
    assert!(!code.contains_unknown());
    assert_eq!(
        (
            code.primitives()[0].length,
            code.primitives()[0].aligned_length
        ),
        (-1, -1)
    );
    assert_eq!(identity(cases.u8), PrimitiveSource::Type(cases.u8));
}
