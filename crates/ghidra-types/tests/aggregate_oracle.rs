//! Independent ordinary-aggregate oracle derived from the retained Java sources.
//!
//! Source paths below are relative to
//! Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/data/:
//! - DataTypeImpl.java:99-117: primitive aligned length precedes final alignment.
//! - DataOrganizationImpl.java:414-420,502-536: floor lookup, cap, pointer exception.
//! - AlignedComponentPacker.java:298-323,450-474: ordinary member placement and LCM.
//! - AlignedStructurePacker.java:99-119: structure minimum and tail padding.
//! - CompositeAlignmentHelper.java:49-77: union minimum, LCM, and absolute cap.
//! - ArrayDataType.java:196-210: zero arrays expose length one, arrays use stride.
//! - CompositeDataTypeImpl.java:74-76: a composite's aligned length is its length.
//!
//! This deliberately uses a separate reference representation, a linear size-map
//! scan, division-based rounding, and a multiple-search LCM. No production layout
//! or geometry helpers produce expected values. Graphs contain only defined,
//! automatically packed, ordinary datatypes; mutable undefined placeholders and
//! bitfields are outside this oracle's contract.

use std::sync::Arc;

use ghidra_languages::{DataOrganization, ResolvedDataOrganization, SizeAlignment};
use ghidra_types::{
    Builtin, Composite, Field, Limits, MinimumAlignment, Packing, TypeDefinition, TypeId, TypeKind,
    TypeLayouts,
};

#[derive(Debug, Clone, Copy)]
enum Scalar {
    Integer,
    Float,
    Opaque,
    Enum,
    Builtin(Builtin),
}

#[derive(Debug, Clone)]
enum ReferenceType {
    Scalar {
        bytes: u32,
        kind: Scalar,
    },
    Pointer(Option<u32>),
    Alias(usize),
    Array {
        element: usize,
        count: u64,
    },
    Aggregate {
        union: bool,
        members: Vec<usize>,
        cap: Option<u32>,
        minimum: MinimumAlignment,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ReferenceLayout {
    logical: u64,
    exposed: u64,
    aligned: u64,
    alignment: u32,
    // (type index, offset, component bytes, placement alignment)
    members: Vec<(usize, u64, u64, u32)>,
    stride: Option<u64>,
}

fn plain(logical: u64, exposed: u64, aligned: u64, alignment: u32) -> ReferenceLayout {
    ReferenceLayout {
        logical,
        exposed,
        aligned,
        alignment,
        members: Vec::new(),
        stride: None,
    }
}

fn rounded(value: u64, alignment: u32) -> u64 {
    let divisor = u64::from(alignment);
    value.div_ceil(divisor) * divisor
}

// All oracle alignments are deliberately small; this is independent of the
// Euclidean-GCD implementation used by production and the retained Java helper.
fn common_multiple(first: u32, second: u32) -> u32 {
    let mut candidate = first;
    while !candidate.is_multiple_of(second) {
        candidate += first;
    }
    candidate
}

fn size_alignment(bytes: u64, org: &ResolvedDataOrganization) -> u32 {
    let mut alignment = org.default_alignment;
    let mut selected_size = 0;
    for entry in &org.size_alignment_map {
        if u64::from(entry.size) <= bytes && entry.size >= selected_size {
            selected_size = entry.size;
            alignment = entry.alignment;
        }
    }
    if org.absolute_max_alignment == 0 {
        alignment
    } else {
        alignment.min(org.absolute_max_alignment)
    }
}

fn expected(nodes: &[ReferenceType], org: &ResolvedDataOrganization) -> Vec<ReferenceLayout> {
    let mut results: Vec<ReferenceLayout> = Vec::with_capacity(nodes.len());
    for (index, node) in nodes.iter().enumerate() {
        let value = match node {
            ReferenceType::Scalar { bytes, kind } => {
                let raw = u64::from(*bytes);
                let aligned = if matches!(kind, Scalar::Enum) {
                    raw
                } else {
                    rounded(raw, size_alignment(raw, org))
                };
                plain(raw, raw, aligned, size_alignment(aligned, org))
            }
            ReferenceType::Pointer(declared_bytes) => {
                let bytes = declared_bytes.unwrap_or(org.pointer_size);
                let has_exact_entry = org.size_alignment_map.iter().any(|e| e.size == bytes);
                let alignment = if has_exact_entry {
                    size_alignment(u64::from(bytes), org)
                } else {
                    org.default_pointer_alignment
                };
                plain(
                    u64::from(bytes),
                    u64::from(bytes),
                    u64::from(bytes),
                    alignment,
                )
            }
            ReferenceType::Alias(target) => {
                assert!(
                    *target < index,
                    "oracle graphs must be topologically ordered"
                );
                let target = &results[*target];
                plain(
                    target.logical,
                    target.exposed,
                    target.aligned,
                    target.alignment,
                )
            }
            ReferenceType::Array { element, count } => {
                assert!(
                    *element < index,
                    "oracle array must reference an earlier type"
                );
                let element = &results[*element];
                let size = element.aligned * count;
                let mut result = plain(size, size.max(1), size.max(1), element.alignment);
                result.stride = Some(element.aligned);
                result
            }
            ReferenceType::Aggregate {
                union,
                members,
                cap,
                minimum,
            } => {
                let mut end = 0;
                let mut alignment = 1;
                let mut gcc_running_alignment = 1;
                let mut member_layouts = Vec::new();
                for member in members {
                    assert!(
                        *member < index,
                        "oracle members must reference earlier types"
                    );
                    let field = &results[*member];
                    let field_alignment = cap.map_or(field.alignment, |n| n.min(field.alignment));
                    let field_size = if field.logical == 0 { 0 } else { field.aligned };
                    let offset = if *union {
                        0
                    } else {
                        rounded(end, field_alignment)
                    };
                    if *union {
                        end = end.max(field_size);
                    } else {
                        end = offset + field_size;
                    }
                    // GCC keeps ordinary fields in one packer group. Its
                    // lastAlignment is a running maximum; MS starts a fresh
                    // group for each ordinary field. This matters for
                    // nonpower alignments, even without any bitfields.
                    let conveyed = if !union && !org.use_ms_bitfield_convention {
                        gcc_running_alignment = gcc_running_alignment.max(field_alignment);
                        gcc_running_alignment
                    } else {
                        field_alignment
                    };
                    alignment = common_multiple(alignment, conveyed);
                    member_layouts.push((*member, offset, field_size, field_alignment));
                }
                let imposed = match minimum {
                    MinimumAlignment::Default => 1,
                    MinimumAlignment::Machine => org.machine_alignment,
                    MinimumAlignment::Explicit(n) => *n,
                };
                alignment = if *union {
                    let combined = common_multiple(alignment, imposed);
                    if org.absolute_max_alignment == 0 {
                        combined
                    } else {
                        combined.min(org.absolute_max_alignment)
                    }
                } else {
                    alignment.max(imposed)
                };
                let size = rounded(end, alignment);
                let mut result = plain(size, size.max(1), size.max(1), alignment);
                result.members = member_layouts;
                result
            }
        };
        results.push(value);
    }
    results
}

fn definitions(nodes: &[ReferenceType]) -> Arc<[TypeDefinition]> {
    nodes
        .iter()
        .enumerate()
        .map(|(index, node)| {
            let kind = match node {
                ReferenceType::Scalar { bytes, kind } => match kind {
                    Scalar::Integer => TypeKind::Integer {
                        bytes: *bytes,
                        signed: index % 2 == 0,
                    },
                    Scalar::Float => TypeKind::Float { bytes: *bytes },
                    Scalar::Opaque => TypeKind::Opaque { bytes: *bytes },
                    Scalar::Enum => TypeKind::Enum {
                        bytes: *bytes,
                        signed: index % 2 == 0,
                    },
                    Scalar::Builtin(builtin) => TypeKind::Builtin(*builtin),
                },
                ReferenceType::Pointer(bytes) => TypeKind::Pointer {
                    target: TypeId(0),
                    bytes: *bytes,
                },
                ReferenceType::Alias(target) => TypeKind::Alias(TypeId(*target)),
                ReferenceType::Array { element, count } => TypeKind::Array {
                    element: TypeId(*element),
                    count: *count,
                },
                ReferenceType::Aggregate {
                    union,
                    members,
                    cap,
                    minimum,
                } => {
                    let composite = Composite {
                        fields: members
                            .iter()
                            .enumerate()
                            .map(|(ordinal, member)| {
                                Field::new(format!("field_{ordinal}"), TypeId(*member))
                            })
                            .collect(),
                        packing: cap.map_or(Packing::Default, Packing::Explicit),
                        minimum_alignment: *minimum,
                    };
                    if *union {
                        TypeKind::Union(composite)
                    } else {
                        TypeKind::Structure(composite)
                    }
                }
            };
            TypeDefinition::new(format!("oracle_type_{index}"), kind)
        })
        .collect::<Vec<_>>()
        .into()
}

fn check(
    nodes: &[ReferenceType],
    org: &ResolvedDataOrganization,
    context: &str,
) -> (TypeLayouts, Vec<ReferenceLayout>) {
    let reference = expected(nodes, org);
    let actual = TypeLayouts::new(definitions(nodes), org.clone(), Limits::default())
        .unwrap_or_else(|error| panic!("{context}: valid oracle graph failed: {error:?}"));
    assert_eq!(actual.layouts().len(), reference.len(), "{context}");
    for (index, oracle) in reference.iter().enumerate() {
        let layout = actual.layout(TypeId(index)).unwrap();
        let geometry = layout.geometry;
        let message = format!("{context}, type {index}: {:?}", nodes[index]);
        assert_eq!(
            geometry.size,
            Some(oracle.logical),
            "logical size: {message}"
        );
        assert_eq!(
            geometry.length,
            Some(oracle.exposed),
            "public length: {message}"
        );
        assert_eq!(
            geometry.aligned_length,
            Some(oracle.aligned),
            "aligned length: {message}"
        );
        assert_eq!(geometry.alignment, oracle.alignment, "alignment: {message}");
        assert_eq!(
            geometry.is_zero_length(),
            oracle.logical == 0,
            "zero flag: {message}"
        );
        assert_eq!(
            layout.array_stride, oracle.stride,
            "array stride: {message}"
        );
        let fields: Vec<_> = layout
            .fields
            .iter()
            .map(|field| (field.ty.0, field.offset, field.bytes, field.alignment))
            .collect();
        assert_eq!(fields, oracle.members, "component geometry: {message}");
    }
    (actual, reference)
}

fn aggregate(
    union: bool,
    members: &[usize],
    cap: Option<u32>,
    minimum: MinimumAlignment,
) -> ReferenceType {
    ReferenceType::Aggregate {
        union,
        members: members.to_vec(),
        cap,
        minimum,
    }
}

fn scalar(bytes: u32) -> ReferenceType {
    ReferenceType::Scalar {
        bytes,
        kind: Scalar::Integer,
    }
}

fn map(entries: &[(u32, u32)]) -> Vec<SizeAlignment> {
    entries
        .iter()
        .map(|&(size, alignment)| SizeAlignment { size, alignment })
        .collect()
}

fn profiles() -> Vec<ResolvedDataOrganization> {
    let mut conventional = DataOrganization::default().resolve(8);
    conventional.long_size = 8;
    conventional.long_double_size = 16;

    let mut capped = conventional.clone();
    capped.absolute_max_alignment = 4;
    capped.machine_alignment = 16;
    capped.default_alignment = 2;
    capped.default_pointer_alignment = 32;
    capped.pointer_size = 3;
    capped.size_alignment_map.push(SizeAlignment {
        size: 16,
        alignment: 16,
    });

    let mut sparse = conventional.clone();
    sparse.default_alignment = 4;
    sparse.default_pointer_alignment = 16;
    sparse.pointer_size = 5;
    sparse.size_alignment_map = map(&[(2, 2), (8, 8), (32, 16)]);

    let mut thresholds = conventional.clone();
    thresholds.machine_alignment = 4;
    thresholds.pointer_size = 3;
    thresholds.char_size = 3;
    thresholds.wchar_size = 5;
    thresholds.short_size = 3;
    thresholds.integer_size = 5;
    thresholds.long_size = 9;
    thresholds.long_long_size = 12;
    thresholds.float_size = 3;
    thresholds.double_size = 9;
    thresholds.long_double_size = 17;
    thresholds.size_alignment_map = map(&[(1, 1), (3, 4), (4, 8), (8, 16), (17, 32)]);

    let mut empty_map = conventional.clone();
    empty_map.default_alignment = 8;
    empty_map.machine_alignment = 16;
    empty_map.default_pointer_alignment = 2;
    empty_map.pointer_size = 6;
    empty_map.size_alignment_map.clear();

    let mut descending = conventional.clone();
    descending.absolute_max_alignment = 8;
    descending.machine_alignment = 32;
    descending.pointer_size = 12;
    descending.default_pointer_alignment = 64;
    descending.size_alignment_map = map(&[(1, 8), (4, 2), (8, 1), (16, 16)]);

    vec![
        conventional,
        capped,
        sparse,
        thresholds,
        empty_map,
        descending,
    ]
}

struct Deterministic(u64);

impl Deterministic {
    fn pick(&mut self, bound: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        // Avoid the short alternating period in the low bits of an LCG.
        ((self.0 >> 24) % bound as u64) as usize
    }
}

fn graph(seed: u64, org: &ResolvedDataOrganization) -> Vec<ReferenceType> {
    let mut nodes = Vec::new();
    for (index, bytes) in [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 12, 16, 17, 24, 31, 33]
        .into_iter()
        .enumerate()
    {
        let kind = match index % 3 {
            0 => Scalar::Integer,
            1 => Scalar::Float,
            _ => Scalar::Opaque,
        };
        nodes.push(ReferenceType::Scalar { bytes, kind });
    }
    for bytes in 1..=8 {
        nodes.push(ReferenceType::Scalar {
            bytes,
            kind: Scalar::Enum,
        });
    }
    for (builtin, bytes) in [
        (Builtin::Bool, 1),
        (Builtin::Char, org.char_size),
        (Builtin::SignedChar, org.char_size),
        (Builtin::UnsignedChar, org.char_size),
        (Builtin::WChar, org.wchar_size),
        (Builtin::Short, org.short_size),
        (Builtin::UnsignedShort, org.short_size),
        (Builtin::Int, org.integer_size),
        (Builtin::UnsignedInt, org.integer_size),
        (Builtin::Long, org.long_size),
        (Builtin::UnsignedLong, org.long_size),
        (Builtin::LongLong, org.long_long_size),
        (Builtin::UnsignedLongLong, org.long_long_size),
        (Builtin::Float, org.float_size),
        (Builtin::Double, org.double_size),
        (Builtin::LongDouble, org.long_double_size),
    ] {
        nodes.push(ReferenceType::Scalar {
            bytes,
            kind: Scalar::Builtin(builtin),
        });
    }
    for width in [
        None,
        Some(1),
        Some(3),
        Some(4),
        Some(5),
        Some(8),
        Some(12),
        Some(16),
    ] {
        nodes.push(ReferenceType::Pointer(width));
    }
    let first_empty = nodes.len();
    for union in [false, true] {
        for minimum in [
            MinimumAlignment::Default,
            MinimumAlignment::Machine,
            MinimumAlignment::Explicit(16),
        ] {
            nodes.push(aggregate(union, &[], None, minimum));
        }
    }
    nodes.push(ReferenceType::Alias(2));
    let zero_array = nodes.len();
    nodes.push(ReferenceType::Array {
        element: 2,
        count: 0,
    });
    nodes.push(ReferenceType::Array {
        element: first_empty,
        count: 0,
    });
    let nested_array = nodes.len();
    nodes.push(ReferenceType::Array {
        element: zero_array,
        count: 3,
    });
    nodes.push(ReferenceType::Array {
        element: first_empty,
        count: 2,
    });
    nodes.push(ReferenceType::Alias(zero_array));
    nodes.push(ReferenceType::Alias(nested_array));

    let mut random = Deterministic(seed ^ 0xe912_713a_7b28_4f65);
    let minima = [
        MinimumAlignment::Default,
        MinimumAlignment::Machine,
        MinimumAlignment::Explicit(1),
        MinimumAlignment::Explicit(2),
        MinimumAlignment::Explicit(4),
        MinimumAlignment::Explicit(8),
        MinimumAlignment::Explicit(16),
        MinimumAlignment::Explicit(32),
    ];
    let caps = [None, Some(1), Some(2), Some(4), Some(8), Some(16)];
    // Freeze the available predecessors per layer: depth and byte sizes stay
    // small even when the generated fields repeatedly select large children.
    for _layer in 0..4 {
        let available = nodes.len();
        for _ in 0..16 {
            let node = match random.pick(6) {
                0 => ReferenceType::Alias(random.pick(available)),
                1 => ReferenceType::Array {
                    element: random.pick(available),
                    count: random.pick(5) as u64,
                },
                choice => {
                    let members = (0..random.pick(7))
                        .map(|_| random.pick(available))
                        .collect();
                    ReferenceType::Aggregate {
                        union: choice % 2 == 0,
                        members,
                        cap: caps[random.pick(caps.len())],
                        minimum: minima[random.pick(minima.len())],
                    }
                }
            };
            nodes.push(node);
        }
    }
    nodes
}

#[test]
fn deterministic_acyclic_graphs_match_the_independent_aggregate_oracle() {
    let mut graph_count = 0;
    let mut type_count = 0;
    let mut field_count = 0;
    for (profile, organization) in profiles().into_iter().enumerate() {
        for ms in [false, true] {
            let mut org = organization.clone();
            org.use_ms_bitfield_convention = ms;
            org.bitfield_type_alignment_enabled = !ms;
            org.bitfield_zero_length_boundary = if ms { 16 } else { 0 };
            for seed in 0..16 {
                let nodes = graph(seed, &org);
                let context = format!("profile={profile}, MS={ms}, seed={seed}");
                let (actual, reference) = check(&nodes, &org, &context);
                check_permuted_ids(&actual, &reference, seed + 71, &context);
                graph_count += 1;
                type_count += reference.len();
                field_count += reference
                    .iter()
                    .map(|layout| layout.members.len())
                    .sum::<usize>();
            }
        }
    }
    assert_eq!(graph_count, 192);
    assert_eq!(type_count, 24_000);
    assert_eq!(field_count, 24_048);
}

// Preserve the independent expected layouts while scrambling production IDs.
// This exercises forward by-value references without teaching the simple
// reference evaluator to share production's dependency-walk algorithm.
fn check_permuted_ids(
    actual: &TypeLayouts,
    reference: &[ReferenceLayout],
    seed: u64,
    context: &str,
) {
    let mut random = Deterministic(seed);
    let mut order: Vec<_> = (0..reference.len()).collect(); // new -> original
    for end in (1..order.len()).rev() {
        let choice = random.pick(end + 1);
        order.swap(end, choice);
    }
    let mut new_id = vec![0; order.len()];
    for (new, old) in order.iter().enumerate() {
        new_id[*old] = new;
    }
    let mut definitions: Vec<_> = order
        .iter()
        .map(|old| actual.definitions()[*old].clone())
        .collect();
    let mut forward = 0;
    for (index, definition) in definitions.iter_mut().enumerate() {
        let mut rewrite = |id: &mut TypeId| {
            *id = TypeId(new_id[id.0]);
            forward += usize::from(id.0 > index);
        };
        match &mut definition.kind {
            TypeKind::Alias(target)
            | TypeKind::Array {
                element: target, ..
            } => rewrite(target),
            TypeKind::Structure(c) | TypeKind::Union(c) => {
                for field in &mut c.fields {
                    rewrite(&mut field.ty);
                }
            }
            TypeKind::Pointer { target, .. } => *target = TypeId(new_id[target.0]),
            TypeKind::Function {
                result, parameters, ..
            } => {
                *result = TypeId(new_id[result.0]);
                for parameter in parameters {
                    *parameter = TypeId(new_id[parameter.0]);
                }
            }
            _ => (),
        }
    }
    assert!(forward > 0, "no forward by-value references: {context}");
    let permuted = TypeLayouts::new(
        definitions.into(),
        actual.organization().clone(),
        Limits::default(),
    )
    .unwrap();
    for (old, oracle) in reference.iter().enumerate() {
        let layout = permuted.layout(TypeId(new_id[old])).unwrap();
        assert_eq!(
            layout.geometry,
            actual.layout(TypeId(old)).unwrap().geometry,
            "permuted geometry: {context}"
        );
        assert_eq!(
            layout.array_stride, oracle.stride,
            "permuted stride: {context}"
        );
        let expected: Vec<_> = oracle
            .members
            .iter()
            .map(|(ty, offset, bytes, align)| (new_id[*ty], *offset, *bytes, *align))
            .collect();
        let fields: Vec<_> = layout
            .fields
            .iter()
            .map(|f| (f.ty.0, f.offset, f.bytes, f.alignment))
            .collect();
        assert_eq!(fields, expected, "permuted fields: {context}");
    }
}

#[test]
fn parent_packing_caps_placement_without_repacking_the_child() {
    let org = DataOrganization::default().resolve(8);
    let nodes = vec![
        scalar(1),
        scalar(4),
        aggregate(false, &[0, 1, 0], None, MinimumAlignment::Default),
        aggregate(false, &[0, 2, 0], Some(1), MinimumAlignment::Default),
        ReferenceType::Array {
            element: 2,
            count: 3,
        },
        aggregate(true, &[3, 4], Some(2), MinimumAlignment::Default),
    ];
    let (_, reference) = check(&nodes, &org, "nested packing");
    assert_eq!(
        reference[2].members,
        vec![(0, 0, 1, 1), (1, 4, 4, 4), (0, 8, 1, 1)]
    );
    assert_eq!(reference[2].logical, 12);
    assert_eq!(
        reference[3].members,
        vec![(0, 0, 1, 1), (2, 1, 12, 1), (0, 13, 1, 1)]
    );
    assert_eq!((reference[3].logical, reference[3].alignment), (14, 1));
    assert_eq!((reference[4].stride, reference[4].logical), (Some(12), 36));
    assert_eq!((reference[5].logical, reference[5].alignment), (36, 2));
}

#[test]
fn zero_arrays_align_members_and_empty_aggregate_elements_still_have_stride_one() {
    let org = DataOrganization::default().resolve(8);
    let nodes = vec![
        scalar(1),
        scalar(4),
        ReferenceType::Array {
            element: 1,
            count: 0,
        },
        aggregate(false, &[0, 2], None, MinimumAlignment::Default),
        aggregate(false, &[], None, MinimumAlignment::Explicit(8)),
        ReferenceType::Array {
            element: 4,
            count: 2,
        },
        aggregate(false, &[0, 4, 0], None, MinimumAlignment::Default),
        aggregate(true, &[2, 4], None, MinimumAlignment::Default),
        ReferenceType::Alias(2),
        ReferenceType::Array {
            element: 8,
            count: 3,
        },
    ];
    let (_, reference) = check(&nodes, &org, "logical zeros and array strides");
    assert_eq!(
        (
            reference[2].logical,
            reference[2].exposed,
            reference[2].aligned
        ),
        (0, 1, 1)
    );
    assert_eq!(reference[3].members, vec![(0, 0, 1, 1), (2, 4, 0, 4)]);
    assert_eq!((reference[3].logical, reference[3].alignment), (4, 4));
    assert_eq!(
        (
            reference[4].logical,
            reference[4].exposed,
            reference[4].alignment
        ),
        (0, 1, 8)
    );
    assert_eq!(
        (
            reference[5].stride,
            reference[5].logical,
            reference[5].alignment
        ),
        (Some(1), 2, 8)
    );
    assert_eq!(
        reference[6].members,
        vec![(0, 0, 1, 1), (4, 8, 0, 8), (0, 8, 1, 1)]
    );
    assert_eq!((reference[6].logical, reference[6].alignment), (16, 8));
    assert_eq!(
        (
            reference[7].logical,
            reference[7].exposed,
            reference[7].alignment
        ),
        (0, 1, 8)
    );
    assert_eq!((reference[9].stride, reference[9].logical), (Some(1), 3));
}

#[test]
fn primitives_enums_and_pointer_map_misses_keep_distinct_lengths_and_alignment() {
    let mut org = DataOrganization::default().resolve(3);
    org.absolute_max_alignment = 4;
    org.default_pointer_alignment = 16;
    org.size_alignment_map = map(&[(1, 1), (2, 2), (4, 8)]);
    let nodes = vec![
        scalar(3),
        ReferenceType::Scalar {
            bytes: 3,
            kind: Scalar::Enum,
        },
        ReferenceType::Pointer(None),
        ReferenceType::Pointer(Some(4)),
        ReferenceType::Array {
            element: 0,
            count: 2,
        },
        ReferenceType::Array {
            element: 1,
            count: 2,
        },
        ReferenceType::Array {
            element: 2,
            count: 2,
        },
        aggregate(false, &[0, 1, 2], Some(2), MinimumAlignment::Default),
    ];
    let (_, reference) = check(&nodes, &org, "scalar and pointer distinctions");
    assert_eq!(
        (
            reference[0].logical,
            reference[0].aligned,
            reference[0].alignment
        ),
        (3, 4, 4)
    );
    assert_eq!(
        (
            reference[1].logical,
            reference[1].aligned,
            reference[1].alignment
        ),
        (3, 3, 2)
    );
    assert_eq!(
        (
            reference[2].logical,
            reference[2].aligned,
            reference[2].alignment
        ),
        (3, 3, 16)
    );
    assert_eq!((reference[3].logical, reference[3].alignment), (4, 4));
    assert_eq!((reference[4].stride, reference[4].logical), (Some(4), 8));
    assert_eq!((reference[5].stride, reference[5].logical), (Some(3), 6));
    assert_eq!((reference[6].stride, reference[6].logical), (Some(3), 6));
    assert_eq!(
        reference[7].members,
        vec![(0, 0, 4, 2), (1, 4, 3, 2), (2, 8, 3, 2)]
    );
}

#[test]
fn nonpower_minimum_uses_structure_max_but_union_lcm_then_absolute_cap() {
    let mut org = DataOrganization::default().resolve(8);
    org.absolute_max_alignment = 4;
    org.machine_alignment = 3;
    let nodes = vec![
        scalar(2),
        aggregate(false, &[0], None, MinimumAlignment::Explicit(3)),
        aggregate(true, &[0], None, MinimumAlignment::Explicit(3)),
        aggregate(false, &[0], Some(1), MinimumAlignment::Machine),
        aggregate(true, &[0], Some(1), MinimumAlignment::Machine),
        aggregate(false, &[], Some(1), MinimumAlignment::Explicit(9)),
        aggregate(true, &[], Some(1), MinimumAlignment::Explicit(9)),
    ];
    let (_, reference) = check(&nodes, &org, "nonpower imposed alignment");
    assert_eq!((reference[1].logical, reference[1].alignment), (3, 3));
    assert_eq!((reference[2].logical, reference[2].alignment), (4, 4));
    assert_eq!((reference[3].logical, reference[3].alignment), (3, 3));
    assert_eq!((reference[4].logical, reference[4].alignment), (3, 3));
    assert_eq!((reference[5].logical, reference[5].alignment), (0, 9));
    assert_eq!((reference[6].logical, reference[6].alignment), (0, 4));
}

#[test]
fn ascending_nonpower_member_alignments_require_a_default_lcm() {
    let mut org = DataOrganization::default().resolve(8);
    org.size_alignment_map = map(&[(1, 1), (2, 2), (3, 3)]);
    let nodes = vec![
        scalar(2),
        scalar(3),
        aggregate(false, &[0, 1], None, MinimumAlignment::Default),
        aggregate(true, &[0, 1], None, MinimumAlignment::Default),
        aggregate(false, &[0, 1], None, MinimumAlignment::Explicit(4)),
        aggregate(true, &[0, 1], None, MinimumAlignment::Explicit(4)),
    ];
    // Ascending members convey both alignments under either compiler mode.
    let (_, reference) = check(&nodes, &org, "source-verifiable nonpower LCM");
    assert_eq!(reference[2].members, vec![(0, 0, 2, 2), (1, 3, 3, 3)]);
    assert_eq!((reference[2].logical, reference[2].alignment), (6, 6));
    assert_eq!((reference[3].logical, reference[3].alignment), (6, 6));
    assert_eq!((reference[4].logical, reference[4].alignment), (6, 6));
    assert_eq!((reference[5].logical, reference[5].alignment), (12, 12));
}

#[test]
fn gcc_running_alignment_preserves_the_source_nonpower_order_difference() {
    let mut org = DataOrganization::default().resolve(8);
    org.size_alignment_map = map(&[(1, 1), (4, 4), (6, 6)]);
    let nodes = vec![
        scalar(6),
        scalar(4),
        aggregate(false, &[0, 1], None, MinimumAlignment::Default),
        aggregate(false, &[1, 0], None, MinimumAlignment::Default),
        aggregate(true, &[0, 1], None, MinimumAlignment::Default),
        aggregate(true, &[1, 0], None, MinimumAlignment::Default),
    ];
    for ms in [false, true] {
        org.use_ms_bitfield_convention = ms;
        let (_, reference) = check(&nodes, &org, &format!("nonpower member order, MS={ms}"));
        assert_eq!(reference[2].members, vec![(0, 0, 6, 6), (1, 8, 4, 4)]);
        assert_eq!(reference[3].members, vec![(1, 0, 4, 4), (0, 6, 6, 6)]);
        assert_eq!(reference[2].logical, 12);
        assert_eq!(reference[2].alignment, if ms { 12 } else { 6 });
        assert_eq!((reference[3].logical, reference[3].alignment), (12, 12));
        assert_eq!((reference[4].logical, reference[4].alignment), (12, 12));
        assert_eq!((reference[5].logical, reference[5].alignment), (12, 12));
    }
}
