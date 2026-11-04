//! Independent references for the native TypeFactory alignment component.
//!
//! The primary oracle deliberately builds the small dense table used by
//! type.cc:5172, instead of production's sparse representation. Its lookup is
//! type.cc:3805; padding and the second lookup follow type.cc:3821/3921.
//! Large declaration keys use a separate declaration-order scan, avoiding a
//! multi-gigabyte reference table. No Java organization resolver is an oracle.

use std::collections::BTreeSet;
use std::path::PathBuf;

use ghidra_abi::{NativeAlignmentError, NativeAlignmentLimits, NativeAlignmentMap};
use ghidra_languages::{Catalog, CompilerSpec, SizeAlignment};

const SIGNED_MAX: u64 = i32::MAX as u64;

struct DenseNativeMap(Vec<u32>);

impl DenseNativeMap {
    fn decode(declared: Option<&[SizeAlignment]>) -> Self {
        let Some(declared) = declared else {
            // setDefaultAlignmentMap, type.cc:5200, is a nine-slot table.
            return Self(vec![1, 1, 2, 2, 4, 4, 4, 4, 8]);
        };
        assert!(
            !declared.is_empty(),
            "oracle expects a nonempty declared map"
        );
        let maximum = declared.iter().map(|entry| entry.size).max().unwrap();
        assert!(maximum <= 256, "dense oracle keys must stay bounded");
        let mut slots = vec![None; maximum as usize + 1];
        for entry in declared {
            slots[entry.size as usize] = Some(entry.alignment);
        }
        slots[0] = Some(1); // This overwrites even an explicit zero-size entry.
        let mut previous = 1;
        Self(
            slots
                .into_iter()
                .map(|entry| {
                    if let Some(alignment) = entry {
                        previous = alignment;
                    }
                    previous
                })
                .collect(),
        )
    }

    fn alignment(&self, size: u64) -> u32 {
        if size >= self.0.len() as u64 {
            *self.0.last().unwrap()
        } else {
            self.0[size as usize]
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Geometry {
    Value {
        size: u32,
        aligned_size: u32,
        alignment: u32,
    },
    InvalidSize(u64),
    Overflow {
        size: u32,
        alignment: u32,
    },
}

// Use remainder and addition, independently of production's div_ceil. The
// signed-int rejection is this Rust component's explicit supported boundary;
// this test does not prescribe C++ behavior outside that boundary.
fn primitive_geometry(size: u64, alignment: &impl Fn(u64) -> u32) -> Geometry {
    if size > SIGNED_MAX {
        return Geometry::InvalidSize(size);
    }
    let raw_alignment = alignment(size);
    assert!(raw_alignment > 0);
    let remainder = size % u64::from(raw_alignment);
    let padding = if remainder == 0 {
        0
    } else {
        u64::from(raw_alignment) - remainder
    };
    let padded = size + padding;
    if padded > SIGNED_MAX {
        return Geometry::Overflow {
            size: size as u32,
            alignment: raw_alignment,
        };
    }
    Geometry::Value {
        size: size as u32,
        aligned_size: padded as u32,
        alignment: alignment(padded),
    }
}

fn observed_geometry(map: &NativeAlignmentMap, size: u64) -> Geometry {
    match map.primitive_geometry(size) {
        Ok(value) => Geometry::Value {
            size: value.size,
            aligned_size: value.aligned_size,
            alignment: value.alignment,
        },
        Err(NativeAlignmentError::InvalidSize(size)) => Geometry::InvalidSize(size),
        Err(NativeAlignmentError::Overflow { size, alignment }) => {
            Geometry::Overflow { size, alignment }
        }
        Err(other) => panic!("unexpected geometry failure: {other:?}"),
    }
}

fn map(entries: &[(u32, u32)]) -> Vec<SizeAlignment> {
    entries
        .iter()
        .map(|&(size, alignment)| SizeAlignment { size, alignment })
        .collect()
}

fn size_queries() -> Vec<u64> {
    let mut queries: BTreeSet<u64> = (0..=256).collect();
    for bit in 0..64 {
        let power = 1_u64 << bit;
        queries.insert(power - 1);
        queries.insert(power);
        queries.insert(power + 1);
    }
    for distance in 0..=128 {
        queries.insert(SIGNED_MAX - distance);
        queries.insert(SIGNED_MAX + distance);
    }
    queries.extend([
        u64::from(u32::MAX) - 1,
        u64::from(u32::MAX),
        u64::from(u32::MAX) + 1,
        u64::MAX - 1,
        u64::MAX,
    ]);
    queries.into_iter().collect()
}

#[derive(Default, Debug)]
struct Checks {
    maps: usize,
    alignments: usize,
    geometries: usize,
    padded: usize,
    changed_final_alignment: usize,
    invalid_sizes: usize,
    overflows: usize,
}

fn compare(
    declared: Option<&[SizeAlignment]>,
    reference_alignment: impl Fn(u64) -> u32,
    queries: &[u64],
    checks: &mut Checks,
) {
    let actual = NativeAlignmentMap::new(declared, NativeAlignmentLimits::default()).unwrap();
    compare_map(&actual, declared, reference_alignment, queries, checks);
}

fn compare_map(
    actual: &NativeAlignmentMap,
    declared: Option<&[SizeAlignment]>,
    reference_alignment: impl Fn(u64) -> u32,
    queries: &[u64],
    checks: &mut Checks,
) {
    checks.maps += 1;
    for &size in queries {
        assert_eq!(
            actual.alignment(size),
            reference_alignment(size),
            "alignment at size {size}, declarations {declared:?}"
        );
        checks.alignments += 1;
        let expected = primitive_geometry(size, &reference_alignment);
        assert_eq!(
            observed_geometry(actual, size),
            expected,
            "primitive at size {size}, declarations {declared:?}"
        );
        checks.geometries += 1;
        match expected {
            Geometry::Value {
                aligned_size,
                alignment,
                ..
            } => {
                checks.padded += usize::from(u64::from(aligned_size) != size);
                checks.changed_final_alignment +=
                    usize::from(alignment != reference_alignment(size));
            }
            Geometry::InvalidSize(_) => checks.invalid_sizes += 1,
            Geometry::Overflow { .. } => checks.overflows += 1,
        }
    }
}

fn compare_dense(declared: Option<&[SizeAlignment]>, queries: &[u64], checks: &mut Checks) {
    let reference = DenseNativeMap::decode(declared);
    compare(declared, |size| reference.alignment(size), queries, checks);
}

// A fixed generator makes failures reproducible without an external RNG or a
// random seed from the environment. Inputs include non-power-of-two alignments.
fn next(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state >> 24
}

#[test]
fn dense_native_oracle_covers_declared_maps_and_full_size_queries() {
    let queries = size_queries();
    assert!(queries.len() >= 650);
    let mut checks = Checks::default();
    compare_dense(None, &queries, &mut checks);

    let directed = [
        vec![(0, 0)],
        vec![(0, 99)],
        vec![(8, 3)], // No implicit entries at 1, 2, or 4.
        vec![(1, 8), (4, 2), (8, 1), (16, 16)],
        vec![(0, 0), (4, 7), (0, 99), (4, 3)],
        vec![(17, 5), (2, 3), (9, 1), (2, 7)],
        vec![(1, 3), (3, 8), (8, 2), (16, 5)],
        vec![(4, 2), (3, 16), (1, 3)],
        vec![(31, 255), (1, 257), (16, 1)],
        vec![(1, i32::MAX as u32), (7, 2)],
    ];
    for entries in directed {
        compare_dense(Some(&map(&entries)), &queries, &mut checks);
    }

    // Exhaust every ordered pair in a bounded key/value product. Equal keys
    // exercise last-wins ordering; distinct keys include gaps and decreases.
    let keys = [0, 1, 2, 3, 7, 8, 16, 31];
    let alignments = [1, 2, 3, 4, 8, 16];
    for first_key in keys {
        for second_key in keys {
            for first_alignment in alignments {
                for second_alignment in alignments {
                    let entries =
                        map(&[(first_key, first_alignment), (second_key, second_alignment)]);
                    compare_dense(Some(&entries), &queries, &mut checks);
                }
            }
        }
    }

    let values = [
        1,
        2,
        3,
        4,
        5,
        7,
        8,
        11,
        16,
        31,
        32,
        63,
        64,
        255,
        257,
        i32::MAX as u32 - 1,
        i32::MAX as u32,
    ];
    let mut state = 0x6e61_7469_7665_616c;
    for _ in 0..2048 {
        let length = 1 + next(&mut state) % 12;
        let entries: Vec<_> = (0..length)
            .map(|_| SizeAlignment {
                size: (next(&mut state) % 65) as u32,
                alignment: values[next(&mut state) as usize % values.len()],
            })
            .collect();
        compare_dense(Some(&entries), &queries, &mut checks);
    }

    assert_eq!(checks.maps, 4363);
    assert_eq!(checks.alignments, checks.maps * queries.len());
    assert_eq!(checks.geometries, checks.alignments);
    assert!(checks.padded > 100_000);
    assert!(checks.changed_final_alignment > 1_000);
    assert!(checks.invalid_sizes > 900_000);
    assert!(checks.overflows > 10_000);
    eprintln!("dense native alignment oracle: {checks:?}");
}

// Direct declaration-order scan is intentionally neither a sorted sparse map
// nor the dense oracle. It preserves the last occurrence of an equal-size key.
fn scan_declared_alignment(declared: &[SizeAlignment], size: u64) -> u32 {
    let mut chosen_size = 0;
    let mut alignment = 1;
    for entry in declared {
        if entry.size != 0 && u64::from(entry.size) <= size && entry.size >= chosen_size {
            chosen_size = entry.size;
            alignment = entry.alignment;
        }
    }
    alignment
}

#[test]
fn large_sparse_keys_match_a_declaration_order_reference() {
    let maximum = i32::MAX as u32;
    let keys = [
        0,
        1,
        3,
        1 << 16,
        1 << 30,
        maximum - 16,
        maximum - 3,
        maximum - 1,
        maximum,
    ];
    let values = [1, 2, 3, 5, 8, 257, maximum - 1, maximum];
    let mut queries: BTreeSet<_> = size_queries().into_iter().collect();
    for key in keys {
        queries.insert(u64::from(key).saturating_sub(1));
        queries.insert(u64::from(key));
        queries.insert(u64::from(key) + 1);
    }
    let queries: Vec<_> = queries.into_iter().collect();
    let mut checks = Checks::default();
    let mut state = 0x7370_6172_7365_6b65;
    for _ in 0..256 {
        let length = 1 + next(&mut state) % 12;
        let entries: Vec<_> = (0..length)
            .map(|_| SizeAlignment {
                size: keys[next(&mut state) as usize % keys.len()],
                alignment: values[next(&mut state) as usize % values.len()],
            })
            .collect();
        compare(
            Some(&entries),
            |size| scan_declared_alignment(&entries, size),
            &queries,
            &mut checks,
        );
    }
    assert_eq!(checks.maps, 256);
    assert_eq!(checks.alignments, checks.maps * queries.len());
    assert_eq!(checks.geometries, checks.alignments);
    assert!(checks.changed_final_alignment > 100);
    assert!(checks.overflows > 1_000);
    eprintln!("large-key native alignment oracle: {checks:?}");
}

#[test]
fn retained_compiler_spec_declarations_match_the_native_dense_oracle() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let catalog = Catalog::discover(&root).unwrap();
    let paths: BTreeSet<_> = catalog
        .languages
        .iter()
        .flat_map(|language| &language.compilers)
        .filter_map(|compiler| compiler.spec.available_path())
        .map(|path| std::fs::canonicalize(path).unwrap())
        .collect();
    assert_eq!(
        paths.len(),
        107,
        "distinct retained compiler specifications"
    );

    let queries = size_queries();
    let mut raw_checks = Checks::default();
    let mut bridge_checks = Checks::default();
    let mut declared_maps = 0;
    for path in paths {
        let source = without_xml_comments(&std::fs::read_to_string(&path).unwrap());
        let spec = CompilerSpec::from_path(&path).unwrap();
        // The declaration model stores entries but not presence of an empty
        // map element. Inspect source presence so absence selects native defaults.
        let declared = if source.contains("<size_alignment_map") {
            declared_maps += 1;
            let entries = &spec.data_organization.as_ref().unwrap().size_alignment_map;
            assert!(
                !entries.is_empty(),
                "empty retained map in {}",
                path.display()
            );
            Some(entries.as_slice())
        } else {
            None
        };
        compare_dense(declared, &queries, &mut raw_checks);

        // DecompInterface/CompilerSpec sends DataOrganizationImpl.encode's
        // resolved entries. Use those as decoder input, not Java's capped
        // getAlignment result, when checking the actual bridge constructor.
        for pointer_size in [2, 4, 8] {
            let organization = spec.resolved_data_organization(pointer_size);
            let entries = &organization.size_alignment_map;
            let encoded = (!entries.is_empty()).then_some(entries.as_slice());
            let reference = DenseNativeMap::decode(encoded);
            let actual = NativeAlignmentMap::from_organization(
                &organization,
                NativeAlignmentLimits::default(),
            )
            .unwrap();
            compare_map(
                &actual,
                encoded,
                |size| reference.alignment(size),
                &queries,
                &mut bridge_checks,
            );
        }
    }
    assert_eq!(raw_checks.maps, 107);
    assert_eq!(bridge_checks.maps, 321);
    assert!(declared_maps > 50);
    for checks in [&raw_checks, &bridge_checks] {
        assert_eq!(checks.alignments, checks.maps * queries.len());
        assert_eq!(checks.geometries, checks.alignments);
    }
    eprintln!(
        "retained native alignment oracle: {declared_maps} raw declared maps, \
         raw {raw_checks:?}, resolved Java-to-native bridge {bridge_checks:?}"
    );
}

fn without_xml_comments(mut source: &str) -> String {
    let mut result = String::new();
    while let Some(start) = source.find("<!--") {
        result.push_str(&source[..start]);
        let remainder = &source[start + 4..];
        let end = remainder
            .find("-->")
            .expect("retained XML comment terminates");
        source = &remainder[end + 3..];
    }
    result.push_str(source);
    result
}
