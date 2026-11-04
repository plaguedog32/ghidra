use ghidra_abi::*;
use ghidra_languages::{DataOrganization, SizeAlignment};
use ghidra_types::{TypeDefinition, TypeId, TypeKind, TypeLayouts};

fn entry(size: u32, alignment: u32) -> SizeAlignment {
    SizeAlignment { size, alignment }
}
fn map(entries: &[SizeAlignment]) -> NativeAlignmentMap {
    NativeAlignmentMap::new(Some(entries), Default::default()).unwrap()
}

#[test]
fn absent_map_has_the_native_default_and_queries_saturate_at_the_last_entry() {
    let m = NativeAlignmentMap::new(None, Default::default()).unwrap();
    assert_eq!(m.origin(), NativeAlignmentOrigin::Default);
    assert_eq!(
        (0..=12).map(|size| m.alignment(size)).collect::<Vec<_>>(),
        [1, 1, 2, 2, 4, 4, 4, 4, 8, 8, 8, 8, 8]
    );
    assert_eq!(m.alignment(u64::MAX), 8);
    assert_eq!(
        m.primitive_geometry(0).unwrap(),
        NativePrimitiveGeometry {
            size: 0,
            aligned_size: 0,
            alignment: 1
        }
    );
    assert_eq!(
        m.primitive_geometry(3).unwrap(),
        NativePrimitiveGeometry {
            size: 3,
            aligned_size: 4,
            alignment: 4
        }
    );
    assert_eq!(
        m.usage(),
        NativeAlignmentUsage {
            declarations: 0,
            stored_entries: 5,
            work: 6
        }
    );
}

#[test]
fn declared_map_replaces_defaults_instead_of_adding_java_seed_entries() {
    let m = map(&[entry(4, 2)]);
    assert_eq!(m.origin(), NativeAlignmentOrigin::Declared);
    assert_eq!(m.entries(), [entry(0, 1), entry(4, 2)]);
    assert_eq!(
        (0..=8).map(|size| m.alignment(size)).collect::<Vec<_>>(),
        [1, 1, 1, 1, 2, 2, 2, 2, 2]
    );
    assert_eq!(
        m.primitive_geometry(3).unwrap(),
        NativePrimitiveGeometry {
            size: 3,
            aligned_size: 3,
            alignment: 1
        }
    );
    assert_eq!(
        NativeAlignmentMap::new(Some(&[]), Default::default()).unwrap_err(),
        NativeAlignmentError::EmptyMap
    );
}

#[test]
fn duplicates_are_last_wins_sizes_are_sorted_and_zero_is_always_one() {
    let m = map(&[
        entry(8, 8),
        entry(4, 4),
        entry(2, 2),
        entry(4, 3),
        entry(0, 0),
        entry(0, 17),
    ]);
    assert_eq!(
        m.entries(),
        [entry(0, 1), entry(2, 2), entry(4, 3), entry(8, 8)]
    );
    assert_eq!(m.alignment(0), 1);
    assert_eq!(m.alignment(5), 3);
    assert_eq!(
        m.primitive_geometry(5).unwrap(),
        NativePrimitiveGeometry {
            size: 5,
            aligned_size: 6,
            alignment: 3
        }
    );
    assert_eq!(m.usage().declarations, 6);
}

#[test]
fn primitive_rounding_then_alignment_lookup_is_not_iterated_to_a_fixpoint() {
    let m = map(&[entry(3, 5), entry(5, 2)]);
    assert_eq!(
        m.primitive_geometry(3).unwrap(),
        NativePrimitiveGeometry {
            size: 3,
            aligned_size: 5,
            alignment: 2
        }
    );
    assert_eq!(
        m.primitive_geometry(4).unwrap(),
        NativePrimitiveGeometry {
            size: 4,
            aligned_size: 5,
            alignment: 2
        }
    );
    assert_eq!(
        m.primitive_geometry(6).unwrap(),
        NativePrimitiveGeometry {
            size: 6,
            aligned_size: 6,
            alignment: 2
        }
    );
}

#[test]
fn java_caps_and_pointer_defaults_are_not_native_primitive_rules() {
    let organization = DataOrganization {
        absolute_max_alignment: Some(1),
        default_pointer_alignment: Some(32),
        ..Default::default()
    }
    .resolve(8);
    let layouts = TypeLayouts::new(
        vec![
            TypeDefinition::new(
                "int3",
                TypeKind::Integer {
                    bytes: 3,
                    signed: true,
                },
            ),
            TypeDefinition::new(
                "ptr3",
                TypeKind::Pointer {
                    target: TypeId(0),
                    bytes: Some(3),
                },
            ),
        ]
        .into(),
        organization.clone(),
        Default::default(),
    )
    .unwrap();
    let integer = layouts.layout(TypeId(0)).unwrap().geometry;
    assert_eq!((integer.aligned_length, integer.alignment), (Some(3), 1));
    let pointer = layouts.layout(TypeId(1)).unwrap().geometry;
    assert_eq!((pointer.aligned_length, pointer.alignment), (Some(3), 32));
    let m = NativeAlignmentMap::from_organization(&organization, Default::default()).unwrap();
    assert_eq!(m.origin(), NativeAlignmentOrigin::Declared);
    // Both native scalar and pointer objects pass through findAdd geometry.
    assert_eq!(
        m.primitive_geometry(3).unwrap(),
        NativePrimitiveGeometry {
            size: 3,
            aligned_size: 4,
            alignment: 4
        }
    );
}

#[test]
fn organization_bridge_uses_the_resolved_seeded_map_and_omits_an_empty_map() {
    let mut organization = DataOrganization {
        size_alignment_map: vec![entry(4, 2)],
        ..Default::default()
    }
    .resolve(8);
    let m = NativeAlignmentMap::from_organization(&organization, Default::default()).unwrap();
    assert_eq!(
        m.entries(),
        [
            entry(0, 1),
            entry(1, 1),
            entry(2, 2),
            entry(4, 2),
            entry(8, 8)
        ]
    );
    // A raw standalone map containing only size4 has no seeded size2 key.
    assert_eq!(map(&[entry(4, 2)]).alignment(2), 1);
    assert_eq!(m.alignment(2), 2);
    organization.size_alignment_map.clear();
    let m = NativeAlignmentMap::from_organization(&organization, Default::default()).unwrap();
    assert_eq!(m.origin(), NativeAlignmentOrigin::Default);
    assert_eq!(m.alignment(8), 8);
}

#[test]
fn large_size_keys_have_sparse_storage_and_checked_signed_int_geometry() {
    let m = map(&[entry(i32::MAX as u32, 16)]);
    assert_eq!(m.entries().len(), 2);
    assert_eq!(
        m.usage(),
        NativeAlignmentUsage {
            declarations: 1,
            stored_entries: 2,
            work: 6
        }
    );
    assert_eq!(m.alignment(i32::MAX as u64 - 1), 1);
    assert_eq!(m.alignment(u64::MAX), 16);
    assert_eq!(
        m.primitive_geometry(i32::MAX as u64 - 1)
            .unwrap()
            .aligned_size,
        i32::MAX as u32 - 1
    );
    assert_eq!(
        m.primitive_geometry(i32::MAX as u64).unwrap_err(),
        NativeAlignmentError::Overflow {
            size: i32::MAX as u32,
            alignment: 16
        }
    );
    assert_eq!(
        m.primitive_geometry(u64::MAX).unwrap_err(),
        NativeAlignmentError::InvalidSize(u64::MAX)
    );
}

#[test]
fn malformed_entries_fail_explicitly_before_any_result_escapes() {
    for entries in [
        vec![entry(1, 0)],
        vec![entry(i32::MAX as u32 + 1, 1)],
        vec![entry(1, i32::MAX as u32 + 1)],
    ] {
        assert!(matches!(
            NativeAlignmentMap::new(Some(&entries), Default::default()),
            Err(NativeAlignmentError::InvalidEntry { index: 0, .. })
        ));
    }
    // Size zero is overwritten, so its zero value is not a divide-by-zero map.
    assert_eq!(
        map(&[entry(0, 0)]).primitive_geometry(7).unwrap().alignment,
        1
    );
    let m = NativeAlignmentMap::new(None, Default::default()).unwrap();
    assert_eq!(
        m.primitive_geometry(i32::MAX as u64).unwrap_err(),
        NativeAlignmentError::Overflow {
            size: i32::MAX as u32,
            alignment: 8
        }
    );
}

#[test]
fn exact_input_and_work_bounds_include_duplicate_declarations() {
    let entries = [entry(4, 4), entry(2, 2), entry(4, 8)];
    let limits = NativeAlignmentLimits {
        max_entries: 3,
        max_work: 15,
    };
    let m = NativeAlignmentMap::new(Some(&entries), limits).unwrap();
    // Initial zero entry 1; visits+inserts 3+4+4; final records 3.
    assert_eq!(
        m.usage(),
        NativeAlignmentUsage {
            declarations: 3,
            stored_entries: 3,
            work: 15
        }
    );
    assert_eq!(m.limits(), limits);
    assert_eq!(
        NativeAlignmentMap::new(
            Some(&entries),
            NativeAlignmentLimits {
                max_entries: 2,
                ..limits
            }
        )
        .unwrap_err(),
        NativeAlignmentError::Limit("entries")
    );
    for max_work in 0..15 {
        assert_eq!(
            NativeAlignmentMap::new(Some(&entries), NativeAlignmentLimits { max_work, ..limits })
                .unwrap_err(),
            NativeAlignmentError::Limit("work")
        );
    }
    for max_work in 0..6 {
        assert_eq!(
            NativeAlignmentMap::new(None, NativeAlignmentLimits { max_work, ..limits })
                .unwrap_err(),
            NativeAlignmentError::Limit("work")
        );
    }
    // Defaults use a fixed allocation, not caller-supplied declarations.
    assert!(
        NativeAlignmentMap::new(
            None,
            NativeAlignmentLimits {
                max_entries: 0,
                max_work: 6
            }
        )
        .is_ok()
    );
    // Declaration-count preflight precedes malformed record inspection.
    assert_eq!(
        NativeAlignmentMap::new(
            Some(&[entry(1, 0)]),
            NativeAlignmentLimits {
                max_entries: 0,
                max_work: 0
            }
        )
        .unwrap_err(),
        NativeAlignmentError::Limit("entries")
    );
}

#[test]
fn maps_are_owned_thread_safe_and_scale_by_record_count() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<NativeAlignmentMap>();
    for n in [1_000_usize, 4_000, 16_000] {
        let entries = (1..=n)
            .map(|n| entry(n as u32, (n % 7 + 1) as u32))
            .collect::<Vec<_>>();
        let m = map(&entries);
        assert_eq!(m.entries().len(), n + 1);
        let log = (usize::BITS - (n + 1).leading_zeros()) as u64;
        assert!(m.usage().work <= (n as u64) * (log + 3) + n as u64 + 2);
        let usage = m.usage();
        let clone = m.clone();
        drop(entries);
        drop(m);
        assert_eq!(clone.alignment(n as u64), (n % 7 + 1) as u32);
        assert_eq!(clone.usage(), usage);
    }
}
