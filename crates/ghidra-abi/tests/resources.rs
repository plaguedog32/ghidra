use std::sync::Arc;

use ghidra_abi::*;
use ghidra_languages::{CompilerSpec, Extension, ModelStatus, ParamEntry, Storage, StorageClass};
use ghidra_pcode::{AddressSpace, Endianness, SpaceId, SpaceKind};

fn spec(input: &str, output: &str) -> CompilerSpec {
    let text = format!(
        r#"<compiler_spec><stackpointer register="sp" space="ram"/>
<default_proto><prototype name="p" extrapop="0" stackshift="0">
<input>{input}</input><output>{output}</output></prototype></default_proto></compiler_spec>"#
    );
    let spec = CompilerSpec::parse_str(&text, None, &Default::default()).unwrap();
    assert!(spec.is_fully_modeled(), "{:?}", spec.diagnostics);
    spec
}
fn file() -> RegisterFile {
    let spaces = [
        (0, "const", SpaceKind::Constant, 8),
        (1, "ram", SpaceKind::Ram, 4),
        (2, "register", SpaceKind::Register, 8),
    ]
    .into_iter()
    .map(|(id, name, kind, address_size)| AddressSpace {
        id: SpaceId(id),
        name: name.into(),
        kind,
        address_size,
        word_size: 1,
        endianness: Endianness::Little,
    })
    .collect();
    let registers = [
        ("r0", 0, 4),
        ("r1", 4, 4),
        ("r2", 8, 4),
        ("wide", 0, 8),
        ("super", 0, 16),
        ("cross", 4, 8),
        ("float", 256, 8),
        ("giant", 0, 264),
        ("sp", 512, 4),
    ]
    .into_iter()
    .map(|(name, offset, size)| RegisterDefinition {
        name: name.into(),
        space: SpaceId(2),
        offset,
        size,
    })
    .collect();
    RegisterFile::new(spaces, SpaceId(1), registers, Default::default()).unwrap()
}
fn storage(spec: CompilerSpec) -> Arc<CompilerStorage> {
    Arc::new(CompilerStorage::new(Arc::new(spec), Arc::new(file()), Default::default()).unwrap())
}
fn plan(input: &str) -> CompilerResources {
    CompilerResources::new(storage(spec(input, "")), Default::default()).unwrap()
}
fn reg(name: &str, size: u32) -> String {
    format!(r#"<pentry minsize="1" maxsize="{size}"><register name="{name}"/></pentry>"#)
}
fn groups(plan: &CompilerResources, direction: ParameterDirection) -> Vec<Vec<usize>> {
    plan.list(0, direction)
        .unwrap()
        .entries
        .iter()
        .map(|e| e.groups.iter().map(|g| g.0).collect())
        .collect()
}

#[test]
fn explicit_groups_share_resources_and_aligned_pool_slots_are_not_group_ids() {
    let input = format!(
        r#"<group>
<pentry minsize="4" maxsize="8" storage="float"><register name="float"/></pentry>
{}</group>{}<pentry minsize="1" maxsize="500" align="4"><addr space="stack" offset="4"/></pentry>"#,
        reg("r0", 4),
        reg("r1", 4)
    );
    let resources =
        CompilerResources::new(storage(spec(&input, &reg("r0", 4))), Default::default()).unwrap();
    assert_eq!(
        groups(&resources, ParameterDirection::Input),
        [vec![0], vec![0], vec![1], vec![2]]
    );
    assert_eq!(groups(&resources, ParameterDirection::Output), [vec![0]]);
    let input = resources.list(0, ParameterDirection::Input).unwrap();
    assert_eq!(input.group_count, 3);
    assert_eq!(input.entries[0].declared_group, Some(0));
    assert_eq!(input.entries[1].declared_group, Some(0));
    assert!(!input.entries[3].exclusion);
    assert_eq!(input.entries[3].slot_capacity, 125);
    assert_eq!(resources.group_count(), 4); // Input and output have separate namespaces.
}

#[test]
fn containing_pools_reuse_primitive_resources_without_recounting_overlaps() {
    let resources = plan(&format!(
        "{}{}{}{}",
        reg("r0", 4),
        reg("r1", 4),
        reg("wide", 8),
        reg("super", 16)
    ));
    assert_eq!(
        groups(&resources, ParameterDirection::Input),
        [vec![0], vec![1], vec![0, 1], vec![0, 1]]
    );
    let input = resources.list(0, ParameterDirection::Input).unwrap();
    assert!(!input.entries[0].overlapping);
    assert!(input.entries[2].overlapping && input.entries[3].overlapping);
    assert_eq!(input.group_count, 2);
    // The pentry's maximum, rather than its physical register alias's full
    // width, describes its resource interval.
    let resources = plan(&format!("{}{}", reg("r1", 4), reg("wide", 4)));
    assert_eq!(
        groups(&resources, ParameterDirection::Input),
        [vec![0], vec![1]]
    );
}

#[test]
fn inherited_group_repetitions_are_retained_in_sorted_order() {
    let input = format!(
        r#"<group>
<pentry minsize="1" maxsize="8" storage="float"><register name="float"/></pentry>
{}</group>{}"#,
        reg("r0", 4),
        reg("giant", 264)
    );
    let resources = plan(&input);
    assert_eq!(
        groups(&resources, ParameterDirection::Input),
        [vec![0], vec![0], vec![0, 0]]
    );
    assert_eq!(
        resources
            .list(0, ParameterDirection::Input)
            .unwrap()
            .group_count,
        1
    );
}

#[test]
fn containment_in_reverse_order_and_crossing_intervals_fail_explicitly() {
    for input in [
        format!("{}{}", reg("wide", 8), reg("r0", 4)),
        format!("{}{}", reg("wide", 8), reg("cross", 8)),
    ] {
        let error =
            CompilerResources::new(storage(spec(&input, "")), Default::default()).unwrap_err();
        assert!(matches!(
            error,
            ResourceError::IllegalOverlap {
                site: BindingSite::Input { entry: 1, .. },
                previous: BindingSite::Input { entry: 0, .. },
            }
        ));
    }
}

#[test]
fn joins_inherit_exact_predecessor_pool_resources_and_ignore_literal_padding() {
    let joined =
        r#"<pentry minsize="1" maxsize="8"><addr space="join" piece1="r0" piece2="r1"/></pentry>"#;
    let resources = plan(&format!("{}{}{joined}", reg("r0", 4), reg("r1", 4)));
    assert_eq!(
        groups(&resources, ParameterDirection::Input),
        [vec![0], vec![1], vec![0, 1]]
    );
    let padded = r#"<pentry minsize="1" maxsize="8"><addr space="join" piece1="const:0xffffffffffffffff:4" piece2="r0"/></pentry>"#;
    let resources = plan(&format!("{}{padded}", reg("r0", 4)));
    assert_eq!(
        groups(&resources, ParameterDirection::Input),
        [vec![0], vec![0]]
    );
    // A physical alias's width does not make a smaller pentry an exact match.
    let error = CompilerResources::new(
        storage(spec(&format!("{}{padded}", reg("r0", 2)), "")),
        Default::default(),
    )
    .unwrap_err();
    assert!(matches!(
        error,
        ResourceError::Invalid {
            reason: "join must match an earlier parameter pool",
            ..
        }
    ));
    // Finding even one matching piece is sufficient, as in resolveJoin.
    let resources = plan(&format!("{}{joined}", reg("r0", 4)));
    assert_eq!(
        groups(&resources, ParameterDirection::Input),
        [vec![0], vec![0]]
    );
}

#[test]
fn a_later_contiguous_pool_cannot_subsume_an_earlier_join() {
    let input = format!(
        r#"{}{}
<pentry minsize="1" maxsize="8"><addr space="join" piece1="r0" piece2="r1"/></pentry>{}"#,
        reg("r0", 4),
        reg("r1", 4),
        reg("wide", 8)
    );
    assert!(matches!(
        CompilerResources::new(storage(spec(&input, "")), Default::default()),
        Err(ResourceError::IllegalOverlap {
            previous: BindingSite::Input { entry: 2, .. },
            ..
        })
    ));
}

#[test]
fn signed_stack_intervals_are_compared_in_normalized_byte_order() {
    let resources = plan(
        r#"<pentry minsize="1" maxsize="4"><addr space="stack" offset="-4"/></pentry>
<pentry minsize="1" maxsize="8"><addr space="stack" offset="-8"/></pentry>"#,
    );
    assert_eq!(
        groups(&resources, ParameterDirection::Input),
        [vec![0], vec![0]]
    );
    // Capacity is not an allocation width, including near a space boundary.
    let input =
        r#"<pentry minsize="1" maxsize="8"><addr space="stack" offset="0x7fffffff"/></pentry>"#;
    let storage = storage(spec(input, ""));
    assert_eq!(storage.bindings()[0].storage.size(), None);
    let resources = CompilerResources::new(storage, Default::default()).unwrap();
    assert_eq!(groups(&resources, ParameterDirection::Input), [vec![0]]);
}

#[test]
fn malformed_caller_constructed_group_metadata_and_incomplete_models_are_rejected() {
    let valid = spec(
        &format!("{}{}{}", reg("r0", 4), reg("r1", 4), reg("r2", 4)),
        "",
    );
    let mut unknown = valid.clone();
    unknown.prototypes[0].input.entries[0].group = Some(0);
    assert!(matches!(
        CompilerResources::new(storage(unknown), Default::default()),
        Err(ResourceError::Invalid {
            reason: "unknown declared group",
            ..
        })
    ));
    let mut reused = valid.clone();
    reused.prototypes[0].input.group_count = 1;
    reused.prototypes[0].input.entries[0].group = Some(0);
    reused.prototypes[0].input.entries[2].group = Some(0);
    assert!(matches!(
        CompilerResources::new(storage(reused), Default::default()),
        Err(ResourceError::Invalid {
            reason: "declared groups must be contiguous and ordered",
            ..
        })
    ));
    let mut indistinguishable = valid.clone();
    indistinguishable.prototypes[0].input.group_count = 1;
    for entry in &mut indistinguishable.prototypes[0].input.entries[..2] {
        entry.group = Some(0);
    }
    assert!(matches!(
        CompilerResources::new(storage(indistinguishable), Default::default()),
        Err(ResourceError::Invalid {
            reason: "group members are not distinguished by size/class order",
            ..
        })
    ));
    let mut incomplete = valid;
    incomplete.prototypes[0].status = ModelStatus::Incomplete { errors: 1 };
    assert!(matches!(
        CompilerResources::new(storage(incomplete), Default::default()),
        Err(ResourceError::IncompleteModel(0))
    ));
}

#[test]
fn all_resource_budgets_pass_exactly_and_fail_one_below_without_partial_output() {
    let storage = storage(spec(
        &format!("{}{}{}", reg("r0", 4), reg("r1", 4), reg("wide", 8)),
        &reg("r2", 4),
    ));
    let result = CompilerResources::new(storage.clone(), Default::default()).unwrap();
    let exact = ResourceLimits {
        max_models: 1,
        max_entries: result.entry_count(),
        max_regions: result.region_count(),
        max_groups: result.group_count(),
        max_group_references: result.group_references(),
        max_work: result.build_work(),
    };
    CompilerResources::new(storage.clone(), exact).unwrap();
    for limits in [
        ResourceLimits {
            max_models: 0,
            ..exact
        },
        ResourceLimits {
            max_entries: exact.max_entries - 1,
            ..exact
        },
        ResourceLimits {
            max_regions: exact.max_regions - 1,
            ..exact
        },
        ResourceLimits {
            max_groups: exact.max_groups - 1,
            ..exact
        },
        ResourceLimits {
            max_group_references: exact.max_group_references - 1,
            ..exact
        },
        ResourceLimits {
            max_work: exact.max_work - 1,
            ..exact
        },
    ] {
        assert!(matches!(
            CompilerResources::new(storage.clone(), limits),
            Err(ResourceError::Limit(_))
        ));
    }
    for max_work in 0..exact.max_work {
        assert!(matches!(
            CompilerResources::new(storage.clone(), ResourceLimits { max_work, ..exact }),
            Err(ResourceError::Limit("work"))
        ));
    }
    assert!(Arc::ptr_eq(result.storage(), &storage));
    assert!(result.list(usize::MAX, ParameterDirection::Input).is_none());
    fn send_sync<T: Send + Sync>() {}
    send_sync::<CompilerResources>();
}

fn raw_entry(offset: u64, size: u32) -> ParamEntry {
    ParamEntry {
        min_size: 1,
        max_size: size,
        align: None,
        storage_class: StorageClass::General,
        extension: Extension::None,
        storage: Storage::Varnode {
            space: "register".into(),
            offset,
            size,
        },
        group: None,
        line: 0,
    }
}

#[test]
fn generated_resource_groups_match_a_byte_set_reference() {
    let mut seed = 0x98ad_7182_3448_u64;
    let mut valid = 0;
    let mut rejected = 0;
    for case in 0..1000 {
        let mut source = spec("", "");
        let mut bytes: Vec<Vec<u64>> = Vec::new();
        let mut expected: Vec<(Vec<usize>, bool)> = Vec::new();
        let mut next_group = 0;
        let mut conflict = false;
        for i in 0..24 {
            seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
            let (offset, size) = if case % 4 == 0 {
                (i * 8, 4)
            } else if case % 4 == 1 {
                (0, i + 1)
            } else {
                ((seed >> 24) % 128, 1 + (seed >> 40) % 16)
            };
            source.prototypes[0]
                .input
                .entries
                .push(raw_entry(offset, size as u32));
            if conflict {
                continue;
            }
            let current: Vec<_> = (offset..offset + size).collect();
            let mut groups = Vec::new();
            for (j, previous) in bytes.iter().enumerate() {
                if !previous.iter().any(|v| current.contains(v)) {
                    continue;
                }
                if !previous.iter().all(|v| current.contains(v)) {
                    conflict = true;
                    break;
                }
                if !expected[j].1 {
                    groups.extend_from_slice(&expected[j].0);
                }
            }
            if conflict {
                continue;
            }
            let overlap = !groups.is_empty();
            if !overlap {
                groups.push(next_group);
                next_group += 1;
            }
            groups.sort_unstable();
            expected.push((groups, overlap));
            bytes.push(current);
        }
        match CompilerResources::new(storage(source), Default::default()) {
            Ok(resources) => {
                assert!(!conflict);
                let actual = resources.list(0, ParameterDirection::Input).unwrap();
                assert_eq!(actual.group_count, next_group);
                for (actual, expected) in actual.entries.iter().zip(expected) {
                    assert_eq!(
                        actual.groups.iter().map(|g| g.0).collect::<Vec<_>>(),
                        expected.0
                    );
                    assert_eq!(actual.overlapping, expected.1);
                }
                valid += 1;
            }
            Err(ResourceError::IllegalOverlap { .. }) => {
                assert!(conflict);
                rejected += 1;
            }
            Err(error) => panic!("unexpected: {error}"),
        }
    }
    assert!(valid >= 500 && rejected > 0);
}

#[test]
fn large_disjoint_lists_fail_at_a_work_budget_instead_of_running_unbounded() {
    let mut source = spec("", "");
    source.prototypes[0].input.entries = (0..2000).map(|i| raw_entry(i * 8, 4)).collect();
    let storage = storage(source);
    assert!(matches!(
        CompilerResources::new(
            storage.clone(),
            ResourceLimits {
                max_work: 25_000,
                ..Default::default()
            }
        ),
        Err(ResourceError::Limit("work"))
    ));
    let result = CompilerResources::new(storage, Default::default()).unwrap();
    assert_eq!(
        result
            .list(0, ParameterDirection::Input)
            .unwrap()
            .group_count,
        2000
    );
}

#[test]
fn upward_growth_rechecks_alignment_even_if_a_caller_forces_complete_status() {
    let mut source = spec("", "");
    source.stack_pointer.as_mut().unwrap().growth = ghidra_languages::StackGrowth::Positive;
    let mut entry = raw_entry(0, 10);
    entry.align = Some(4);
    source.prototypes[0].input.entries.push(entry);
    source.prototypes[0].status = ModelStatus::Complete;
    assert!(matches!(
        CompilerResources::new(storage(source), Default::default()),
        Err(ResourceError::Invalid {
            site: BindingSite::Input { model: 0, entry: 0 },
            reason: "positive growth requires a whole number of pool slots",
        })
    ));
}

#[test]
fn signed_stack_containment_across_zero_uses_mathematical_coordinates() {
    let resources = plan(
        r#"<pentry minsize="1" maxsize="4"><addr space="stack" offset="0"/></pentry>
<pentry minsize="1" maxsize="8"><addr space="stack" offset="-4"/></pentry>"#,
    );
    assert_eq!(
        groups(&resources, ParameterDirection::Input),
        [vec![0], vec![0]]
    );
}

#[test]
#[ignore = "compiles four full processor sources; run explicitly for real ABI resource probes"]
fn real_compiler_resource_profiles_keep_expected_sharing() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../Ghidra/Processors");
    let catalog = ghidra_languages::Catalog::discover(&root).unwrap();
    for (language_id, compilers) in [
        ("x86:LE:64:default", &["windows", "gcc", "golang"][..]),
        ("ARM:LE:32:v7", &["default"][..]),
        ("MIPS:BE:32:default", &["default"][..]),
        ("AARCH64:LE:64:v8A", &["golang"][..]),
    ] {
        let definition = catalog.by_id(language_id).unwrap();
        let language =
            ghidra_sleigh::SleighLanguage::from_language(definition, &Default::default()).unwrap();
        let registers = language
            .registers()
            .unwrap()
            .into_iter()
            .map(|r| RegisterDefinition {
                name: r.name,
                space: r.space,
                offset: r.offset,
                size: r.size,
            })
            .collect();
        let file = Arc::new(
            RegisterFile::new(
                language.spaces().to_vec(),
                language.code_space(),
                registers,
                Default::default(),
            )
            .unwrap(),
        );
        drop(language);
        for compiler in compilers {
            let spec = Arc::new(definition.load_compiler_spec(compiler).unwrap());
            assert!(spec.is_fully_modeled());
            let source_entries: usize = spec
                .prototypes
                .iter()
                .map(|p| p.input.entries.len() + p.output.entries.len())
                .sum();
            let storage =
                Arc::new(CompilerStorage::new(spec, file.clone(), Default::default()).unwrap());
            let result = CompilerResources::new(storage, Default::default()).unwrap();
            assert_eq!(result.entry_count(), source_entries);
            for model in result.models() {
                for list in [&model.input, &model.output] {
                    for entry in &list.entries {
                        assert!(!entry.groups.is_empty());
                        assert!(entry.groups.windows(2).all(|p| p[0] <= p[1]));
                        assert!(entry.groups.iter().all(|g| g.0 < list.group_count));
                    }
                }
            }
            if *compiler == "windows" {
                assert_eq!(
                    &groups(&result, ParameterDirection::Input)[..4],
                    &[vec![0], vec![0], vec![1], vec![1]]
                );
                assert_eq!(
                    result
                        .list(0, ParameterDirection::Input)
                        .unwrap()
                        .group_count,
                    5
                );
            }
        }
    }
}
