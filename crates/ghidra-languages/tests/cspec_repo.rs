//! Compiler specs from this checkout's real `.cspec` files. Upstream specs are the
//! authority; these tests only read them.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use ghidra_languages::{
    AssignStrategy, Catalog, CompilerSpec, DatatypeClass, Error, Extension, Extrapop,
    HiddenReturnStrategy, JoinPiece, LanguageDefinition, MemoryTag, MetaType, ModelRef,
    ModelStatus, ParamList, RuleAction, RuleQualifier, RuleSideEffect, StackGrowth, Storage,
    StorageClass,
};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn catalog() -> &'static Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG.get_or_init(|| Catalog::discover(&repo_root()).expect("discover repo catalog"))
}

fn lang(id: &str) -> &'static LanguageDefinition {
    catalog()
        .by_id(id)
        .unwrap_or_else(|| panic!("language {id} not in catalog"))
}

fn cspec(language: &str, compiler: &str) -> CompilerSpec {
    lang(language)
        .load_compiler_spec(compiler)
        .unwrap_or_else(|e| panic!("{language}/{compiler}: {e}"))
}

fn reg(name: &str) -> Storage {
    Storage::Register { name: name.into() }
}

fn regs(list: &ParamList) -> Vec<&str> {
    list.register_names()
}

fn names(storage: &[Storage]) -> Vec<String> {
    storage
        .iter()
        .map(|s| match s {
            Storage::Register { name } => name.clone(),
            other => format!("{other:?}"),
        })
        .collect()
}

/// Every `.cspec` below `dir`, skipping build output.
fn walk_cspecs(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let path = entry.path();
        let ty = entry.file_type().unwrap();
        if ty.is_dir() {
            let name = entry.file_name();
            if !matches!(name.to_str(), Some("build" | "bin" | "target" | ".git")) {
                walk_cspecs(&path, out);
            }
        } else if path.extension().is_some_and(|e| e == "cspec") {
            out.push(std::path::absolute(&path).unwrap());
        }
    }
}

fn normal(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in path.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

#[test]
fn every_referenced_compiler_spec_is_fully_modeled() {
    let referenced: BTreeSet<PathBuf> = catalog()
        .languages
        .iter()
        .flat_map(|l| &l.compilers)
        .filter_map(|c| c.spec.available_path().map(normal))
        .collect();
    assert_eq!(referenced.len(), 107, "distinct referenced .cspec files");

    let mut prototypes = 0;
    let mut entries = 0;
    let mut rules = 0;
    let mut groups = 0;
    let mut joins = 0;
    let mut aliases = 0;
    let mut implicit_thiscall = 0;
    let mut merged = 0;
    for path in &referenced {
        let spec = CompilerSpec::from_path(path).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            spec.diagnostics.is_empty(),
            "{}: {:#?}",
            path.display(),
            spec.diagnostics
        );
        assert!(spec.unmodeled.is_empty(), "{}", path.display());
        assert!(spec.is_fully_modeled(), "{}", path.display());
        assert!(spec.default_model().is_some(), "{}", path.display());
        let coverage = spec.coverage();
        assert_eq!(coverage.complete_prototypes, coverage.prototypes);
        prototypes += spec.prototypes.len();
        for p in &spec.prototypes {
            for list in [&p.input, &p.output] {
                entries += list.entries.len();
                rules += list.rules.len();
                groups += list.group_count;
                joins += list
                    .entries
                    .iter()
                    .filter(|e| matches!(e.storage, Storage::Join { .. }))
                    .count();
            }
        }
        aliases += spec.aliases.iter().filter(|a| !a.implicit).count();
        implicit_thiscall += spec.aliases.iter().filter(|a| a.implicit).count();
        merged += spec.merged_models.len();
    }
    // Cross-checked against an independent count of the XML (comments/CDATA removed).
    assert_eq!(prototypes, 178);
    assert_eq!(entries, 1551);
    assert_eq!(rules, 230);
    assert_eq!(groups, 28);
    assert_eq!(joins, 92);
    assert_eq!(aliases, 3);
    assert_eq!(implicit_thiscall, 102);
    assert_eq!(merged, 6);
}

#[test]
fn unreferenced_compiler_specs_also_parse() {
    let mut all = Vec::new();
    walk_cspecs(&repo_root().join("Ghidra"), &mut all);
    walk_cspecs(&repo_root().join("GhidraBuild"), &mut all);
    let all: BTreeSet<PathBuf> = all.iter().map(|p| normal(p)).collect();
    let referenced: BTreeSet<PathBuf> = catalog()
        .languages
        .iter()
        .flat_map(|l| &l.compilers)
        .filter_map(|c| c.spec.available_path().map(normal))
        .collect();
    let others: Vec<&PathBuf> = all.difference(&referenced).collect();
    // Emulator test mock, Skeleton template and three old Toy specs.
    assert_eq!(others.len(), 5, "{others:#?}");
    let mut parsed = 0;
    for path in others {
        if path.ends_with("Emulation/src/test/resources/mock.cspec") {
            // An empty file upstream: a parse error, not a spec.
            assert!(matches!(
                CompilerSpec::from_path(path),
                Err(Error::Xml { .. })
            ));
            continue;
        }
        let spec = CompilerSpec::from_path(path).unwrap_or_else(|e| panic!("{e}"));
        assert!(
            spec.is_fully_modeled(),
            "{}: {:#?}",
            path.display(),
            spec.diagnostics
        );
        parsed += 1;
    }
    assert_eq!(parsed, 4);
}

#[test]
fn x86_64_windows_fastcall() {
    let spec = cspec("x86:LE:64:default", "windows");
    let org = spec.data_organization.as_ref().unwrap();
    assert_eq!(org.absolute_max_alignment, Some(0));
    assert_eq!(org.pointer_size, Some(8));
    assert_eq!(org.long_size, Some(4));
    assert_eq!(org.wchar_size, Some(2));
    assert_eq!(org.long_double_size, Some(8));
    assert_eq!(org.size_alignment_map.len(), 4);
    assert_eq!(
        org.bitfield_packing.as_ref().unwrap().use_ms_convention,
        Some(true)
    );
    let resolved = spec.resolved_data_organization(8);
    assert!(resolved.use_ms_bitfield_convention);
    assert_eq!(resolved.machine_alignment, 2);
    assert_eq!(resolved.alignment_for_size(8), Some(8));
    assert_eq!(resolved.alignment_for_size(16), None);
    assert!(resolved.char_signed, "Ghidra default");

    let sp = spec.stack_pointer.as_ref().unwrap();
    assert_eq!((sp.register.as_str(), sp.space.as_str()), ("RSP", "ram"));
    assert_eq!(sp.growth, StackGrowth::Negative);
    assert_eq!(
        spec.return_address,
        Some(Storage::Varnode {
            space: "stack".into(),
            offset: 0,
            size: 8
        })
    );
    assert_eq!(
        spec.global,
        [
            MemoryTag::Range(ghidra_languages::AddressRange {
                space: "ram".into(),
                first: None,
                last: None
            }),
            MemoryTag::Register {
                name: "MXCSR".into()
            }
        ]
    );

    assert_eq!(spec.default_model.as_deref(), Some("__fastcall"));
    let fastcall = spec.prototype("__fastcall").unwrap();
    assert_eq!(fastcall.status, ModelStatus::Complete);
    assert_eq!(fastcall.extrapop, Extrapop::Known(8));
    assert_eq!(fastcall.stackshift, 8);
    assert_eq!(fastcall.strategy, AssignStrategy::Standard);
    assert!(!fastcall.has_this);
    let input = &fastcall.input;
    assert_eq!(input.pointer_max, Some(8));
    assert_eq!(input.group_count, 4);
    // Group order pairs the nth float and nth integer register.
    assert_eq!(
        regs(input),
        [
            "XMM0_Qa", "RCX", "XMM1_Qa", "RDX", "XMM2_Qa", "R8", "XMM3_Qa", "R9"
        ]
    );
    for g in 0..4 {
        let members: Vec<_> = input.group(g).collect();
        assert_eq!(members.len(), 2);
        assert_eq!(members[0].storage_class, StorageClass::Float);
        assert_eq!((members[0].min_size, members[0].max_size), (4, 8));
        assert_eq!(members[1].storage_class, StorageClass::General);
        assert_eq!((members[1].min_size, members[1].max_size), (1, 8));
    }
    let stack = input.stack_entry().unwrap();
    assert_eq!(stack.group, None);
    assert_eq!(
        stack.storage.signed_offset(),
        Some(40),
        "32-byte shadow space + ret"
    );
    assert_eq!(
        (stack.max_size, stack.align, stack.alignment()),
        (500, Some(8), 8)
    );
    assert_eq!(stack.slots(), 62);
    assert_eq!(input.rules.len(), 1);
    let rule = &input.rules[0];
    assert_eq!(rule.datatype.class, DatatypeClass::Meta(MetaType::Struct));
    assert_eq!(rule.datatype.sizes, [3, 5, 6, 7]);
    assert_eq!(rule.action, RuleAction::ConvertToPointer);
    assert_eq!(regs(&fastcall.output), ["XMM0_Qa", "RAX"]);
    assert_eq!(
        fastcall.output.rules[0].action,
        RuleAction::HiddenReturn {
            strategy: None,
            void_lock: None
        }
    );
    assert_eq!(names(&fastcall.killed_by_call), ["RAX", "XMM0"]);
    assert_eq!(
        fastcall.unaffected.len(),
        22,
        "one ram varnode + 21 registers"
    );
    assert_eq!(
        fastcall.unaffected[0],
        Storage::Varnode {
            space: "ram".into(),
            offset: 0,
            size: 8
        }
    );
    assert_eq!(fastcall.unaffected[1], reg("RBX"));
    let local = fastcall.local_range.as_ref().unwrap();
    assert_eq!(
        local[0],
        MemoryTag::Range(ghidra_languages::AddressRange {
            space: "stack".into(),
            first: Some(0xffff_ffff_fff0_bdc1),
            last: Some(u64::MAX)
        })
    );
    // No model-level return address: the spec-level one applies.
    assert!(fastcall.return_address.is_none());
    assert_eq!(spec.return_address_for(fastcall).len(), 1);

    let thiscall = spec.prototype("__thiscall").unwrap();
    assert!(thiscall.has_this, "hasthis defaults from the name");
    assert!(thiscall.input.this_before_return_pointer);
    // Explicit aliases resolve to their parent; no implicit __thiscall is needed.
    let cdecl = spec.model("__cdecl").unwrap();
    assert!(matches!(cdecl, ModelRef::Alias { .. }));
    assert_eq!(cdecl.prototype().unwrap().name, "__fastcall");
    assert!(spec.aliases.iter().all(|a| !a.implicit));
    assert_eq!(
        spec.model_names(),
        ["__fastcall", "__thiscall", "__cdecl", "__stdcall"]
    );
    let fixups: Vec<_> = spec.call_fixups.iter().map(|f| f.name.as_str()).collect();
    assert_eq!(
        fixups,
        [
            "alloca_probe",
            "guard_dispatch_icall",
            "security_check_cookie"
        ]
    );
    assert_eq!(spec.call_fixups[0].targets.len(), 5);
    assert_eq!(
        spec.call_fixups[0].pcode.body.as_deref().map(str::trim),
        Some("RSP = RSP + 8;")
    );
}

#[test]
fn x86_64_gcc_sysv() {
    let spec = cspec("x86:LE:64:default", "gcc");
    let org = spec.data_organization.as_ref().unwrap();
    assert_eq!(org.long_size, Some(8));
    assert_eq!(org.long_double_size, Some(10));
    assert_eq!(org.absolute_max_alignment, None);
    let resolved = spec.resolved_data_organization(8);
    assert_eq!(resolved.absolute_max_alignment, 0);
    assert_eq!(resolved.alignment_for_size(16), Some(16));
    assert_eq!(resolved.size_alignment_map.len(), 5);

    assert_eq!(spec.default_model.as_deref(), Some("__stdcall"));
    let sysv = spec.prototype("__stdcall").unwrap();
    assert_eq!(sysv.input.group_count, 0);
    assert_eq!(
        regs(&sysv.input),
        [
            "XMM0_Qa", "XMM1_Qa", "XMM2_Qa", "XMM3_Qa", "XMM4_Qa", "XMM5_Qa", "XMM6_Qa", "XMM7_Qa",
            "RDI", "RSI", "RDX", "RCX", "R8", "R9"
        ]
    );
    let classes: Vec<_> = sysv.input.entries.iter().map(|e| e.storage_class).collect();
    assert!(classes[..8].iter().all(|c| *c == StorageClass::Float));
    assert!(classes[8..].iter().all(|c| *c == StorageClass::General));
    let stack = sysv.input.stack_entry().unwrap();
    assert_eq!(stack.storage.signed_offset(), Some(8));
    assert_eq!(sysv.input.rules.len(), 2);
    assert_eq!(sysv.input.rules[0].datatype.class, DatatypeClass::Any);
    assert_eq!(sysv.input.rules[0].datatype.max_size, Some(16));
    assert!(matches!(
        sysv.input.rules[0].action,
        RuleAction::JoinDualClass {
            storage_a: None,
            storage_b: None,
            ..
        }
    ));
    assert_eq!(sysv.input.rules[1].action, RuleAction::GotoStack);
    assert_eq!(regs(&sysv.output), ["XMM0_Qa", "XMM1_Qa", "RAX", "RDX"]);
    assert_eq!(names(&sysv.killed_by_call), ["RAX", "RDX", "XMM0"]);

    let ms = spec.prototype("MSABI").unwrap();
    assert_eq!(ms.input.group_count, 4);
    let syscall = spec.prototype("syscall").unwrap();
    assert_eq!(
        regs(&syscall.input),
        ["RDI", "RSI", "RDX", "R10", "R8", "R9"]
    );
    assert!(syscall.output.killed_by_call);

    // No __thiscall in the file: Ghidra aliases it to the default model.
    let this = spec.model("__thiscall").unwrap();
    let ModelRef::Alias { alias, target } = this else {
        panic!("expected implicit alias, got {this:?}");
    };
    assert!(alias.implicit);
    assert_eq!(target.name, "__stdcall");
    assert_eq!(this.has_this(), Some(true));
}

#[test]
fn x86_32_windows_merged_model_and_unknown_extrapop() {
    let spec = cspec("x86:LE:32:default", "windows");
    let stdcall = spec.prototype("__stdcall").unwrap();
    assert_eq!(stdcall.extrapop, Extrapop::Unknown);
    assert_eq!(stdcall.stackshift, 4);
    assert_eq!(spec.merged_models.len(), 1);
    let merged = &spec.merged_models[0];
    assert_eq!(merged.name, "__fastcall/__thiscall/__stdcall");
    assert_eq!(merged.models, ["__stdcall", "__fastcall", "__thiscall"]);
    assert_eq!(
        spec.eval_current_prototype.as_deref(),
        Some("__fastcall/__thiscall/__stdcall")
    );
    let eval = spec
        .model(spec.eval_current_prototype.as_deref().unwrap())
        .unwrap();
    assert!(matches!(eval, ModelRef::Merged(_)));
    assert_eq!(
        eval.prototype(),
        None,
        "selection by scoring is not implemented"
    );
}

#[test]
fn arm_aapcs() {
    let spec = cspec("ARM:LE:32:v7", "default");
    assert_eq!(spec.function_pointer_align, Some(2));
    assert_eq!(spec.stack_pointer.as_ref().unwrap().register, "sp");
    assert!(spec.return_address.is_none());
    let proto = spec.default_model().unwrap().prototype().unwrap();
    assert_eq!(proto.name, "__stdcall");
    assert_eq!(proto.extrapop, Extrapop::Known(0));
    assert!(spec.return_address_for(proto).is_empty());
    let floats: Vec<String> = (0..16).map(|i| format!("s{i}")).collect();
    let mut expected: Vec<&str> = floats.iter().map(String::as_str).collect();
    expected.extend(["r0", "r1", "r2", "r3"]);
    assert_eq!(regs(&proto.input), expected);
    let r0 = &proto.input.entries[16];
    assert_eq!(r0.extension, Extension::IntType);
    assert_eq!(proto.input.entries[0].extension, Extension::None);
    let stack = proto.input.stack_entry().unwrap();
    assert_eq!(stack.storage.signed_offset(), Some(0));
    assert_eq!(stack.alignment(), 4);

    let rules = &proto.input.rules;
    assert_eq!(rules.len(), 7);
    assert_eq!(
        rules[0].qualifiers,
        [RuleQualifier::Varargs {
            first: None,
            last: None
        }]
    );
    assert_eq!(
        rules[2].datatype.class,
        DatatypeClass::HomogeneousFloatAggregate
    );
    assert_eq!(
        rules[2].action,
        RuleAction::Join {
            storage: Some(StorageClass::Float),
            reverse_justify: None,
            reverse_significance: None,
            align: Some(true),
            stack_spill: Some(false),
            backfill: None
        }
    );
    assert_eq!(rules[3].action, RuleAction::GotoStack);
    assert_eq!(
        rules[3].side_effects,
        [RuleSideEffect::ConsumeExtra {
            storage: StorageClass::Float,
            match_size: None
        }]
    );
    assert!(matches!(
        rules[4].action,
        RuleAction::Join {
            backfill: Some(true),
            ..
        }
    ));
    assert_eq!(names(&proto.killed_by_call).len(), 13);
    assert!(proto.unaffected.contains(&reg("lr")));

    let soft = spec.prototype("__stdcall_softfp").unwrap();
    assert_eq!(regs(&soft.input), ["r0", "r1", "r2", "r3"]);
    let fixup = &spec.callother_fixups[0];
    assert_eq!(fixup.target_op, "setISAMode");
    assert_eq!(fixup.pcode.incidental_copy, Some(true));
    assert_eq!(fixup.pcode.inputs[0].name, "newTB");
    assert_eq!(spec.call_fixups.len(), 6);
}

#[test]
fn mips32_o32() {
    let spec = cspec("MIPS:BE:32:default", "default");
    let org = spec.data_organization.as_ref().unwrap();
    assert_eq!(org.pointer_size, Some(4));
    assert_eq!(org.integer_size, None, "not declared in mips32be.cspec");
    assert_eq!(spec.resolved_data_organization(4).integer_size, 4);
    assert_eq!(spec.return_address, Some(reg("ra")));
    assert_eq!(
        spec.global[1],
        MemoryTag::Range(ghidra_languages::AddressRange {
            space: "register".into(),
            first: Some(0x2000),
            last: Some(0x2fff)
        })
    );
    let proto = spec.prototype("__stdcall").unwrap();
    assert_eq!(spec.return_address_for(proto), [reg("ra")]);
    assert_eq!(
        regs(&proto.input),
        ["f12_13", "f14_15", "a0", "a1", "a2", "a3"]
    );
    let stack = proto.input.stack_entry().unwrap();
    assert_eq!(stack.storage.signed_offset(), Some(16), "o32 home area");
    let rules = &proto.input.rules;
    assert_eq!(rules.len(), 7);
    assert_eq!(
        rules[0].qualifiers,
        [RuleQualifier::Varargs {
            first: Some(0),
            last: None
        }]
    );
    assert_eq!(
        rules[0].action,
        RuleAction::Consume {
            storage: StorageClass::General
        }
    );
    // float, double: position 0 plus a datatype_at(1) qualifier, two extra GPRs consumed.
    let r1 = &rules[1];
    assert_eq!(r1.qualifiers.len(), 2);
    assert_eq!(r1.qualifiers[0], RuleQualifier::Position { index: 0 });
    let RuleQualifier::DatatypeAt { index, datatype } = &r1.qualifiers[1] else {
        panic!("{:?}", r1.qualifiers[1]);
    };
    assert_eq!(*index, 1);
    assert_eq!((datatype.min_size, datatype.max_size), (Some(5), Some(8)));
    assert_eq!(r1.side_effects.len(), 2);
    assert!(matches!(
        rules[4].action,
        RuleAction::Join {
            reverse_justify: Some(true),
            ..
        }
    ));
    assert_eq!(names(&proto.internal_storage), ["gp"]);
    assert_eq!(proto.local_range.as_ref().unwrap().len(), 2);
    assert!(rules.iter().all(|r| r.preconditions.is_empty()));
    let entry = spec.prototype("processEntry").unwrap();
    assert_eq!(entry.input.pointer_max, Some(4));
}

#[test]
fn join_pieces_follow_piece_numbers_not_attribute_order() {
    let spec = cspec("AARCH64:LE:64:v8A", "golang");
    let proto = spec.default_model().unwrap().prototype().unwrap();
    let joins: Vec<_> = proto
        .output
        .entries
        .iter()
        .filter_map(|e| match &e.storage {
            Storage::Join { pieces, .. } => Some((e.min_size, e.max_size, pieces)),
            _ => None,
        })
        .collect();
    // Written as piece2="x0" piece1="x1".
    let (min, max, pieces) = joins[0];
    assert_eq!((min, max), (9, 16));
    assert_eq!(
        pieces,
        &vec![
            JoinPiece::Register { name: "x1".into() },
            JoinPiece::Register { name: "x0".into() }
        ]
    );
    let (_, _, three) = joins[1];
    let order: Vec<_> = three
        .iter()
        .map(|p| match p {
            JoinPiece::Register { name } => name.as_str(),
            JoinPiece::Varnode { .. } => "?",
        })
        .collect();
    assert_eq!(order, ["x2", "x1", "x0"]);

    let m68k = cspec("68000:BE:32:default", "default");
    let proto = m68k.default_model().unwrap().prototype().unwrap();
    let join = proto
        .output
        .entries
        .iter()
        .find(|e| matches!(e.storage, Storage::Join { .. }))
        .unwrap();
    assert_eq!(
        join.storage,
        Storage::Join {
            pieces: vec![
                JoinPiece::Register { name: "D0".into() },
                JoinPiece::Register { name: "D1".into() }
            ],
            logical_size: None
        }
    );
    assert_eq!(
        join.storage.known_size(),
        None,
        "register sizes need the language"
    );
}

#[test]
fn positive_stack_growth_and_register_strategy() {
    let spec = cspec("8051:BE:16:default", "default");
    let sp = spec.stack_pointer.as_ref().unwrap();
    assert_eq!(sp.growth, StackGrowth::Positive);
    assert_eq!(sp.space, "INTMEM");
    let proto = spec.default_model().unwrap().prototype().unwrap();
    assert_eq!(proto.strategy, AssignStrategy::Register);
    assert_eq!(proto.extrapop, Extrapop::Known(-2));
    assert_eq!(proto.stackshift, -2);
    assert_eq!(&regs(&proto.input)[..3], ["ACC", "DPTR", "B"]);
}

#[test]
fn no_shipped_spec_sets_a_hidden_return_strategy() {
    let mut seen = 0;
    for language in &catalog().languages {
        for compiler in &language.compilers {
            let spec = compiler.load_spec().unwrap();
            for p in &spec.prototypes {
                for rule in p.input.rules.iter().chain(&p.output.rules) {
                    if let RuleAction::HiddenReturn {
                        strategy: Some(s), ..
                    } = rule.action
                    {
                        assert!(matches!(
                            s,
                            HiddenReturnStrategy::Special | HiddenReturnStrategy::NormalParam
                        ));
                        seen += 1;
                    }
                }
            }
        }
    }
    // No shipped spec sets an explicit strategy; the default is left to the resolver.
    assert_eq!(seen, 0);
}

#[test]
fn compiler_lookup_errors() {
    let x64 = lang("x86:LE:64:default");
    match x64.load_compiler_spec("nope") {
        Err(Error::UnknownCompiler {
            language_id,
            compiler_id,
        }) => {
            assert_eq!(language_id, "x86:LE:64:default");
            assert_eq!(compiler_id, "nope");
        }
        other => panic!("{other:?}"),
    }
    let via_def = x64.compiler("windows").unwrap().load_spec().unwrap();
    assert_eq!(via_def, x64.load_compiler_spec("windows").unwrap());
}
