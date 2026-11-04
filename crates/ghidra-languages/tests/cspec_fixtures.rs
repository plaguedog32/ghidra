//! Synthetic compiler specs: valid forms, malformed input and adversarial files.

use std::fs;
use std::path::Path;

use ghidra_languages::{
    AssetKind, AssetStatus, Catalog, CompilerSpec, DiagnosticKind, Error, Extrapop, JoinPiece,
    Limits, ModelRef, ModelStatus, RuleAction, Severity, StackGrowth, Storage, StorageClass,
    UnmodeledReason,
};

fn parse(text: &str) -> CompilerSpec {
    CompilerSpec::parse_str(text, Some(Path::new("test.cspec")), &Limits::default())
        .unwrap_or_else(|e| panic!("{e}"))
}

/// A `<compiler_spec>` with `body` inside and a valid default prototype appended.
fn with_default(body: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<compiler_spec>
{body}
  <default_proto>
    <prototype name="__stdcall" extrapop="4" stackshift="4">
      <input>
        <pentry minsize="1" maxsize="4"><register name="r0"/></pentry>
        <pentry minsize="1" maxsize="500" align="4"><addr offset="4" space="stack"/></pentry>
      </input>
      <output><pentry minsize="1" maxsize="4"><register name="r0"/></pentry></output>
    </prototype>
  </default_proto>
</compiler_spec>"#
    )
}

/// One prototype `name` with `input` and `output` bodies.
fn proto(name: &str, input: &str, output: &str) -> String {
    format!(
        r#"<?xml version="1.0"?>
<compiler_spec>
  <default_proto>
    <prototype name="{name}" extrapop="0" stackshift="0">
      <input>{input}</input>
      <output>{output}</output>
    </prototype>
  </default_proto>
</compiler_spec>"#
    )
}

fn kinds(spec: &CompilerSpec, severity: Severity) -> Vec<DiagnosticKind> {
    spec.diagnostics
        .iter()
        .filter(|d| d.severity == severity)
        .map(|d| d.kind.clone())
        .collect()
}

fn errors(spec: &CompilerSpec) -> Vec<DiagnosticKind> {
    kinds(spec, Severity::Error)
}

fn write(root: &Path, rel: &str, content: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

#[test]
fn minimal_spec_is_fully_modeled() {
    let spec = parse(&with_default(""));
    assert!(spec.diagnostics.is_empty(), "{:#?}", spec.diagnostics);
    assert!(spec.is_fully_modeled());
    let p = spec.default_model().unwrap().prototype().unwrap();
    assert_eq!(p.status, ModelStatus::Complete);
    assert_eq!(p.input.entries.len(), 2);
    assert_eq!(
        p.input.stack_entry().unwrap().storage.signed_offset(),
        Some(4)
    );
    // Absent <data_organization>: Ghidra defaults plus the language pointer size.
    assert!(spec.data_organization.is_none());
    let org = spec.resolved_data_organization(2);
    assert_eq!(org.pointer_size, 2);
    assert_eq!(org.long_size, 4);
    assert_eq!(org.size_alignment_map.len(), 4);
    // Implicit __thiscall alias.
    assert_eq!(spec.model_names(), ["__stdcall", "__thiscall"]);
    let coverage = spec.coverage();
    assert_eq!((coverage.prototypes, coverage.complete_prototypes), (1, 1));
}

#[test]
fn xml_level_attacks_are_hard_errors() {
    let limits = Limits::default();
    let dtd = r#"<?xml version="1.0"?>
<!DOCTYPE x [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]>
<compiler_spec>&b;</compiler_spec>"#;
    assert!(matches!(
        CompilerSpec::parse_str(dtd, None, &limits),
        Err(Error::Xml { line: 2, .. })
    ));
    let entity = "<compiler_spec>&ext;</compiler_spec>";
    assert!(matches!(
        CompilerSpec::parse_str(entity, None, &limits),
        Err(Error::Xml { .. })
    ));
    assert!(matches!(
        CompilerSpec::parse_str("<processor_spec/>", None, &limits),
        Err(Error::Schema { .. })
    ));
    assert!(matches!(
        CompilerSpec::parse_str("", None, &limits),
        Err(Error::Xml { .. })
    ));
    assert!(matches!(
        CompilerSpec::parse_str("<compiler_spec><a></compiler_spec>", None, &limits),
        Err(Error::Xml { .. })
    ));

    let small = Limits {
        max_file_bytes: 64,
        ..Limits::default()
    };
    assert!(matches!(
        CompilerSpec::parse_str(&with_default(""), None, &small),
        Err(Error::Limit { .. })
    ));
    let shallow = Limits {
        max_depth: 4,
        ..Limits::default()
    };
    assert!(matches!(
        CompilerSpec::parse_str(&with_default(""), None, &shallow),
        Err(Error::Limit { .. })
    ));
    let few = Limits {
        max_elements: 5,
        ..Limits::default()
    };
    assert!(matches!(
        CompilerSpec::parse_str(&with_default(""), None, &few),
        Err(Error::Limit { .. })
    ));
    let long_attr = format!(
        "<compiler_spec><properties><property key=\"k\" value=\"{}\"/></properties></compiler_spec>",
        "x".repeat(200)
    );
    let short_text = Limits {
        max_text_bytes: 100,
        ..Limits::default()
    };
    assert!(matches!(
        CompilerSpec::parse_str(&long_attr, None, &short_text),
        Err(Error::Limit { .. })
    ));
}

#[test]
fn compiler_spec_paths_stay_inside_the_catalog() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write(root, "Proc/data/languages/toy.slaspec", "# source");
    write(root, "Proc/data/languages/toy.pspec", "<processor_spec/>");
    write(root, "Proc/data/languages/good.cspec", &with_default(""));
    write(root, "outside.cspec", &with_default(""));
    write(
        root,
        "Proc/data/languages/toy.ldefs",
        r#"<language_definitions>
  <language processor="Toy" endian="little" size="32" variant="v" version="1"
            slafile="toy.sla" processorspec="toy.pspec" id="Toy:LE:32:v">
    <description>toy</description>
    <compiler name="good" spec="good.cspec" id="good"/>
    <compiler name="escape" spec="../../../../escape.cspec" id="escape"/>
    <compiler name="absolute" spec="C:/Windows/evil.cspec" id="absolute"/>
    <compiler name="missing" spec="missing.cspec" id="missing"/>
  </language>
</language_definitions>"#,
    );
    let catalog = Catalog::discover(root).unwrap();
    let toy = catalog.by_id("Toy:LE:32:v").unwrap();
    assert!(toy.load_compiler_spec("good").unwrap().is_fully_modeled());
    for (id, status) in [
        ("escape", AssetStatus::Rejected),
        ("absolute", AssetStatus::Rejected),
        ("missing", AssetStatus::Missing),
    ] {
        match toy.load_compiler_spec(id) {
            Err(Error::AssetUnavailable {
                asset: AssetKind::CompilerSpec,
                status: s,
                ..
            }) => assert_eq!(s, status, "{id}"),
            other => panic!("{id}: {other:?}"),
        }
        match toy.compiler(id).unwrap().load_spec() {
            Err(Error::CompilerSpecUnavailable {
                compiler_id,
                status: s,
                ..
            }) => {
                assert_eq!(compiler_id, id);
                assert_eq!(s, status);
            }
            other => panic!("{id}: {other:?}"),
        }
    }
}

#[test]
fn oversized_file_on_disk_is_rejected_before_parsing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("big.cspec");
    fs::write(&path, with_default(&"<!-- pad -->\n".repeat(1000))).unwrap();
    let limits = Limits {
        max_file_bytes: 1024,
        ..Limits::default()
    };
    assert!(matches!(
        CompilerSpec::from_path_with(&path, &limits),
        Err(Error::Limit { .. })
    ));
    assert!(CompilerSpec::from_path(&path).unwrap().is_fully_modeled());
}

#[test]
fn data_organization_values_and_validation() {
    let spec = parse(&with_default(
        r#"<data_organization>
     <pointer_size value="0x8"/>
     <long_size value="8"/>
     <integer_size value="-4"/>
     <short_size/>
     <char_type signed="false"/>
     <size_alignment_map>
       <entry size="16" alignment="16"/>
       <entry size="8" alignment="4"/>
       <entry size="8" alignment="8"/>
     </size_alignment_map>
     <bitfield_packing><zero_length_boundary value="4"/><bogus value="1"/></bitfield_packing>
     <pointer_widgets value="1"/>
   </data_organization>"#,
    ));
    let org = spec.data_organization.as_ref().unwrap();
    assert_eq!(org.pointer_size, Some(8));
    assert_eq!(org.long_size, Some(8));
    assert_eq!(org.integer_size, None, "negative size rejected");
    assert_eq!(org.short_size, None, "missing value rejected");
    assert_eq!(org.char_signed, Some(false));
    assert_eq!(org.size_alignment_map.len(), 3);
    let resolved = spec.resolved_data_organization(4);
    assert_eq!(
        resolved.alignment_for_size(8),
        Some(8),
        "later mapping wins"
    );
    assert_eq!(resolved.alignment_for_size(16), Some(16));
    assert_eq!(resolved.bitfield_zero_length_boundary, 4);
    assert!(!resolved.char_signed);
    assert_eq!(
        errors(&spec),
        [
            DiagnosticKind::InvalidAttribute,
            DiagnosticKind::MissingAttribute
        ]
    );
    let warnings = kinds(&spec, Severity::Warning);
    assert!(warnings.contains(&DiagnosticKind::DuplicateEntry));
    assert_eq!(
        warnings
            .iter()
            .filter(|k| **k == DiagnosticKind::UnknownElement)
            .count(),
        2
    );
    assert!(!spec.is_fully_modeled(), "errors were reported");
    // The prototypes themselves are unaffected by data-organization errors.
    assert!(spec.prototypes.iter().all(|p| p.is_complete()));
}

#[test]
fn parameter_order_groups_and_stack_offsets() {
    let spec = parse(&proto(
        "__fastcall",
        r#"<group>
             <pentry minsize="4" maxsize="8" storage="float"><register name="f0"/></pentry>
             <pentry minsize="1" maxsize="8"><register name="a0"/></pentry>
           </group>
           <group>
             <pentry minsize="4" maxsize="8" metatype="float"><register name="f1"/></pentry>
             <pentry minsize="1" maxsize="8" extension="sign"><register name="a1"/></pentry>
           </group>
           <pentry minsize="1" maxsize="8"><register name="a2"/></pentry>
           <pentry minsize="1" maxsize="500" align="8"><addr offset="-16" space="stack"/></pentry>
           <pentry minsize="1" maxsize="8" size="8"><addr offset="0x100" space="ram" size="8"/></pentry>"#,
        r#"<pentry minsize="1" maxsize="16"><addr space="join" piece1="a1" piece2="ram:0x20:8" size="16"/></pentry>"#,
    ));
    assert!(spec.is_fully_modeled(), "{:#?}", spec.diagnostics);
    let p = spec.prototype("__fastcall").unwrap();
    assert_eq!(p.input.group_count, 2);
    assert_eq!(p.input.register_names(), ["f0", "a0", "f1", "a1", "a2"]);
    let groups: Vec<_> = p.input.entries.iter().map(|e| e.group).collect();
    assert_eq!(
        groups,
        [Some(0), Some(0), Some(1), Some(1), None, None, None]
    );
    assert_eq!(p.input.entries[2].storage_class, StorageClass::Float);
    assert_eq!(
        p.input.entries[3].extension,
        ghidra_languages::Extension::Sign
    );
    let stack = p.input.stack_entry().unwrap();
    assert_eq!(stack.storage.signed_offset(), Some(-16));
    assert_eq!(stack.slots(), 62);
    // Legacy `size` is Ghidra's align; equal to maxsize means a single slot.
    let ram = &p.input.entries[6];
    assert_eq!((ram.align, ram.alignment(), ram.slots()), (Some(8), 0, 1));
    assert_eq!(
        p.output.entries[0].storage,
        Storage::Join {
            pieces: vec![
                JoinPiece::Register { name: "a1".into() },
                JoinPiece::Varnode {
                    space: "ram".into(),
                    offset: 0x20,
                    size: 8
                }
            ],
            logical_size: Some(16)
        }
    );
    assert_eq!(p.output.entries[0].storage.known_size(), Some(16));
}

#[test]
fn malformed_entries_mark_the_prototype_incomplete() {
    let spec = parse(&proto(
        "p",
        r#"<pentry minsize="0" maxsize="4"><register name="r0"/></pentry>
           <pentry minsize="4" maxsize="2"><register name="r1"/></pentry>
           <pentry minsize="1" maxsize="99999999999"><register name="r2"/></pentry>
           <pentry minsize="1" maxsize="4" storage="weird"><register name="r3"/></pentry>
           <pentry minsize="1" maxsize="4" extension="maybe"><register name="r4"/></pentry>
           <pentry minsize="1" maxsize="4" colour="red"><register name="r5"/></pentry>
           <pentry minsize="1" maxsize="4"/>
           <pentry minsize="1" maxsize="4"><register name="r6"/><register name="r7"/></pentry>
           <pentry minsize="1" maxsize="8"><varnode space="ram" offset="0" size="4"/></pentry>
           <pentry maxsize="4"><register name="r8"/></pentry>
           <bogus/>"#,
        "",
    ));
    let p = spec.prototype("p").unwrap();
    // r5 (unknown attribute) and the oversized varnode entry are kept but flagged.
    let kept: Vec<_> = p.input.entries.iter().map(|e| e.line).collect();
    assert_eq!(kept.len(), 2, "{:#?}", p.input.entries);
    assert_eq!(p.input.register_names(), ["r5"]);
    let ModelStatus::Incomplete { errors: n } = p.status else {
        panic!("expected incomplete");
    };
    assert_eq!(n, errors(&spec).len());
    assert_eq!(n, 11, "{:#?}", spec.diagnostics);
    assert!(spec.diagnostics.iter().all(|d| d.line.is_some()));
    assert!(errors(&spec).contains(&DiagnosticKind::InconsistentSpec));
    assert!(!spec.is_fully_modeled());
    assert_eq!(spec.coverage().complete_prototypes, 0);
}

#[test]
fn storage_class_order_and_group_rules() {
    // general before float breaks Ghidra's storage-class ordering.
    let spec = parse(&proto(
        "p",
        r#"<pentry minsize="1" maxsize="4"><register name="r0"/></pentry>
           <pentry minsize="1" maxsize="4" storage="float"><register name="f0"/></pentry>"#,
        "",
    ));
    assert_eq!(errors(&spec), [DiagnosticKind::InconsistentSpec]);
    assert_eq!(
        spec.prototypes[0].input.entries.len(),
        2,
        "kept, but flagged"
    );
    // separatefloat="false" turns the check off.
    let spec = parse(
        &proto(
            "p",
            r#"<pentry minsize="1" maxsize="4"><register name="r0"/></pentry>
           <pentry minsize="1" maxsize="4" storage="float"><register name="f0"/></pentry>"#,
            "",
        )
        .replace("<input>", "<input separatefloat=\"false\">"),
    );
    assert!(spec.is_fully_modeled(), "{:#?}", spec.diagnostics);
    // Indistinguishable group members and general-before-specific.
    let spec = parse(&proto(
        "p",
        r#"<group>
             <pentry minsize="1" maxsize="4"><register name="a"/></pentry>
             <pentry minsize="1" maxsize="4"><register name="b"/></pentry>
           </group>
           <group>
             <pentry minsize="1" maxsize="4"><register name="c"/></pentry>
             <pentry minsize="1" maxsize="4" storage="float"><register name="d"/></pentry>
           </group>
           <group>
             <pentry minsize="1" maxsize="4"><register name="e"/></pentry>
             <pentry minsize="5" maxsize="8"><register name="f"/></pentry>
           </group>
           <group/>"#,
        "",
    ));
    assert_eq!(
        errors(&spec),
        [
            DiagnosticKind::InconsistentSpec,
            DiagnosticKind::InconsistentSpec
        ]
    );
    assert_eq!(
        kinds(&spec, Severity::Warning),
        [DiagnosticKind::MissingElement]
    );
    assert_eq!(spec.prototypes[0].input.group_count, 4);
    // A join inside a group is rejected by Ghidra.
    let spec = parse(&proto(
        "p",
        r#"<group><pentry minsize="1" maxsize="8"><addr space="join" piece1="a" piece2="b"/></pentry></group>"#,
        "",
    ));
    assert_eq!(errors(&spec), [DiagnosticKind::InconsistentSpec]);
}

#[test]
fn join_piece_numbering_and_syntax() {
    let entry = |addr: &str| {
        parse(&proto(
            "p",
            &format!(r#"<pentry minsize="1" maxsize="8">{addr}</pentry>"#),
            "",
        ))
    };
    // Attribute order is irrelevant; piece numbers decide.
    let spec = entry(r#"<addr space="join" piece3="c" piece1="a" piece2="b"/>"#);
    let Storage::Join { pieces, .. } = &spec.prototypes[0].input.entries[0].storage else {
        panic!();
    };
    let names: Vec<_> = pieces
        .iter()
        .map(|p| match p {
            JoinPiece::Register { name } => name.as_str(),
            JoinPiece::Varnode { .. } => "?",
        })
        .collect();
    assert_eq!(names, ["a", "b", "c"]);
    // pieces wider than 9 are fine as long as they are contiguous
    let many: String = (1..=12).map(|i| format!(" piece{i}=\"r{i}\"")).collect();
    let spec = entry(&format!(r#"<addr space="join"{many}/>"#));
    assert!(spec.is_fully_modeled());

    for bad in [
        r#"<addr space="join" piece1="a" piece3="c"/>"#,
        r#"<addr space="join" piece2="b"/>"#,
        r#"<addr space="join"/>"#,
        r#"<addr space="join" piece1="ram:0x10"/>"#,
        r#"<addr space="join" piece1="ram:zz:4"/>"#,
        r#"<addr space="join" piece1=":0:4"/>"#,
        r#"<addr space="join" piece1=""/>"#,
        r#"<addr space="join" piece0="a"/>"#,
    ] {
        let spec = entry(bad);
        assert!(
            spec.prototypes[0].input.entries.is_empty(),
            "{bad}: {:#?}",
            spec.prototypes[0].input.entries
        );
        assert!(!errors(&spec).is_empty(), "{bad}");
        assert!(!spec.prototypes[0].is_complete(), "{bad}");
    }
    // Explicit maxsize larger than the known join size.
    let spec = entry(r#"<addr space="join" piece1="ram:0:2" piece2="ram:4:2"/>"#);
    assert_eq!(errors(&spec), [DiagnosticKind::InconsistentSpec]);
}

#[test]
fn varnode_lists_reject_joins_and_keep_order() {
    let spec = parse(&with_default("").replace(
        "</output>",
        r#"</output>
      <unaffected>
        <register name="s1"/>
        <varnode space="ram" offset="0x10" size="4"/>
        <addr space="ram" offset="0x20"/>
        <varnode space="join" piece1="a" piece2="b"/>
        <varnode space="ram" size="4"/>
        <register/>
        <register name="s0"/>
      </unaffected>
      <killedbycall><register name="r0"/></killedbycall>
      <likelytrash><register name="t0"/></likelytrash>
      <returnaddress><register name="lr"/></returnaddress>"#,
    ));
    let p = spec.prototype("__stdcall").unwrap();
    assert_eq!(p.unaffected.len(), 4);
    assert_eq!(p.unaffected[0], Storage::Register { name: "s1".into() });
    assert_eq!(
        p.unaffected[2],
        Storage::Address {
            space: "ram".into(),
            offset: 0x20,
            size: None
        }
    );
    assert_eq!(p.unaffected[3], Storage::Register { name: "s0".into() });
    assert_eq!(
        errors(&spec),
        [
            DiagnosticKind::InconsistentSpec,
            DiagnosticKind::MissingAttribute,
            DiagnosticKind::MissingAttribute
        ]
    );
    assert_eq!(
        kinds(&spec, Severity::Warning),
        [DiagnosticKind::UnsupportedForm]
    );
    assert_eq!(p.status, ModelStatus::Incomplete { errors: 3 });
    assert_eq!(
        spec.return_address_for(p),
        [Storage::Register { name: "lr".into() }]
    );
}

#[test]
fn model_rules_are_typed_and_ordered() {
    let spec = parse(&proto(
        "p",
        r#"<pentry minsize="1" maxsize="4"><register name="r0"/></pentry>
           <rule>
             <datatype name="float" minsize="1" maxsize="4"/>
             <position index="0"/>
             <datatype_at index="1"><datatype name="array" minelements="2"/></datatype_at>
             <varargs first="1" last="3"/>
             <consume_extra storage="general" matchsize="true"/>
             <join_dual_class a="float" b="general" fillalternate="1"/>
             <extra_stack afterbytes="8" afterstorage="float"/>
             <consume_remaining storage="float"/>
           </rule>
           <rule><datatype name="homogeneous-float-aggregate" maxprimitives="4"/><join_per_primitive storage="float"/></rule>
           <rule><datatype name="any"/><hidden_return strategy="normalparam" voidlock="true"/></rule>"#,
        "",
    ));
    assert!(spec.is_fully_modeled(), "{:#?}", spec.diagnostics);
    let rules = &spec.prototypes[0].input.rules;
    assert_eq!(rules.len(), 3);
    let r = &rules[0];
    assert_eq!(r.qualifiers.len(), 3);
    assert_eq!(r.preconditions.len(), 1);
    assert_eq!(r.side_effects.len(), 2);
    assert_eq!(
        r.action,
        RuleAction::JoinDualClass {
            storage_a: Some(StorageClass::Float),
            storage_b: Some(StorageClass::General),
            reverse_justify: None,
            reverse_significance: None,
            stack_spill: None,
            fill_alternate: Some(true),
        }
    );
    assert_eq!(rules[1].datatype.max_primitives, Some(4));
    assert_eq!(
        rules[2].action,
        RuleAction::HiddenReturn {
            strategy: Some(ghidra_languages::HiddenReturnStrategy::NormalParam),
            void_lock: Some(true)
        }
    );
}

#[test]
fn malformed_rules_are_dropped_with_errors() {
    let bad_rules = [
        // No datatype first.
        r#"<rule><consume storage="general"/></rule>"#,
        // Unknown meta-type.
        r#"<rule><datatype name="widget"/><goto_stack/></rule>"#,
        // sizes mixed with minsize.
        r#"<rule><datatype name="struct" sizes="1,2" minsize="1"/><goto_stack/></rule>"#,
        // Bad size list.
        r#"<rule><datatype name="struct" sizes="1,,2"/><goto_stack/></rule>"#,
        // No action.
        r#"<rule><datatype name="any"/></rule>"#,
        // Unknown action.
        r#"<rule><datatype name="any"/><teleport/></rule>"#,
        // Unknown side effect.
        r#"<rule><datatype name="any"/><goto_stack/><shrug/></rule>"#,
        // Bad storage class.
        r#"<rule><datatype name="any"/><consume storage="pink"/></rule>"#,
        // Bad hidden-return strategy.
        r#"<rule><datatype name="any"/><hidden_return strategy="later"/></rule>"#,
        // Position without index.
        r#"<rule><datatype name="any"/><position/><goto_stack/></rule>"#,
        // datatype_at without a datatype.
        r#"<rule><datatype name="any"/><datatype_at index="0"/><goto_stack/></rule>"#,
    ];
    for rule in bad_rules {
        let spec = parse(&proto(
            "p",
            &format!(r#"<pentry minsize="1" maxsize="4"><register name="r0"/></pentry>{rule}"#),
            "",
        ));
        let p = &spec.prototypes[0];
        assert!(p.input.rules.is_empty(), "{rule}");
        assert!(!errors(&spec).is_empty(), "{rule}");
        assert!(!p.is_complete(), "{rule}");
        assert!(!spec.is_fully_modeled(), "{rule}");
    }
    // Entries after a rule are rejected by Ghidra.
    let spec = parse(&proto(
        "p",
        r#"<rule><datatype name="any"/><goto_stack/></rule>
           <pentry minsize="1" maxsize="4"><register name="r0"/></pentry>"#,
        "",
    ));
    assert_eq!(errors(&spec), [DiagnosticKind::InconsistentSpec]);
    assert!(spec.prototypes[0].input.entries.is_empty());
    assert_eq!(spec.prototypes[0].input.rules.len(), 1);
}

#[test]
fn prototype_attributes() {
    let spec = parse(
        r#"<compiler_spec>
  <default_proto>
    <prototype name="__stdcall" extrapop="unknown" stackshift="0x4" strategy="register"
               constructor="true">
      <input pointermax="16" thisbeforeretpointer="yes" killedbycall="1"/>
      <output/>
      <pcode inject="uponreturn" dynamic="true"/>
      <pcode inject="uponentry"><body>x = 1;</body></pcode>
      <sharestack first="input" align="8"/>
      <paramrange><range space="stack" first="0" last="15"/></paramrange>
    </prototype>
  </default_proto>
  <prototype name="hasthis_explicit" extrapop="-2" stackshift="-2" hasthis="true">
    <input/><output/>
  </prototype>
  <prototype name="__thiscall" extrapop="0" stackshift="0" hasthis="false">
    <input/><output/>
  </prototype>
</compiler_spec>"#,
    );
    assert!(spec.is_fully_modeled(), "{:#?}", spec.diagnostics);
    let p = spec.prototype("__stdcall").unwrap();
    assert_eq!(p.extrapop, Extrapop::Unknown);
    assert_eq!(p.stackshift, 4);
    assert_eq!(p.strategy, ghidra_languages::AssignStrategy::Register);
    assert!(p.constructor);
    assert_eq!(p.input.pointer_max, Some(16));
    assert!(p.input.this_before_return_pointer);
    assert!(p.input.killed_by_call);
    // Ghidra names them `@@inject_uponreturn` then `@@inject_uponentry`; this is the only
    // order of two payloads it accepts.
    assert_eq!(p.injections.len(), 2);
    assert_eq!(
        p.injections[0].point,
        ghidra_languages::InjectionPoint::UponReturn
    );
    assert!(p.injections[0].pcode.is_dynamic());
    assert_eq!(p.injections[0].pcode.effective_body(), None);
    assert_eq!(p.injections[1].pcode.body.as_deref(), Some("x = 1;"));
    let share = p.share_stack.as_ref().unwrap();
    assert!(share.input_first);
    assert_eq!(share.align, Some(8));
    assert_eq!(p.param_range.as_ref().unwrap().len(), 1);
    let explicit = spec.prototype("hasthis_explicit").unwrap();
    assert_eq!(explicit.extrapop, Extrapop::Known(-2));
    assert!(explicit.has_this);
    // An explicit hasthis overrides the name default.
    assert!(!spec.prototype("__thiscall").unwrap().has_this);
    assert!(
        spec.aliases.is_empty(),
        "__thiscall exists, no implicit alias"
    );
}

#[test]
fn unusable_prototypes_are_dropped() {
    let spec = parse(
        r#"<compiler_spec>
  <default_proto>
    <prototype name="good" extrapop="0" stackshift="0"><input/><output/></prototype>
  </default_proto>
  <prototype name="bad name" extrapop="0" stackshift="0"><input/><output/></prototype>
  <prototype name="noextra" stackshift="0"><input/><output/></prototype>
  <prototype name="badpop" extrapop="lots" stackshift="0"><input/><output/></prototype>
  <prototype name="badshift" extrapop="0" stackshift="0x1ffffffff"><input/><output/></prototype>
  <prototype name="badstrategy" extrapop="0" stackshift="0" strategy="packreg"><input/><output/></prototype>
  <prototype name="good" extrapop="4" stackshift="4"><input/><output/></prototype>
  <prototype name="noinput" extrapop="0" stackshift="0"><output/></prototype>
  <prototype name="badpcode" extrapop="0" stackshift="0"><input/><output/><pcode inject="sometime"/></prototype>
</compiler_spec>"#,
    );
    let names: Vec<_> = spec.prototypes.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["good", "noinput", "badpcode"]);
    assert_eq!(spec.prototype("good").unwrap().extrapop, Extrapop::Known(0));
    // Missing <input> is a warning; Ghidra uses an empty list.
    assert!(spec.prototype("noinput").unwrap().is_complete());
    assert!(!spec.prototype("badpcode").unwrap().is_complete());
    assert_eq!(errors(&spec).len(), 7, "{:#?}", spec.diagnostics);
    assert!(
        errors(&spec).contains(&DiagnosticKind::DuplicateEntry),
        "duplicate model name"
    );
}

#[test]
fn aliases_merged_models_and_defaults() {
    let spec = parse(
        r#"<compiler_spec>
  <prototype name="first" extrapop="0" stackshift="0"><input/><output/></prototype>
  <prototype name="second" extrapop="0" stackshift="0"><input/><output/></prototype>
  <modelalias name="__cdecl" parent="first"/>
  <modelalias name="chain" parent="__cdecl"/>
  <modelalias name="ghost" parent="nobody"/>
  <modelalias name="first" parent="second"/>
  <resolveprototype name="either">
    <model name="first"/><model name="__cdecl"/>
  </resolveprototype>
  <modelalias name="ofmerged" parent="either"/>
  <resolveprototype name="broken"><model name="missing"/></resolveprototype>
  <eval_current_prototype name="either"/>
  <eval_called_prototype name="nowhere"/>
</compiler_spec>"#,
    );
    // No <default_proto>: Ghidra falls back to the first <prototype>.
    assert_eq!(spec.default_model.as_deref(), Some("first"));
    assert_eq!(
        spec.model_names(),
        ["first", "second", "__cdecl", "__thiscall", "either"]
    );
    let thiscall = spec.model("__thiscall").unwrap();
    assert!(matches!(thiscall, ModelRef::Alias { alias, .. } if alias.implicit));
    assert_eq!(spec.merged_models[0].models, ["first", "__cdecl"]);
    let errs = errors(&spec);
    assert_eq!(
        errs,
        [
            DiagnosticKind::UnresolvedReference, // alias of alias
            DiagnosticKind::UnresolvedReference, // missing parent
            DiagnosticKind::DuplicateEntry,      // alias named like a prototype
            DiagnosticKind::UnresolvedReference, // alias of merged model
            DiagnosticKind::UnresolvedReference, // merged names a missing model
        ]
    );
    let warnings = kinds(&spec, Severity::Warning);
    assert_eq!(
        warnings,
        [
            DiagnosticKind::MissingElement,      // no default_proto
            DiagnosticKind::UnresolvedReference  // eval_called_prototype
        ]
    );
    assert!(spec.diagnostics.iter().all(|d| d.line.is_some()));

    let empty = parse("<compiler_spec/>");
    assert!(empty.default_model.is_none());
    assert_eq!(errors(&empty), [DiagnosticKind::MissingElement]);
    assert!(!empty.is_fully_modeled());
}

#[test]
fn spec_level_declarations() {
    let spec = parse(&with_default(
        r#"<properties>
    <property key="a" value="1"/><property key="a" value="2"/>
  </properties>
  <stackpointer register="SP" space="ram" growth="positive" reversejustify="yes"/>
  <spacebase name="gp_space" register="gp" space="ram"/>
  <spacebase name="gp_space" register="gp" space="ram"/>
  <deadcodedelay space="register" delay="2"/>
  <inferptrbounds><range space="ram" first="0x1000" last="0x1fff"/></inferptrbounds>
  <aggressivetrim signext="true"/>
  <prefersplit style="inhalf"><register name="q0"/><varnode space="register" offset="0" size="16"/></prefersplit>
  <nohighptr><range space="ram" first="0" last="0xff"/></nohighptr>
  <readonly><range space="ram" first="0x8000"/></readonly>
  <global><range space="ram"/></global>
  <global><register name="gp"/></global>
  <funcptr align="4"/>
  <returnaddress><varnode space="stack" offset="-2" size="2"/></returnaddress>
  <context_data>
    <context_set space="ram"><set name="mode" val="1"/></context_set>
    <tracked_set space="ram"><set name="DF" val="0"/></tracked_set>
  </context_data>
  <callfixup name="probe"><target name="__probe"/><pcode paramshift="1"><input name="x" size="4"/><body>r0 = x;</body></pcode></callfixup>
  <callotherfixup targetop="nop"><pcode dynamic="true"><output name="y"/><body/></pcode></callotherfixup>"#,
    ));
    assert_eq!(spec.property("a"), Some("2"));
    let sp = spec.stack_pointer.as_ref().unwrap();
    assert_eq!(sp.growth, StackGrowth::Positive);
    // BasicCompilerSpec.getBooleanValue accepts only "1"/"true".
    assert!(!sp.reverse_justify);
    assert_eq!(spec.space_bases.len(), 1);
    assert_eq!(spec.dead_code_delays[0].delay, 2);
    assert_eq!(spec.infer_pointer_bounds[0].first, Some(0x1000));
    assert_eq!(spec.aggressive_trim, Some(true));
    assert_eq!(spec.prefer_split.len(), 2);
    assert_eq!(spec.no_high_ptr.as_ref().unwrap().len(), 1);
    assert_eq!(spec.read_only.as_ref().unwrap().len(), 1);
    assert_eq!(spec.global.len(), 2, "<global> accumulates");
    assert_eq!(spec.function_pointer_align, Some(4));
    assert_eq!(
        spec.return_address.as_ref().unwrap().signed_offset(),
        Some(-2)
    );
    assert_eq!(spec.context_sets.len(), 1);
    assert_eq!(spec.tracked_sets.len(), 1);
    assert_eq!(spec.context_sets[0].values[0].name, "mode");
    let fixup = &spec.call_fixups[0];
    assert_eq!(fixup.targets, ["__probe"]);
    assert_eq!(fixup.pcode.param_shift, Some(1));
    assert_eq!(fixup.pcode.inputs[0].size, Some(4));
    assert_eq!(spec.callother_fixups[0].pcode.outputs[0].size, None);
    // A dynamic payload may have an empty body; the text is kept as written.
    assert_eq!(spec.callother_fixups[0].pcode.body.as_deref(), Some(""));
    assert_eq!(spec.callother_fixups[0].pcode.effective_body(), None);
    // Positive growth: the default prototype's stack entry (maxsize 500, align 4) has
    // 500 % 4 == 0, so no error. Duplicate spacebase is the only error.
    assert_eq!(errors(&spec), [DiagnosticKind::DuplicateEntry]);
    let warnings = kinds(&spec, Severity::Warning);
    assert!(
        warnings.contains(&DiagnosticKind::InvalidAttribute),
        "reversejustify=yes"
    );
    assert!(
        warnings.contains(&DiagnosticKind::UnsupportedForm),
        "half-open range"
    );
    assert!(
        warnings.contains(&DiagnosticKind::DuplicateEntry),
        "property"
    );
}

#[test]
fn positive_growth_alignment_follows_document_order() {
    let body = |sp_first: bool| {
        let sp = r#"<stackpointer register="SP" space="ram" growth="positive"/>"#;
        let p = r#"<default_proto><prototype name="p" extrapop="0" stackshift="0">
      <input><pentry minsize="1" maxsize="6" align="4"><addr offset="0" space="stack"/></pentry></input>
      <output/></prototype></default_proto>"#;
        if sp_first {
            format!("<compiler_spec>{sp}{p}</compiler_spec>")
        } else {
            format!("<compiler_spec>{p}{sp}</compiler_spec>")
        }
    };
    let spec = parse(&body(true));
    assert_eq!(errors(&spec), [DiagnosticKind::InconsistentSpec]);
    // Ghidra reads sequentially; a later stack pointer does not apply.
    assert!(parse(&body(false)).is_fully_modeled());
}

#[test]
fn bad_spec_level_forms() {
    let spec = parse(&with_default(
        r#"<stackpointer register="SP" space="ram" growth="sideways"/>
  <prefersplit style="inthird"><register name="q0"/></prefersplit>
  <returnaddress><register name="lr"/><register name="lr2"/></returnaddress>
  <funcptr align="x"/>
  <global><varnode space="ram" offset="0" size="1"/></global>
  <default_proto><prototype name="second" extrapop="0" stackshift="0"><input/><output/></prototype></default_proto>
  <default_proto/>"#,
    ));
    assert!(spec.stack_pointer.is_none());
    assert!(spec.prefer_split.is_empty());
    assert_eq!(
        spec.return_address,
        Some(Storage::Register { name: "lr".into() })
    );
    assert_eq!(
        spec.default_model.as_deref(),
        Some("second"),
        "first default wins"
    );
    assert_eq!(
        errors(&spec),
        [
            DiagnosticKind::InvalidAttribute,
            DiagnosticKind::InvalidAttribute,
            DiagnosticKind::InconsistentSpec,
            DiagnosticKind::InvalidAttribute,
            DiagnosticKind::UnknownElement,
            DiagnosticKind::MissingElement,
        ]
    );
    // The appended second <default_proto> is reported, not adopted.
    assert!(kinds(&spec, Severity::Warning).contains(&DiagnosticKind::DuplicateEntry));
}

#[test]
fn unmodeled_and_unknown_elements_are_reported() {
    let spec = parse(&with_default(
        r#"<segmentop space="ram" userop="segment" farpointer="yes"><pcode><body>x = 1;</body></pcode></segmentop>
  <enum size="4" signed="true"/>
  <flux_capacitor/>"#,
    ));
    assert_eq!(spec.unmodeled.len(), 2);
    assert_eq!(spec.unmodeled[0].element, "segmentop");
    assert_eq!(spec.unmodeled[0].reason, UnmodeledReason::NotModeled);
    assert_eq!(spec.unmodeled[1].reason, UnmodeledReason::IgnoredByGhidra);
    let c = spec.coverage();
    assert_eq!((c.not_modeled, c.ignored_by_ghidra), (1, 1));
    assert_eq!((c.errors, c.warnings, c.infos), (0, 2, 1));
    // Parsed, every prototype complete, but not fully modeled because of <segmentop>.
    assert_eq!(c.complete_prototypes, c.prototypes);
    assert!(!spec.is_fully_modeled());

    // <enum> alone (ignored by Ghidra too) and unknown elements do not block it.
    let spec = parse(&with_default(r#"<enum size="4"/><flux_capacitor/>"#));
    assert!(spec.is_fully_modeled());
    assert_eq!(
        kinds(&spec, Severity::Warning),
        [DiagnosticKind::UnknownElement]
    );
}

#[test]
fn numeric_edge_cases() {
    let spec = parse(&proto(
        "p",
        r#"<pentry minsize="01" maxsize="010"><register name="r0"/></pentry>
           <pentry minsize="1" maxsize="4"><addr space="ram" offset="0xffffffffffffffff"/></pentry>
           <pentry minsize="1" maxsize="4"><addr space="ram" offset="0x1ffffffffffffffff"/></pentry>
           <pentry minsize="1" maxsize="4"><addr space="ram" offset="+4"/></pentry>
           <pentry minsize="1" maxsize="4"><addr space="ram" offset=""/></pentry>
           <pentry minsize="1" maxsize="4"><addr space="ram" offset="-0x10"/></pentry>
           <pentry minsize="1" maxsize="4"><addr space="ram"/></pentry>"#,
        "",
    ));
    let entries = &spec.prototypes[0].input.entries;
    // Leading zero is octal in SpecXmlUtils.decodeInt: 010 == 8.
    assert_eq!((entries[0].min_size, entries[0].max_size), (1, 8));
    assert_eq!(
        entries[1].storage,
        Storage::Address {
            space: "ram".into(),
            offset: u64::MAX,
            size: None
        }
    );
    // `-0x10` fails like Java's BigInteger parse; a missing <addr> offset is 0.
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[2].storage.signed_offset(), Some(0));
    assert_eq!(errors(&spec), vec![DiagnosticKind::InvalidAttribute; 4]);
}
