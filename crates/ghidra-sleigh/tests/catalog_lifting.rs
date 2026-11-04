use std::{collections::BTreeMap, fs};

use ghidra_languages::{Catalog, LanguageDefinition, TruncatedSpace};
use ghidra_pcode::{Endianness, SpaceKind, Value, machine::Machine};
use ghidra_sleigh::{Error, SleighLanguage};

fn recipe(pspec: &str, attrs: &str) -> (tempfile::TempDir, LanguageDefinition) {
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("tiny.slaspec"),
        include_str!("fixtures/tiny.slaspec"),
    )
    .unwrap();
    fs::write(
        directory.path().join("tiny.sinc"),
        include_str!("fixtures/tiny.sinc"),
    )
    .unwrap();
    fs::write(directory.path().join("tiny.pspec"), pspec).unwrap();
    fs::write(
        directory.path().join("tiny.ldefs"),
        format!(
            r#"
        <language_definitions><language processor="Toy" endian="little" size="32"
          variant="default" version="1" id="Toy:LE:32:default" slafile="tiny.sla"
          processorspec="tiny.pspec" {attrs}><description>fixture</description>
        </language></language_definitions>"#
        ),
    )
    .unwrap();
    let catalog = Catalog::discover(directory.path()).unwrap();
    assert_eq!(catalog.languages.len(), 1, "{:?}", catalog.diagnostics);
    (directory, catalog.languages[0].clone())
}

const CONTEXT: &str = r#"<processor_spec><context_data>
    <context_set space="ram"><set name="phase" val="0"/></context_set>
    <context_set space="ram" first="0x1000" last="0x1000"><set name="phase" val="1"/></context_set>
    <context_set space="other"><set name="not_a_field" val="1"/></context_set>
    <tracked_set space="ram"><set name="r0" val="12"/></tracked_set>
</context_data></processor_spec>"#;

#[test]
fn segmented_address_metadata_gates_unimplemented_address_domains() {
    for kind in ["real", "", "future-mode"] {
        let (_directory, definition) = recipe(
            &format!(
                r#"<processor_spec><segmented_address space="ram" type="{kind}"/></processor_spec>"#
            ),
            "",
        );
        assert!(
            matches!(SleighLanguage::from_language(&definition, &BTreeMap::new()),
            Err(Error::Unsupported(message)) if message.contains("real-mode segmented"))
        );
    }
    let (directory, definition) = recipe(
        r#"<processor_spec><segmented_address space="ram" type="protected"/></processor_spec>"#,
        "",
    );
    let processor = definition.load_processor_spec().unwrap();
    assert_eq!(
        processor.segmented_address.as_ref().unwrap().kind,
        "protected"
    );
    assert!(
        processor
            .unmodeled_elements
            .iter()
            .any(|e| e == "segmented_address")
    );
    let language = SleighLanguage::from_language(&definition, &BTreeMap::new()).unwrap();
    assert_eq!(
        language
            .spaces()
            .iter()
            .find(|s| s.id == language.code_space())
            .unwrap()
            .address_size,
        4
    );
    let source = include_str!("fixtures/tiny.slaspec").replace("size=4 default", "size=8 default");
    fs::write(directory.path().join("tiny.slaspec"), source).unwrap();
    assert!(
        matches!(SleighLanguage::from_language(&definition, &BTreeMap::new()),
        Err(Error::Unsupported(message)) if message.contains("32-bit byte-addressed"))
    );
}

#[test]
fn code_space_ranges_overrides_and_commits_keep_their_precedence() {
    let (_directory, definition) = recipe(CONTEXT, "");
    let mut language = SleighLanguage::from_language(&definition, &BTreeMap::new()).unwrap();
    assert_eq!(language.decode(0x1000, &[6]).unwrap().text, "mode");
    assert_eq!(language.decode(0x1001, &[6]).unwrap().text, "base");
    language.decode(0x1000, &[5]).unwrap();
    assert_eq!(language.decode(0x1001, &[6]).unwrap().text, "mode");
    language.reset_context();
    assert_eq!(language.decode(0x1001, &[6]).unwrap().text, "base");
    let mut explicit =
        SleighLanguage::from_language(&definition, &BTreeMap::from([("phase".into(), 0)])).unwrap();
    assert_eq!(explicit.decode(0x1000, &[6]).unwrap().text, "base");
    // The tracked r0 and unrelated-space not_a_field were never decode fields.
    let machine = Machine::new(language.spaces().to_vec(), 65536).unwrap();
    assert!(
        machine
            .read_varnode(&language.register("r0").unwrap())
            .is_err()
    );
}

#[test]
fn little_instruction_big_data_load_preserves_register_alias_layout() {
    let (directory, mut definition) = recipe("<processor_spec/>", "");
    let source = format!(
        "{}\ndefine register offset=0 size=1 [ r0l ];\n",
        include_str!("fixtures/tiny.slaspec")
    );
    fs::write(directory.path().join("tiny.slaspec"), source).unwrap();
    definition.endian = Endianness::Big;
    let mut language = SleighLanguage::from_language(&definition, &BTreeMap::new()).unwrap();
    assert_eq!(language.source_endianness(), Endianness::Little);
    assert!(
        language
            .spaces()
            .iter()
            .filter(|s| s.kind == SpaceKind::Ram)
            .all(|s| s.endianness == Endianness::Big)
    );
    let r0 = language.register("r0").unwrap();
    let r0l = language.register("r0l").unwrap();
    assert_eq!(r0l.offset, r0.offset);
    let lifted = language.decode(0x1000, &[3]).unwrap();
    let mut machine = Machine::new(language.spaces().to_vec(), 65536).unwrap();
    machine
        .write_varnode(
            &language.register("r1").unwrap(),
            &Value::from_u64(4, 0x2000).unwrap(),
        )
        .unwrap();
    machine
        .map_bytes(language.code_space(), 0x2000, &[0x12, 0x34, 0x56, 0x78])
        .unwrap();
    machine
        .run(&[lifted.instruction], language.code_space(), 0x1000, 100)
        .unwrap();
    assert_eq!(
        machine.read_varnode(&r0).unwrap().to_u64(),
        Some(0x12345678)
    );
    assert_eq!(machine.read_varnode(&r0l).unwrap().to_u64(), Some(0x78));
}

#[test]
fn incompatible_endian_and_truncated_spaces_fail_explicitly() {
    let (_directory, mut definition) = recipe("<processor_spec/>", "");
    definition.endian = Endianness::Big;
    definition.instruction_endian = Endianness::Big;
    assert!(
        matches!(SleighLanguage::from_language(&definition, &BTreeMap::new()),
        Err(Error::Unsupported(message)) if message.contains("data/instruction byte order"))
    );
    definition.instruction_endian = Endianness::Little;
    definition.endian = Endianness::Little;
    definition.truncated_spaces.push(TruncatedSpace {
        space: "ram".into(),
        size: 2,
    });
    assert!(
        matches!(SleighLanguage::from_language(&definition, &BTreeMap::new()),
        Err(Error::Unsupported(message)) if message.contains("truncates"))
    );
}

#[test]
fn wide_and_invalid_context_is_reported_without_truncation() {
    let (_directory, definition) = recipe(
        r#"<processor_spec><context_data>
      <context_set space="ram"><set name="phase" val="0x10000000000000000"/></context_set>
    </context_data></processor_spec>"#,
        "",
    );
    assert!(
        matches!(SleighLanguage::from_language(&definition, &BTreeMap::new()),
        Err(Error::Context(message)) if message.contains("64-bit"))
    );
    let (_directory, definition) = recipe(
        r#"<processor_spec><context_data>
      <context_set space="ram" first="0x1000" last="0x1000"><set name="phase" val="0x10000000000000000"/></context_set>
    </context_data></processor_spec>"#,
        "",
    );
    let mut language = SleighLanguage::from_language(&definition, &BTreeMap::new()).unwrap();
    assert!(matches!(
        language.decode(0x1000, &[6]),
        Err(Error::Context(_))
    ));
    assert_eq!(language.decode(0x1001, &[6]).unwrap().text, "base");
    let (_directory, definition) = recipe(
        r#"<processor_spec><context_data>
      <context_set space="ram"><set name="phase" val="bad"/></context_set>
    </context_data></processor_spec>"#,
        "",
    );
    assert!(matches!(
        SleighLanguage::from_language(&definition, &BTreeMap::new()),
        Err(Error::Context(_))
    ));
}

#[test]
fn context_changes_inside_delay_bundles_are_rejected_before_commits() {
    let (_directory, definition) = recipe(CONTEXT, "");
    let mut language = SleighLanguage::from_language(&definition, &BTreeMap::new()).unwrap();
    assert!(matches!(language.decode(0x1000, &[16, 6]),
        Err(Error::Unsupported(message)) if message.contains("delay-slot")));
    assert_eq!(language.decode(0x1001, &[6]).unwrap().text, "base");
}

#[test]
fn instruction_token_endian_can_differ_from_global_storage_order() {
    let (directory, mut definition) = recipe("<processor_spec/>", "");
    let source = include_str!("fixtures/big.slaspec").replace(
        "define token instruction_word(16)",
        "define token instruction_word(16) endian=little",
    );
    fs::write(directory.path().join("tiny.slaspec"), source).unwrap();
    definition.endian = Endianness::Big;
    definition.instruction_endian = Endianness::Little;
    let mut language = SleighLanguage::from_language(&definition, &BTreeMap::new()).unwrap();
    assert_eq!(language.source_endianness(), Endianness::Big);
    assert_eq!(language.decode(0x1000, &[0x34, 0x12]).unwrap().text, "inc");
    assert!(language.decode(0x1000, &[0x12, 0x34]).is_err());
}

#[test]
fn explicit_overrides_have_the_same_precedence_for_raw_and_catalog_loading() {
    let (_directory, definition) = recipe(CONTEXT, "");
    let explicit = BTreeMap::from([("phase".into(), 1)]);
    let mut catalog = SleighLanguage::from_language(&definition, &explicit).unwrap();
    let mut raw =
        SleighLanguage::from_spec(definition.source.available_path().unwrap(), &explicit).unwrap();
    let per_call = BTreeMap::from([("phase".into(), 0)]);
    assert_eq!(
        raw.decode_with_defaults(0x1001, &[6], &per_call)
            .unwrap()
            .text,
        "mode"
    );
    assert_eq!(
        catalog
            .decode_with_defaults(0x1001, &[6], &per_call)
            .unwrap()
            .text,
        "mode"
    );
}
