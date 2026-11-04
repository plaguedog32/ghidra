use super::*;

fn configuration() -> ProcessorConfiguration {
    ProcessorConfiguration {
        language: LanguageIdentity {
            id: "x86:LE:64:default".into(),
            major: 4,
            minor: 2,
        },
        compiler_id: Some("windows".into()),
        context: BTreeMap::from([("longMode".into(), 1), ("maximum".into(), u64::MAX)]),
    }
}

#[test]
fn version_two_preserves_portable_processor_identity_and_full_width_context() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("processor.ghrs");
    let mut expected = project();
    expected.metadata.processor = Some(configuration());
    expected.save(&path).unwrap();
    let bytes = fs::read(&path).unwrap();
    assert_eq!(u32::from_le_bytes(bytes[8..12].try_into().unwrap()), 2);
    let actual = Project::load(&path).unwrap();
    assert_same_project(&expected, &actual);
    assert_eq!(
        actual.metadata.processor.unwrap().context["maximum"],
        u64::MAX
    );
}

#[test]
fn version_one_migrates_without_language_inference_and_saves_as_version_two() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("legacy.ghrs");
    let expected = project();
    let metadata = serde_json::to_vec(&expected.metadata).unwrap();
    assert!(!String::from_utf8_lossy(&metadata).contains("processor"));
    let mut bytes = encode_raw(&metadata, expected.image.bytes());
    put32(&mut bytes, 8, 1);
    fs::write(&path, bytes).unwrap();
    let actual = Project::load(&path).unwrap();
    assert_same_project(&expected, &actual);
    assert!(actual.metadata.processor.is_none());
    actual.save(&path).unwrap();
    assert_eq!(
        u32::from_le_bytes(fs::read(&path).unwrap()[8..12].try_into().unwrap()),
        2
    );
    assert_same_project(&expected, &Project::load(&path).unwrap());
}

#[test]
fn version_one_rejects_processor_fields_instead_of_reinterpreting_them() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("wrong-schema.ghrs");
    let mut expected = project();
    expected.metadata.processor = Some(configuration());
    let mut bytes = encode_raw(
        &serde_json::to_vec(&expected.metadata).unwrap(),
        expected.image.bytes(),
    );
    put32(&mut bytes, 8, 1);
    fs::write(path.clone(), bytes).unwrap();
    assert!(matches!(Project::load(&path), Err(ProjectError::Json(_))));
}

#[test]
fn malformed_processor_schema_and_duplicate_context_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("malformed.ghrs");
    let valid =
        r#"{"language":{"id":"Toy:LE:32:default","major":1,"minor":0},"context":{"phase":1}}"#;
    let bad = [
        valid.replace("\"phase\":1", "\"phase\":0,\"phase\":1"),
        valid.replace("\"phase\":1", "\"phase\":18446744073709551616"),
        valid.replace("\"phase\":1", "\"phase\":-1"),
        valid.replace("\"phase\":1", "\"phase\":\"1\""),
        valid.replace("\"major\":1", "\"major\":4294967296"),
        valid.replace(
            "\"minor\":0",
            "\"minor\":0,\"source\":\"C:/untrusted.slaspec\"",
        ),
        valid.replace(
            "\"context\":",
            "\"source\":\"/untrusted.slaspec\",\"context\":",
        ),
    ];
    for processor in bad {
        let metadata = format!(
            r#"{{"name":"malformed","annotations":{{}},"last_address":null,"processor":{processor}}}"#
        );
        fs::write(&path, encode_raw(metadata.as_bytes(), &pe_fixture())).unwrap();
        assert!(Project::load(&path).is_err(), "accepted {processor}");
    }
}

#[test]
fn processor_bounds_are_enforced_on_save_and_load_without_replacing_a_project() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("bounded.ghrs");
    let mut expected = project();
    expected.save(&path).unwrap();
    let original = fs::read(&path).unwrap();
    let mut invalid = Vec::new();
    for id in [
        "".to_string(),
        "x".repeat(MAX_LANGUAGE_ID_BYTES + 1),
        "bad\nid".into(),
    ] {
        let mut config = configuration();
        config.language.id = id;
        invalid.push(config);
    }
    for name in [
        "".to_string(),
        "a b".into(),
        "a=b".into(),
        "a,b".into(),
        "a\0b".into(),
        "λ".repeat(MAX_CONTEXT_NAME_BYTES / 2 + 1),
    ] {
        let mut config = configuration();
        config.context.insert(name, 0);
        invalid.push(config);
    }
    for id in [
        "".into(),
        "x".repeat(MAX_COMPILER_ID_BYTES + 1),
        "bad\nid".into(),
    ] {
        let mut config = configuration();
        config.compiler_id = Some(id);
        invalid.push(config);
    }
    let mut too_many = configuration();
    too_many.context = (0..=MAX_CONTEXT_FIELDS)
        .map(|i| (format!("field{i}"), i as u64))
        .collect();
    invalid.push(too_many);
    for config in invalid {
        expected.metadata.processor = Some(config);
        assert!(expected.save(&path).is_err());
        assert_eq!(fs::read(&path).unwrap(), original);
        let metadata = serde_json::to_vec(&expected.metadata).unwrap();
        let malformed = directory.path().join("invalid.ghrs");
        fs::write(&malformed, encode_raw(&metadata, expected.image.bytes())).unwrap();
        assert!(Project::load(&malformed).is_err());
    }
    let mut largest = configuration();
    largest.context = (0..MAX_CONTEXT_FIELDS)
        .map(|i| {
            (
                format!("{}{:03}", "x".repeat(MAX_CONTEXT_NAME_BYTES - 3), i),
                u64::MAX,
            )
        })
        .collect();
    expected.metadata.processor = Some(largest);
    expected.save(&path).unwrap();
    assert_same_project(&expected, &Project::load(&path).unwrap());
}
