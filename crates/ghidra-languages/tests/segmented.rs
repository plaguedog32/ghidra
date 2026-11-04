use ghidra_languages::ProcessorSpec;

#[test]
fn segmented_space_metadata_retains_type_defaults_and_first_declaration() {
    let parse = |text: &str| ProcessorSpec::parse_str(text, None, &Default::default()).unwrap();
    let default = parse(r#"<processor_spec><segmented_address space="ram"/></processor_spec>"#);
    assert_eq!(default.segmented_address.as_ref().unwrap().kind, "");
    assert_eq!(default.segmented_address.as_ref().unwrap().space, "ram");
    assert!(default.diagnostics.is_empty());
    let duplicate = parse(
        r#"<processor_spec><segmented_address space="ram" type="protected"/>
        <segmented_address space="other" type="real"/></processor_spec>"#,
    );
    assert_eq!(
        duplicate.segmented_address.as_ref().unwrap().kind,
        "protected"
    );
    assert_eq!(duplicate.diagnostics.len(), 1);
    for invalid in [
        r#"<segmented_address/>"#,
        r#"<segmented_address space="ram"><future/></segmented_address>"#,
    ] {
        let spec = parse(&format!("<processor_spec>{invalid}</processor_spec>"));
        assert!(!spec.diagnostics.is_empty());
    }
}
