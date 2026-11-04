//! DataOrganizationImpl.restoreXml assigns fields directly, unlike the public
//! Java primitive-size setters. These synthetic cases distinguish those paths;
//! the retained compiler specs happen not to distinguish them.
use ghidra_languages::{CompilerSpec, ResolvedDataOrganization};

const DEFAULT: &str = r#"<default_proto><prototype name="p" extrapop="0" stackshift="0"><input/><output/></prototype></default_proto>"#;

fn parse(body: &str) -> CompilerSpec {
    let spec = CompilerSpec::parse_str(
        &format!("<compiler_spec>{body}{DEFAULT}</compiler_spec>"),
        None,
        &Default::default(),
    )
    .unwrap();
    assert!(spec.is_fully_modeled(), "{:?}", spec.diagnostics);
    spec
}

fn sizes(org: &ResolvedDataOrganization) -> [u32; 7] {
    [
        org.short_size,
        org.integer_size,
        org.long_size,
        org.long_long_size,
        org.float_size,
        org.double_size,
        org.long_double_size,
    ]
}

#[test]
fn xml_primitive_sizes_are_independent_instead_of_using_coupled_setters() {
    // DataOrganizationImpl.java:973-991 assigns these fields directly. Calling
    // its setters would instead impose short<=int<=long<=longlong and
    // float<=double<=longdouble and change several values below.
    let steps = [
        ("short_size", 8),
        ("integer_size", 1),
        ("long_size", 3),
        ("long_long_size", 2),
        ("float_size", 16),
        ("double_size", 4),
        ("long_double_size", 1),
    ];
    let text: String = steps
        .iter()
        .map(|(name, value)| format!(r#"<{name} value="{value}"/>"#))
        .collect();
    let reverse: String = steps
        .iter()
        .rev()
        .map(|(name, value)| format!(r#"<{name} value="{value}"/>"#))
        .collect();
    let forward = parse(&format!("<data_organization>{text}</data_organization>"));
    let backward = parse(&format!("<data_organization>{reverse}</data_organization>"));
    assert!(forward.diagnostics.is_empty());
    assert!(backward.diagnostics.is_empty());
    assert_eq!(forward.data_organization, backward.data_organization);
    assert_eq!(
        sizes(&forward.resolved_data_organization(8)),
        [8, 1, 3, 2, 16, 4, 1]
    );
}

#[test]
fn primitive_size_overrides_do_not_change_absent_neighbors_or_zero_values() {
    for (name, value, expected) in [
        ("integer_size", 1, [2, 1, 4, 8, 4, 8, 8]),
        ("float_size", 16, [2, 4, 4, 8, 16, 8, 8]),
        ("long_long_size", 0, [2, 4, 4, 0, 4, 8, 8]),
        ("double_size", 0, [2, 4, 4, 8, 4, 0, 8]),
    ] {
        let spec = parse(&format!(
            r#"<data_organization><{name} value="{value}"/></data_organization>"#
        ));
        assert_eq!(sizes(&spec.resolved_data_organization(8)), expected);
        assert!(spec.diagnostics.is_empty(), "{:?}", spec.diagnostics);
        if name == "integer_size" {
            let organization = spec.data_organization.as_ref().unwrap();
            assert_eq!(organization.short_size, None);
            assert_eq!(organization.long_size, None);
        }
    }
}

#[test]
fn repeated_blocks_and_values_only_replace_their_own_fields() {
    let spec = parse(
        r#"<data_organization><integer_size value="16"/><long_size value="2"/><double_size value="32"/></data_organization>
<data_organization><integer_size value="4"/><float_size value="16"/><integer_size value="1"/></data_organization>"#,
    );
    assert_eq!(
        sizes(&spec.resolved_data_organization(8)),
        [2, 1, 2, 8, 16, 32, 8]
    );
    assert_eq!(
        spec.data_organization.as_ref().unwrap().integer_size,
        Some(1)
    );
    assert_eq!(spec.diagnostics.len(), 2); // repeated block and integer in its block
    assert!(
        spec.diagnostics
            .iter()
            .any(|d| d.message.contains("integer_size") && d.message.contains("last wins"))
    );
}
