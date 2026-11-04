//! Load-time space availability is separate from end-of-file fallback geometry.
use std::path::Path;

use ghidra_languages::{CompilerSpec, DiagnosticKind, Error, Limits, Severity};

const SP: &str = r#"<stackpointer register="sp" space="ram"/>"#;
const DEFAULT: &str = r#"<default_proto><prototype name="p" extrapop="0" stackshift="0"><input/><output/></prototype></default_proto>"#;
const STACK_INPUT: &str = r#"<default_proto><prototype name="p" extrapop="0" stackshift="0"><input><pentry minsize="1" maxsize="4"><addr space="stack" offset="0"/></pentry></input><output/></prototype></default_proto>"#;

fn parse(body: &str) -> CompilerSpec {
    CompilerSpec::parse_str(
        &format!("<compiler_spec>{body}</compiler_spec>"),
        None,
        &Limits::default(),
    )
    .unwrap()
}

fn stack_errors(spec: &CompilerSpec) -> usize {
    spec.diagnostics
        .iter()
        .filter(|d| {
            d.severity == Severity::Error
                && d.kind == DiagnosticKind::UnresolvedReference
                && d.message.contains("earlier <stackpointer>")
        })
        .count()
}

#[test]
fn stack_entries_require_an_earlier_pointer_even_on_the_same_xml_line() {
    for body in [STACK_INPUT.to_owned(), format!("{STACK_INPUT}{SP}")] {
        let spec = parse(&body);
        assert_eq!(stack_errors(&spec), 1);
        assert!(!spec.is_fully_modeled());
        assert!(!spec.prototypes[0].is_complete());
        // Broken load order is visible without discarding captured data.
        assert_eq!(spec.prototypes[0].input.entries.len(), 1);
        assert!(spec.prototypes[0].input.entries[0].storage.is_stack());
        assert_eq!(spec.diagnostics[0].line, Some(1));
    }
    let spec = parse(&format!("{SP}{STACK_INPUT}"));
    assert!(spec.is_fully_modeled(), "{:?}", spec.diagnostics);
    assert_eq!(stack_errors(&spec), 0);
    // No pointer is necessary when nothing references its load-time space.
    assert!(parse(DEFAULT).is_fully_modeled());
}

#[test]
fn every_decoded_stack_space_reference_obeys_load_order() {
    for consumer in [
        r#"<global><range space="stack" first="0" last="3"/></global>"#,
        r#"<readonly><range space="stack" first="0" last="3"/></readonly>"#,
        r#"<nohighptr><range space="stack" first="0" last="3"/></nohighptr>"#,
        r#"<inferptrbounds><range space="stack" first="0" last="3"/></inferptrbounds>"#,
        r#"<returnaddress><varnode space="stack" offset="0" size="4"/></returnaddress>"#,
        r#"<prefersplit style="inhalf"><addr space="stack" offset="0" size="4"/></prefersplit>"#,
        r#"<deadcodedelay space="stack" delay="0"/>"#,
        r#"<spacebase name="frame" register="r0" space="stack"/>"#,
        r#"<context_data><context_set space="stack"><set name="mode" val="0"/></context_set></context_data>"#,
        r#"<context_data><tracked_set space="stack"><set name="r0" val="0"/></tracked_set></context_data>"#,
    ] {
        let before = parse(&format!("{consumer}{SP}{DEFAULT}"));
        assert_eq!(
            stack_errors(&before),
            1,
            "{consumer}: {:?}",
            before.diagnostics
        );
        assert!(!before.is_fully_modeled());
        let after = parse(&format!("{SP}{consumer}{DEFAULT}"));
        assert!(
            after.is_fully_modeled(),
            "{consumer}: {:?}",
            after.diagnostics
        );
    }
    for storage in [
        r#"<varnode space="stack" offset="0" size="4"/>"#,
        r#"<addr space="join" piece1="r0" piece2="stack:0:4"/>"#,
    ] {
        let prototype = format!(
            r#"<default_proto><prototype name="p" extrapop="0" stackshift="0"><input><pentry minsize="1" maxsize="4">{storage}</pentry></input><output/></prototype></default_proto>"#
        );
        let before = parse(&format!("{prototype}{SP}"));
        assert_eq!(stack_errors(&before), 1, "{:?}", before.diagnostics);
        assert!(!before.prototypes[0].is_complete());
        let after = parse(&format!("{SP}{prototype}"));
        assert!(after.is_fully_modeled(), "{:?}", after.diagnostics);
    }
}

#[test]
fn register_range_tags_resolve_explicit_space_before_register_names() {
    for tag in [
        "global",
        "readonly",
        "nohighptr",
        "localrange",
        "paramrange",
    ] {
        let tags = format!(r#"<{tag}><register name="r0" space="stack"/></{tag}>"#);
        let consumer = if matches!(tag, "localrange" | "paramrange") {
            format!(
                r#"<default_proto><prototype name="p" extrapop="0" stackshift="0"><input/><output/>{tags}</prototype></default_proto>"#
            )
        } else {
            format!("{tags}{DEFAULT}")
        };
        for body in [consumer.clone(), format!("{consumer}{SP}")] {
            let spec = parse(&body);
            assert_eq!(stack_errors(&spec), 1, "{tag}: {:?}", spec.diagnostics);
            assert!(!spec.is_fully_modeled());
            if matches!(tag, "localrange" | "paramrange") {
                assert!(!spec.prototypes[0].is_complete());
            }
        }
        let valid = parse(&format!("{SP}{consumer}"));
        assert!(valid.is_fully_modeled(), "{tag}: {:?}", valid.diagnostics);
        assert!(valid.diagnostics.is_empty(), "{:?}", valid.diagnostics);
        if matches!(tag, "global" | "readonly" | "nohighptr") {
            let frame = parse(&format!(
                r#"<spacebase name="stack" register="r1" space="ram"/>{consumer}"#
            ));
            assert_eq!(stack_errors(&frame), 0);
        }
    }
}

#[test]
fn invalid_or_discarded_pointer_declarations_do_not_activate_stack_space() {
    for pointer in [
        r#"<stackpointer register="sp" space="ram" growth="sideways"/>"#,
        r#"<stackpointer space="ram"/>"#,
        r#"<future><stackpointer register="sp" space="ram"/></future>"#,
    ] {
        let spec = parse(&format!("{pointer}{STACK_INPUT}"));
        assert_eq!(stack_errors(&spec), 1, "{:?}", spec.diagnostics);
        assert!(spec.stack_pointer.is_none());
    }
    let backing = parse(&format!(
        r#"<stackpointer register="sp" space="stack"/>{DEFAULT}"#
    ));
    assert_eq!(stack_errors(&backing), 1);
    assert!(!backing.is_fully_modeled());
}

#[test]
fn ignored_subtrees_attributes_and_text_are_not_resolved_as_stack_addresses() {
    let spec = parse(&format!(
        r#"<properties><property key="space" value="stack"/></properties>
<future space="stack"><varnode space="stack" offset="0" size="4"/></future>
<callfixup name="f"><pcode><body><![CDATA[local stack:4 = 1;]]></body></pcode></callfixup>{DEFAULT}"#
    ));
    assert_eq!(stack_errors(&spec), 0);
    assert!(spec.is_fully_modeled(), "{:?}", spec.diagnostics);
}

#[test]
fn global_style_compiler_frames_use_extra_ranges_but_other_consumers_use_stack_space() {
    let frame = r#"<spacebase name="stack" register="r0" space="ram"/>"#;
    for tag in ["global", "readonly", "nohighptr"] {
        let ranges = format!(r#"<{tag}><range space="stack" first="0" last="3"/></{tag}>"#);
        let valid = parse(&format!("{frame}{ranges}{DEFAULT}"));
        assert!(valid.is_fully_modeled(), "{:?}", valid.diagnostics);
        let before = parse(&format!("{ranges}{frame}{DEFAULT}"));
        assert_eq!(stack_errors(&before), 1);
    }
    let other = parse(&format!(
        r#"{frame}<inferptrbounds><range space="stack" first="0" last="3"/></inferptrbounds>{DEFAULT}"#
    ));
    assert_eq!(stack_errors(&other), 1);
    let local = parse(&format!(
        r#"{frame}<default_proto><prototype name="p" extrapop="0" stackshift="0"><input/><output/><localrange><range space="stack" first="0" last="3"/></localrange></prototype></default_proto>"#
    ));
    assert_eq!(stack_errors(&local), 1);
}

#[test]
fn new_diagnostics_obey_exact_count_and_path_byte_limits() {
    let text = format!("<compiler_spec>{STACK_INPUT}</compiler_spec>");
    let label = "é".repeat(64);
    let path = Path::new(&label);
    let base = CompilerSpec::parse_str(&text, Some(path), &Limits::default()).unwrap();
    assert_eq!(base.diagnostics.len(), 1);
    let bytes = base.diagnostics[0].message.len() + path.as_os_str().len();
    let limits = Limits {
        max_cspec_diagnostics: 1,
        max_cspec_diagnostic_bytes: bytes,
        ..Limits::default()
    };
    assert!(CompilerSpec::parse_str(&text, Some(path), &limits).is_ok());
    for limited in [
        Limits {
            max_cspec_diagnostics: 0,
            ..limits
        },
        Limits {
            max_cspec_diagnostic_bytes: bytes - 1,
            ..limits
        },
    ] {
        assert!(matches!(
            CompilerSpec::parse_str(&text, Some(path), &limited),
            Err(Error::Limit { .. })
        ));
    }
}
