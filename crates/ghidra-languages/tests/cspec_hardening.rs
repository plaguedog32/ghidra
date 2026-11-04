//! Regressions for compiler-spec hardening: resource budgets, bounded diagnostics, and
//! the Ghidra semantics of size lists, numbers, leaf tags, p-code payloads and booleans.
//!
//! Work and size bounds are asserted through the deterministic budgets in [`Limits`],
//! never through wall-clock time.

use std::fmt::Write as _;
use std::path::Path;

use ghidra_languages::{
    CompilerSpec, DatatypeClass, DiagnosticKind, Error, InjectionPoint, Limits, MetaType,
    ModelStatus, RuleAction, Severity, SizeAlignment,
};

const LABEL: &str = "test.cspec";

fn parse_with(text: &str, limits: &Limits) -> Result<CompilerSpec, Error> {
    CompilerSpec::parse_str(text, Some(Path::new(LABEL)), limits)
}

fn parse(text: &str) -> CompilerSpec {
    parse_with(text, &Limits::default()).unwrap_or_else(|e| panic!("{e}"))
}

fn with_work(max_cspec_work: u64) -> Limits {
    Limits {
        max_cspec_work,
        ..Limits::default()
    }
}

fn is_limit(result: &Result<CompilerSpec, Error>, needle: &str) -> bool {
    matches!(result, Err(Error::Limit { message, .. }) if message.contains(needle))
}

/// Smallest `max_cspec_work` that parses `text`, found by bisection. The budget is
/// deterministic, so this is exact.
fn min_work(text: &str) -> u64 {
    let (mut lo, mut hi) = (0u64, Limits::default().max_cspec_work);
    assert!(parse_with(text, &with_work(hi)).is_ok());
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if parse_with(text, &with_work(mid)).is_ok() {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    lo
}

fn errors(spec: &CompilerSpec) -> Vec<DiagnosticKind> {
    kinds(spec, Severity::Error)
}

fn kinds(spec: &CompilerSpec, severity: Severity) -> Vec<DiagnosticKind> {
    spec.diagnostics
        .iter()
        .filter(|d| d.severity == severity)
        .map(|d| d.kind.clone())
        .collect()
}

fn diagnostic_bytes(spec: &CompilerSpec) -> usize {
    spec.diagnostics
        .iter()
        .map(|d| d.message.len() + d.path.as_ref().map_or(0, |p| p.as_os_str().len()))
        .sum()
}

/// A spec whose default prototype has `input` as its `<input>` body and `extra` after
/// `<output>`; `top` goes before `<default_proto>`.
fn spec(top: &str, input: &str, extra: &str) -> String {
    format!(
        r#"<?xml version="1.0"?>
<compiler_spec>
{top}
  <default_proto>
    <prototype name="p" extrapop="0" stackshift="0">
      <input>{input}</input>
      <output><pentry minsize="1" maxsize="4"><register name="r0"/></pentry></output>
      {extra}
    </prototype>
  </default_proto>
</compiler_spec>"#
    )
}

fn top(body: &str) -> String {
    spec(body, "", "")
}

fn input(body: &str) -> String {
    spec("", body, "")
}

fn proto_extra(body: &str) -> String {
    spec("", "", body)
}

fn rule(body: &str) -> String {
    input(&format!(
        r#"<pentry minsize="1" maxsize="4"><register name="r0"/></pentry><rule>{body}</rule>"#
    ))
}

// ---------------------------------------------------------------------------------------
// P1: group conflicts and budgets
// ---------------------------------------------------------------------------------------

fn group(entries: impl Iterator<Item = String>) -> String {
    let mut body = String::from("<group>");
    for e in entries {
        body.push_str(&e);
    }
    body.push_str("</group>");
    input(&body)
}

fn identical_group(n: usize) -> String {
    group(
        (0..n).map(|_| r#"<pentry minsize="1" maxsize="8"><register name="r0"/></pentry>"#.into()),
    )
}

/// `n` entries with disjoint size ranges: every pair is distinguishable, so Ghidra (and
/// this crate) compares all `n * (n - 1) / 2` pairs.
fn distinct_group(n: usize) -> String {
    group((1..=n).map(|k| {
        format!(r#"<pentry minsize="{k}" maxsize="{k}"><register name="r{k}"/></pentry>"#)
    }))
}

#[test]
fn identical_group_entries_give_one_bounded_error() {
    // The review's amplification input: 2000 identical entries in one group used to give
    // 1,999,000 diagnostics. Ghidra throws at the first conflict, and so do we.
    let text = identical_group(2000);
    assert!(text.len() < 160 * 1024);
    let spec = parse(&text);
    assert_eq!(errors(&spec), [DiagnosticKind::InconsistentSpec]);
    assert_eq!(spec.diagnostics.len(), 1, "{:#?}", spec.diagnostics);
    assert!(diagnostic_bytes(&spec) < 512);
    let p = &spec.prototypes[0];
    assert_eq!(p.input.entries.len(), 2000, "entries are kept, flagged");
    assert_eq!(p.status, ModelStatus::Incomplete { errors: 1 });
    assert!(!spec.is_fully_modeled());
    // Ghidra compares the last two entries first, so only one pair is examined: the
    // work is linear in the input (two elements per entry plus a few).
    let work = min_work(&text);
    assert!(work <= 2 * 2000 + 16, "work {work}");
    assert!(work >= 2 * 2000, "every entry is visited: {work}");
}

#[test]
fn group_pair_comparisons_are_charged_and_bounded() {
    let n = 120u64;
    let pairs = n * (n - 1) / 2;
    let text = distinct_group(n as usize);
    let spec = parse(&text);
    assert!(spec.is_fully_modeled(), "{:#?}", spec.diagnostics);
    assert_eq!(spec.prototypes[0].input.entries.len(), n as usize);

    let need = min_work(&text);
    // Exact boundary: one unit less is a resource error, never a partial spec.
    assert!(
        parse_with(&text, &with_work(need))
            .unwrap()
            .is_fully_modeled()
    );
    assert!(is_limit(
        &parse_with(&text, &with_work(need - 1)),
        "max_cspec_work"
    ));
    // The pairs dominate; elements add about two units per entry.
    assert!(need >= pairs + 2 * n, "need {need}, pairs {pairs}");
    assert!(need <= pairs + 2 * n + 16, "need {need}, pairs {pairs}");
    // One more entry costs its two elements plus `n` new pairs.
    assert_eq!(min_work(&distinct_group(n as usize + 1)), need + 2 + n);

    // A group too large for the budget is rejected, not accepted unchecked.
    let big = distinct_group(1000);
    assert!(is_limit(
        &parse_with(&big, &with_work(400_000)),
        "max_cspec_work"
    ));
    assert!(
        parse_with(&big, &with_work(600_000))
            .unwrap()
            .is_fully_modeled()
    );
}

#[test]
fn diagnostic_count_budget_has_an_exact_boundary() {
    // Every entry carries an attribute Ghidra rejects: one error each, entry kept.
    let entries: String = (0..50)
        .map(|i| {
            format!(
                r#"<pentry minsize="1" maxsize="4" colour="c{i}"><register name="r0"/></pentry>"#
            )
        })
        .collect();
    let text = input(&entries);
    let spec = parse(&text);
    let count = spec.diagnostics.len();
    assert_eq!(errors(&spec).len(), 50);
    assert_eq!(
        spec.prototypes[0].status,
        ModelStatus::Incomplete { errors: 50 }
    );

    let at = Limits {
        max_cspec_diagnostics: count,
        ..Limits::default()
    };
    assert_eq!(parse_with(&text, &at).unwrap().diagnostics.len(), count);
    let below = Limits {
        max_cspec_diagnostics: count - 1,
        ..Limits::default()
    };
    assert!(is_limit(
        &parse_with(&text, &below),
        "max_cspec_diagnostics"
    ));
    let none = Limits {
        max_cspec_diagnostics: 0,
        ..Limits::default()
    };
    assert!(is_limit(&parse_with(&text, &none), "max_cspec_diagnostics"));
    // A clean spec needs no diagnostic budget at all.
    assert!(parse_with(&input(""), &none).unwrap().is_fully_modeled());
}

#[test]
fn diagnostic_byte_budget_has_an_exact_boundary() {
    let entries: String = (0..20)
        .map(|_| r#"<pentry minsize="1" maxsize="4" colour="x"><register name="r0"/></pentry>"#)
        .collect();
    let text = input(&entries);
    let spec = parse(&text);
    let bytes = diagnostic_bytes(&spec);
    assert!(bytes > LABEL.len() * 20, "path bytes are counted");
    let at = Limits {
        max_cspec_diagnostic_bytes: bytes,
        ..Limits::default()
    };
    assert_eq!(parse_with(&text, &at).unwrap(), spec);
    let below = Limits {
        max_cspec_diagnostic_bytes: bytes - 1,
        ..Limits::default()
    };
    assert!(is_limit(
        &parse_with(&text, &below),
        "max_cspec_diagnostic_bytes"
    ));
}

#[test]
fn shared_context_diagnostics_obey_count_and_path_byte_budgets() {
    let text = top(&format!(
        "<context_data><context_set space=\"ram\">{}</context_set></context_data>",
        "<set name=\"mode\" val=\"bad\"/>".repeat(8)
    ));
    let path_text = "p".repeat(32_768);
    let path = Some(Path::new(&path_text));
    let spec = CompilerSpec::parse_str(&text, path, &Limits::default()).unwrap();
    assert_eq!(spec.diagnostics.len(), 8);
    assert_eq!(spec.context_sets[0].values.len(), 8);
    assert!(spec.context_sets[0].values.iter().all(|v| v.value == 0));
    let bytes = diagnostic_bytes(&spec);
    let exact = Limits {
        max_cspec_diagnostics: 8,
        max_cspec_diagnostic_bytes: bytes,
        ..Limits::default()
    };
    assert_eq!(CompilerSpec::parse_str(&text, path, &exact).unwrap(), spec);
    for limits in [
        Limits {
            max_cspec_diagnostics: 7,
            ..exact
        },
        Limits {
            max_cspec_diagnostics: 0,
            ..exact
        },
        Limits {
            max_cspec_diagnostic_bytes: bytes - 1,
            ..exact
        },
        Limits {
            max_cspec_diagnostic_bytes: 0,
            ..exact
        },
    ] {
        assert!(matches!(
            CompilerSpec::parse_str(&text, path, &limits),
            Err(Error::Limit { .. })
        ));
    }
}

#[test]
fn context_diagnostic_quotes_are_bounded_without_changing_stored_values() {
    let name = "界".repeat(30_000);
    let raw = "x".repeat(100_000);
    let text = top(&format!(
        "<context_data><context_set space=\"ram\"><set name=\"{name}\" val=\"{raw}\"/></context_set></context_data>"
    ));
    let spec = parse(&text);
    assert_eq!(spec.diagnostics.len(), 1);
    assert!(spec.diagnostics[0].message.len() < 256);
    assert_eq!(spec.context_sets[0].values[0].name, name);
    assert_eq!(spec.context_sets[0].values[0].raw, raw);
    assert_eq!(spec.context_sets[0].values[0].value, 0);
}

#[test]
fn diagnostic_floods_fail_under_default_limits() {
    // 12,000 flagged entries exceed the default 10,000-diagnostic budget: the parse is a
    // resource error instead of a spec with diagnostics silently missing.
    let entries: String = (0..12_000)
        .map(|_| r#"<pentry minsize="1" maxsize="4" c=""><register name="r"/></pentry>"#)
        .collect();
    let result = parse_with(&input(&entries), &Limits::default());
    assert!(is_limit(&result, "max_cspec_diagnostics"), "{result:?}");
}

#[test]
fn quoted_spec_text_is_clipped_in_diagnostics() {
    // A long attribute value and a long element name repeated in many warnings.
    let value = "v".repeat(200_000);
    let name = "n".repeat(100_000);
    let attrs: String = (0..60).map(|i| format!(" a{i}=\"\"")).collect();
    let text = top(&format!(
        r#"<data_organization><bitfield_packing><{name}{attrs}/></bitfield_packing></data_organization>
  <stackpointer register="SP" space="ram" reversejustify="{value}"/>
  <funcptr align="{value}"/>"#
    ));
    let spec = parse(&text);
    // 60 unknown attributes, the ignored element, reversejustify and funcptr.
    assert_eq!(spec.diagnostics.len(), 63, "{:#?}", spec.diagnostics.len());
    for d in &spec.diagnostics {
        assert!(d.message.len() <= 400, "{} bytes", d.message.len());
    }
    assert!(diagnostic_bytes(&spec) < 63 * 400);
    assert_eq!(errors(&spec), [DiagnosticKind::InvalidAttribute]);
}

// ---------------------------------------------------------------------------------------
// P2: size lists
// ---------------------------------------------------------------------------------------

fn datatype_rule(attrs: &str) -> CompilerSpec {
    parse(&rule(&format!(
        r#"<datatype name="struct" {attrs}/><goto_stack/>"#
    )))
}

#[test]
fn datatype_sizes_follow_size_restricted_filter() {
    for (attrs, sizes) in [
        (r#"sizes="010""#, vec![10]),
        (r#"sizes="08""#, vec![8]),
        (r#"sizes="4 8""#, vec![4, 8]),
        (r#"sizes="4  8,""#, vec![4, 8]),
        (r#"sizes="+3,5,6,7""#, vec![3, 5, 6, 7]),
        (r#"sizes="8,4,8""#, vec![8, 4, 8]),
    ] {
        let spec = datatype_rule(attrs);
        assert!(spec.is_fully_modeled(), "{attrs}: {:#?}", spec.diagnostics);
        let filter = &spec.prototypes[0].input.rules[0].datatype;
        assert_eq!(filter.sizes, sizes, "{attrs}");
        assert_eq!((filter.min_size, filter.max_size), (None, None), "{attrs}");
    }
    for attrs in [
        r#"sizes="0""#,
        r#"sizes="0x10""#,
        r#"sizes="4, 8""#,
        r#"sizes="4,,8""#,
        r#"sizes=",4""#,
        r#"sizes="""#,
        r#"sizes="-4""#,
        r#"sizes="2147483648""#,
    ] {
        let spec = datatype_rule(attrs);
        assert!(spec.prototypes[0].input.rules.is_empty(), "{attrs}");
        assert_eq!(
            errors(&spec),
            [DiagnosticKind::InvalidAttribute],
            "{attrs}: {:#?}",
            spec.diagnostics
        );
        assert!(!spec.is_fully_modeled(), "{attrs}");
    }
    // Only delimiters: no pieces, which Ghidra treats as no size restriction.
    let spec = datatype_rule(r#"sizes=",""#);
    assert!(spec.is_fully_modeled(), "{:#?}", spec.diagnostics);
    assert!(spec.prototypes[0].input.rules[0].datatype.sizes.is_empty());
}

#[test]
fn datatype_size_attributes_mix_in_document_order() {
    // Ghidra only objects to sizes after a non-zero bound, or a bound after a list.
    let spec = datatype_rule(r#"minsize="0" sizes="4""#);
    assert!(spec.is_fully_modeled(), "{:#?}", spec.diagnostics);
    let filter = &spec.prototypes[0].input.rules[0].datatype;
    assert_eq!((filter.min_size, filter.sizes.as_slice()), (None, &[4][..]));

    let spec = datatype_rule(r#"sizes="," minsize="2""#);
    assert!(spec.is_fully_modeled(), "{:#?}", spec.diagnostics);
    assert_eq!(spec.prototypes[0].input.rules[0].datatype.min_size, Some(2));

    for attrs in [
        r#"sizes="4" minsize="0""#,
        r#"minsize="2" sizes="4""#,
        r#"maxsize="8" sizes="4""#,
    ] {
        let spec = datatype_rule(attrs);
        assert_eq!(errors(&spec), [DiagnosticKind::InconsistentSpec], "{attrs}");
        assert!(spec.prototypes[0].input.rules.is_empty(), "{attrs}");
    }
}

#[test]
fn class_specific_datatype_attributes_are_only_decoded_where_used() {
    // MetaTypeFilter never reads minelements, so Ghidra accepts any text there.
    let spec = datatype_rule(r#"minelements="lots" maxprimitives="x""#);
    assert!(spec.is_fully_modeled(), "{:#?}", spec.diagnostics);
    assert_eq!(kinds(&spec, Severity::Warning).len(), 2);
    let filter = &spec.prototypes[0].input.rules[0].datatype;
    assert_eq!(filter.class, DatatypeClass::Meta(MetaType::Struct));
    assert_eq!(filter.min_elements, None);

    let spec = parse(&rule(
        r#"<datatype name="array" minelements="lots"/><goto_stack/>"#,
    ));
    assert_eq!(errors(&spec), [DiagnosticKind::InvalidAttribute]);
}

// ---------------------------------------------------------------------------------------
// P2: size alignment maps and other repeated keys
// ---------------------------------------------------------------------------------------

#[test]
fn large_size_alignment_maps_are_linear_and_last_wins() {
    let n = 40_000u32;
    let mut map = String::from("<data_organization><size_alignment_map>");
    for size in 1..=n {
        write!(
            map,
            r#"<entry size="{size}" alignment="{}"/>"#,
            size % 16 + 1
        )
        .unwrap();
    }
    // Repeats in the same map and in a later <data_organization>.
    map.push_str(r#"<entry size="8" alignment="2"/></size_alignment_map></data_organization>"#);
    map.push_str(
        r#"<data_organization><size_alignment_map><entry size="16" alignment="3"/><entry size="99999" alignment="4"/></size_alignment_map></data_organization>"#,
    );
    let text = top(&map);
    assert!(text.len() > 1_300_000);
    let spec = parse(&text);
    let org = spec.data_organization.as_ref().unwrap();
    assert_eq!(
        org.size_alignment_map.len(),
        n as usize + 3,
        "declaration order kept"
    );
    assert_eq!(
        org.size_alignment_map[n as usize],
        SizeAlignment {
            size: 8,
            alignment: 2
        }
    );
    // Two repeated sizes, each reported once; plus the repeated <data_organization>.
    let duplicates = kinds(&spec, Severity::Warning)
        .iter()
        .filter(|k| **k == DiagnosticKind::DuplicateEntry)
        .count();
    assert_eq!(duplicates, 3, "{:#?}", spec.diagnostics);
    assert!(errors(&spec).is_empty());

    let resolved = spec.resolved_data_organization(4);
    assert_eq!(resolved.size_alignment_map.len(), n as usize + 1);
    assert!(
        resolved
            .size_alignment_map
            .windows(2)
            .all(|w| w[0].size < w[1].size),
        "sorted, one entry per size"
    );
    assert_eq!(resolved.alignment_for_size(8), Some(2), "later entry wins");
    assert_eq!(
        resolved.alignment_for_size(16),
        Some(3),
        "later element wins"
    );
    assert_eq!(resolved.alignment_for_size(39_999), Some(39_999 % 16 + 1));
    assert_eq!(resolved.alignment_for_size(99_999), Some(4));
    assert_eq!(resolved.alignment_for_size(50_000), None);

    // One work unit per element: the map adds no per-entry rescans. Each entry costs
    // one unit, so the whole file fits in about `n` units and not in fewer.
    let n = u64::from(n);
    assert!(parse_with(&text, &with_work(n + 32)).is_ok());
    assert!(is_limit(
        &parse_with(&text, &with_work(n)),
        "max_cspec_work"
    ));
}

#[test]
fn many_models_and_names_resolve_through_indexes() {
    let n = 3000;
    let mut body = String::from("<properties>");
    for i in 0..n {
        write!(body, r#"<property key="k{i}" value="v"/>"#).unwrap();
    }
    body.push_str("</properties>");
    for i in 0..n {
        write!(
            body,
            r#"<prototype name="m{i}" extrapop="0" stackshift="0"><input/><output/></prototype><modelalias name="a{i}" parent="m{i}"/><callfixup name="f{i}"><pcode><body>x=1;</body></pcode></callfixup>"#
        )
        .unwrap();
    }
    body.push_str(r#"<resolveprototype name="merged">"#);
    for i in (0..n).step_by(3) {
        write!(body, r#"<model name="m{i}"/><model name="a{i}"/>"#).unwrap();
    }
    body.push_str("</resolveprototype>");
    let spec = parse(&top(&body));
    assert!(spec.is_fully_modeled(), "{:#?}", spec.diagnostics);
    assert_eq!(spec.prototypes.len(), n + 1);
    assert_eq!(spec.aliases.len(), n + 1, "plus the implicit __thiscall");
    assert_eq!(spec.merged_models[0].models.len(), 2 * n / 3);
    assert_eq!(spec.call_fixups.len(), n);
    assert_eq!(spec.properties.len(), n);
}

#[test]
fn repeated_names_follow_ghidra() {
    let spec = parse(&top(
        r#"<properties><property key="a" value="1"/></properties>
  <properties><property key="a" value="2"/></properties>
  <callfixup name="f"><pcode><body>x=1;</body></pcode></callfixup>
  <callfixup name="f"><pcode><body>x=2;</body></pcode></callfixup>
  <callotherfixup targetop="op"><pcode><body>x=1;</body></pcode></callotherfixup>
  <callotherfixup targetop="op"><pcode><body>x=2;</body></pcode></callotherfixup>"#,
    ));
    // Properties are a map (last wins, warning); fixups registered twice are rejected.
    assert_eq!(spec.property("a"), Some("2"));
    assert_eq!(
        errors(&spec),
        [
            DiagnosticKind::DuplicateEntry,
            DiagnosticKind::DuplicateEntry
        ]
    );
    assert_eq!(spec.call_fixups.len(), 1);
    assert_eq!(spec.call_fixups[0].pcode.body.as_deref(), Some("x=1;"));
    assert_eq!(spec.callother_fixups.len(), 1);
    assert!(!spec.is_fully_modeled());

    // A top-level <resolveprototype> named __thiscall does not stop Ghidra adding its
    // implicit alias, which then collides; inside <default_proto> it does.
    let spec = parse(
        r#"<compiler_spec>
  <default_proto><prototype name="p" extrapop="0" stackshift="0"><input/><output/></prototype></default_proto>
  <resolveprototype name="__thiscall"><model name="p"/></resolveprototype>
</compiler_spec>"#,
    );
    assert_eq!(errors(&spec), [DiagnosticKind::DuplicateEntry]);
    let spec = parse(
        r#"<compiler_spec>
  <prototype name="p" extrapop="0" stackshift="0"><input/><output/></prototype>
  <default_proto><resolveprototype name="__thiscall"><model name="p"/></resolveprototype></default_proto>
</compiler_spec>"#,
    );
    assert!(spec.is_fully_modeled(), "{:#?}", spec.diagnostics);
    assert!(spec.aliases.is_empty());
}

// ---------------------------------------------------------------------------------------
// P2: Java int range
// ---------------------------------------------------------------------------------------

#[test]
fn nonnegative_int_fields_reject_values_java_would_wrap() {
    let entry = |max: &str| {
        parse(&input(&format!(
            r#"<pentry minsize="1" maxsize="{max}"><addr space="ram" offset="0"/></pentry>"#
        )))
    };
    let spec = entry("2147483647");
    assert!(spec.is_fully_modeled(), "{:#?}", spec.diagnostics);
    assert_eq!(
        spec.prototypes[0].input.entries[0].max_size,
        i32::MAX as u32
    );
    for max in ["2147483648", "0x80000000", "4294967295", "0xffffffff"] {
        let spec = entry(max);
        assert!(spec.prototypes[0].input.entries.is_empty(), "{max}");
        assert_eq!(errors(&spec), [DiagnosticKind::InvalidAttribute], "{max}");
        assert!(!spec.prototypes[0].is_complete(), "{max}");
        assert!(!spec.is_fully_modeled(), "{max}");
    }

    let big = "2147483648";
    for text in [
        top(&format!(
            r#"<data_organization><pointer_size value="{big}"/></data_organization>"#
        )),
        top(&format!(
            r#"<data_organization><size_alignment_map><entry size="{big}" alignment="1"/></size_alignment_map></data_organization>"#
        )),
        top(&format!(r#"<funcptr align="{big}"/>"#)),
        input(&format!(
            r#"<pentry minsize="1" maxsize="4" align="{big}"><register name="r0"/></pentry>"#
        )),
        input(&format!(
            r#"<pentry minsize="1" maxsize="4"><varnode space="ram" offset="0" size="{big}"/></pentry>"#
        )),
        input(&format!(
            r#"<pentry minsize="1" maxsize="4"><addr space="join" piece1="ram:0:{big}"/></pentry>"#
        )),
        input(&format!(
            r#"<pentry minsize="1" maxsize="4"><addr space="join" piece1="r0" size="{big}"/></pentry>"#
        )),
        rule(&format!(
            r#"<datatype name="any" maxsize="{big}"/><goto_stack/>"#
        )),
        proto_extra(&format!(
            r#"<pcode inject="uponentry"><input name="x" size="{big}"/><body>x=1;</body></pcode>"#
        )),
    ] {
        let spec = parse(&text);
        assert!(
            errors(&spec).contains(&DiagnosticKind::InvalidAttribute),
            "{text}: {:#?}",
            spec.diagnostics
        );
        assert!(!spec.is_fully_modeled(), "{text}");
    }
    let spec = parse(&spec_with_input_attrs(&format!(r#"pointermax="{big}""#)));
    assert_eq!(errors(&spec), [DiagnosticKind::InvalidAttribute]);
}

fn spec_with_input_attrs(attrs: &str) -> String {
    input("").replace("<input>", &format!("<input {attrs}>"))
}

// ---------------------------------------------------------------------------------------
// P2: leaf tags
// ---------------------------------------------------------------------------------------

#[test]
fn nested_elements_in_leaf_tags_are_errors() {
    let r0 = r#"<pentry minsize="1" maxsize="4"><register name="r0"/></pentry>"#;
    let cases = [
        rule(r#"<datatype name="any"/><consume storage="general"><future/></consume>"#),
        rule(r#"<datatype name="any"><x/></datatype><goto_stack/>"#),
        rule(r#"<datatype name="any"/><varargs><x/></varargs><goto_stack/>"#),
        rule(r#"<datatype name="any"/><position index="0"><x/></position><goto_stack/>"#),
        rule(r#"<datatype name="any"/><goto_stack/><extra_stack><x/></extra_stack>"#),
        rule(
            r#"<datatype name="any"/><consume_extra storage="general"><x/></consume_extra><goto_stack/>"#,
        ),
        input(r#"<pentry minsize="1" maxsize="4"><register name="r0"><x/></register></pentry>"#),
        proto_extra(
            r#"<unaffected><varnode space="ram" offset="0" size="4"><x/></varnode></unaffected>"#,
        ),
        proto_extra(r#"<localrange><range space="stack"><x/></range></localrange>"#),
        proto_extra(r#"<sharestack first="input"><x/></sharestack>"#),
        proto_extra(
            r#"<pcode inject="uponentry"><input name="a"><x/></input><body>a=1;</body></pcode>"#,
        ),
        proto_extra(r#"<pcode inject="uponentry"><body>a=1;<x/></body></pcode>"#),
        top(r#"<properties><property key="k" value="v"><x/></property></properties>"#),
        top(r#"<data_organization><char_type signed="true"><x/></char_type></data_organization>"#),
        top(
            r#"<data_organization><pointer_size value="4"><x/></pointer_size></data_organization>"#,
        ),
        top(r#"<data_organization><mystery><x/></mystery></data_organization>"#),
        top(
            r#"<data_organization><size_alignment_map><entry size="1" alignment="1"><x/></entry></size_alignment_map></data_organization>"#,
        ),
        top(
            r#"<data_organization><bitfield_packing><use_MS_convention value="true"><x/></use_MS_convention></bitfield_packing></data_organization>"#,
        ),
        top(
            r#"<data_organization><bitfield_packing><mystery><x/></mystery></bitfield_packing></data_organization>"#,
        ),
        top(r#"<stackpointer register="SP" space="ram"><x/></stackpointer>"#),
        top(r#"<spacebase name="gp" register="gp" space="ram"><x/></spacebase>"#),
        top(r#"<funcptr align="4"><x/></funcptr>"#),
        top(r#"<deadcodedelay space="ram" delay="1"><x/></deadcodedelay>"#),
        top(r#"<aggressivetrim signext="true"><x/></aggressivetrim>"#),
        top(r#"<eval_current_prototype name="p"><x/></eval_current_prototype>"#),
        top(r#"<global><range space="ram"><x/></range></global>"#),
        top(r#"<returnaddress><register name="lr"><x/></register></returnaddress>"#),
        top(
            r#"<callfixup name="f"><target name="t"><x/></target><pcode><body>a=1;</body></pcode></callfixup>"#,
        ),
        top(
            r#"<context_data><context_set space="ram"><set name="m" val="1"><x/></set></context_set></context_data>"#,
        ),
        top(&format!(
            r#"<prototype name="q" extrapop="0" stackshift="0"><input>{r0}</input><output/></prototype><modelalias name="a" parent="q"><x/></modelalias>"#
        )),
        top(&format!(
            r#"<prototype name="q" extrapop="0" stackshift="0"><input>{r0}</input><output/></prototype><resolveprototype name="m"><model name="q"><x/></model></resolveprototype>"#
        )),
    ];
    for text in &cases {
        let spec = parse(text);
        let leaf_errors = spec
            .diagnostics
            .iter()
            .filter(|d| {
                d.severity == Severity::Error
                    && d.kind == DiagnosticKind::UnknownElement
                    && d.message.contains("must not contain elements")
            })
            .count();
        assert_eq!(leaf_errors, 1, "{text}: {:#?}", spec.diagnostics);
        assert!(!spec.is_fully_modeled(), "{text}");
    }
    // The review's example: previously complete and fully modeled.
    let spec = parse(&cases[0]);
    let p = &spec.prototypes[0];
    assert!(!p.is_complete());
    assert_eq!(
        p.input.rules[0].action,
        RuleAction::Consume {
            storage: ghidra_languages::StorageClass::General
        },
        "the rule is still captured, but flagged"
    );
    // Many nested elements still give one error.
    let spec = parse(&rule(&format!(
        r#"<datatype name="any"/><consume storage="general">{}</consume>"#,
        "<x/>".repeat(1000)
    )));
    assert_eq!(errors(&spec).len(), 1, "{:#?}", spec.diagnostics);
}

#[test]
fn input_ghidra_ignores_stays_fully_modeled() {
    for text in [
        // Unknown attributes are ignored by Ghidra.
        input("").replace(
            r#"<prototype name="p""#,
            r#"<prototype colour="blue" name="p""#,
        ),
        // Discarded subtrees: unknown top-level, prototype and <properties> children.
        top("<flux><capacitor><x/></capacitor></flux>"),
        proto_extra("<future_tag><nested/></future_tag>"),
        top(r#"<properties><other><x/></other><property key="k" value="v"/></properties>"#),
        // Unknown leaves in <data_organization> and <bitfield_packing> are ignored.
        top(
            r#"<data_organization><mystery value="1"/><bitfield_packing><odd/></bitfield_packing></data_organization>"#,
        ),
    ] {
        let spec = parse(&text);
        assert!(errors(&spec).is_empty(), "{text}: {:#?}", spec.diagnostics);
        assert!(!spec.diagnostics.is_empty(), "{text}: reported as warnings");
        assert!(spec.is_fully_modeled(), "{text}");
    }
}

// ---------------------------------------------------------------------------------------
// P2: p-code payloads
// ---------------------------------------------------------------------------------------

fn fixup(pcode: &str) -> CompilerSpec {
    parse(&top(&format!(r#"<callfixup name="f">{pcode}</callfixup>"#)))
}

#[test]
fn static_payloads_need_a_non_empty_final_body() {
    // Missing, empty and whitespace-only bodies of a static payload are rejected.
    for pcode in [
        r#"<pcode><input name="a"/></pcode>"#,
        r#"<pcode><body/></pcode>"#,
        "<pcode><body> \n\t\r </body></pcode>",
        "<pcode><body><![CDATA[  ]]></body></pcode>",
        // An unrecognised `dynamic` reads as false, so the payload is static.
        r#"<pcode dynamic="sometimes"><body/></pcode>"#,
    ] {
        let spec = fixup(pcode);
        assert!(
            errors(&spec).contains(&DiagnosticKind::MissingElement),
            "{pcode}: {:#?}",
            spec.diagnostics
        );
        assert!(!spec.is_fully_modeled(), "{pcode}");
        // Captured for inspection with the exact text, but never claimed complete.
        assert_eq!(spec.call_fixups.len(), 1, "{pcode}");
    }
    let spec = fixup("<pcode><body> \n\t </body></pcode>");
    assert_eq!(spec.call_fixups[0].pcode.body.as_deref(), Some(" \n\t "));
    assert_eq!(spec.call_fixups[0].pcode.effective_body(), None);

    // Dynamic payloads may omit the body or leave it blank.
    for pcode in [
        r#"<pcode dynamic="true"/>"#,
        r#"<pcode dynamic="true"><input name="a"/><body>  </body></pcode>"#,
    ] {
        let spec = fixup(pcode);
        assert!(spec.is_fully_modeled(), "{pcode}: {:#?}", spec.diagnostics);
    }

    // The body text is kept exactly; Ghidra compiles the trimmed text.
    let spec = fixup(
        "<pcode><input name=\"a\" size=\"4\"/><body><![CDATA[\n  r0 = a;\n]]></body></pcode>",
    );
    assert!(spec.is_fully_modeled(), "{:#?}", spec.diagnostics);
    let pcode = &spec.call_fixups[0].pcode;
    assert_eq!(pcode.body.as_deref(), Some("\n  r0 = a;\n"));
    assert_eq!(pcode.effective_body(), Some("r0 = a;"));
}

#[test]
fn body_must_be_the_last_payload_child() {
    for (pcode, kind) in [
        (
            r#"<pcode><body>a=1;</body><input name="a"/></pcode>"#,
            DiagnosticKind::InconsistentSpec,
        ),
        (
            r#"<pcode><body>a=1;</body><body>a=2;</body></pcode>"#,
            DiagnosticKind::InconsistentSpec,
        ),
        (
            r#"<pcode><widget name="a"/><body>a=1;</body></pcode>"#,
            DiagnosticKind::UnknownElement,
        ),
        (
            r#"<pcode inject="sideways"><body>a=1;</body></pcode>"#,
            DiagnosticKind::InvalidAttribute,
        ),
    ] {
        let spec = fixup(pcode);
        assert_eq!(errors(&spec), [kind], "{pcode}: {:#?}", spec.diagnostics);
        assert!(!spec.is_fully_modeled(), "{pcode}");
    }
    // With a repeated body the first one is the one Ghidra reads.
    let spec = fixup(r#"<pcode><body>a=1;</body><body>a=2;</body></pcode>"#);
    assert_eq!(spec.call_fixups[0].pcode.body.as_deref(), Some("a=1;"));
}

#[test]
fn prototype_injections_follow_ghidra_naming() {
    let entry = r#"<pcode inject="uponentry"><body>a=1;</body></pcode>"#;
    let ret = r#"<pcode inject="uponreturn"><body>a=2;</body></pcode>"#;
    // Ghidra names a payload `uponentry` once any uponentry payload was seen, so only
    // uponreturn followed by uponentry registers two distinct names.
    let ok = parse(&proto_extra(&format!("{ret}{entry}")));
    assert!(ok.is_fully_modeled(), "{:#?}", ok.diagnostics);
    let points: Vec<_> = ok.prototypes[0]
        .injections
        .iter()
        .map(|i| i.point)
        .collect();
    assert_eq!(
        points,
        [InjectionPoint::UponReturn, InjectionPoint::UponEntry]
    );
    for body in [
        format!("{entry}{ret}"),
        format!("{entry}{entry}"),
        format!("{ret}{ret}"),
    ] {
        let spec = parse(&proto_extra(&body));
        assert_eq!(errors(&spec), [DiagnosticKind::DuplicateEntry], "{body}");
        assert!(!spec.prototypes[0].is_complete(), "{body}");
    }
}

// ---------------------------------------------------------------------------------------
// P2: booleans
// ---------------------------------------------------------------------------------------

#[test]
fn char_type_keeps_the_current_value_for_unrecognised_text() {
    let org = |body: &str| {
        parse(&top(&format!(
            "<data_organization>{body}</data_organization>"
        )))
    };

    // First and only <char_type> unrecognised: the default (signed) stays.
    let spec = org(r#"<char_type signed="maybe"/>"#);
    assert_eq!(spec.data_organization.as_ref().unwrap().char_signed, None);
    assert!(spec.resolved_data_organization(4).char_signed);
    assert_eq!(
        kinds(&spec, Severity::Warning),
        [DiagnosticKind::InvalidAttribute]
    );
    assert!(spec.diagnostics[0].message.contains("the default, true"));
    assert!(spec.is_fully_modeled(), "Ghidra accepts it");

    // false, then unrecognised: false stays.
    let spec = org(r#"<char_type signed="false"/><char_type signed="maybe"/>"#);
    assert_eq!(
        spec.data_organization.as_ref().unwrap().char_signed,
        Some(false)
    );
    assert!(!spec.resolved_data_organization(4).char_signed);
    let invalid: Vec<_> = spec
        .diagnostics
        .iter()
        .filter(|d| d.kind == DiagnosticKind::InvalidAttribute)
        .collect();
    assert_eq!(invalid.len(), 1);
    assert!(invalid[0].message.contains("false from the previous"));

    // Recognised spellings (first character) still apply.
    let spec = org(r#"<char_type signed="no"/><char_type signed="Yes"/>"#);
    assert_eq!(
        spec.data_organization.as_ref().unwrap().char_signed,
        Some(false),
        "Y is not y"
    );
    let spec = org(r#"<char_type signed="0"/><char_type signed="true"/>"#);
    assert_eq!(
        spec.data_organization.as_ref().unwrap().char_signed,
        Some(true)
    );
}

#[test]
fn one_argument_booleans_still_read_false() {
    let spec = parse(&top(r#"<aggressivetrim signext="maybe"/>"#));
    assert_eq!(spec.aggressive_trim, Some(false));
    let spec = parse(&spec_with_input_attrs(
        r#"separatefloat="maybe" killedbycall="maybe""#,
    ));
    let list = &spec.prototypes[0].input;
    assert!(
        !list.separate_float,
        "decodeBoolean(value) is false for bad text"
    );
    assert!(!list.killed_by_call);
    assert_eq!(kinds(&spec, Severity::Warning).len(), 2);
    let spec = parse(&top(
        r#"<data_organization><bitfield_packing><type_alignment_enabled value="maybe"/></bitfield_packing></data_organization>"#,
    ));
    assert!(
        !spec
            .resolved_data_organization(4)
            .bitfield_type_alignment_enabled
    );
}

// ---------------------------------------------------------------------------------------
// Attribute order in <pentry>
// ---------------------------------------------------------------------------------------

#[test]
fn pentry_synonyms_follow_document_order() {
    let entry = |attrs: &str| {
        let spec = parse(&input(&format!(
            r#"<pentry minsize="1" maxsize="16" {attrs}><addr space="stack" offset="0"/></pentry>"#
        )));
        (spec.prototypes[0].input.entries.first().cloned(), spec)
    };
    let (e, spec) = entry(r#"align="4" size="8""#);
    assert_eq!(e.unwrap().align, Some(8), "the later attribute wins");
    assert_eq!(
        kinds(&spec, Severity::Warning),
        [DiagnosticKind::DuplicateEntry]
    );
    let (e, _) = entry(r#"size="8" align="4""#);
    assert_eq!(e.unwrap().align, Some(4));
    let (e, _) = entry(r#"storage="float" metatype="general""#);
    assert_eq!(
        e.unwrap().storage_class,
        ghidra_languages::StorageClass::General
    );
    // Ghidra decodes both, so a bad earlier value is still rejected.
    let (e, spec) = entry(r#"align="x" size="4""#);
    assert!(e.is_none());
    assert_eq!(errors(&spec), [DiagnosticKind::InvalidAttribute]);
}
