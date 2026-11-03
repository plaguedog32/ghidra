//! Synthetic catalogs built in temporary directories.

use std::fs;
use std::path::Path;

use ghidra_languages::{
    AssetKind, AssetStatus, Catalog, DiagnosticKind, DiscoveryOptions, Endianness, Error, Limits,
    ProcessorSpec, ResolvedValue, Severity, ValueOrigin,
};

fn write(root: &Path, rel: &str, content: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
}

fn pairs(values: &[ResolvedValue]) -> Vec<(&str, u128)> {
    values.iter().map(|v| (v.name.as_str(), v.value)).collect()
}

const PSPEC: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<processor_spec><programcounter register="pc"/></processor_spec>"#;

fn language(id: &str, extra_attrs: &str, sla: &str, pspec: &str) -> String {
    format!(
        r#"<language processor="Toy" endian="little" size="32" variant="v" version="1.2"
              slafile="{sla}" processorspec="{pspec}" id="{id}" {extra_attrs}>
    <description>toy</description>
    <compiler name="default" spec="toy.cspec" id="default"/>
  </language>"#
    )
}

fn ldefs(languages: &[String]) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<language_definitions>\n{}\n</language_definitions>\n",
        languages.join("\n")
    )
}

/// A minimal valid module at `Proc/data/languages`.
fn toy_module(root: &Path) {
    write(root, "Proc/data/languages/toy.slaspec", "# source");
    write(root, "Proc/data/languages/toy.pspec", PSPEC);
    write(root, "Proc/data/languages/toy.cspec", "<compiler_spec/>");
}

fn kinds(catalog: &Catalog) -> Vec<DiagnosticKind> {
    catalog.diagnostics.iter().map(|d| d.kind.clone()).collect()
}

#[test]
fn escaped_xml_entities_comments_and_cdata() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    toy_module(root);
    write(
        root,
        "Proc/data/languages/toy.ldefs",
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!-- leading comment with <language> markup inside -->
<language_definitions>
  <!--
  <language processor="Hidden" endian="little" size="8" variant="x" version="1"
            slafile="nope.sla" processorspec="nope.pspec" id="commented:out"/>
  -->
  <language processor="Toy" endian="little" size="0x20" variant="A&amp;B &quot;q&quot;"
            version="1.2" slafile="toy.sla" processorspec="toy.pspec"
            id="Toy:LE:32:A&amp;B">
    <description>Toy &lt;test&gt; &#x41;&#66; <![CDATA[<raw & cdata>]]> <!-- note --> end</description>
    <compiler name="Visual &apos;C&apos;" spec="toy.cspec" id="default"/>
    <external_name tool="gnu" name="toy&amp;co"/>
    <external_name tool="" name="dropped"/>
  </language>
</language_definitions>
"#,
    );
    let catalog = Catalog::discover(root).unwrap();
    assert!(catalog.diagnostics.is_empty(), "{:#?}", catalog.diagnostics);
    assert_eq!(catalog.languages.len(), 1);
    let toy = catalog.by_id("Toy:LE:32:A&B").unwrap();
    assert_eq!(toy.variant, "A&B \"q\"");
    assert_eq!(toy.size, 32, "0x20 decodes like SpecXmlUtils.decodeInt");
    assert_eq!(toy.description, "Toy <test> AB <raw & cdata>  end");
    assert_eq!(toy.compilers[0].name, "Visual 'C'");
    assert_eq!(toy.external_names.len(), 1);
    assert_eq!(toy.external_names[0].name, "toy&co");
    assert!(catalog.by_id("commented:out").is_none());
}

#[test]
fn undeclared_entities_and_dtds_are_rejected_without_expansion() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    toy_module(root);
    write(
        root,
        "Proc/data/languages/a_entity.ldefs",
        r#"<language_definitions><language id="x">&custom;</language></language_definitions>"#,
    );
    write(
        root,
        "Proc/data/languages/b_dtd.ldefs",
        r#"<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;">]>
<language_definitions>&lol2;</language_definitions>"#,
    );
    write(
        root,
        "Proc/data/languages/c_ok.ldefs",
        &ldefs(&[language("Toy:LE:32:v", "", "toy.sla", "toy.pspec")]),
    );
    let catalog = Catalog::discover(root).unwrap();
    assert_eq!(catalog.languages.len(), 1, "valid file still loads");
    let malformed: Vec<_> = catalog
        .diagnostics
        .iter()
        .filter(|d| d.kind == DiagnosticKind::MalformedXml)
        .collect();
    assert_eq!(malformed.len(), 2, "{:#?}", catalog.diagnostics);
    assert!(malformed[0].message.contains("custom"));
    assert!(malformed[1].message.contains("DOCTYPE"));
    assert!(malformed.iter().all(|d| d.severity == Severity::Error));
}

#[test]
fn malformed_xml_variants_are_reported_per_file() {
    let cases = [
        ("unclosed", "<language_definitions><language>"),
        ("mismatch", "<language_definitions></language>"),
        (
            "two_roots",
            "<language_definitions/><language_definitions/>",
        ),
        ("text_outside", "junk<language_definitions/>"),
        ("bad_attr", "<language_definitions a=\"1\" a=\"2\"/>"),
        ("empty", ""),
        (
            "latin1",
            "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><language_definitions/>",
        ),
    ];
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    for (name, body) in cases {
        write(root, &format!("Proc/data/languages/{name}.ldefs"), body);
    }
    let catalog = Catalog::discover(root).unwrap();
    assert!(catalog.languages.is_empty());
    assert_eq!(catalog.ldefs_files.len(), cases.len());
    let bad = catalog
        .diagnostics
        .iter()
        .filter(|d| d.kind == DiagnosticKind::MalformedXml)
        .count();
    assert_eq!(bad, cases.len(), "{:#?}", catalog.diagnostics);
    // Wrong root element is also an error, not a silent empty file.
    write(root, "Other/x.ldefs", "<processor_spec/>");
    let catalog = Catalog::discover(root).unwrap();
    assert!(
        catalog
            .diagnostics
            .iter()
            .any(|d| d.message.contains("expected <language_definitions>"))
    );
}

#[test]
fn variants_and_sla_to_slaspec_mapping() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    toy_module(root);
    write(root, "Proc/data/languages/plain.slaspec", "");
    write(root, "Proc/data/languages/sub/nested.slaspec", "");
    write(
        root,
        "Proc/data/languages/toy.ldefs",
        &ldefs(&[
            language("Toy:LE:32:a", "", "toy.sla", "toy.pspec"),
            language("Toy:LE:32:b", "", "toy.sla", "toy.pspec"),
            language("Toy:LE:32:c", "", "plain", "toy.pspec"),
            language("Toy:LE:32:d", "", "sub/nested.sla", "toy.pspec"),
            language(
                "Toy:LE:32:e",
                "deprecated=\"true\" hidden=\"yes\"",
                "absent.sla",
                "toy.pspec",
            ),
            language(
                "Toy:BE:32:f",
                "instructionEndian=\"little\"",
                "toy.sla",
                "toy.pspec",
            )
            .replace("endian=\"little\" size", "endian=\"big\" size"),
        ]),
    );
    let catalog = Catalog::discover(root).unwrap();
    assert_eq!(catalog.languages.len(), 6, "{:#?}", catalog.diagnostics);
    let src = |id: &str| catalog.by_id(id).unwrap().source.clone();
    assert_eq!(
        src("Toy:LE:32:a").path,
        src("Toy:LE:32:b").path,
        "variants share source"
    );
    assert!(src("Toy:LE:32:a").path.unwrap().ends_with("toy.slaspec"));
    assert!(src("Toy:LE:32:c").path.unwrap().ends_with("plain.slaspec"));
    assert!(
        src("Toy:LE:32:d")
            .path
            .unwrap()
            .ends_with(Path::new("sub").join("nested.slaspec"))
    );

    // Missing source keeps the language and says where it was expected.
    let e = catalog.by_id("Toy:LE:32:e").unwrap();
    assert!(e.deprecated && e.hidden);
    assert_eq!(e.source.status, AssetStatus::Missing);
    assert!(e.source.path.as_ref().unwrap().ends_with("absent.slaspec"));
    assert!(e.processor_spec.is_available());
    let d: Vec<_> = catalog.diagnostics_for("Toy:LE:32:e").collect();
    assert_eq!(d.len(), 1);
    assert_eq!(
        d[0].kind,
        DiagnosticKind::MissingAsset(AssetKind::SleighSource)
    );
    assert!(d[0].message.contains("absent.slaspec"));

    let f = catalog.by_id("Toy:BE:32:f").unwrap();
    assert_eq!(f.endian, Endianness::Big);
    assert_eq!(f.instruction_endian, Endianness::Little);
    assert_eq!(f.version.major, 1);
    assert_eq!(f.version.minor, 2);
}

#[test]
fn unknown_attributes_and_elements_warn_but_keep_language() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    toy_module(root);
    let lang = language(
        "Toy:LE:32:v",
        "futureAttr=\"1\" deprecated=\"maybe\"",
        "toy.sla",
        "toy.pspec",
    )
    .replace("<description>", "<future_tag/><description>");
    write(root, "Proc/data/languages/toy.ldefs", &ldefs(&[lang]));
    let catalog = Catalog::discover(root).unwrap();
    let toy = catalog.by_id("Toy:LE:32:v").unwrap();
    assert!(!toy.deprecated, "unrecognised boolean is false like Ghidra");
    let k = kinds(&catalog);
    assert!(k.contains(&DiagnosticKind::UnknownAttribute));
    assert!(k.contains(&DiagnosticKind::UnknownElement));
    assert!(k.contains(&DiagnosticKind::InvalidAttribute));
    assert!(
        catalog
            .diagnostics
            .iter()
            .all(|d| d.severity == Severity::Warning)
    );
}

#[test]
fn invalid_required_fields_drop_only_that_language() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    toy_module(root);
    write(
        root,
        "Proc/data/languages/toy.ldefs",
        &ldefs(&[
            language("Toy:LE:32:ok", "", "toy.sla", "toy.pspec"),
            language("Toy:LE:32:noproc", "", "toy.sla", "toy.pspec")
                .replace("processor=\"Toy\" ", ""),
            language("Toy:XX:32:endian", "", "toy.sla", "toy.pspec")
                .replace("endian=\"little\"", "endian=\"middle\""),
            language("Toy:LE:32:size", "", "toy.sla", "toy.pspec")
                .replace("size=\"32\"", "size=\"wide\""),
            language("Toy:LE:32:version", "", "toy.sla", "toy.pspec")
                .replace("version=\"1.2\"", "version=\"one\""),
        ]),
    );
    let catalog = Catalog::discover(root).unwrap();
    let ids: Vec<_> = catalog.languages.iter().map(|l| l.id.as_str()).collect();
    assert_eq!(ids, ["Toy:LE:32:ok"]);
    let errors: Vec<_> = catalog
        .diagnostics
        .iter()
        .filter(|d| d.severity == Severity::Error)
        .collect();
    assert_eq!(errors.len(), 4, "{errors:#?}");
    assert_eq!(errors[0].kind, DiagnosticKind::MissingAttribute);
    assert_eq!(errors[0].language_id.as_deref(), Some("Toy:LE:32:noproc"));
}

#[test]
fn duplicate_language_and_compiler_ids() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    toy_module(root);
    write(
        root,
        "Proc/data/languages/a.ldefs",
        &ldefs(
            &[language("Toy:LE:32:v", "", "toy.sla", "toy.pspec").replace(
                "</language>",
                "<compiler name=\"again\" spec=\"toy.cspec\" id=\"default\"/></language>",
            )],
        ),
    );
    write(
        root,
        "Proc/data/languages/b.ldefs",
        &ldefs(&[language("Toy:LE:32:v", "", "toy.sla", "toy.pspec")
            .replace("toy</desc", "second</desc")]),
    );
    let catalog = Catalog::discover(root).unwrap();
    assert_eq!(catalog.languages.len(), 1);
    let kept = &catalog.languages[0];
    assert_eq!(kept.description, "toy", "first definition wins");
    assert_eq!(kept.compilers.len(), 1);
    let k = kinds(&catalog);
    assert!(k.contains(&DiagnosticKind::DuplicateLanguageId));
    assert!(k.contains(&DiagnosticKind::DuplicateCompilerId));
    let dup = catalog
        .diagnostics
        .iter()
        .find(|d| d.kind == DiagnosticKind::DuplicateLanguageId)
        .unwrap();
    assert!(dup.path.as_ref().unwrap().ends_with("b.ldefs"));
    assert!(dup.message.contains("a.ldefs"));
}

#[test]
fn oversized_and_deep_documents_hit_limits() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    toy_module(root);
    let limits = Limits {
        max_file_bytes: 4096,
        max_depth: 8,
        max_elements: 50,
        ..Limits::default()
    };
    write(
        root,
        "Proc/data/languages/big.ldefs",
        &format!(
            "<language_definitions><!-- {} --></language_definitions>",
            "x".repeat(5000)
        ),
    );
    write(
        root,
        "Proc/data/languages/deep.ldefs",
        &format!(
            "<language_definitions>{}{}</language_definitions>",
            "<a>".repeat(20),
            "</a>".repeat(20)
        ),
    );
    write(
        root,
        "Proc/data/languages/many.ldefs",
        &format!(
            "<language_definitions>{}</language_definitions>",
            "<x/>".repeat(60)
        ),
    );
    write(
        root,
        "Proc/data/languages/ok.ldefs",
        &ldefs(&[language("Toy:LE:32:v", "", "toy.sla", "toy.pspec")]),
    );
    let options = DiscoveryOptions {
        limits,
        ..DiscoveryOptions::default()
    };
    let catalog = Catalog::discover_with(root, &options).unwrap();
    assert_eq!(catalog.languages.len(), 1);
    let limited = catalog
        .diagnostics
        .iter()
        .filter(|d| d.kind == DiagnosticKind::LimitExceeded)
        .count();
    assert_eq!(limited, 3, "{:#?}", catalog.diagnostics);

    // Language count and walk-entry limits.
    let options = DiscoveryOptions {
        limits: Limits {
            max_languages: 0,
            ..Limits::default()
        },
        ..DiscoveryOptions::default()
    };
    let catalog = Catalog::discover_with(root, &options).unwrap();
    assert!(catalog.languages.is_empty());
    assert!(kinds(&catalog).contains(&DiagnosticKind::LimitExceeded));
    let options = DiscoveryOptions {
        limits: Limits {
            max_walk_entries: 2,
            ..Limits::default()
        },
        ..DiscoveryOptions::default()
    };
    let catalog = Catalog::discover_with(root, &options).unwrap();
    assert!(catalog.has_errors());
    assert!(
        catalog
            .diagnostics
            .iter()
            .any(|d| d.message.contains("incomplete"))
    );

    // Oversized pspec text.
    let tiny = Limits {
        max_file_bytes: 10,
        ..Limits::default()
    };
    assert!(matches!(
        ProcessorSpec::parse_str(PSPEC, None, &tiny),
        Err(Error::Limit { .. })
    ));
}

#[test]
fn asset_paths_are_confined_to_the_catalog_root() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("catalog");
    toy_module(&root);
    // A real file just outside the root must not be reachable.
    write(dir.path(), "outside.pspec", PSPEC);
    write(&root, "Shared/common/shared.pspec", PSPEC);
    write(
        &root,
        "Proc/data/languages/toy.ldefs",
        &ldefs(&[
            language("t:escape", "", "toy.sla", "../../../../outside.pspec"),
            language(
                "t:deep_escape",
                "",
                "toy.sla",
                "../../../../../../../../etc/passwd.pspec",
            ),
            language("t:abs_unix", "", "toy.sla", "/etc/toy.pspec"),
            language("t:abs_drive", "", "toy.sla", "C:/Windows/toy.pspec"),
            language("t:abs_unc", "", "toy.sla", "\\\\server\\share\\toy.pspec"),
            language(
                "t:backslash_escape",
                "",
                "..\\..\\..\\..\\outside.sla",
                "toy.pspec",
            ),
            language(
                "t:cross_dir",
                "",
                "toy.sla",
                "../../../Shared/common/shared.pspec",
            ),
            language(
                "t:manual",
                "manualindexfile=\"../manuals/none.idx\"",
                "toy.sla",
                "toy.pspec",
            ),
        ]),
    );
    let catalog = Catalog::discover(&root).unwrap();
    assert_eq!(catalog.languages.len(), 8, "languages are kept and flagged");
    for id in [
        "t:escape",
        "t:deep_escape",
        "t:abs_unix",
        "t:abs_drive",
        "t:abs_unc",
    ] {
        let l = catalog.by_id(id).unwrap();
        assert_eq!(l.processor_spec.status, AssetStatus::Rejected, "{id}");
        assert!(l.processor_spec.path.is_none());
        match l.load_processor_spec() {
            Err(Error::AssetUnavailable { asset, status, .. }) => {
                assert_eq!(asset, AssetKind::ProcessorSpec);
                assert_eq!(status, AssetStatus::Rejected);
            }
            other => panic!("{id}: expected AssetUnavailable, got {other:?}"),
        }
        assert!(
            catalog
                .diagnostics_for(id)
                .any(|d| d.kind == DiagnosticKind::RejectedAssetPath(AssetKind::ProcessorSpec))
        );
    }
    let bs = catalog.by_id("t:backslash_escape").unwrap();
    assert_eq!(bs.source.status, AssetStatus::Rejected);

    let cross = catalog.by_id("t:cross_dir").unwrap();
    assert_eq!(cross.processor_spec.status, AssetStatus::Present);
    let spec = cross.load_processor_spec().unwrap();
    assert_eq!(spec.program_counter.as_deref(), Some("pc"));

    let manual = catalog
        .by_id("t:manual")
        .unwrap()
        .manual_index
        .clone()
        .unwrap();
    assert_eq!(manual.status, AssetStatus::Missing);
    assert!(
        manual
            .path
            .unwrap()
            .starts_with(std::path::absolute(&root).unwrap())
    );
}

#[test]
fn fallback_search_by_name_and_ambiguity() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    toy_module(root);
    write(root, "Other/data/languages/unique.pspec", PSPEC);
    write(root, "A/data/languages/twin.pspec", PSPEC);
    write(root, "B/data/languages/twin.pspec", PSPEC);
    write(
        root,
        "Proc/data/languages/toy.ldefs",
        &ldefs(&[
            language("t:unique", "", "toy.sla", "unique.pspec"),
            language("t:twin", "", "toy.sla", "twin.pspec"),
        ]),
    );
    let catalog = Catalog::discover(root).unwrap();
    let unique = catalog.by_id("t:unique").unwrap();
    assert_eq!(unique.processor_spec.status, AssetStatus::FoundBySearch);
    assert!(unique.load_processor_spec().is_ok());
    let twin = catalog.by_id("t:twin").unwrap();
    assert_eq!(twin.processor_spec.status, AssetStatus::Ambiguous);
    assert!(twin.load_processor_spec().is_err());
    assert!(
        catalog
            .diagnostics_for("t:twin")
            .any(|d| d.kind == DiagnosticKind::AmbiguousAsset(AssetKind::ProcessorSpec))
    );
}

#[test]
fn test_resources_and_build_dirs_are_skipped_by_default() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    toy_module(root);
    let body = ldefs(&[language("t:x", "", "toy.sla", "toy.pspec")]);
    write(
        root,
        "Emu/src/test/resources/mock.ldefs",
        &body.replace("t:x", "t:mock"),
    );
    write(
        root,
        "Proc/build/data/languages/built.ldefs",
        &body.replace("t:x", "t:built"),
    );
    write(root, "Proc/data/languages/toy.ldefs", &body);
    let catalog = Catalog::discover(root).unwrap();
    let ids: Vec<_> = catalog.languages.iter().map(|l| l.id.as_str()).collect();
    assert_eq!(ids, ["t:x"]);
    let options = DiscoveryOptions {
        include_test_resources: true,
        ..DiscoveryOptions::default()
    };
    let catalog = Catalog::discover_with(root, &options).unwrap();
    assert!(catalog.by_id("t:mock").is_some());
    assert!(catalog.by_id("t:built").is_none());
}

#[test]
fn invalid_root_is_an_error() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(
        Catalog::discover(&dir.path().join("missing")),
        Err(Error::InvalidRoot { .. })
    ));
    write(dir.path(), "file.txt", "x");
    assert!(matches!(
        Catalog::discover(&dir.path().join("file.txt")),
        Err(Error::InvalidRoot { .. })
    ));
}

#[cfg(any(unix, windows))]
#[test]
fn symlinked_directories_are_not_followed() {
    let dir = tempfile::tempdir().unwrap();
    let outside = dir.path().join("outside");
    write(
        &outside,
        "data/languages/evil.ldefs",
        &ldefs(&[language("t:evil", "", "toy.sla", "toy.pspec")]),
    );
    let root = dir.path().join("root");
    toy_module(&root);
    #[cfg(unix)]
    let made = std::os::unix::fs::symlink(&outside, root.join("link"));
    // Junctions need no privilege on Windows and must be treated like symlinks.
    #[cfg(windows)]
    let made = std::os::windows::fs::symlink_dir(&outside, root.join("link")).or_else(|_| {
        std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(root.join("link"))
            .arg(&outside)
            .output()
            .map_err(|e| e.to_string())
            .and_then(|o| {
                if o.status.success() {
                    Ok(())
                } else {
                    Err("mklink failed".into())
                }
            })
    });
    if made.is_err() {
        eprintln!("symlink creation not permitted here; skipping");
        return;
    }
    assert!(
        root.join("link/data/languages/evil.ldefs").exists(),
        "link resolves"
    );
    let catalog = Catalog::discover(&root).unwrap();
    assert!(catalog.by_id("t:evil").is_none());
    assert!(kinds(&catalog).contains(&DiagnosticKind::SymlinkSkipped));
}

const CONTEXT_PSPEC: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<processor_spec>
  <properties>
    <property key="a" value="1"/>
    <property key="a" value="2"/>
    <property key="escaped" value="x &lt; y &amp;&amp; z"/>
  </properties>
  <programcounter register="PC"/>
  <register_data><register name="r0" group="G"/></register_data>
  <context_data>
    <context_set space="ram">
      <set name="mode" val="0"/>
      <set name="width" val="0x2"/>
    </context_set>
    <tracked_set space="ram">
      <set name="DF" val="0"/>
    </tracked_set>
    <context_set space="ram" first="0x1000" last="0x1fff">
      <set name="mode" val="1"/>
    </context_set>
    <context_set space="ram" first="0x1800" last="0x18ff">
      <set name="mode" val="2"/>
      <set name="extra" val="010"/>
    </context_set>
    <tracked_set space="ram" first="0x1000" last="0x10ff">
      <set name="bank" val="3"/>
    </tracked_set>
    <context_set space="rom">
      <set name="mode" val="7"/>
    </context_set>
    <context_set space="ram" first="0x9000">
      <set name="tail" val="1"/>
    </context_set>
  </context_data>
</processor_spec>
"#;

#[test]
fn ranged_context_versus_globals_and_tracked_separation() {
    let spec = ProcessorSpec::parse_str(CONTEXT_PSPEC, None, &Limits::default()).unwrap();
    assert_eq!(spec.program_counter.as_deref(), Some("PC"));
    assert_eq!(spec.property("a"), Some("2"), "last duplicate wins");
    assert_eq!(spec.property("escaped"), Some("x < y && z"));
    assert_eq!(spec.unmodeled_elements, ["register_data"]);
    assert_eq!(spec.context_sets.len(), 5);
    assert_eq!(spec.tracked_sets.len(), 2);
    assert_eq!(spec.referenced_spaces(), ["ram", "rom"]);

    // Globals: only unranged context blocks for that space.
    assert_eq!(
        pairs(&spec.context_globals("ram")),
        [("mode", 0), ("width", 2)]
    );
    assert_eq!(pairs(&spec.context_globals("rom")), [("mode", 7)]);
    assert_eq!(pairs(&spec.tracked_globals("ram")), [("DF", 0)]);

    // Outside every range: same as globals.
    assert_eq!(
        pairs(&spec.context_at("ram", 0x10)),
        [("mode", 0), ("width", 2)]
    );
    // Ranged override, later blocks win where they overlap.
    assert_eq!(
        pairs(&spec.context_at("ram", 0x1000)),
        [("mode", 1), ("width", 2)]
    );
    assert_eq!(
        pairs(&spec.context_at("ram", 0x1850)),
        [("mode", 2), ("width", 2), ("extra", 10)],
        "set values with leading zeros are decimal in SleighLanguage"
    );
    assert_eq!(
        pairs(&spec.context_at("ram", 0x1fff)),
        [("mode", 1), ("width", 2)]
    );
    assert_eq!(
        pairs(&spec.context_at("ram", 0x2000)),
        [("mode", 0), ("width", 2)]
    );
    // Open upper bound.
    assert_eq!(
        pairs(&spec.context_at("ram", u64::MAX)),
        [("mode", 0), ("width", 2), ("tail", 1)]
    );
    let at = spec.context_at("ram", 0x1850);
    assert_eq!(
        at[0].origin,
        ValueOrigin::Ranged {
            block: 2,
            first: Some(0x1800),
            last: Some(0x18ff)
        }
    );
    assert_eq!(at[1].origin, ValueOrigin::SpaceWide { block: 0 });

    // Tracked registers stay out of decode context and vice versa.
    assert_eq!(
        pairs(&spec.tracked_at("ram", 0x1080)),
        [("DF", 0), ("bank", 3)]
    );
    assert_eq!(pairs(&spec.tracked_at("ram", 0x1100)), [("DF", 0)]);
    assert!(
        spec.context_at("ram", 0x1080)
            .iter()
            .all(|v| v.name != "bank" && v.name != "DF")
    );
    assert!(
        spec.tracked_at("ram", 0x1850)
            .iter()
            .all(|v| v.name != "mode")
    );

    // Diagnostics: the repeated property and the open-ended range.
    let k: Vec<_> = spec.diagnostics.iter().map(|d| d.kind.clone()).collect();
    assert_eq!(
        k,
        [
            DiagnosticKind::DuplicateEntry,
            DiagnosticKind::UnsupportedForm
        ]
    );
    assert_eq!(spec.diagnostics[1].line, Some(31));
}

#[test]
fn unsupported_and_invalid_context_forms_are_reported() {
    let text = r#"<processor_spec>
  <context_data>
    <register_set space="ram"><set name="x" val="1"/></register_set>
    <context_set><set name="nospace" val="1"/></context_set>
    <context_set space="ram" first="0x20" last="0x10"><set name="backwards" val="1"/></context_set>
    <context_set space="ram" first="0X10" last="0x20"><set name="badhex" val="1"/></context_set>
    <context_set space="ram" color="red">
      <set name="neg" val="-1"/>
      <set name="junk" val="zz"/>
      <set name="huge" val="0x1ffffffffffffffffffffffffffffffff"/>
      <set name="noval"/>
      <set name="ok" val="5" extra="1"/>
      <unexpected/>
    </context_set>
    <tracked_set space="ram"/>
  </context_data>
  <mystery/>
</processor_spec>"#;
    let spec =
        ProcessorSpec::parse_str(text, Some(Path::new("t.pspec")), &Limits::default()).unwrap();
    assert_eq!(spec.context_sets.len(), 1);
    assert_eq!(spec.tracked_sets.len(), 1);
    assert_eq!(
        pairs(&spec.context_globals("ram")),
        [("junk", 0), ("ok", 5)]
    );
    let msgs: Vec<String> = spec.diagnostics.iter().map(|d| d.message.clone()).collect();
    let has = |needle: &str| msgs.iter().any(|m| m.contains(needle));
    assert!(has("unsupported <register_set>"), "{msgs:#?}");
    assert!(has("has no `space`"));
    assert!(has("first 0x20 > last 0x10"));
    assert!(has("`first=\"0X10\"`"));
    assert!(has("ignored attribute `color`"));
    assert!(has("negative value `-1`"));
    assert!(has("using 0 like Ghidra"));
    assert!(has("exceeds 128 bits"));
    assert!(has("needs `name` and `val`"));
    assert!(has("ignored attribute `extra`"));
    assert!(has("unsupported <unexpected>"));
    assert!(has("contains no <set>"));
    assert!(has("ignored element <mystery>"));
    assert!(
        spec.diagnostics
            .iter()
            .all(|d| d.path.as_deref() == Some(Path::new("t.pspec")))
    );

    assert!(matches!(
        ProcessorSpec::parse_str("<language_definitions/>", None, &Limits::default()),
        Err(Error::Schema { .. })
    ));
    assert!(matches!(
        ProcessorSpec::parse_str("<processor_spec><context_data>", None, &Limits::default()),
        Err(Error::Xml { .. })
    ));
}
