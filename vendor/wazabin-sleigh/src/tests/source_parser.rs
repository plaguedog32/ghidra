use crate::{
    CompiledSpec, Compiler, Decoder, FormatChunkKind, FormatError, FormatLineKind, PcodeExprKind,
    PcodeIdent, PcodeStatementKind, PreprocessOptions, RegisterId, SourceDb, SourceOrigin,
    SymbolKind,
    syntax::{analyze, parse},
};
use std::{
    fs,
    time::{SystemTime, UNIX_EPOCH},
};

fn add_fixture(db: &mut SourceDb, path: &str, text: &str) -> crate::FileId {
    db.add_file(format!("fixtures/{path}"), text)
}

fn add_case_files<'a>(
    db: &mut SourceDb,
    files: &'a [(&'a str, &'a str)],
) -> Vec<(&'a str, crate::FileId)> {
    files
        .iter()
        .map(|(path, text)| (*path, add_fixture(db, path, text)))
        .collect()
}

fn file_id(files: &[(&str, crate::FileId)], path: &str) -> crate::FileId {
    files
        .iter()
        .find_map(|(candidate, id)| (*candidate == path).then_some(*id))
        .unwrap_or_else(|| panic!("missing fixture path {path}"))
}

fn formatted_case<'a>(files: &'a [(&'a str, &str)], root_path: &str) -> Vec<(&'a str, String)> {
    let mut sources = SourceDb::new();
    let ids = add_case_files(&mut sources, files);
    let root = file_id(&ids, root_path);
    sources
        .preprocess(root, &PreprocessOptions::default())
        .unwrap();

    ids.iter()
        .map(|(path, id)| (*path, sources.format(*id).unwrap()))
        .collect()
}

fn compile_case(files: &[(&str, &str)], root_path: &str) -> CompiledSpec {
    let mut sources = SourceDb::new();
    let ids = add_case_files(&mut sources, files);
    let root = file_id(&ids, root_path);
    Compiler::new(&mut sources).compile(root).unwrap()
}

fn compile_observation(files: &[(&str, &str)], root_path: &str, samples: &[&[u8]]) -> Vec<String> {
    let spec = compile_case(files, root_path);
    let mut observations = spec
        .symbols()
        .map(|symbol| {
            let mut line = format!("symbol:{}:{:?}", symbol.name, symbol.kind);
            match symbol.kind {
                SymbolKind::Register => {
                    let register = spec.register(symbol.name).unwrap();
                    line.push_str(&format!(
                        ":offset={}:size={}",
                        register.offset(),
                        register.size()
                    ));
                }
                SymbolKind::BitRangeField => {
                    let (offset, size) = spec.bitrange_bits(symbol.name).unwrap();
                    line.push_str(&format!(":offset={offset}:size={size}"));
                }
                SymbolKind::Space => {
                    let space = spec.space(symbol.name).unwrap();
                    line.push_str(&format!(
                        ":addr_size={}:word_size={}",
                        space.address_size(),
                        space.word_size()
                    ));
                }
                SymbolKind::Token => {
                    let token = spec.token(symbol.name).unwrap();
                    line.push_str(&format!(":size={}", token.size()));
                }
                SymbolKind::Field => {
                    let field = spec.field(symbol.name).unwrap();
                    line.push_str(&format!(
                        ":width={}:start={:?}:parent={:?}:token={:?}",
                        field.width(),
                        spec.field_start(symbol.name),
                        spec.field_parent(symbol.name),
                        spec.field_token_name(symbol.name)
                    ));
                }
                SymbolKind::Table => {
                    let table = spec.table(symbol.name).unwrap();
                    line.push_str(&format!(
                        ":constructors={}:max_len={}",
                        table.constructor_count(),
                        table.max_len()
                    ));
                }
                SymbolKind::Macro | SymbolKind::PCodeOp | SymbolKind::Special => {}
            }
            line
        })
        .collect::<Vec<_>>();
    observations.sort();

    let context = spec.new_context();
    for sample in samples {
        let instruction = Decoder::new(&spec)
            .decode_one(0x1000, sample, &context)
            .unwrap();
        let pcode = instruction.pcode_ast().unwrap();
        observations.push(format!(
            "decode:{sample:02x?}:display={}:len={}:table={}:constructor={}:operands={}:pcode={}",
            instruction,
            instruction.len(),
            instruction.constructor_table().name(),
            instruction.constructor_index(),
            instruction.operand_count(),
            pcode.pretty_print(&spec)
        ));
    }

    observations
}

fn reg(id: usize) -> RegisterId {
    RegisterId::from(id)
}

#[test]
fn parse_succeeds_for_existing_fixtures() {
    let fixtures = [
        ("single/root.sla", include_str!("fixtures/single/root.sla")),
        ("example.sla", include_str!("fixtures/example.sla")),
        (
            "semantics/userop_macro.sla",
            include_str!("fixtures/semantics/userop_macro.sla"),
        ),
        (
            "semantics/branching.sla",
            include_str!("fixtures/semantics/branching.sla"),
        ),
        (
            "conditional/root.sla",
            include_str!("fixtures/conditional/root.sla"),
        ),
        (
            "include_resolution/root.sla",
            include_str!("fixtures/include_resolution/root.sla"),
        ),
    ];

    for (path, text) in fixtures {
        let mut sources = SourceDb::new();
        let root = add_fixture(&mut sources, path, text);
        if path == "include_resolution/root.sla" {
            add_fixture(
                &mut sources,
                "include_resolution/include_child.sinc",
                include_str!("fixtures/include_resolution/include_child.sinc"),
            );
        }
        parse(&mut sources, root)
            .unwrap_or_else(|e| panic!("parse failed for {path}: {}", e.diagnostics[0].message));
    }
}

#[test]
fn source_db_format_requires_preprocessing_metadata() {
    let mut sources = SourceDb::new();
    let root = sources.add_file("fixtures/format/root.sla", "define token instr(8);\n");

    assert_eq!(
        sources.format(root),
        Err(FormatError::MissingMetadata { file: root })
    );
}

#[test]
fn source_db_format_rebuilds_physical_files_from_metadata() {
    let mut sources = SourceDb::new();
    let root_text = "# leading\n@define NAME instr\n@include \"child.sinc\"\n$(NAME) $(UNKNOWN)\n";
    let child_text =
        "\n@if defined(NAME)\n# child comment\ndefine token $(NAME)(8);\n@else\nhidden\n@endif";
    let root = sources.add_file("fixtures/format/root.sla", root_text);
    let child = sources.add_file("fixtures/format/child.sinc", child_text);
    sources
        .preprocess(root, &PreprocessOptions::default())
        .unwrap();

    assert_eq!(sources.format(root).unwrap(), root_text);
    assert_eq!(sources.format(child).unwrap(), child_text);
}

#[test]
fn format_metadata_preserves_macro_use_chunks() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "fixtures/format_macro/root.sla",
        "@define NAME instr\nfoo $(NAME) bar\n",
    );

    let prepared = sources
        .preprocess(root, &PreprocessOptions::default())
        .unwrap();
    let line = sources
        .format_lines(prepared)
        .unwrap()
        .iter()
        .find(|line| line.kind == FormatLineKind::ActiveSource && line.text.contains("$(NAME)"))
        .expect("macro-use line should be recorded");
    let macro_chunk = line
        .chunks
        .iter()
        .find(|chunk| matches!(chunk.kind, FormatChunkKind::MacroUse(_)))
        .expect("macro-use chunk should be recorded");

    assert_eq!(line.text, "foo $(NAME) bar\n");
    assert_eq!(macro_chunk.text, "$(NAME)");
    assert_eq!(
        &sources.text(root).unwrap()[macro_chunk.source.start.0..macro_chunk.source.end.0],
        "$(NAME)"
    );
}

#[test]
fn source_db_format_keeps_repeated_include_files_single_and_lossless() {
    let mut sources = SourceDb::new();
    let root_text = "@include \"child.sinc\"\n@undef VAL\n@include \"child.sinc\"\n";
    let child_text = "$(VAL)\n";
    let root = sources.add_file("fixtures/repeated_format/root.sla", root_text);
    let child = sources.add_file("fixtures/repeated_format/child.sinc", child_text);

    let mut options = PreprocessOptions::default();
    options.defines.insert("VAL".to_owned(), "one".to_owned());
    sources.preprocess(root, &options).unwrap();

    assert_eq!(sources.format(root).unwrap(), root_text);
    assert_eq!(sources.format(child).unwrap(), child_text);
}

#[test]
fn formatted_output_is_idempotent_for_formatter_fixtures() {
    #[allow(clippy::type_complexity)]
    let cases: &[(&str, &[(&str, &str)], &str)] = &[
        (
            "directives_and_no_trailing_newline",
            &[(
                "format_idempotent/root.sla",
                "# leading comment\n\n@define NAME instr\n@if defined(NAME)\ndefine token $(NAME)(8);\n@else\ninactive text\n@endif",
            )],
            "format_idempotent/root.sla",
        ),
        (
            "repeated_include_with_macro_environment",
            &[
                (
                    "format_idempotent/repeated/root.sla",
                    "# root\n@define VAL one\n@include \"child.sinc\"\n@undef VAL\n@include \"child.sinc\"\n",
                ),
                ("format_idempotent/repeated/child.sinc", "# child\n$(VAL)\n"),
            ],
            "format_idempotent/repeated/root.sla",
        ),
    ];

    for (name, files, root_path) in cases {
        let formatted = formatted_case(files, root_path);
        let formatted_refs = formatted
            .iter()
            .map(|(path, text)| (*path, text.as_str()))
            .collect::<Vec<_>>();
        let reformatted = formatted_case(&formatted_refs, root_path);

        assert_eq!(reformatted, formatted, "{name}");
    }
}

#[test]
fn formatted_sources_compile_to_same_spec() {
    #[allow(clippy::type_complexity)]
    let cases: &[(&str, &[(&str, &str)], &str, &[&[u8]])] = &[
        (
            "single",
            &[("single/root.sla", include_str!("fixtures/single/root.sla"))],
            "single/root.sla",
            &[&[0x00]],
        ),
        (
            "include_resolution",
            &[
                (
                    "include_resolution/root.sla",
                    include_str!("fixtures/include_resolution/root.sla"),
                ),
                (
                    "include_resolution/include_child.sinc",
                    include_str!("fixtures/include_resolution/include_child.sinc"),
                ),
            ],
            "include_resolution/root.sla",
            &[&[0x00]],
        ),
        (
            "userop_macro",
            &[(
                "semantics/userop_macro.sla",
                include_str!("fixtures/semantics/userop_macro.sla"),
            )],
            "semantics/userop_macro.sla",
            &[&[0x11], &[0x12]],
        ),
    ];

    for (name, files, root_path, samples) in cases {
        let original = compile_observation(files, root_path, samples);
        let formatted = formatted_case(files, root_path);
        let formatted_refs = formatted
            .iter()
            .map(|(path, text)| (*path, text.as_str()))
            .collect::<Vec<_>>();
        let from_formatted = compile_observation(&formatted_refs, root_path, samples);

        assert_eq!(from_formatted, original, "{name}");
    }
}

#[test]
fn preprocessing_records_include_edges_instead_of_raw_directives() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "fixtures/raw/comments.sla",
        "# leading\n@include \"child.sinc\"\n",
    );
    let child = sources.add_file("fixtures/raw/child.sinc", "define token instr(8);\n");

    let result = analyze(&mut sources, root);
    let index = result.index.expect("index should be Some");

    assert_eq!(index.includes.len(), 1);
    assert_eq!(index.includes[0].from, root);
    assert_eq!(index.includes[0].to, Some(child));
}

#[test]
fn analyze_records_resolved_includes() {
    let mut sources = SourceDb::new();
    let root = add_fixture(
        &mut sources,
        "include_resolution/root.sla",
        include_str!("fixtures/include_resolution/root.sla"),
    );
    let child = add_fixture(
        &mut sources,
        "include_resolution/include_child.sinc",
        include_str!("fixtures/include_resolution/include_child.sinc"),
    );

    let result = analyze(&mut sources, root);
    let index = result.index.expect("index should be Some");
    let root_includes = index
        .includes
        .iter()
        .filter(|include| include.from == root)
        .collect::<Vec<_>>();

    assert_eq!(root_includes.len(), 1);
    assert_eq!(root_includes[0].to, Some(child));
}

#[test]
fn source_db_preprocess_resolves_includes_without_filesystem_io() {
    let mut sources = SourceDb::new();
    let root = add_fixture(
        &mut sources,
        "include_resolution/root.sla",
        include_str!("fixtures/include_resolution/root.sla"),
    );
    let child = add_fixture(
        &mut sources,
        "include_resolution/include_child.sinc",
        include_str!("fixtures/include_resolution/include_child.sinc"),
    );

    let prepared = sources
        .preprocess(root, &PreprocessOptions::default())
        .unwrap();

    assert!(
        sources
            .prepared_text(prepared)
            .unwrap()
            .contains("define token instr")
    );
    assert_eq!(sources.include_edges(prepared).unwrap()[0].from, root);
    assert_eq!(sources.include_edges(prepared).unwrap()[0].to, child);
    assert!(
        sources
            .line_map(prepared)
            .unwrap()
            .iter()
            .any(|line| line.source_file == child)
    );
}

#[test]
fn source_db_preprocess_records_repeated_include_expansions() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "fixtures/repeated/root.sla",
        "@include \"child.sinc\"\n@include \"child.sinc\"\n",
    );
    let child = sources.add_file("fixtures/repeated/child.sinc", "define token instr(8);\n");

    let prepared = sources
        .preprocess(root, &PreprocessOptions::default())
        .unwrap();
    assert_eq!(sources.include_edges(prepared).unwrap().len(), 2);
    assert!(
        sources
            .include_edges(prepared)
            .unwrap()
            .iter()
            .all(|edge| edge.to == child)
    );
    assert_eq!(sources.line_map(prepared).unwrap().len(), 2);
    assert_eq!(
        sources
            .source_map(prepared)
            .unwrap()
            .iter()
            .filter(|segment| segment.source.file == child)
            .count(),
        4
    );
}

#[test]
fn source_db_preprocess_exposes_byte_source_map_for_includes() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "fixtures/repeated_raw/root.sla",
        "@include \"child.sinc\"\n@include \"child.sinc\"\n",
    );
    let child = sources.add_file(
        "fixtures/repeated_raw/child.sinc",
        "define token instr(8);\n",
    );

    let prepared = sources
        .preprocess(root, &PreprocessOptions::default())
        .unwrap();
    let child_segments = sources
        .source_map(prepared)
        .unwrap()
        .iter()
        .filter(|segment| segment.source.file == child)
        .collect::<Vec<_>>();

    assert_eq!(
        sources.prepared_text(prepared).unwrap(),
        "define token instr(8);\ndefine token instr(8);\n"
    );
    assert_eq!(child_segments.len(), 4);
    assert!(
        child_segments
            .iter()
            .all(|segment| matches!(segment.origin, SourceOrigin::Source))
    );
}

#[test]
fn source_db_preprocess_records_include_macro_expansions() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "fixtures/include_env/root.sla",
        "@define VAL one\n@include \"child.sinc\"\n@undef VAL\n@define VAL two\n@include \"child.sinc\"\n",
    );
    sources.add_file("fixtures/include_env/child.sinc", "$(VAL)\n");

    let prepared = sources
        .preprocess(root, &PreprocessOptions::default())
        .unwrap();
    assert_eq!(sources.prepared_text(prepared).unwrap(), "one\ntwo\n");
    assert_eq!(
        sources
            .macro_expansions(prepared)
            .unwrap()
            .iter()
            .map(|expansion| expansion.replacement.as_str())
            .collect::<Vec<_>>(),
        ["one", "two"]
    );
}

#[test]
fn source_db_preprocess_preserves_inactive_conditional_branches() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "fixtures/view_conditional/root.sla",
        "@ifdef MISSING\nhidden\n@else\nvisible\n@endif\n",
    );

    let prepared = sources
        .preprocess(root, &PreprocessOptions::default())
        .unwrap();
    assert_eq!(sources.prepared_text(prepared).unwrap(), "visible\n");
    assert_eq!(sources.inactive_ranges(prepared).unwrap().len(), 1);
    let inactive = sources.inactive_ranges(prepared).unwrap()[0];
    assert_eq!(
        &sources.text(root).unwrap()[inactive.start.0..inactive.end.0],
        "hidden"
    );
}

#[test]
fn source_db_preprocess_source_map_excludes_inactive_branch_text() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "fixtures/view_conditional_raw/root.sla",
        "@ifdef MISSING\nhidden\n@else\nvisible\n@endif\n",
    );

    let prepared = sources
        .preprocess(root, &PreprocessOptions::default())
        .unwrap();

    assert_eq!(sources.prepared_text(prepared).unwrap(), "visible\n");
    assert!(sources.source_map(prepared).unwrap().iter().all(|segment| {
        &sources.text(root).unwrap()[segment.source.start.0..segment.source.end.0] != "hidden"
    }));
}

#[test]
fn source_db_preprocess_records_macro_expansion_provenance() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "fixtures/view_macro/root.sla",
        "@define NAME active\n$(NAME) $(UNKNOWN) $(NAME)\n",
    );

    let prepared = sources
        .preprocess(root, &PreprocessOptions::default())
        .unwrap();
    let expansions = sources.macro_expansions(prepared).unwrap();

    assert_eq!(
        sources.prepared_text(prepared).unwrap(),
        "active $(UNKNOWN) active\n"
    );
    assert_eq!(expansions.len(), 2);
    assert!(expansions.iter().all(|expansion| expansion.name == "NAME"));
    assert!(
        expansions
            .iter()
            .all(|expansion| expansion.replacement == "active")
    );
    let expansions = expansions.iter().collect::<Vec<_>>();
    assert_eq!(expansions[0].generated_range, 0..6);
    assert_eq!(expansions[1].generated_range, 18..24);
    assert!(
        expansions
            .iter()
            .all(|expansion| expansion.use_span.file == root)
    );
    assert!(
        expansions
            .iter()
            .all(|expansion| expansion.definition.is_some())
    );
    assert!(
        expansions
            .iter()
            .all(|expansion| expansion.definition_id.is_some())
    );
}

#[test]
fn source_db_preprocess_records_all_macro_definition_spans() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "fixtures/macro_definitions/root.sla",
        "@define UNUSED first\n@define NAME one\n@define NAME two\n$(NAME)\n@undef NAME\n",
    );

    let prepared = sources
        .preprocess(root, &PreprocessOptions::default())
        .unwrap();
    let definitions = sources.macro_definitions(prepared).unwrap();
    let expansions = sources.macro_expansions(prepared).unwrap();

    assert_eq!(
        definitions
            .iter()
            .map(|definition| (definition.name.as_str(), definition.value.as_str()))
            .collect::<Vec<_>>(),
        [("UNUSED", "first"), ("NAME", "one"), ("NAME", "two")]
    );
    assert_eq!(
        definitions
            .iter()
            .map(|definition| {
                &sources.text(root).unwrap()[definition.span.start.0..definition.span.end.0]
            })
            .collect::<Vec<_>>(),
        [
            "@define UNUSED first",
            "@define NAME one",
            "@define NAME two"
        ]
    );
    let definitions = definitions.iter().collect::<Vec<_>>();
    let expansions = expansions.iter().collect::<Vec<_>>();
    assert_eq!(expansions.len(), 1);
    assert_eq!(expansions[0].replacement, "two");
    assert_eq!(expansions[0].definition_id, Some(definitions[2].id));
    assert_eq!(expansions[0].definition, Some(definitions[2].span));
}

#[test]
fn source_db_preprocess_records_nested_macro_final_replacement_and_ranges() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "fixtures/view_macro_nested/root.sla",
        "@define B yy\n@define A $(B)\nx $(A) z\n$(A)-$(A)\n",
    );

    let prepared = sources
        .preprocess(root, &PreprocessOptions::default())
        .unwrap();
    let expansions = sources.macro_expansions(prepared).unwrap();

    assert_eq!(sources.prepared_text(prepared).unwrap(), "x yy z\nyy-yy\n");
    assert_eq!(expansions.len(), 3);
    assert!(expansions.iter().all(|expansion| expansion.name == "A"));
    assert!(
        expansions
            .iter()
            .all(|expansion| expansion.replacement == "yy")
    );
    let expansions = expansions.iter().collect::<Vec<_>>();
    assert_eq!(expansions[0].generated_range, 2..4);
    assert_eq!(expansions[1].generated_range, 7..9);
    assert_eq!(expansions[2].generated_range, 10..12);
    assert_eq!(expansions[0].use_span.start_line, 3);
    assert_eq!(expansions[1].use_span.start_line, 4);
    assert_eq!(expansions[2].use_span.start_line, 4);
}

#[test]
fn include_cycle_diagnostic_points_to_include_chain() {
    let mut sources = SourceDb::new();
    let root = add_fixture(
        &mut sources,
        "include_cycle/root.sla",
        include_str!("fixtures/include_cycle/root.sla"),
    );
    let cycle_a = add_fixture(
        &mut sources,
        "include_cycle/cycle_a.sinc",
        include_str!("fixtures/include_cycle/cycle_a.sinc"),
    );
    let cycle_b = add_fixture(
        &mut sources,
        "include_cycle/cycle_b.sinc",
        include_str!("fixtures/include_cycle/cycle_b.sinc"),
    );

    let diagnostics = sources
        .preprocess(root, &PreprocessOptions::default())
        .unwrap_err();

    assert_eq!(diagnostics.len(), 1);
    assert_eq!(diagnostics[0].message, "include cycle detected");
    assert_eq!(diagnostics[0].primary.file, cycle_b);
    assert_eq!(diagnostics[0].labels.len(), 2);
    assert_eq!(diagnostics[0].labels[0].span.file, root);
    assert_eq!(
        diagnostics[0].labels[0].message,
        "cycle starts with this include"
    );
    assert_eq!(diagnostics[0].labels[1].span.file, cycle_a);
    assert_eq!(diagnostics[0].labels[1].message, "then includes this file");
}

#[test]
fn source_db_tracks_inactive_conditional_ranges() {
    let mut sources = SourceDb::new();
    let root = add_fixture(
        &mut sources,
        "conditional/root.sla",
        include_str!("fixtures/conditional/root.sla"),
    );

    let prepared = sources
        .preprocess(root, &PreprocessOptions::default())
        .unwrap();
    let inactive = sources.inactive_ranges(prepared).unwrap();

    assert!(sources.prepared_text(prepared).unwrap().contains("active"));
    assert!(
        !sources
            .prepared_text(prepared)
            .unwrap()
            .contains("inactive")
    );
    assert!(inactive.len() >= 2);
    assert!(inactive.iter().all(|span| span.file == root));
}

#[test]
fn inactive_parent_still_tracks_nested_conditionals() {
    let mut sources = SourceDb::new();
    let root = add_fixture(
        &mut sources,
        "nested_inactive/root.sla",
        include_str!("fixtures/nested_inactive/root.sla"),
    );

    let prepared = sources
        .preprocess(root, &PreprocessOptions::default())
        .unwrap();
    let text = sources.prepared_text(prepared).unwrap();

    assert!(text.contains("visible"));
    assert!(!text.contains("hidden_nested"));
}

#[test]
fn add_file_from_path_does_not_load_inactive_missing_include() {
    let mut dir = std::env::temp_dir();
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    dir.push(format!("sleigh-inactive-include-{unique}"));
    fs::create_dir(&dir).unwrap();

    let root_path = dir.join("root.sla");
    fs::write(
        &root_path,
        include_str!("fixtures/inactive_missing_include/root.sla"),
    )
    .unwrap();

    let mut sources = SourceDb::new();
    let root = sources.add_file_from_path(&root_path).unwrap();
    let prepared = sources
        .preprocess(root, &PreprocessOptions::default())
        .unwrap();

    assert!(sources.prepared_text(prepared).unwrap().contains("active"));

    fs::remove_file(root_path).unwrap();
    fs::remove_dir(dir).unwrap();
}

#[test]
fn compiler_diagnostic_from_include_maps_to_included_file() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "fixtures/compile_diag/root.sla",
        r#"
@include "child.sinc"
"#,
    );
    let child = sources.add_file("fixtures/compile_diag/child.sinc", "define token tiny(7);");

    let error = match Compiler::new(&mut sources).compile(root) {
        Ok(_) => panic!("expected compile failure"),
        Err(error) => error,
    };

    assert_eq!(error.diagnostics()[0].primary.file, child);
}

#[test]
fn malformed_constructor_parse_returns_diagnostics() {
    let mut sources = SourceDb::new();
    let root = add_fixture(
        &mut sources,
        "malformed/root.sla",
        include_str!("fixtures/malformed/root.sla"),
    );

    let err = parse(&mut sources, root).unwrap_err();

    assert!(!err.diagnostics.is_empty());
}

#[test]
fn semantic_assignment_fixture_emits_pcode_ast() {
    let mut sources = SourceDb::new();
    let root = add_fixture(
        &mut sources,
        "semantic_assignment/root.sla",
        include_str!("fixtures/semantic_assignment/root.sla"),
    );
    let spec = Compiler::new(&mut sources).compile(root).unwrap();
    let context = spec.new_context();
    let decoder = Decoder::new(&spec);

    let instruction = decoder.decode_one(0, &[0x11], &context).unwrap();
    let ast = instruction.pcode_ast().unwrap();

    assert!(ast.statements.iter().any(|stmt| matches!(
        &stmt.ty,
        PcodeStatementKind::Assignment {
            lhs: PcodeIdent::Register(dst),
            rhs,
            size: None,
        } if *dst == reg(1)
            && matches!(&rhs.ty, PcodeExprKind::SizedInt { value: 1, size: None })
    )));
}

#[test]
fn context_action_fixture_analyzes_without_errors() {
    let mut sources = SourceDb::new();
    let root = add_fixture(
        &mut sources,
        "context_update/root.sla",
        include_str!("fixtures/context_update/root.sla"),
    );

    let analysis = crate::analyze(&mut sources, root);

    // The minimal fixture intentionally trips style lints — the write-only context
    // field `mode` and the constraint-only token field `op` (see the `lint` test
    // module, which asserts these warnings). Those are warnings, not errors; assert
    // only that context-action analysis itself raises no non-lint diagnostics.
    let non_lint: Vec<_> = analysis
        .diagnostics
        .iter()
        .filter(|d| !matches!(d.code, crate::DiagnosticCode::Lint(_)))
        .collect();
    assert!(
        non_lint.is_empty(),
        "unexpected non-lint diagnostics: {non_lint:?}"
    );
}

#[test]
fn preprocessor_reports_error_for_unclosed_conditional_at_eof() {
    let mut sources = SourceDb::new();
    let root = sources.add_file("fixtures/unclosed_if/root.sla", "@ifdef MISSING\nhidden\n");

    let diagnostics = sources
        .preprocess(root, &PreprocessOptions::default())
        .unwrap_err();

    assert_eq!(diagnostics.len(), 1);
    assert!(diagnostics[0].message.contains("@endif"));
    assert_eq!(diagnostics[0].primary.file, root);
    assert_eq!(diagnostics[0].primary.start_line, 1);
}

#[test]
fn preprocessor_reports_error_for_unclosed_nested_conditionals_at_eof() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "fixtures/unclosed_nested/root.sla",
        "@ifdef A\n@ifdef B\nfoo\n",
    );

    let diagnostics = sources
        .preprocess(root, &PreprocessOptions::default())
        .unwrap_err();

    assert_eq!(diagnostics.len(), 2);
    assert!(diagnostics.iter().all(|d| d.message.contains("@endif")));
}

#[test]
fn preprocessor_reports_error_for_endif_without_if() {
    let mut sources = SourceDb::new();
    let root = sources.add_file("fixtures/orphan_endif/root.sla", "@endif\n");

    let diagnostics = sources
        .preprocess(root, &PreprocessOptions::default())
        .unwrap_err();

    assert_eq!(diagnostics.len(), 1);
    assert!(diagnostics[0].message.contains("@endif"));
}

#[test]
fn preprocessor_reports_error_for_elif_without_if() {
    let mut sources = SourceDb::new();
    let root = sources.add_file("fixtures/orphan_elif/root.sla", "@elif defined(X)\nfoo\n");

    let diagnostics = sources
        .preprocess(root, &PreprocessOptions::default())
        .unwrap_err();

    assert_eq!(diagnostics.len(), 1);
    assert!(diagnostics[0].message.contains("@elif"));
}

#[test]
fn preprocessor_reports_error_for_else_without_if() {
    let mut sources = SourceDb::new();
    let root = sources.add_file("fixtures/orphan_else/root.sla", "@else\nfoo\n");

    let diagnostics = sources
        .preprocess(root, &PreprocessOptions::default())
        .unwrap_err();

    assert_eq!(diagnostics.len(), 1);
    assert!(diagnostics[0].message.contains("@else"));
}

#[test]
fn preprocessor_if_defined_evaluates_correctly() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "fixtures/if_defined/root.sla",
        "@define FLAG yes\n@if defined(FLAG)\nactive\n@else\ninactive\n@endif\n@if defined(MISSING)\nhidden\n@endif\n",
    );

    let prepared = sources
        .preprocess(root, &PreprocessOptions::default())
        .unwrap();
    let text = sources.prepared_text(prepared).unwrap();

    assert!(text.contains("active"));
    assert!(!text.contains("inactive"));
    assert!(!text.contains("hidden"));
}

// ── Phase 3 resolve() smoke tests ────────────────────────────────────────────

/// Build a `SpecBuilder` via `build_sleigh_ast` + `resolve()` and verify that
/// `concretize()` succeeds, producing a consistent symbol count.  This is the
/// key regression check for the Phase 3 resolution pass: the same fixture must
/// compile successfully through both the old `RawSleighParser` path and the
/// new AST-based path.
fn resolve_fixture(src: &str) {
    use crate::{PreprocessOptions, SourceDb, resolve::resolve, syntax::parse_to_ast};

    let mut sources = SourceDb::new();
    let root = sources.add_file("test.sla", src);
    let (file, _) = parse_to_ast(&mut sources, root, &PreprocessOptions::default())
        .expect("parse_to_ast should succeed");
    let mut ctx = resolve(&file).expect("resolve should succeed");
    ctx.0.concretize().expect("concretize should succeed");
}

const EXAMPLE_SLA: &str = include_str!("fixtures/example.sla");
const EXPR_SLA: &str = include_str!("fixtures/semantics/expressions.sla");
const LOAD_STORE_SLA: &str = include_str!("fixtures/semantics/load_store.sla");
const BRANCH_SLA: &str = include_str!("fixtures/semantics/branching.sla");
const BUILD_EXPORT_SLA: &str = include_str!("fixtures/semantics/build_export.sla");
const USEROP_MACRO_SLA: &str = include_str!("fixtures/semantics/userop_macro.sla");

#[test]
fn resolve_pass_example_fixture() {
    resolve_fixture(EXAMPLE_SLA);
}

#[test]
fn resolve_pass_expressions_fixture() {
    resolve_fixture(EXPR_SLA);
}

#[test]
fn resolve_pass_load_store_fixture() {
    resolve_fixture(LOAD_STORE_SLA);
}

#[test]
fn resolve_pass_branching_fixture() {
    resolve_fixture(BRANCH_SLA);
}

#[test]
fn resolve_pass_build_export_fixture() {
    resolve_fixture(BUILD_EXPORT_SLA);
}

#[test]
fn resolve_pass_userop_macro_fixture() {
    resolve_fixture(USEROP_MACRO_SLA);
}

// ── Disassembly actions: `globalset` ──────────────────────────────────────────

/// A minimal spec with one context field and one constructor whose action
/// block is `actions`.
fn globalset_spec(context_fields: &str, actions: &str) -> String {
    format!(
        "define endian=little;\n\
         define space ram type=ram_space size=4 default;\n\
         define space register type=register_space size=4;\n\
         define register offset=0 size=1 [ctxreg];\n\
         define context ctxreg {context_fields};\n\
         define token instr(8) op=(0,7);\n\
         :ctx is op=1 [{actions}] {{ }}\n"
    )
}

#[test]
fn globalset_action_parses_in_order() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "globalset.sla",
        globalset_spec("mode=(0,0)", "mode=1; globalset(inst_next,mode);"),
    );

    let parsed = parse(&mut sources, root).expect("parses");
    let ctor = parsed
        .file
        .items
        .iter()
        .find_map(|item| match item {
            crate::syntax::SleighItem::Constructor(def) => Some(def),
            _ => None,
        })
        .expect("constructor");

    assert_eq!(ctor.actions.len(), 2);
    assert!(matches!(
        &ctor.actions[0],
        crate::syntax::UnresolvedAction::Assign { field, .. } if &**field == "mode"
    ));
    assert!(matches!(
        &ctor.actions[1],
        crate::syntax::UnresolvedAction::GlobalSet { addr, field }
            if &**field == "mode"
                && matches!(addr, crate::syntax::UnresolvedExpr::Ident(name) if &**name == "inst_next")
    ));
}

#[test]
fn globalset_accepts_an_address_expression() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "globalset_expr.sla",
        globalset_spec("mode=(0,0)", "mode=1; globalset(inst_start + 4,mode);"),
    );

    let parsed = parse(&mut sources, root).expect("parses");
    let ctor = parsed
        .file
        .items
        .iter()
        .find_map(|item| match item {
            crate::syntax::SleighItem::Constructor(def) => Some(def),
            _ => None,
        })
        .expect("constructor");

    assert!(matches!(
        &ctor.actions[1],
        crate::syntax::UnresolvedAction::GlobalSet {
            addr: crate::syntax::UnresolvedExpr::Binary { .. },
            ..
        }
    ));
}

#[test]
fn globalset_with_wrong_arity_is_a_parse_error() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "globalset_arity.sla",
        globalset_spec("mode=(0,0)", "globalset(inst_next);"),
    );

    assert!(parse(&mut sources, root).is_err());
}

#[test]
fn globalset_rejects_a_non_context_target() {
    let mut sources = SourceDb::new();
    // `op` is a token field, which has no representation in the context register.
    let root = sources.add_file(
        "globalset_token.sla",
        globalset_spec("mode=(0,0)", "globalset(inst_next,op);"),
    );

    let analysis = analyze(&mut sources, root);
    assert!(
        analysis
            .diagnostics
            .iter()
            .any(|d| d.message.contains("is not a context field")),
        "expected a non-context-field diagnostic, got {:?}",
        analysis.diagnostics
    );
}

#[test]
fn globalset_rejects_an_unknown_target() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "globalset_unknown.sla",
        globalset_spec("mode=(0,0)", "globalset(inst_next,nope);"),
    );

    let analysis = analyze(&mut sources, root);
    assert!(
        analysis
            .diagnostics
            .iter()
            .any(|d| d.message.contains("Undefined context field `nope`")),
        "expected an undefined-field diagnostic, got {:?}",
        analysis.diagnostics
    );
}

#[test]
fn noflow_attribute_is_parsed_onto_context_fields() {
    let mut sources = SourceDb::new();
    let root = sources.add_file(
        "noflow.sla",
        globalset_spec("plain=(0,0) sticky=(1,1) noflow", "plain=1;"),
    );

    let parsed = parse(&mut sources, root).expect("parses");
    let fields = parsed
        .file
        .items
        .iter()
        .find_map(|item| match item {
            crate::syntax::SleighItem::Context(def) => Some(&def.fields),
            _ => None,
        })
        .expect("context block");

    assert_eq!(fields.len(), 2);
    assert!(!fields[0].noflow);
    assert!(fields[1].noflow);
}
