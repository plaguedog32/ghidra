use super::*;
use std::time::{Duration, Instant};

const SOURCE: &str = r#"
define endian=little;
define space ram type=ram_space size=8 default;
define space register type=register_space size=8;
define register offset=0 size=8 [ rax rip ctx ];
define context ctx phase=(0,0);
define token inst40(40) op=(0,7) imm=(8,39);
define token byte(8) byteop=(0,7);
:mov imm is op=0xb8 & imm { rax = zext(imm); }
:ret is byteop=0xc3 { return [rip]; }
"#;

pub(crate) struct Fixture {
    pub directory: tempfile::TempDir,
    pub request: FunctionRequest,
}

pub(crate) fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("test.slaspec"), SOURCE).unwrap();
    std::fs::write(
        directory.path().join("test.pspec"),
        "<processor_spec><programcounter register=\"rip\"/></processor_spec>",
    )
    .unwrap();
    std::fs::write(directory.path().join("test.cspec"), "<compiler_spec/>").unwrap();
    std::fs::write(directory.path().join("test.ldefs"), r#"<language_definitions>
      <language id="x86:LE:64:test" processor="x86" endian="little" size="64" variant="test" version="1.0" slafile="test.sla" processorspec="test.pspec">
        <description>Test x86-sized source</description><compiler id="default" name="Test" spec="test.cspec"/>
      </language></language_definitions>"#).unwrap();
    let catalog = ghidra_languages::Catalog::discover(directory.path()).unwrap();
    assert!(!catalog.has_errors(), "{:?}", catalog.diagnostics);
    let definition = catalog.by_id("x86:LE:64:test").unwrap().clone();
    let mut bytes = crate::demo::pe64();
    bytes[0x200..0x240].fill(0xcc);
    bytes[0x200..0x206].copy_from_slice(&[0xb8, 1, 0, 0, 0, 0xc3]);
    let loaded = crate::report::load_bytes("test".into(), bytes).unwrap();
    let request = FunctionRequest {
        key: RequestKey {
            id: 1,
            generation: 2,
            revision: 3,
            entry: loaded.image.entry,
        },
        config: LanguageConfig {
            source: directory.path().join("test.slaspec"),
            definition: Some(definition),
            context: BTreeMap::new(),
            revision: 0,
        },
        image: loaded.image,
        functions: loaded.functions,
        havoc_unknown: false,
    };
    Fixture { directory, request }
}

pub(crate) fn analyze(request: &FunctionRequest) -> Result<FunctionView, String> {
    Compiler::default().analyze(request)
}

#[test]
fn recovered_binary_function_is_lifted_to_verified_native_ssa_with_source_bytes() {
    let fixture = fixture();
    let result = analyze(&fixture.request).unwrap();
    assert!(result.complete);
    assert_eq!(result.native.len(), 2);
    assert_eq!(result.native[0].bytes, [0xb8, 1, 0, 0, 0]);
    assert_eq!(result.native[1].bytes, [0xc3]);
    result.analysis.ssa().verify(result.analysis.raw()).unwrap();
    let json: serde_json::Value = serde_json::from_str(&result.json).unwrap();
    assert_eq!(json["schema"], "ghidra-rs.function-analysis");
    assert_eq!(json["function"]["entry"], fixture.request.image.entry);
    assert_eq!(json["function"]["recovery_complete"], true);
    assert_eq!(json["analysis"]["schema"], "ghidra-rs.pcode-analysis");
    assert_eq!(json["analysis"]["policies"]["unique_scope"], "instruction");
    assert_eq!(json["analysis"]["policies"]["ssa_verified"], true);
    // Expressions are built on the worker from the same verified snapshot.
    assert!(Arc::ptr_eq(&result.analysis, result.expressions.analysis()));
    assert_eq!(
        result.expression_operations.len(),
        result.expressions.operations().count()
    );
    assert_eq!(json["expressions"]["schema"], "ghidra-rs.expressions");
    crate::expression_report::tests::validate(&json["analysis"], &json["expressions"]);
    let operations = json["expressions"]["operations"].as_array().unwrap();
    let ret = operations.iter().find(|o| o["opcode"] == "RETURN").unwrap();
    assert_eq!(ret["result"], "none");
    assert_eq!(ret["operands"][0]["role"], "value");
    let exported = crate::expression_report::json(&result.expressions, MAX_JSON, "cap").unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&exported).unwrap(),
        json["expressions"]
    );
    assert!(
        result
            .analysis
            .cfg()
            .exits()
            .iter()
            .any(|e| e.kind == ghidra_cfg::ExitKind::Return)
    );
    // The lifted function is executable by the P-code interpreter, not by the host.
    let language = SleighLanguage::from_language(
        fixture.request.config.definition.as_ref().unwrap(),
        &BTreeMap::new(),
    )
    .unwrap();
    let rip = language.register("rip").unwrap();
    let rax = language.register("rax").unwrap();
    let mut machine =
        ghidra_pcode::machine::Machine::new(language.spaces().to_vec(), 65536).unwrap();
    machine
        .write_varnode(&rip, &ghidra_pcode::Value::from_u64(8, 0x8000).unwrap())
        .unwrap();
    machine
        .run(
            result.analysis.cfg().instructions(),
            language.code_space(),
            result.entry,
            100,
        )
        .unwrap();
    assert_eq!(machine.read_varnode(&rax).unwrap().to_u64(), Some(1));
}

#[test]
fn catalog_mismatch_raw_source_and_invalid_function_domains_are_rejected() {
    let fixture = fixture();
    let mut request = fixture.request.clone();
    request.config.definition = None;
    assert!(analyze(&request).unwrap_err().contains("catalog"));
    let mut request = fixture.request.clone();
    request.config.definition.as_mut().unwrap().size = 32;
    assert!(analyze(&request).unwrap_err().contains("bitness"));
    request.config.definition.as_mut().unwrap().size = 64;
    request.config.definition.as_mut().unwrap().processor = "ARM".into();
    assert!(analyze(&request).unwrap_err().contains("x86"));
    let mut request = fixture.request.clone();
    request.key.entry += 1;
    assert!(analyze(&request).unwrap_err().contains("unavailable"));
    let mut request = fixture.request.clone();
    let mut functions = (*request.functions).clone();
    functions.functions[0].instructions =
        vec![functions.functions[0].instructions[0].clone(); MAX_FUNCTION_INSTRUCTIONS + 1];
    request.functions = Arc::new(functions);
    assert!(analyze(&request).unwrap_err().contains("5000"));
}

#[test]
fn recovered_bytes_and_sleigh_boundaries_must_agree() {
    let fixture = fixture();
    let mut request = fixture.request.clone();
    let mut functions = (*request.functions).clone();
    functions.functions[0].instructions[0].bytes[1] ^= 1;
    request.functions = Arc::new(functions);
    assert!(analyze(&request).unwrap_err().contains("differ"));
    std::fs::write(
        fixture.directory.path().join("test.slaspec"),
        SOURCE
            .replace(
                "define token inst40(40) op=(0,7) imm=(8,39);",
                "define token inst40(8) op=(0,7); ",
            )
            .replace(
                ":mov imm is op=0xb8 & imm { rax = zext(imm); }",
                ":mov is op=0xb8 { rax = 1; }",
            ),
    )
    .unwrap();
    assert!(analyze(&fixture.request).unwrap_err().contains("boundary"));
}

#[test]
fn oversized_disassembly_is_rejected_before_accumulating_function_text() {
    let fixture = fixture();
    let source = SOURCE.replace(":mov imm", &format!(":{} imm", "x".repeat(4097)));
    std::fs::write(fixture.directory.path().join("test.slaspec"), source).unwrap();
    assert!(analyze(&fixture.request).unwrap_err().contains("4096"));
}

#[test]
fn context_committing_instructions_require_flow_analysis_instead_of_silent_resets() {
    let fixture = fixture();
    let source = SOURCE.replace(
        "is op=0xb8 & imm {",
        "is op=0xb8 & imm [ phase=1; globalset(inst_next,phase); ] {",
    );
    std::fs::write(fixture.directory.path().join("test.slaspec"), source).unwrap();
    assert!(
        analyze(&fixture.request)
            .unwrap_err()
            .contains("context commits")
    );
}

#[test]
fn cache_reuse_and_reload_are_explicit_and_incomplete_recovery_stays_incomplete() {
    let fixture = fixture();
    let mut request = fixture.request.clone();
    let mut functions = (*request.functions).clone();
    functions.functions[0].complete = false;
    request.functions = Arc::new(functions);
    let mut compiler = Compiler::default();
    assert!(!compiler.analyze(&request).unwrap().complete);
    std::fs::remove_file(fixture.directory.path().join("test.slaspec")).unwrap();
    assert!(!compiler.analyze(&request).unwrap().complete);
    request.config.revision += 1;
    assert!(compiler.analyze(&request).is_err());
    assert!(compiler.failed.is_some());
    assert!(compiler.analyze(&request).is_err());
}

#[test]
fn latest_function_request_eventually_wins_the_bounded_worker_queue() {
    let fixture = fixture();
    let worker = FunctionWorker::spawn();
    for id in 1..=20 {
        let mut request = fixture.request.clone();
        request.key.id = id;
        worker.request(request).unwrap();
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(response) = worker.try_recv().unwrap()
            && response.key.id == 20
        {
            assert!(response.result.is_ok());
            break;
        }
        assert!(
            Instant::now() < deadline,
            "function worker did not deliver latest request"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

#[test]
fn unknown_calls_are_explicitly_rejected_or_conservatively_marked() {
    let fixture = fixture();
    let source = SOURCE.replace("rax = zext(imm);", "rax = zext(imm); call [rip];");
    std::fs::write(fixture.directory.path().join("test.slaspec"), source).unwrap();
    let mut compiler = Compiler::default();
    assert!(
        compiler
            .analyze(&fixture.request)
            .unwrap_err()
            .contains("Call")
    );
    std::fs::remove_file(fixture.directory.path().join("test.slaspec")).unwrap();
    let mut request = fixture.request.clone();
    request.havoc_unknown = true;
    let result = compiler.analyze(&request).unwrap();
    assert_eq!(result.analysis.cfg().calls().len(), 1);
    let json: serde_json::Value = serde_json::from_str(&result.json).unwrap();
    crate::expression_report::tests::validate(&json["analysis"], &json["expressions"]);
    let call = result
        .expressions
        .operations()
        .find(|o| o.opcode == ghidra_pcode::Opcode::Callind)
        .unwrap();
    assert!(call.output.is_none());
    for value in result
        .analysis
        .ssa()
        .statement(call.statement)
        .unwrap()
        .defs()
    {
        assert!(matches!(
            result.expressions.definition(*value).unwrap(),
            ghidra_analysis::ExpressionDefinition::Opaque { .. }
        ));
    }
    assert!(
        result
            .analysis
            .raw()
            .blocks
            .iter()
            .enumerate()
            .any(
                |(node, statements)| statements.iter().enumerate().any(|(index, _)| {
                    matches!(
                        result
                            .analysis
                            .statement(ghidra_ssa::StatementId { node, index }),
                        Some(ghidra_analysis::AdaptedStatement::Operation {
                            effects: ghidra_analysis::AppliedEffects::Conservative(_),
                            ..
                        })
                    )
                })
            )
    );
}

#[test]
fn function_json_reserves_exactly_and_serializes_expressions_into_the_remaining_cap() {
    let metadata = br#"{"entry":1}"#;
    let dataflow = br#"{"schema":"ghidra-rs.pcode-analysis"}"#;
    let report = br#"{"schema":"ghidra-rs.expressions"}"#;
    let fixed = FUNCTION_PREFIX.len()
        + metadata.len()
        + ANALYSIS_KEY.len()
        + dataflow.len()
        + EXPRESSIONS_KEY.len()
        + 1;
    let exact = fixed + report.len();
    let mut offered = None;
    let json = function_json(metadata, dataflow, exact, |remaining| {
        offered = Some(remaining);
        Ok(report.to_vec())
    })
    .unwrap();
    assert_eq!(offered, Some(report.len()));
    assert_eq!(json.len(), exact);
    assert_eq!(json.capacity(), exact);
    let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(parsed["schema"], "ghidra-rs.function-analysis");
    assert_eq!(parsed["function"]["entry"], 1);
    assert_eq!(parsed["analysis"]["schema"], "ghidra-rs.pcode-analysis");
    assert_eq!(parsed["expressions"]["schema"], "ghidra-rs.expressions");
    // The expression writer receives the remaining budget and enforces it.
    let error = function_json(metadata, dataflow, exact - 1, |remaining| {
        let mut output = crate::analysis_cli::LimitedOutput::new(remaining, FUNCTION_TOO_LARGE);
        std::io::Write::write_all(&mut output, report).map_err(|e| e.to_string())?;
        Ok(output.into_bytes())
    })
    .unwrap_err();
    assert!(error.contains("64 MiB"));
    // A writer that ignores its budget is still rejected.
    assert!(
        function_json(metadata, dataflow, exact - 1, |_| Ok(report.to_vec()))
            .unwrap_err()
            .contains("64 MiB")
    );
    // No expression budget remains once the fixed parts exceed the cap.
    let mut called = false;
    assert!(
        function_json(metadata, dataflow, fixed - 1, |_| {
            called = true;
            Ok(Vec::new())
        })
        .is_err()
    );
    assert!(!called);
}

#[test]
fn ordinary_analysis_errors_keep_the_compiled_language_for_expression_runs() {
    let fixture = fixture();
    let mut compiler = Compiler::default();
    assert!(compiler.analyze(&fixture.request).is_ok());
    let mut request = fixture.request.clone();
    let mut functions = (*request.functions).clone();
    functions.functions[0].instructions[0].bytes[1] ^= 1;
    request.functions = Arc::new(functions);
    assert!(compiler.analyze(&request).unwrap_err().contains("differ"));
    assert!(compiler.compiled.is_some());
    // Removing the source proves the retained compiled language is reused.
    std::fs::remove_file(fixture.directory.path().join("test.slaspec")).unwrap();
    let result = compiler.analyze(&fixture.request).unwrap();
    assert!(!result.expressions.nodes().is_empty());
}

#[test]
fn function_command_arguments_preserve_context_and_reject_ambiguous_options() {
    let parse = |entry, arguments: &[&str]| {
        CommandArguments::parse(
            entry,
            &arguments.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
    };
    let arguments = parse("0x1000", &["--havoc-unknown", "longMode=1", "addrsize=0x2"]).unwrap();
    assert_eq!(arguments.entry, 0x1000);
    assert!(arguments.havoc_unknown);
    assert_eq!(arguments.context["addrsize"], 2);
    assert!(parse("0x", &[]).is_err());
    assert!(parse("1000", &["--havoc-unknown", "--havoc-unknown"]).is_err());
    assert!(parse("1000", &["--unknown"]).is_err());
    assert!(parse("1000", &["longMode=1", "longMode=0"]).is_err());
}

#[test]
#[ignore = "compiles the retained x86 source and analyzes a real recovered binary function"]
fn upstream_x86_function_lifts_to_ssa_and_executes_pcode() {
    let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Ghidra/Processors");
    let catalog = ghidra_languages::Catalog::discover(&root).unwrap();
    let definition = catalog.by_id("x86:LE:64:default").unwrap().clone();
    let loaded =
        crate::report::load_bytes("real source probe".into(), crate::demo::pe64()).unwrap();
    let request = FunctionRequest {
        key: RequestKey {
            id: 1,
            generation: 1,
            revision: 1,
            entry: loaded.image.entry + 0x1e,
        },
        config: LanguageConfig {
            source: definition.source.available_path().unwrap().to_path_buf(),
            definition: Some(definition),
            context: BTreeMap::new(),
            revision: 0,
        },
        image: loaded.image,
        functions: loaded.functions,
        havoc_unknown: false,
    };
    let mut compiler = Compiler::default();
    let result = compiler.analyze(&request).unwrap();
    assert!(result.complete);
    assert!(result.native.len() >= 5);
    assert!(result.analysis.ssa().phi_count() > 0);
    // The real function's expressions reference the same SSA IDs and keep
    // its loop phis as definitions rather than expanded terms.
    let json: serde_json::Value = serde_json::from_str(&result.json).unwrap();
    crate::expression_report::tests::validate(&json["analysis"], &json["expressions"]);
    assert!(
        json["expressions"]["values"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["definition"]["kind"] == "phi")
    );
    let graph = result.analysis.ssa().graph();
    assert!(
        !graph
            .dominators(result.analysis.ssa().entry())
            .unwrap()
            .natural_loops()
            .unwrap()
            .is_empty()
    );
    let language = &compiler.compiled.as_ref().unwrap().1;
    let mut machine =
        ghidra_pcode::machine::Machine::new(language.spaces().to_vec(), 1024 * 1024).unwrap();
    let register = language
        .spaces()
        .iter()
        .find(|s| s.kind == ghidra_pcode::SpaceKind::Register)
        .unwrap();
    let initialized_registers = vec![0; 65536];
    machine
        .map_bytes(register.id, 0, &initialized_registers)
        .unwrap();
    machine
        .write_varnode(
            &language.register("RCX").unwrap(),
            &ghidra_pcode::Value::from_u64(8, 3).unwrap(),
        )
        .unwrap();
    machine
        .write_varnode(
            &language.register("RSP").unwrap(),
            &ghidra_pcode::Value::from_u64(8, 0x8000).unwrap(),
        )
        .unwrap();
    machine
        .map_bytes(language.code_space(), 0x8000, &0x9000u64.to_le_bytes())
        .unwrap();
    machine
        .run(
            result.analysis.cfg().instructions(),
            language.code_space(),
            result.entry,
            1000,
        )
        .unwrap();
    assert_eq!(
        machine
            .read_varnode(&language.register("RAX").unwrap())
            .unwrap()
            .to_u64(),
        Some(3)
    );
}
