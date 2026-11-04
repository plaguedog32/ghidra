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
    // Constants share the worker's exact expression and SSA allocations.
    assert!(Arc::ptr_eq(
        result.constants.expressions(),
        &result.expressions
    ));
    assert!(Arc::ptr_eq(result.constants.analysis(), &result.analysis));
    crate::constant_report::tests::validate(
        &json["analysis"],
        &json["expressions"],
        &json["constants"],
    );
    let exported = crate::constant_report::json(&result.constants, MAX_JSON, "cap").unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&exported).unwrap(),
        json["constants"]
    );
    assert_eq!(
        result.constant_values,
        result
            .constants
            .constants()
            .map(|(id, _)| id)
            .collect::<Vec<_>>()
    );
    let mut keys: Vec<_> = json.as_object().unwrap().keys().cloned().collect();
    keys.sort();
    assert_eq!(
        keys,
        [
            "analysis",
            "constants",
            "expressions",
            "function",
            "schema",
            "schema_version"
        ]
    );
    // `rax = zext(1)` is a known constant; the RETURN target read from rip is
    // entry state and stays unknown rather than becoming zero.
    let return_target = operations.iter().find(|o| o["opcode"] == "RETURN").unwrap()["operands"][0]
        ["node"]
        .as_u64()
        .unwrap() as usize;
    assert_ne!(
        json["constants"]["terms"][return_target]["fact"],
        "constant"
    );
    assert!(
        json["constants"]["values"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v["fact"] == "constant" && v["hex"] == "0x1" && v["bytes"] == 8)
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
    crate::constant_report::tests::validate(
        &json["analysis"],
        &json["expressions"],
        &json["constants"],
    );
    // Calls are not summarized, so both call outcomes stay feasible.
    let mut call_outcomes = 0;
    for (id, edge) in result.analysis.cfg().edges().iter().enumerate() {
        if matches!(
            edge.role,
            ghidra_cfg::EdgeRole::CallReturn | ghidra_cfg::EdgeRole::CallNoReturn
        ) {
            call_outcomes += 1;
            assert!(result.constants.is_cfg_edge_feasible(id).unwrap());
        }
    }
    assert_eq!(call_outcomes, 2);
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
        // Opaque outputs are unknown, never a guessed constant.
        assert!(result.constants.value(*value).unwrap().is_unknown());
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
fn function_json_reserves_exactly_and_serializes_reports_into_the_remaining_cap() {
    let metadata = br#"{"entry":1}"#;
    let dataflow = br#"{"schema":"ghidra-rs.pcode-analysis"}"#;
    let report = br#"{"schema":"ghidra-rs.expressions"}"#;
    let facts = br#"{"schema":"ghidra-rs.constants"}"#;
    let fixed = FUNCTION_PREFIX.len()
        + metadata.len()
        + ANALYSIS_KEY.len()
        + dataflow.len()
        + EXPRESSIONS_KEY.len()
        + CONSTANTS_KEY.len()
        + 1;
    let exact = fixed + report.len() + facts.len();
    let mut offered = (None, None);
    let json = function_json(
        metadata,
        dataflow,
        exact,
        |remaining| {
            offered.0 = Some(remaining);
            Ok(report.to_vec())
        },
        |remaining| {
            offered.1 = Some(remaining);
            Ok(facts.to_vec())
        },
    )
    .unwrap();
    // Constants receive exactly what the expressions left.
    assert_eq!(
        offered,
        (Some(report.len() + facts.len()), Some(facts.len()))
    );
    assert_eq!(json.len(), exact);
    assert_eq!(json.capacity(), exact);
    let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(parsed["schema"], "ghidra-rs.function-analysis");
    assert_eq!(parsed["function"]["entry"], 1);
    assert_eq!(parsed["analysis"]["schema"], "ghidra-rs.pcode-analysis");
    assert_eq!(parsed["expressions"]["schema"], "ghidra-rs.expressions");
    assert_eq!(parsed["constants"]["schema"], "ghidra-rs.constants");
    let bounded = |bytes: &'static [u8]| {
        move |remaining: usize| {
            let mut output = crate::analysis_cli::LimitedOutput::new(remaining, FUNCTION_TOO_LARGE);
            std::io::Write::write_all(&mut output, bytes).map_err(|e| e.to_string())?;
            Ok(output.into_bytes())
        }
    };
    // Each writer receives the remaining budget and enforces it.
    for maximum in [exact - 1, exact - facts.len() - 1] {
        let error = function_json(metadata, dataflow, maximum, bounded(report), bounded(facts))
            .unwrap_err();
        assert!(error.contains("64 MiB"), "{error}");
    }
    // Writers that ignore their budgets are still rejected.
    assert!(
        function_json(
            metadata,
            dataflow,
            exact - 1,
            |_| Ok(report.to_vec()),
            |_| Ok(facts.to_vec())
        )
        .unwrap_err()
        .contains("64 MiB")
    );
    let mut constants_called = false;
    assert!(
        function_json(
            metadata,
            dataflow,
            fixed + report.len() - 1,
            |_| Ok(report.to_vec()),
            |_| {
                constants_called = true;
                Ok(Vec::new())
            }
        )
        .is_err()
    );
    assert!(!constants_called);
    // No report budget remains once the fixed parts exceed the cap.
    let called = std::cell::Cell::new(false);
    assert!(
        function_json(
            metadata,
            dataflow,
            fixed - 1,
            |_| {
                called.set(true);
                Ok(Vec::new())
            },
            |_| {
                called.set(true);
                Ok(Vec::new())
            }
        )
        .is_err()
    );
    assert!(!called.get());
    assert_eq!(MAX_DOCUMENT + 1, MAX_JSON);
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
fn append_field_reserves_exactly_and_serializes_into_the_remaining_cap() {
    let document = br#"{"schema":"ghidra-rs.function-analysis","constants":{}}"#;
    let report = br#"{"schema":"ghidra-rs.simplification"}"#;
    let exact = document.len() + SIMPLIFICATION_KEY.len() + report.len();
    let capped = |remaining: usize| {
        if report.len() > remaining {
            Err(FUNCTION_TOO_LARGE.to_string())
        } else {
            Ok(report.to_vec())
        }
    };
    let json = append_field(document, SIMPLIFICATION_KEY, exact, |remaining| {
        assert_eq!(remaining, report.len());
        capped(remaining)
    })
    .unwrap();
    assert_eq!(json.len(), exact);
    assert!(json.starts_with(&document[..document.len() - 1]));
    let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();
    assert_eq!(
        parsed["simplification"]["schema"],
        "ghidra-rs.simplification"
    );
    assert!(parsed["constants"].is_object());
    assert_eq!(
        append_field(document, SIMPLIFICATION_KEY, exact - 1, capped).unwrap_err(),
        FUNCTION_TOO_LARGE
    );
    // Too small for the fixed parts: the report is never serialized.
    let mut called = false;
    assert!(
        append_field(document, SIMPLIFICATION_KEY, document.len(), |_| {
            called = true;
            Ok(Vec::new())
        })
        .is_err()
    );
    assert!(!called);
    assert!(append_field(b"[1]", SIMPLIFICATION_KEY, 1024, capped).is_err());
}

#[test]
fn simplification_appends_to_the_function_document_from_its_own_snapshot() {
    let fixture = fixture();
    let result = analyze(&fixture.request).unwrap();
    let simplification = crate::simplification_report::build(result.constants.clone()).unwrap();
    assert!(Arc::ptr_eq(simplification.constants(), &result.constants));
    assert!(Arc::ptr_eq(simplification.analysis(), &result.analysis));
    let json = append_field(
        result.json.as_bytes(),
        SIMPLIFICATION_KEY,
        MAX_DOCUMENT,
        |remaining| crate::simplification_report::json(&simplification, remaining, "cap"),
    )
    .unwrap();
    // The unflagged document is an exact byte prefix.
    assert!(json.starts_with(&result.json.as_bytes()[..result.json.len() - 1]));
    let parsed: serde_json::Value = serde_json::from_slice(&json).unwrap();
    crate::simplification_report::tests::validate(
        &parsed["analysis"],
        &parsed["expressions"],
        &parsed["constants"],
        &parsed["simplification"],
    );
    let mut without = parsed.clone();
    without.as_object_mut().unwrap().remove("simplification");
    assert_eq!(
        without,
        serde_json::from_str::<serde_json::Value>(&result.json).unwrap()
    );
    // `rax = zext(1)`: the zero extension of a literal folds exactly.
    let simplification = &parsed["simplification"];
    assert!(
        simplification["terms"]
            .as_array()
            .unwrap()
            .iter()
            .any(|t| t["term"]["kind"] == "literal"
                && t["term"]["hex"] == "0x1"
                && t["term"]["bytes"] == 8)
    );
    assert!(
        simplification["counts"]["literal_outputs"]
            .as_u64()
            .unwrap()
            > 0
    );
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
    assert!(!arguments.simplify);
    let simplified = parse("1000", &["longMode=1", "--simplify", "--havoc-unknown"]).unwrap();
    assert!(simplified.simplify && simplified.havoc_unknown);
    assert_eq!(simplified.context["longMode"], 1);
    assert!(parse("1000", &["--simplify", "--simplify"]).is_err());
    assert!(parse("1000", &["--simplified"]).is_err());
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
    // Constant facts reference the same SSA and term IDs; checked structurally
    // rather than against incidental fact counts.
    assert!(Arc::ptr_eq(
        result.constants.expressions(),
        &result.expressions
    ));
    assert!(Arc::ptr_eq(result.constants.analysis(), &result.analysis));
    crate::constant_report::tests::validate(
        &json["analysis"],
        &json["expressions"],
        &json["constants"],
    );
    assert_eq!(
        result.constant_values,
        result
            .constants
            .constants()
            .map(|(id, _)| id)
            .collect::<Vec<_>>()
    );
    // The real function also simplifies from the same allocations; checked
    // structurally, with its reductions printed rather than asserted.
    let simplification = crate::simplification_report::build(result.constants.clone()).unwrap();
    assert!(Arc::ptr_eq(simplification.constants(), &result.constants));
    let simplified: serde_json::Value = serde_json::from_slice(
        &crate::simplification_report::json(&simplification, MAX_JSON, "cap").unwrap(),
    )
    .unwrap();
    crate::simplification_report::tests::validate(
        &json["analysis"],
        &json["expressions"],
        &json["constants"],
        &simplified,
    );
    eprintln!("real x86 simplification counts: {}", simplified["counts"]);
    // The loop's carried values merge distinct constants or inputs, so at least
    // one loop phi is unknown; entry state is never a constant.
    let constants = &json["constants"];
    assert!(
        json["expressions"]["values"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| {
                v["definition"]["kind"] == "phi"
                    && constants["values"][v["id"].as_u64().unwrap() as usize]["fact"] == "unknown"
            })
    );
    assert!(
        json["constants"]["node_executable"][json["analysis"]["entry"].as_u64().unwrap() as usize]
            == true
    );
    eprintln!(
        "real x86 constants: {} known, {} unknown, {} unreached values; {}/{} CFG edges feasible; {} faults",
        constants["counts"]["constant_values"],
        constants["counts"]["unknown_values"],
        constants["counts"]["unreached_values"],
        constants["counts"]["feasible_cfg_edges"],
        constants["counts"]["cfg_edges"],
        constants["counts"]["faults"]
    );
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
