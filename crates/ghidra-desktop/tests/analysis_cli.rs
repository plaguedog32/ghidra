use std::{path::PathBuf, process::Command};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ghidra-rs"))
}
fn example() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../examples/pcode/sum-loop.json")
}

#[test]
fn command_runs_without_java_and_emits_only_the_analysis_document() {
    let mut command = binary();
    command
        .args(["--analyze-pcode"])
        .arg(example())
        .env("JAVA_HOME", "");
    #[cfg(windows)]
    {
        command.env(
            "PATH",
            PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32"),
        );
    }
    #[cfg(not(windows))]
    command.env("PATH", "/nonexistent");
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "ghidra-rs.pcode-analysis");
    assert_eq!(report["policies"]["ssa_verified"], true);
    assert_eq!(report["natural_loops"].as_array().unwrap().len(), 1);
}

#[test]
fn expression_export_is_opt_in_java_free_and_fails_without_partial_stdout() {
    let mut command = binary();
    command
        .arg("--analyze-pcode")
        .arg(example())
        .arg("--expressions")
        .env("JAVA_HOME", "");
    #[cfg(windows)]
    {
        command.env(
            "PATH",
            PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32"),
        );
    }
    #[cfg(not(windows))]
    command.env("PATH", "/nonexistent");
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "ghidra-rs.pcode-analysis");
    assert_eq!(report["expressions"]["schema"], "ghidra-rs.expressions");
    assert_eq!(report["expressions"]["schema_version"], 1);
    assert_eq!(
        report["expressions"]["values"].as_array().unwrap().len(),
        report["values"].as_array().unwrap().len()
    );
    let plain = binary()
        .arg("--analyze-pcode")
        .arg(example())
        .output()
        .unwrap();
    let plain: serde_json::Value = serde_json::from_slice(&plain.stdout).unwrap();
    assert!(plain.get("expressions").is_none());

    let output = binary()
        .arg("--analyze-pcode")
        .arg(example())
        .args(["--expressions", "--expressions"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let file = tempfile::NamedTempFile::new().unwrap();
    file.as_file().set_len(16 * 1024 * 1024 + 1).unwrap();
    let output = binary()
        .arg("--analyze-pcode")
        .arg(file.path())
        .arg("--expressions")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("16 MiB"));
    let output = binary().arg("--help").output().unwrap();
    assert!(String::from_utf8_lossy(&output.stdout).contains("[--expressions]"));
}

#[test]
fn constants_export_is_opt_in_java_free_and_fails_without_partial_stdout() {
    let mut command = binary();
    command
        .arg("--analyze-pcode")
        .arg(example())
        .arg("--constants")
        .env("JAVA_HOME", "");
    #[cfg(windows)]
    {
        command.env(
            "PATH",
            PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32"),
        );
    }
    #[cfg(not(windows))]
    command.env("PATH", "/nonexistent");
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    // One document followed by exactly one newline.
    assert!(output.stdout.ends_with(b"}\n") && !output.stdout.ends_with(b"\n\n"));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema"], "ghidra-rs.pcode-analysis");
    // Constants imply the expressions their term IDs index.
    assert_eq!(report["expressions"]["schema"], "ghidra-rs.expressions");
    let constants = &report["constants"];
    assert_eq!(constants["schema"], "ghidra-rs.constants");
    assert_eq!(constants["schema_version"], 1);
    assert_eq!(
        constants["values"].as_array().unwrap().len(),
        report["values"].as_array().unwrap().len()
    );
    assert_eq!(
        constants["terms"].as_array().unwrap().len(),
        report["expressions"]["nodes"].as_array().unwrap().len()
    );
    assert_eq!(
        constants["cfg_edge_feasible"].as_array().unwrap().len(),
        report["cfg"]["edges"].as_array().unwrap().len()
    );
    // The loop counter starts at a known constant but merges to unknown.
    let facts: Vec<_> = constants["values"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v["fact"].as_str().unwrap())
        .collect();
    assert!(facts.contains(&"constant") && facts.contains(&"unknown"));
    let both = binary()
        .arg("--analyze-pcode")
        .arg(example())
        .args(["--expressions", "--constants"])
        .output()
        .unwrap();
    assert!(both.status.success());
    assert_eq!(both.stdout, output.stdout);
    let terms = binary()
        .arg("--analyze-pcode")
        .arg(example())
        .arg("--expressions")
        .output()
        .unwrap();
    let terms: serde_json::Value = serde_json::from_slice(&terms.stdout).unwrap();
    assert!(terms.get("constants").is_none());

    for flags in [
        &["--constants", "--constants"][..],
        &["--constants", "--expressions", "--constants"],
        &["--constants", "--folding"],
    ] {
        let output = binary()
            .arg("--analyze-pcode")
            .arg(example())
            .args(flags)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{flags:?}");
        assert!(output.stdout.is_empty());
    }
    let file = tempfile::NamedTempFile::new().unwrap();
    file.as_file().set_len(16 * 1024 * 1024 + 1).unwrap();
    let output = binary()
        .arg("--analyze-pcode")
        .arg(file.path())
        .arg("--constants")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("16 MiB"));
    let output = binary().arg("--help").output().unwrap();
    assert!(String::from_utf8_lossy(&output.stdout).contains("[--expressions] [--constants]"));
}

#[test]
fn simplification_export_is_opt_in_java_free_and_fails_without_partial_stdout() {
    let mut command = binary();
    command
        .arg("--analyze-pcode")
        .arg(example())
        .arg("--simplify")
        .env("JAVA_HOME", "");
    #[cfg(windows)]
    {
        command.env(
            "PATH",
            PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32"),
        );
    }
    #[cfg(not(windows))]
    command.env("PATH", "/nonexistent");
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    assert!(output.stdout.ends_with(b"}\n") && !output.stdout.ends_with(b"\n\n"));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    // Simplification implies the terms and facts its IDs index.
    assert_eq!(report["expressions"]["schema"], "ghidra-rs.expressions");
    assert_eq!(report["constants"]["schema"], "ghidra-rs.constants");
    let simplification = &report["simplification"];
    assert_eq!(simplification["schema"], "ghidra-rs.simplification");
    assert_eq!(simplification["schema_version"], 1);
    assert_eq!(
        simplification["node_terms"].as_array().unwrap().len(),
        report["expressions"]["nodes"].as_array().unwrap().len()
    );
    assert_eq!(
        simplification["values"].as_array().unwrap().len(),
        report["values"].as_array().unwrap().len()
    );
    assert_eq!(simplification["policies"]["decompiled_output"], false);
    // The `--constants` document is an exact byte prefix.
    let constants = binary()
        .arg("--analyze-pcode")
        .arg(example())
        .arg("--constants")
        .output()
        .unwrap();
    assert!(constants.status.success());
    let prefix = &constants.stdout[..constants.stdout.len() - 3];
    assert!(output.stdout.starts_with(prefix));
    assert!(output.stdout[prefix.len()..].starts_with(b",\n  \"simplification\": "));
    for flags in [
        &["--constants", "--simplify"][..],
        &["--simplify", "--expressions"],
        &["--expressions", "--constants", "--simplify"],
    ] {
        let same = binary()
            .arg("--analyze-pcode")
            .arg(example())
            .args(flags)
            .output()
            .unwrap();
        assert!(same.status.success());
        assert_eq!(same.stdout, output.stdout, "{flags:?}");
    }
    for flags in [
        &["--simplify", "--simplify"][..],
        &["--simplify", "--constants", "--simplify"],
        &["--simplify", "--simplification"],
    ] {
        let output = binary()
            .arg("--analyze-pcode")
            .arg(example())
            .args(flags)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2), "{flags:?}");
        assert!(output.stdout.is_empty());
    }
    let file = tempfile::NamedTempFile::new().unwrap();
    file.as_file().set_len(16 * 1024 * 1024 + 1).unwrap();
    let output = binary()
        .arg("--analyze-pcode")
        .arg(file.path())
        .arg("--simplify")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("16 MiB"));
    let output = binary().arg("--help").output().unwrap();
    let help = String::from_utf8_lossy(&output.stdout);
    assert!(help.contains("[--expressions] [--constants] [--simplify]"));
    assert!(help.contains("[--havoc-unknown] [--simplify] [context=value ...]"));
}

#[test]
fn command_rejects_bad_arguments_or_input_without_partial_stdout() {
    let output = binary().arg("--analyze-pcode").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let output = binary()
        .arg("--analyze-pcode")
        .arg(example())
        .arg("--unsupported")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    let file = tempfile::NamedTempFile::new().unwrap();
    let output = binary()
        .arg("--analyze-pcode")
        .arg(file.path())
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
}

#[test]
fn function_command_rejects_invalid_arguments_before_reading_files() {
    let output = binary().arg("--analyze-function").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    for rest in [
        vec!["bad-entry"],
        vec!["1000", "--unknown"],
        vec!["1000", "--havoc-unknown", "--havoc-unknown"],
        vec!["1000", "--simplify", "--simplify"],
        vec!["1000", "--simplify", "--simplified"],
    ] {
        let output = binary()
            .args([
                "--analyze-function",
                "missing.bin",
                ".",
                "x86:LE:64:default",
            ])
            .args(rest)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
    for rest in [&["1000"][..], &["1000", "--simplify"]] {
        let output = binary()
            .args([
                "--analyze-function",
                "missing.bin",
                ".",
                "x86:LE:64:default",
            ])
            .args(rest)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
    }
    let output = binary().arg("--help").output().unwrap();
    assert!(String::from_utf8_lossy(&output.stdout).contains("--analyze-function"));
}
