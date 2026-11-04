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
