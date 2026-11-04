use std::process::Command;

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ghidra-rs"))
}

#[test]
fn compiler_storage_command_is_java_free_and_errors_leave_stdout_empty() {
    let dir = tempfile::tempdir().unwrap();
    let write = |file: &str, text: &str| std::fs::write(dir.path().join(file), text).unwrap();
    write(
        "tiny.slaspec",
        r#"define endian=little;
define space ram type=ram_space size=4 default;
define space register type=register_space size=4;
define register offset=0 size=4 [ r0 sp ];
define token byte(8) op=(0,7);
:nop is op=0 { }
"#,
    );
    write("tiny.pspec", "<processor_spec/>");
    write(
        "tiny.cspec",
        r#"<compiler_spec>
<stackpointer register="sp" space="ram"/>
<default_proto><prototype name="p" extrapop="0" stackshift="0">
<input><pentry minsize="1" maxsize="500" align="4"><addr space="stack" offset="4"/></pentry></input>
<output><pentry minsize="1" maxsize="4"><register name="r0"/></pentry></output>
</prototype></default_proto></compiler_spec>"#,
    );
    write(
        "tiny.ldefs",
        r#"<language_definitions>
<language processor="Tiny" endian="little" size="32" variant="default" version="1"
slafile="tiny.sla" processorspec="tiny.pspec" id="Tiny:LE:32:default">
<description>Process fixture</description><compiler name="test" spec="tiny.cspec" id="test"/>
</language></language_definitions>"#,
    );
    let mut command = binary();
    command
        .arg("--compiler-storage")
        .arg(dir.path())
        .args(["Tiny:LE:32:default", "test"])
        .env("JAVA_HOME", "");
    #[cfg(windows)]
    command.env(
        "PATH",
        std::path::PathBuf::from(std::env::var_os("SystemRoot").unwrap()).join("System32"),
    );
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
    assert_eq!(report["schema"], "ghidra-rs.compiler-storage");
    assert_eq!(report["policies"]["arguments_allocated"], false);
    assert_eq!(report["declarations_fully_modeled"], true);
    assert_eq!(
        report["registers"]["registers"].as_array().unwrap().len(),
        2
    );
    assert_eq!(report["resolved_storage"]["stack"]["address_size"], 4);
    assert!(report.get("resources").is_none());
    let output = binary()
        .arg("--compiler-storage")
        .arg(dir.path())
        .args(["Tiny:LE:32:default", "test", "--resources"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let resource_report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        resource_report["policies"]["overlap_resource_groups_computed"],
        true
    );
    assert_eq!(
        resource_report["resources"]["models"][0]["input"]["entries"][0]["slot_capacity"],
        125
    );
    for rest in [
        vec![],
        vec!["Tiny:LE:32:default"],
        vec!["Tiny:LE:32:default", "test", "extra"],
    ] {
        let output = binary()
            .arg("--compiler-storage")
            .arg(dir.path())
            .args(rest)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
    }
    for (language, compiler) in [("unknown", "test"), ("Tiny:LE:32:default", "missing")] {
        let output = binary()
            .arg("--compiler-storage")
            .arg(dir.path())
            .args([language, compiler])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(output.stdout.is_empty());
    }
    // A name that parsed cleanly must still resolve against the real register file.
    write(
        "tiny.cspec",
        r#"<compiler_spec>
<default_proto><prototype name="p" extrapop="0" stackshift="0">
<input/><output><pentry minsize="1" maxsize="4"><register name="missing"/></pentry></output>
</prototype></default_proto></compiler_spec>"#,
    );
    let output = binary()
        .arg("--compiler-storage")
        .arg(dir.path())
        .args(["Tiny:LE:32:default", "test"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown register"));
    write(
        "tiny.cspec",
        r#"<compiler_spec>
<default_proto><prototype name="p" extrapop="0" stackshift="0">
<input><pentry minsize="1" maxsize="4"><register name="r0"/></pentry>
<pentry minsize="1" maxsize="4"><varnode space="register" offset="2" size="4"/></pentry></input>
<output/></prototype></default_proto></compiler_spec>"#,
    );
    let output = binary()
        .arg("--compiler-storage")
        .arg(dir.path())
        .args(["Tiny:LE:32:default", "test", "--resources"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("illegally overlaps"));
    write(
        "tiny.pspec",
        r#"<processor_spec><segmented_address space="ram" type="real"/></processor_spec>"#,
    );
    let output = binary()
        .arg("--compiler-storage")
        .arg(dir.path())
        .args(["Tiny:LE:32:default", "test"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("real-mode segmented"));
    let help = binary().arg("--help").output().unwrap();
    assert!(String::from_utf8_lossy(&help.stdout).contains("--compiler-storage"));
    assert!(String::from_utf8_lossy(&help.stdout).contains("[--resources]"));
}
