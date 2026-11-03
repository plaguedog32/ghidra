use super::*;
use std::{fs, time::Duration};

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ghidra-sleigh/tests/fixtures/tiny.slaspec")
}

fn request(id: u64, address: u64, byte: u8) -> LiftRequest {
    LiftRequest {
        id,
        generation: 1,
        config: LanguageConfig {
            source: fixture(),
            definition: None,
            context: BTreeMap::new(),
            revision: 0,
        },
        address,
        bytes: vec![byte],
        defaults: BTreeMap::new(),
    }
}

#[test]
fn compiled_source_is_reused_and_explicit_reload_reads_it_again() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("tiny.slaspec");
    fs::copy(fixture(), &source).unwrap();
    fs::copy(
        fixture().with_file_name("tiny.sinc"),
        directory.path().join("tiny.sinc"),
    )
    .unwrap();
    let mut compiler = CompilerCache::default();
    let mut next = request(1, 0x1000, 6);
    next.config.source = source.clone();
    assert!(!compiler.lift(&next).unwrap().cache_hit);
    fs::remove_file(&source).unwrap();
    next.id = 2;
    next.address += 1;
    assert!(compiler.lift(&next).unwrap().cache_hit);
    next.config.revision = 1;
    assert!(compiler.lift(&next).is_err());
    next.config.revision = 0;
    assert!(compiler.lift(&next).unwrap().cache_hit);
}

#[test]
fn independent_selections_reset_dynamic_context_without_recompiling() {
    let mut compiler = CompilerCache::default();
    compiler.lift(&request(1, 0x1000, 5)).unwrap();
    let mode = compiler.lift(&request(2, 0x5000, 6)).unwrap();
    assert_eq!(mode.disassembly, "base");
    assert!(mode.cache_hit);
    let mut new_program = request(3, 0x1001, 6);
    new_program.generation = 2;
    let mode = compiler.lift(&new_program).unwrap();
    assert_eq!(mode.disassembly, "base");
    assert!(mode.cache_hit);
}

#[test]
fn worker_eventually_delivers_latest_coalesced_selection() {
    let worker = LiftingWorker::spawn();
    for id in 1..=16 {
        worker.request(request(id, 0x1000 + id, 6)).unwrap();
    }
    loop {
        let response = worker
            .results
            .recv_timeout(Duration::from_secs(10))
            .unwrap();
        assert!(response.result.is_ok());
        if response.id == 16 {
            assert_eq!(response.address, 0x1010);
            break;
        }
    }
}

#[test]
fn instruction_windows_exclude_disk_padding_and_unmapped_memory() {
    let mut image = BinaryImage::parse(crate::demo::pe64()).unwrap();
    let start = image.entry;
    assert_eq!(instruction_window(&image, start).unwrap().len(), 0x40);
    assert_eq!(instruction_window(&image, start + 0x3f).unwrap().len(), 1);
    assert!(instruction_window(&image, start + 0x40).is_err());
    image.sections.push(image.sections[0].clone());
    assert!(instruction_window(&image, start).is_err());
    image.sections.pop();
    image.sections[0].file_offset = u64::MAX;
    assert!(instruction_window(&image, start).is_err());
}

#[test]
fn pcode_text_uses_register_aliases_and_keeps_explicit_widths() {
    let mut compiler = CompilerCache::default();
    let view = compiler.lift(&request(1, 0x1000, 6)).unwrap();
    assert!(
        view.rows
            .iter()
            .any(|row| row.contains("r0:4 = COPY(0x8:4)"))
    );
    let json: serde_json::Value = serde_json::from_str(&view.json).unwrap();
    assert_eq!(json["schema"], "ghidra-rs.lifted-instruction");
    assert_eq!(json["program"]["instructions"][0]["address"], 0x1000);
    assert_eq!(
        json["program"]["instructions"][0]["ops"][0]["opcode"],
        "COPY"
    );
    let program: ghidra_pcode::machine::ExecutionInput =
        serde_json::from_value(json["program"].clone()).unwrap();
    assert_eq!(program.entry, 0x1000);
}

#[test]
fn failed_recipe_is_retried_only_after_explicit_reload() {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("tiny.slaspec");
    let mut next = request(1, 0x1000, 6);
    next.config.source = source.clone();
    let mut compiler = CompilerCache::default();
    let first = compiler.lift(&next).err().unwrap();
    fs::copy(fixture(), &source).unwrap();
    fs::copy(
        fixture().with_file_name("tiny.sinc"),
        source.with_file_name("tiny.sinc"),
    )
    .unwrap();
    assert_eq!(compiler.lift(&next).err().unwrap(), first);
    next.config.revision += 1;
    assert_eq!(compiler.lift(&next).unwrap().disassembly, "base");
}

#[test]
fn catalog_worker_uses_processor_defaults_and_explicit_overrides() {
    let directory = tempfile::tempdir().unwrap();
    fs::copy(fixture(), directory.path().join("tiny.slaspec")).unwrap();
    fs::copy(
        fixture().with_file_name("tiny.sinc"),
        directory.path().join("tiny.sinc"),
    )
    .unwrap();
    fs::write(
        directory.path().join("tiny.pspec"),
        r#"<processor_spec><context_data>
        <context_set space="ram"><set name="phase" val="1"/></context_set>
        </context_data></processor_spec>"#,
    )
    .unwrap();
    fs::write(
        directory.path().join("tiny.ldefs"),
        r#"<language_definitions>
        <language id="Toy:LE:32:default" processor="Toy" endian="little" size="32"
          variant="default" version="1" slafile="tiny.sla" processorspec="tiny.pspec">
          <description>fixture</description></language></language_definitions>"#,
    )
    .unwrap();
    let catalog = ghidra_languages::Catalog::discover(directory.path()).unwrap();
    let mut next = request(1, 0x1000, 6);
    next.config.definition = Some(catalog.languages[0].clone());
    // Catalog paths, rather than display strings, select the source asset.
    next.config.source = PathBuf::from("unused-display-path.slaspec");
    let mut compiler = CompilerCache::default();
    assert_eq!(compiler.lift(&next).unwrap().disassembly, "mode");
    next.address += 1;
    assert!(compiler.lift(&next).unwrap().cache_hit);
    next.config.context.insert("phase".into(), 0);
    assert_eq!(compiler.lift(&next).unwrap().disassembly, "base");
}
