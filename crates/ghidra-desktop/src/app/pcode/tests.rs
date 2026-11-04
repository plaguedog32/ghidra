use super::*;

fn response(id: u64, generation: u64, address: u64) -> LiftResponse {
    LiftResponse {
        id,
        generation,
        address,
        result: Err("sentinel result".into()),
    }
}

#[test]
fn stale_responses_cannot_replace_another_program_or_selection() {
    let mut state = PcodeState::default();
    let key = state.key(0x1000);
    state.waiting = Some((4, key));
    state.accept(response(3, key.generation, key.address), Some(key.address));
    assert!(state.waiting.is_some());
    state.accept(response(4, key.generation, key.address), Some(0x1001));
    assert!(state.waiting.is_none());
    assert!(state.error.is_none());
    state.waiting = Some((5, key));
    state.clear_for_image();
    state.accept(response(5, key.generation, key.address), Some(key.address));
    assert!(state.error.is_none());
}

#[test]
fn setting_changes_invalidate_only_the_display_not_the_compiler_epoch() {
    let mut state = PcodeState::default();
    let epoch = state.source_epoch;
    let key = state.key(0x1000);
    state.waiting = Some((1, key));
    state.invalidate();
    state.accept(response(1, key.generation, key.address), Some(key.address));
    assert!(state.error.is_none());
    assert_eq!(state.source_epoch, epoch);
    assert_ne!(state.key(0x1000), key);
}

#[test]
fn context_fields_keep_values_and_reject_ambiguous_input() {
    assert_eq!(
        parse_context("longMode=1, addrsize=0x2 opsize=1").unwrap()["addrsize"],
        2
    );
    assert!(parse_context("phase=0 phase=1").is_err());
    assert!(parse_context("phase").is_err());
    assert!(parse_context("=1").is_err());
}

fn configuration() -> ghidra_project::ProcessorConfiguration {
    ghidra_project::ProcessorConfiguration {
        language: ghidra_project::LanguageIdentity {
            id: "not-installed".into(),
            major: 1,
            minor: 2,
        },
        compiler_id: Some("future-abi".into()),
        context: std::collections::BTreeMap::from([("phase".into(), 1)]),
    }
}

#[test]
fn unresolved_configuration_round_trips_and_invalid_drafts_cannot_silently_save() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("configured.ghrs");
    let mut app = Workbench::empty();
    let mut loaded = crate::report::load_bytes("configured".into(), crate::demo::pe64()).unwrap();
    loaded.project_path = Some(path.clone());
    app.selected = Some(loaded.image.entry);
    app.loaded = Some(loaded);
    let saved = configuration();
    app.pcode.restore_configuration(Some(&saved));
    app.processor_configuration_changed();
    assert!(app.dirty);
    assert_eq!(
        app.loaded.as_ref().unwrap().metadata.processor.as_ref(),
        Some(&saved)
    );
    app.pcode.context = "phase=".into();
    app.processor_configuration_changed();
    let revision = app.revision;
    app.save_project(false);
    assert!(app.pending.is_none());
    assert!(!path.exists());
    assert!(
        app.error
            .as_deref()
            .unwrap()
            .contains("invalid processor settings")
    );
    assert_eq!(
        app.loaded.as_ref().unwrap().metadata.processor.as_ref(),
        Some(&saved)
    );
    app.pcode.context = "phase=1".into();
    app.processor_configuration_changed();
    app.save_project(false);
    let result = app
        .pending
        .take()
        .unwrap()
        .recv_timeout(Duration::from_secs(10))
        .unwrap();
    let (send, receive) = mpsc::channel();
    send.send(result).unwrap();
    app.pending = Some(receive);
    app.poll(&egui::Context::default());
    assert_eq!(app.revision, revision);
    assert!(!app.dirty);
    assert!(app.error.is_none());
    assert_eq!(
        Project::load(&path).unwrap().metadata.processor.as_ref(),
        Some(&saved)
    );
    let reopened = crate::report::load_path(&path).unwrap();
    let (send, receive) = mpsc::channel();
    send.send(Ok(WorkResult::Loaded(Box::new(reopened))))
        .unwrap();
    app.pending = Some(receive);
    app.poll(&egui::Context::default());
    assert!(!app.dirty);
    assert_eq!(app.pcode.configuration().unwrap(), Some(saved));
    assert!(app.pcode.catalog.definition.is_none());
    assert!(app.pcode.source.is_empty());
    app.pcode.catalog.use_raw_source();
    app.processor_configuration_changed();
    assert!(app.dirty);
    assert!(app.loaded.as_ref().unwrap().metadata.processor.is_none());
}

#[test]
fn largest_valid_context_can_be_restored_without_ui_truncation() {
    let mut saved = configuration();
    saved.context = (0..ghidra_project::MAX_CONTEXT_FIELDS)
        .map(|i| {
            (
                format!(
                    "{}{:03}",
                    "x".repeat(ghidra_project::MAX_CONTEXT_NAME_BYTES - 3),
                    i
                ),
                u64::MAX,
            )
        })
        .collect();
    let mut state = PcodeState::default();
    state.restore_configuration(Some(&saved));
    assert!(state.context.chars().count() <= ghidra_project::MAX_CONTEXT_TEXT_CHARS);
    assert_eq!(state.configuration().unwrap(), Some(saved));
}

#[test]
fn processor_edits_during_a_save_or_import_cannot_mutate_project_metadata() {
    let mut app = Workbench::empty();
    app.loaded = Some(crate::report::load_bytes("pending".into(), crate::demo::pe64()).unwrap());
    let (_send, receive) = mpsc::channel();
    app.pending = Some(receive);
    app.pcode.restore_configuration(Some(&configuration()));
    app.processor_configuration_changed();
    assert!(!app.dirty);
    assert_eq!(app.revision, 0);
    assert!(app.loaded.as_ref().unwrap().metadata.processor.is_none());
}
