use super::*;

fn sample() -> Workbench {
    let mut app = Workbench::empty();
    let loaded = report::load_bytes("sample".into(), demo::pe64()).unwrap();
    app.selected = Some(loaded.image.entry);
    app.loaded = Some(loaded);
    app
}

fn deliver(app: &mut Workbench, result: Result<WorkResult, String>) {
    let (tx, rx) = mpsc::channel();
    tx.send(result).unwrap();
    app.pending = Some(rx);
    app.poll(&egui::Context::default());
}

#[test]
fn annotations_survive_disassembly_completion_and_failed_import() {
    let mut app = sample();
    let entry = app.selected.unwrap();
    app.set_annotation(
        entry,
        Annotation {
            label: "main".into(),
            comment: "reviewed".into(),
            bookmarked: true,
        },
    );
    let analysis = app
        .loaded
        .as_ref()
        .unwrap()
        .image
        .disassemble(entry, 10)
        .unwrap();
    deliver(&mut app, Ok(WorkResult::Disassembled(analysis)));
    deliver(&mut app, Err("bad import".into()));
    assert_eq!(
        app.loaded.as_ref().unwrap().metadata.annotations[&entry].label,
        "main"
    );
    assert!(app.dirty);
    assert_eq!(app.error.as_deref(), Some("bad import"));
    app.set_annotation(entry, Annotation::default());
    assert!(
        !app.loaded
            .as_ref()
            .unwrap()
            .metadata
            .annotations
            .contains_key(&entry)
    );
}

#[test]
fn stale_save_completion_does_not_mark_newer_edits_saved() {
    let mut app = sample();
    app.set_annotation(
        app.selected.unwrap(),
        Annotation {
            label: "first".into(),
            ..Default::default()
        },
    );
    let saving_revision = app.revision;
    app.set_annotation(
        app.selected.unwrap(),
        Annotation {
            label: "newer".into(),
            ..Default::default()
        },
    );
    deliver(
        &mut app,
        Ok(WorkResult::Saved {
            path: PathBuf::from("saved.ghrs"),
            revision: saving_revision,
        }),
    );
    assert!(app.dirty);
    let revision = app.revision;
    deliver(
        &mut app,
        Ok(WorkResult::Saved {
            path: PathBuf::from("saved.ghrs"),
            revision,
        }),
    );
    assert!(!app.dirty);
    assert_eq!(
        app.loaded.as_ref().unwrap().project_path.as_deref(),
        Some(std::path::Path::new("saved.ghrs"))
    );
}

#[test]
fn unsaved_import_is_deferred_until_user_resolves_changes() {
    let mut app = sample();
    app.set_annotation(
        app.selected.unwrap(),
        Annotation {
            bookmarked: true,
            ..Default::default()
        },
    );
    app.open(Input::Demo);
    assert!(app.pending_open.is_some());
    assert!(app.pending.is_none());
    assert_eq!(app.loaded.as_ref().unwrap().name, "sample");
}

#[test]
fn background_replacement_cannot_accept_edits_to_the_old_project() {
    let mut app = sample();
    let entry = app.selected.unwrap();
    let (tx, rx) = mpsc::channel();
    app.pending = Some(rx);
    app.set_annotation(
        entry,
        Annotation {
            comment: "would be lost".into(),
            ..Default::default()
        },
    );
    assert!(!app.dirty);
    assert!(app.loaded.as_ref().unwrap().metadata.annotations.is_empty());
    tx.send(Ok(WorkResult::Loaded(
        report::load_bytes("replacement".into(), demo::pe64()).unwrap(),
    )))
    .unwrap();
    app.poll(&egui::Context::default());
    assert_eq!(app.loaded.as_ref().unwrap().name, "replacement");
}

#[test]
fn function_view_retains_project_edits_and_uses_reachable_code() {
    let mut app = sample();
    let entry = app.selected.unwrap();
    app.set_annotation(
        entry,
        Annotation {
            comment: "keep me".into(),
            ..Default::default()
        },
    );
    app.navigate_function(entry);
    let loaded = app.loaded.as_ref().unwrap();
    assert_eq!(loaded.analysis_method, "recursive function");
    assert_eq!(loaded.metadata.annotations[&entry].comment, "keep me");
    let analysis = loaded.analysis.as_ref().unwrap();
    assert_eq!(analysis.instructions.last().unwrap().flow, "return");
    assert!(app.dirty);
}

#[test]
fn closing_a_clean_project_waits_for_its_save_worker() {
    let mut app = sample();
    app.saving = true;
    app.handle_close_request(&egui::Context::default());
    assert!(app.confirm_close);
    assert!(!app.approve_close);
    deliver(
        &mut app,
        Ok(WorkResult::Saved {
            path: PathBuf::from("saved.ghrs"),
            revision: 0,
        }),
    );
    assert!(!app.saving);
    assert!(app.approve_close);
}

#[test]
fn reopening_restores_data_selection_instead_of_the_code_entry() {
    let mut bytes = demo::pe64();
    bytes.resize(0x600, 0);
    bytes[0x86..0x88].copy_from_slice(&2_u16.to_le_bytes());
    bytes[0x1b0..0x1b5].copy_from_slice(b".data");
    for (offset, value) in [
        (0x1b8, 0x100_u32),
        (0x1bc, 0x2000),
        (0x1c0, 0x200),
        (0x1c4, 0x400),
        (0x1d4, 0xc0000040),
    ] {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    let mut loaded = report::load_bytes("data project".into(), bytes).unwrap();
    loaded.metadata.last_address = Some(0x1_4000_2004);
    let mut app = Workbench::empty();
    deliver(&mut app, Ok(WorkResult::Loaded(loaded)));
    assert_eq!(app.selected, Some(0x1_4000_2004));
    assert!(app.tab == Tab::Hex);
    assert_eq!(app.hex_offset, 0x400);
    assert!(!app.dirty);
}

#[test]
fn every_desktop_view_renders_with_loaded_project_state() {
    let mut app = sample();
    let context = egui::Context::default();
    for tab in [
        Tab::Listing,
        Tab::Hex,
        Tab::Strings,
        Tab::Sections,
        Tab::Blocks,
        Tab::Functions,
        Tab::Linkage,
        Tab::Bookmarks,
    ] {
        app.tab = tab;
        let input = egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1440.0, 900.0),
            )),
            ..Default::default()
        };
        let output = context.run(input, |ctx| {
            app.toolbar(ctx);
            app.sidebar(ctx);
            app.inspector(ctx);
            app.center(ctx);
        });
        assert!(!output.shapes.is_empty());
    }
}
