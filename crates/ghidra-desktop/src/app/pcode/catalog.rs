use std::{path::PathBuf, sync::mpsc, time::Duration};

use eframe::egui;
use ghidra_languages::{Catalog, LanguageDefinition, Severity};
use ghidra_project::LanguageIdentity;

#[derive(Default)]
pub(super) struct CatalogState {
    catalog: Option<Catalog>,
    pending: Option<mpsc::Receiver<Result<Catalog, String>>>,
    attempted: bool,
    filter: String,
    error: Option<String>,
    resolution_error: Option<String>,
    pub(super) wanted: Option<LanguageIdentity>,
    pub(super) compiler_id: Option<String>,
    pub(super) definition: Option<LanguageDefinition>,
}

fn default_root() -> Option<PathBuf> {
    if let Some(root) = std::env::var_os("GHIDRA_RS_LANGUAGE_ROOT") {
        return Some(PathBuf::from(root));
    }
    let roots = [std::env::current_dir().ok(), std::env::current_exe().ok()];
    for root in roots.into_iter().flatten() {
        for ancestor in root.ancestors() {
            let candidate = ancestor.join("Ghidra/Processors");
            if candidate.is_dir() {
                return Some(candidate);
            }
        }
    }
    None
}

impl CatalogState {
    fn load(&mut self, root: PathBuf) {
        self.attempted = true;
        self.catalog = None;
        self.definition = None;
        self.error = None;
        self.resolution_error = None;
        let (send, receive) = mpsc::channel();
        self.pending = Some(receive);
        std::thread::spawn(move || {
            let result = Catalog::discover(&root).map_err(|error| error.to_string());
            let _ = send.send(result);
        });
    }

    fn ensure_started(&mut self) {
        if !self.attempted {
            self.attempted = true;
            if let Some(root) = default_root() {
                self.load(root);
            }
        }
    }

    pub(super) fn restore(
        &mut self,
        wanted: Option<LanguageIdentity>,
        compiler_id: Option<String>,
    ) {
        self.wanted = wanted;
        self.compiler_id = compiler_id;
        self.resolve();
    }

    pub(super) fn use_raw_source(&mut self) {
        self.wanted = None;
        self.compiler_id = None;
        self.definition = None;
        self.resolution_error = None;
    }

    fn resolve(&mut self) -> bool {
        let previous = self.definition.take();
        self.resolution_error = None;
        if let Some(wanted) = &self.wanted
            && let Some(catalog) = &self.catalog
        {
            match catalog.by_id(&wanted.id) {
                Some(definition)
                    if definition.version.major == wanted.major
                        && definition.version.minor == wanted.minor =>
                {
                    self.definition = Some(definition.clone());
                }
                Some(definition) => {
                    self.resolution_error = Some(format!(
                        "Saved language {} requires version {}.{}, but this catalog has {}. Choose matching assets or explicitly select a language to replace the saved choice.",
                        wanted.id, wanted.major, wanted.minor, definition.version
                    ))
                }
                None => {
                    self.resolution_error = Some(format!(
                        "Saved language {} is unavailable in this catalog. Choose another assets folder or replace the language choice.",
                        wanted.id
                    ))
                }
            }
        }
        self.definition != previous
    }

    pub(super) fn poll(&mut self, ctx: &egui::Context) -> bool {
        if self.wanted.is_some() {
            self.ensure_started();
        }
        let result = self
            .pending
            .as_ref()
            .and_then(|receive| match receive.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => {
                    Some(Err("Language discovery worker stopped".into()))
                }
            });
        let mut changed = false;
        if let Some(result) = result {
            self.pending = None;
            match result {
                Ok(catalog) => {
                    self.catalog = Some(catalog);
                    changed = self.resolve();
                }
                Err(error) => self.error = Some(error),
            }
        }
        if self.pending.is_some() {
            ctx.request_repaint_after(Duration::from_millis(40));
        }
        changed
    }

    /// Returns true only when the active recipe changes. Filtering is not a
    /// language change and must not invalidate a completed lift.
    pub(super) fn ui(&mut self, ui: &mut egui::Ui) -> bool {
        self.ensure_started();
        let mut changed = false;
        ui.horizontal(|ui| {
            ui.label("Language catalog");
            if ui
                .add_enabled(self.pending.is_none(), egui::Button::new("Choose folder…"))
                .clicked()
                && let Some(root) = rfd::FileDialog::new()
                    .set_title("Choose Ghidra language assets")
                    .pick_folder()
            {
                changed = self.definition.is_some();
                self.load(root);
            }
            if self.pending.is_some() {
                ui.spinner();
                ui.label("Discovering language definitions…");
            }
            if self.wanted.is_some() && ui.button("Use raw source").clicked() {
                self.use_raw_source();
                changed = true;
            }
        });
        if let Some(error) = &self.error {
            ui.colored_label(super::GOLD, error);
        }
        if let Some(error) = &self.resolution_error {
            ui.colored_label(super::GOLD, error);
        } else if self.definition.is_none()
            && let Some(wanted) = &self.wanted
        {
            ui.label(format!("Saved language: {} version {}.{}. Choose matching language assets to lift instructions.", wanted.id, wanted.major, wanted.minor));
        }
        if let Some(catalog) = &self.catalog {
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.filter)
                        .char_limit(256)
                        .hint_text("Filter language IDs / processors")
                        .desired_width(240.0),
                );
                let query = self.filter.to_lowercase();
                egui::ComboBox::from_id_salt("processor_language")
                    .selected_text(
                        self.definition
                            .as_ref()
                            .map_or("Choose language…", |language| language.id.as_str()),
                    )
                    .width(340.0)
                    .height(240.0)
                    .show_ui(ui, |ui| {
                        for definition in &catalog.languages {
                            if !query.is_empty()
                                && !definition.id.to_lowercase().contains(&query)
                                && !definition.processor.to_lowercase().contains(&query)
                                && !definition.description.to_lowercase().contains(&query)
                            {
                                continue;
                            }
                            let selected = self
                                .definition
                                .as_ref()
                                .is_some_and(|active| active.id == definition.id);
                            let label = if definition.deprecated {
                                format!("{} (deprecated)", definition.id)
                            } else {
                                definition.id.clone()
                            };
                            if ui
                                .selectable_label(selected, label)
                                .on_hover_text(&definition.description)
                                .clicked()
                                && !selected
                            {
                                self.wanted = Some(LanguageIdentity {
                                    id: definition.id.clone(),
                                    major: definition.version.major,
                                    minor: definition.version.minor,
                                });
                                self.compiler_id = None;
                                self.definition = Some(definition.clone());
                                self.resolution_error = None;
                                changed = true;
                            }
                        }
                    });
            });
            let diagnostics = catalog
                .diagnostics
                .iter()
                .filter(|diagnostic| diagnostic.severity >= Severity::Warning)
                .count();
            ui.label(
                egui::RichText::new(format!(
                    "{} definitions · {} diagnostics · {}",
                    catalog.languages.len(),
                    diagnostics,
                    catalog.root().display()
                ))
                .small()
                .color(super::MUTED),
            );
            if diagnostics != 0 {
                egui::CollapsingHeader::new("Catalog diagnostics").show(ui, |ui| {
                    egui::ScrollArea::vertical()
                        .max_height(120.0)
                        .show(ui, |ui| {
                            for diagnostic in &catalog.diagnostics {
                                ui.label(diagnostic.to_string());
                            }
                        });
                });
            }
        } else if self.pending.is_none() && self.error.is_none() {
            ui.label("Choose the folder containing .ldefs and processor source assets.");
        }
        if let Some(definition) = &self.definition {
            ui.label(
                egui::RichText::new(format!(
                    "{} · {}-bit · data {:?} · instructions {:?}",
                    definition.description,
                    definition.size,
                    definition.endian,
                    definition.instruction_endian
                ))
                .small(),
            );
        }
        changed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn fixture() -> (tempfile::TempDir, Catalog) {
        let directory = tempfile::tempdir().unwrap();
        fs::write(directory.path().join("toy.slaspec"), "# source").unwrap();
        fs::write(directory.path().join("toy.pspec"), "<processor_spec/>").unwrap();
        fs::write(
            directory.path().join("toy.ldefs"),
            r#"<language_definitions>
            <language id="Toy:LE:32:default" processor="Toy" endian="little" size="32"
              variant="default" version="1.2" slafile="toy.sla" processorspec="toy.pspec">
              <description>fixture</description></language></language_definitions>"#,
        )
        .unwrap();
        let catalog = Catalog::discover(directory.path()).unwrap();
        (directory, catalog)
    }

    fn identity() -> LanguageIdentity {
        LanguageIdentity {
            id: "Toy:LE:32:default".into(),
            major: 1,
            minor: 2,
        }
    }

    #[test]
    fn saved_identity_resolves_only_at_the_saved_version() {
        let (_directory, catalog) = fixture();
        let mut state = CatalogState {
            catalog: Some(catalog),
            attempted: true,
            ..Default::default()
        };
        state.restore(Some(identity()), Some("future-abi".into()));
        assert_eq!(state.definition.as_ref().unwrap().id, identity().id);
        let mut mismatch = identity();
        mismatch.minor += 1;
        state.restore(Some(mismatch.clone()), None);
        assert!(state.definition.is_none());
        assert_eq!(state.wanted.as_ref(), Some(&mismatch));
        assert!(state.resolution_error.as_deref().unwrap().contains("1.3"));
        let mut unknown = identity();
        unknown.id = "not-installed".into();
        state.restore(Some(unknown.clone()), None);
        assert!(state.definition.is_none());
        assert_eq!(state.wanted.as_ref(), Some(&unknown));
        assert!(
            state
                .resolution_error
                .as_deref()
                .unwrap()
                .contains("unavailable")
        );
    }

    #[test]
    fn catalog_completion_resolves_the_current_program_not_the_old_request() {
        let (_directory, catalog) = fixture();
        let mut state = CatalogState {
            attempted: true,
            ..Default::default()
        };
        state.restore(Some(identity()), Some("future-abi".into()));
        let (send, receive) = mpsc::channel();
        state.pending = Some(receive);
        let mut next_program = identity();
        next_program.id = "not-installed".into();
        state.restore(Some(next_program.clone()), None);
        send.send(Ok(catalog)).unwrap();
        state.poll(&egui::Context::default());
        assert!(state.definition.is_none());
        assert_eq!(state.wanted, Some(next_program));
        state.restore(Some(identity()), None);
        assert!(state.definition.is_some());
        state.use_raw_source();
        assert!(state.wanted.is_none());
        assert!(state.definition.is_none());
        assert!(state.compiler_id.is_none());
        assert!(state.resolution_error.is_none());
    }

    #[test]
    fn reopening_a_project_restores_the_recipe_and_context_used_by_the_worker() {
        use crate::app::{WorkResult, Workbench};
        use ghidra_project::{ProcessorConfiguration, Project};
        use std::{sync::Arc, time::Instant};

        let (directory, catalog) = fixture();
        let fixtures =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../ghidra-sleigh/tests/fixtures");
        let source = fs::read_to_string(fixtures.join("tiny.slaspec"))
            .unwrap()
            .replace("size=4 default", "size=8 default");
        fs::write(directory.path().join("toy.slaspec"), source).unwrap();
        fs::copy(
            fixtures.join("tiny.sinc"),
            directory.path().join("tiny.sinc"),
        )
        .unwrap();
        let mut bytes = crate::demo::pe64();
        bytes[0x200] = 6; // The source fixture decodes phase=1 as `mode`.
        let image = Arc::new(ghidra_core::BinaryImage::parse(bytes).unwrap());
        let saved = ProcessorConfiguration {
            language: identity(),
            compiler_id: None,
            context: std::collections::BTreeMap::from([("phase".into(), 1)]),
        };
        let mut project = Project::new("restore-and-lift".into(), image);
        project.metadata.processor = Some(saved.clone());
        let path = directory.path().join("configured.ghrs");
        project.save(&path).unwrap();
        let loaded = crate::report::load_path(&path).unwrap();
        let mut app = Workbench::empty();
        app.pcode.catalog.catalog = Some(catalog);
        app.pcode.catalog.attempted = true;
        let (send, receive) = mpsc::channel();
        send.send(Ok(WorkResult::Loaded(Box::new(loaded)))).unwrap();
        app.pending = Some(receive);
        app.poll(&egui::Context::default());
        let address = app.selected.unwrap();
        app.pcode
            .request(&app.loaded.as_ref().unwrap().image, address, None);
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(response) = app.pcode.worker.as_ref().unwrap().try_recv().unwrap() {
                app.pcode.accept(response, app.selected);
                break;
            }
            assert!(
                Instant::now() < deadline,
                "restored language worker timed out"
            );
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(app.pcode.view.as_ref().unwrap().1.disassembly, "mode");
        assert_eq!(app.pcode.configuration().unwrap(), Some(saved));
        assert!(!app.dirty);
    }
}
