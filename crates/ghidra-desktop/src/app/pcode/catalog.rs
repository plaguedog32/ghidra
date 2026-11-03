use std::{path::PathBuf, sync::mpsc, time::Duration};

use eframe::egui;
use ghidra_languages::{Catalog, LanguageDefinition, Severity};

#[derive(Default)]
pub(super) struct CatalogState {
    catalog: Option<Catalog>,
    pending: Option<mpsc::Receiver<Result<Catalog, String>>>,
    attempted: bool,
    filter: String,
    error: Option<String>,
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
        let (send, receive) = mpsc::channel();
        self.pending = Some(receive);
        std::thread::spawn(move || {
            let result = Catalog::discover(&root).map_err(|error| error.to_string());
            let _ = send.send(result);
        });
    }

    pub(super) fn poll(&mut self, ctx: &egui::Context) {
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
        if let Some(result) = result {
            self.pending = None;
            match result {
                Ok(catalog) => self.catalog = Some(catalog),
                Err(error) => self.error = Some(error),
            }
        }
        if self.pending.is_some() {
            ctx.request_repaint_after(Duration::from_millis(40));
        }
    }

    /// Returns true only when the active recipe changes. Filtering is not a
    /// language change and must not invalidate a completed lift.
    pub(super) fn ui(&mut self, ui: &mut egui::Ui) -> bool {
        if !self.attempted {
            self.attempted = true;
            if let Some(root) = default_root() {
                self.load(root);
            }
        }
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
            if self.definition.is_some() && ui.button("Use raw source").clicked() {
                self.definition = None;
                changed = true;
            }
        });
        if let Some(error) = &self.error {
            ui.colored_label(super::GOLD, error);
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
                                self.definition = Some(definition.clone());
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
