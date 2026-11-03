use super::*;
use crate::lifting::{LanguageConfig, LiftRequest, LiftResponse, LiftedView, LiftingWorker};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SelectionKey {
    generation: u64,
    address: u64,
    revision: u64,
}

#[derive(Default)]
pub(super) struct PcodeState {
    source: String,
    context: String,
    revision: u64,
    source_epoch: u64,
    generation: u64,
    next_request: u64,
    waiting: Option<(u64, SelectionKey)>,
    view: Option<(SelectionKey, LiftedView)>,
    error: Option<(SelectionKey, String)>,
    worker: Option<LiftingWorker>,
    automatic: bool,
    history: Vec<u64>,
}

impl PcodeState {
    fn key(&self, address: u64) -> SelectionKey {
        SelectionKey {
            generation: self.generation,
            address,
            revision: self.revision,
        }
    }

    pub(super) fn clear_for_image(&mut self) {
        self.generation = self.generation.wrapping_add(1);
        self.invalidate();
        self.source.clear();
        self.context.clear();
        self.history.clear();
    }

    fn invalidate(&mut self) {
        self.revision = self.revision.wrapping_add(1);
        self.next_request = self.next_request.wrapping_add(1);
        self.waiting = None;
        self.view = None;
        self.error = None;
    }

    fn accept(&mut self, response: LiftResponse, selected: Option<u64>) {
        let Some((id, key)) = self.waiting else {
            return;
        };
        if id != response.id
            || key.generation != response.generation
            || key.address != response.address
        {
            return;
        }
        self.waiting = None;
        if selected != Some(key.address) || key != self.key(key.address) {
            return;
        }
        match response.result {
            Ok(view) => {
                self.view = Some((key, view));
                self.error = None;
            }
            Err(error) => {
                self.error = Some((key, error));
                self.view = None;
            }
        }
    }

    pub(super) fn poll(&mut self, ctx: &egui::Context, selected: Option<u64>) {
        for _ in 0..4 {
            let response = match self.worker.as_ref().map(LiftingWorker::try_recv) {
                Some(Ok(Some(response))) => response,
                Some(Err(error)) => {
                    if let Some((_, key)) = self.waiting.take() {
                        self.error = Some((key, error));
                    }
                    self.worker = None;
                    break;
                }
                _ => break,
            };
            self.accept(response, selected);
        }
        if self.waiting.is_some() {
            ctx.request_repaint_after(Duration::from_millis(40));
        }
    }

    fn request(&mut self, image: &ghidra_core::BinaryImage, address: u64) {
        let key = self.key(address);
        let prepared = parse_context(&self.context).and_then(|context| {
            if self.source.trim().is_empty() {
                return Err("Choose a processor language or SLEIGH source specification".into());
            }
            let bytes = crate::lifting::instruction_window(image, address)?;
            Ok((context, bytes))
        });
        let (context, bytes) = match prepared {
            Ok(prepared) => prepared,
            Err(error) => {
                self.waiting = None;
                self.view = None;
                self.error = Some((key, error));
                return;
            }
        };
        self.next_request = self.next_request.wrapping_add(1);
        let id = self.next_request;
        let worker = self.worker.get_or_insert_with(LiftingWorker::spawn);
        let request = LiftRequest {
            id,
            generation: self.generation,
            config: LanguageConfig {
                source: PathBuf::from(self.source.trim()),
                context,
                revision: self.source_epoch,
            },
            address,
            bytes,
            defaults: Default::default(),
        };
        match worker.request(request) {
            Ok(()) => {
                self.waiting = Some((id, key));
                self.error = None;
                self.view = None;
            }
            Err(error) => {
                self.waiting = None;
                self.error = Some((key, error));
                self.worker = None;
            }
        }
    }
}

fn parse_context(text: &str) -> Result<std::collections::BTreeMap<String, u64>, String> {
    let mut fields = std::collections::BTreeMap::new();
    for field in text
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter(|f| !f.is_empty())
    {
        if fields.len() == 256 {
            return Err("Too many processor context fields".into());
        }
        let (name, value) = field
            .split_once('=')
            .ok_or("Use context fields in the form name=value")?;
        if name.is_empty() {
            return Err("Processor context field name is empty".into());
        }
        let value = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
            .map(|hex| u64::from_str_radix(hex, 16))
            .unwrap_or_else(|| value.parse())
            .map_err(|_| format!("Invalid processor context value: {field}"))?;
        if fields.insert(name.to_owned(), value).is_some() {
            return Err(format!("Duplicate processor context field: {name}"));
        }
    }
    Ok(fields)
}

impl Workbench {
    pub(super) fn pcode_view(&mut self, ui: &mut egui::Ui) {
        let current = self.selected;
        let next = current
            .and_then(|address| {
                self.pcode
                    .view
                    .as_ref()
                    .filter(|(key, _)| *key == self.pcode.key(address))
                    .map(|(_, view)| view.next_address)
            })
            .filter(|address| {
                self.loaded.as_ref().is_some_and(|loaded| {
                    loaded.image.sections.iter().any(|s| {
                        s.executable
                            && *address >= s.address
                            && *address - s.address < s.size.min(s.file_size)
                    })
                })
            });
        let mut navigation = None;
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    !self.pcode.history.is_empty(),
                    egui::Button::new("Previous address"),
                )
                .clicked()
            {
                navigation = self.pcode.history.pop();
            }
            if ui
                .add_enabled(next.is_some(), egui::Button::new("Next instruction"))
                .clicked()
            {
                if let Some(address) = current {
                    if self.pcode.history.len() == 1024 {
                        self.pcode.history.remove(0);
                    }
                    self.pcode.history.push(address);
                }
                navigation = next;
            }
            if let Some(address) = current {
                ui.label(
                    RichText::new(format!("{address:016X}"))
                        .monospace()
                        .color(ACCENT),
                );
            }
        });
        if let Some(address) = navigation {
            self.selected = Some(address);
            self.goto = format!("{address:X}");
        }
        let mut edited = false;
        let mut settings_focused = false;
        ui.horizontal(|ui| {
            ui.label("SLEIGH source");
            let response = ui.add(
                egui::TextEdit::singleline(&mut self.pcode.source)
                    .desired_width(ui.available_width() - 95.0)
                    .hint_text("Processor .slaspec file"),
            );
            edited |= response.changed();
            settings_focused |= response.has_focus();
            if ui.button("Browse…").clicked()
                && let Some(path) = rfd::FileDialog::new()
                    .add_filter("SLEIGH source", &["slaspec"])
                    .pick_file()
            {
                self.pcode.source = path.display().to_string();
                edited = true;
            }
        });
        ui.horizontal(|ui| {
            ui.label("Context");
            let response = ui.add(
                egui::TextEdit::singleline(&mut self.pcode.context)
                    .char_limit(4096)
                    .desired_width(f32::INFINITY)
                    .hint_text("Explicit processor defaults, e.g. longMode=1 addrsize=2 opsize=1"),
            );
            edited |= response.changed();
            settings_focused |= response.has_focus();
        });
        if edited {
            self.pcode.invalidate();
        }
        let mut lift = false;
        ui.horizontal(|ui| {
            if ui
                .add_enabled(
                    self.selected.is_some() && self.pending.is_none(),
                    egui::Button::new("Lift selected instruction"),
                )
                .clicked()
            {
                lift = true;
            }
            ui.checkbox(&mut self.pcode.automatic, "Follow selection");
            if ui.button("Reload source").clicked() {
                self.pcode.source_epoch = self.pcode.source_epoch.wrapping_add(1);
                self.pcode.invalidate();
                lift = true;
            }
            if self.pcode.waiting.is_some() {
                ui.spinner();
                ui.label(RichText::new("Compiling / lifting…").color(MUTED));
            }
        });
        let Some(address) = self.selected else {
            ui.label("Select an executable address to inspect its P-code.");
            return;
        };
        let key = self.pcode.key(address);
        if self.pcode.automatic
            && !settings_focused
            && !self.pcode.source.is_empty()
            && self.pending.is_none()
            && self
                .pcode
                .waiting
                .as_ref()
                .is_none_or(|(_, waiting)| *waiting != key)
            && self
                .pcode
                .view
                .as_ref()
                .is_none_or(|(shown, _)| *shown != key)
            && self
                .pcode
                .error
                .as_ref()
                .is_none_or(|(failed, _)| *failed != key)
        {
            lift = true;
        }
        if lift
            && self.pending.is_none()
            && let Some(loaded) = &self.loaded
        {
            self.pcode.request(&loaded.image, address);
        }
        ui.separator();
        if let Some((failed, error)) = &self.pcode.error
            && *failed == key
        {
            ui.colored_label(GOLD, error);
        }
        let Some((shown, view)) = &self.pcode.view else {
            return;
        };
        if *shown != key {
            return;
        }
        ui.horizontal(|ui| {
            ui.label(
                RichText::new(format!("{address:016X}  {}", view.disassembly))
                    .monospace()
                    .color(ACCENT),
            );
            if ui.button("Copy P-code JSON").clicked() {
                ui.ctx().copy_text(view.json.clone());
            }
        });
        ui.label(
            RichText::new(format!(
                "{} operations · next {:016X} · {} delay slots · {}",
                view.instruction.ops.len(),
                view.next_address,
                view.delay_slots,
                if view.cache_hit {
                    "compiled language reused"
                } else {
                    "language compiled"
                }
            ))
            .small()
            .color(MUTED),
        );
        egui::ScrollArea::both()
            .id_salt("pcode_operations")
            .show_rows(ui, 23.0, view.rows.len(), |ui, rows| {
                for index in rows {
                    ui.label(
                        RichText::new(format!("{index:04}  {}", view.rows[index])).monospace(),
                    );
                }
            });
    }
}

#[cfg(test)]
mod tests;
