use crate::{
    demo,
    report::{self, Loaded},
};
use eframe::egui::{self, Color32, RichText};
use std::{path::PathBuf, sync::mpsc, time::Duration};

const ACCENT: Color32 = Color32::from_rgb(100, 215, 183);
const MUTED: Color32 = Color32::from_rgb(141, 157, 177);
const GOLD: Color32 = Color32::from_rgb(231, 191, 118);

pub enum Input {
    Path(PathBuf),
    Demo,
}

#[derive(Clone, Copy, PartialEq)]
enum Tab {
    Listing,
    Hex,
    Strings,
    Sections,
    Blocks,
}

pub struct Workbench {
    loaded: Option<Loaded>,
    pending: Option<mpsc::Receiver<Result<Loaded, String>>>,
    status: String,
    error: Option<String>,
    path: String,
    goto: String,
    filter: String,
    tab: Tab,
    selected: Option<u64>,
    scroll_to: Option<usize>,
    hex_offset: usize,
}

impl Workbench {
    pub fn new(cc: &eframe::CreationContext<'_>, initial: Option<Input>) -> Self {
        let mut visuals = egui::Visuals::dark();
        visuals.panel_fill = Color32::from_rgb(21, 27, 36);
        visuals.window_fill = Color32::from_rgb(25, 32, 43);
        visuals.extreme_bg_color = Color32::from_rgb(15, 20, 28);
        visuals.selection.bg_fill = Color32::from_rgb(36, 77, 76);
        cc.egui_ctx.set_visuals(visuals);
        let mut style = (*cc.egui_ctx.style()).clone();
        style.spacing.item_spacing = egui::vec2(10.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 7.0);
        cc.egui_ctx.set_style(style);
        let mut app = Self {
            loaded: None,
            pending: None,
            status: "Ready to inspect a binary".into(),
            error: None,
            path: String::new(),
            goto: String::new(),
            filter: String::new(),
            tab: Tab::Listing,
            selected: None,
            scroll_to: None,
            hex_offset: 0,
        };
        if let Some(input) = initial {
            app.open(input);
        }
        app
    }

    fn open(&mut self, input: Input) {
        if self.pending.is_some() {
            return;
        }
        self.status = "Reading binary and analyzing executable bytes…".into();
        self.error = None;
        let (tx, rx) = mpsc::channel();
        self.pending = Some(rx);
        std::thread::spawn(move || {
            let result = match input {
                Input::Path(path) => report::load_path(&path),
                Input::Demo => report::load_bytes("Synthetic sample · PE64".into(), demo::pe64()),
            };
            let _ = tx.send(result);
        });
    }

    fn poll(&mut self, ctx: &egui::Context) {
        let result = self.pending.as_ref().and_then(|rx| match rx.try_recv() {
            Ok(result) => Some(result),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => {
                Some(Err("Analysis worker stopped unexpectedly".into()))
            }
        });
        if let Some(result) = result {
            self.pending = None;
            match result {
                Ok(loaded) => {
                    self.selected = loaded
                        .analysis
                        .as_ref()
                        .and_then(|a| a.instructions.first().map(|i| i.address));
                    self.goto = self.selected.map(|a| format!("{a:X}")).unwrap_or_default();
                    self.path = loaded.name.clone();
                    self.status = format!(
                        "{} bytes imported · analysis is a bounded linear sweep",
                        loaded.image.bytes().len()
                    );
                    self.error = None;
                    self.hex_offset = 0;
                    self.scroll_to = Some(0);
                    self.loaded = Some(loaded);
                }
                Err(error) => {
                    self.status = "Operation failed".into();
                    self.error = Some(error);
                }
            }
        }
        if self.pending.is_some() {
            ctx.request_repaint_after(Duration::from_millis(40));
        }
    }

    fn pick_file(&mut self) {
        if self.pending.is_none()
            && let Some(path) = rfd::FileDialog::new()
                .set_title("Open binary for analysis")
                .pick_file()
        {
            self.open(Input::Path(path));
        }
    }

    fn navigate(&mut self, address: u64) {
        if self.pending.is_some() {
            return;
        }
        self.goto = format!("{address:X}");
        if let Some(loaded) = &self.loaded {
            if let Some(index) = loaded
                .analysis
                .as_ref()
                .and_then(|a| a.instructions.iter().position(|i| i.address == address))
            {
                self.selected = Some(address);
                self.scroll_to = Some(index);
                self.tab = Tab::Listing;
                return;
            }
            let image = loaded.image.clone();
            let name = loaded.name.clone();
            let (tx, rx) = mpsc::channel();
            self.pending = Some(rx);
            self.status = format!("Disassembling at {address:016X}…");
            std::thread::spawn(move || {
                let result = image
                    .disassemble(address, report::INSTRUCTION_LIMIT)
                    .map(|analysis| Loaded {
                        name,
                        image,
                        analysis: Some(analysis),
                        analysis_error: None,
                    })
                    .map_err(|e| e.to_string());
                let _ = tx.send(result);
            });
            self.tab = Tab::Listing;
        }
    }

    fn export(&mut self) {
        let Some(loaded) = &self.loaded else {
            return;
        };
        if let Some(path) = rfd::FileDialog::new()
            .set_file_name("analysis.json")
            .add_filter("JSON report", &["json"])
            .save_file()
        {
            match report::json(loaded)
                .and_then(|json| std::fs::write(&path, json).map_err(|e| e.to_string()))
            {
                Ok(()) => self.status = format!("Report saved to {}", path.display()),
                Err(e) => self.error = Some(format!("Could not save report: {e}")),
            }
        }
    }

    fn toolbar(&mut self, ctx: &egui::Context) {
        egui::TopBottomPanel::top("header").show(ctx, |ui| {
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(RichText::new("G H I D R A").size(22.0).strong());
                ui.label(RichText::new("RUST").color(ACCENT).size(12.0).strong());
                ui.separator();
                ui.label(
                    RichText::new("NATIVE BINARY WORKBENCH")
                        .color(MUTED)
                        .size(11.0),
                );
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    ui.label(
                        RichText::new("0.1  /  DESKTOP MILESTONE")
                            .small()
                            .color(MUTED),
                    );
                });
            });
            ui.add_space(8.0);
            ui.horizontal(|ui| {
                let ready = self.pending.is_none();
                if ui
                    .add_enabled(ready, egui::Button::new("Open binary…"))
                    .clicked()
                {
                    self.pick_file();
                }
                if ui
                    .add_enabled(ready, egui::Button::new("Load sample"))
                    .clicked()
                {
                    self.open(Input::Demo);
                }
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.path)
                        .hint_text("Binary path — or drop a file into this window")
                        .desired_width(ui.available_width() - 170.0),
                );
                let enter = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if (ui.add_enabled(ready, egui::Button::new("Import")).clicked() || enter)
                    && ready
                    && !self.path.is_empty()
                {
                    self.open(Input::Path(PathBuf::from(&self.path)));
                }
                if ui
                    .add_enabled(self.loaded.is_some(), egui::Button::new("Export JSON"))
                    .clicked()
                {
                    self.export();
                }
            });
            ui.add_space(4.0);
        });
    }

    fn sidebar(&mut self, ctx: &egui::Context) {
        let mut jump = None;
        egui::SidePanel::left("navigator")
            .resizable(true)
            .default_width(260.0)
            .width_range(210.0..=450.0)
            .show(ctx, |ui| {
                ui.add_space(10.0);
                label_heading(ui, "PROGRAM");
                let Some(loaded) = &self.loaded else {
                    ui.label(RichText::new("No binary loaded").color(MUTED));
                    return;
                };
                ui.label(RichText::new(&loaded.image.format).size(21.0).strong());
                ui.label(format!(
                    "{} · {} bit",
                    loaded.image.architecture, loaded.image.bitness
                ));
                ui.add_space(5.0);
                key_value(ui, "Entry", &format!("{:016X}", loaded.image.entry));
                key_value(ui, "Base", &format!("{:016X}", loaded.image.image_base));
                key_value(ui, "File", &format!("{} bytes", loaded.image.bytes().len()));
                ui.add_space(12.0);
                ui.separator();
                ui.add_space(5.0);
                label_heading(ui, "MEMORY MAP");
                egui::ScrollArea::vertical()
                    .id_salt("section_nav")
                    .max_height(220.0)
                    .show(ui, |ui| {
                        for section in &loaded.image.sections {
                            ui.horizontal(|ui| {
                                ui.label(
                                    RichText::new(if section.executable { "X" } else { "·" })
                                        .color(if section.executable { ACCENT } else { MUTED }),
                                );
                                if ui
                                    .selectable_label(false, &section.name)
                                    .on_hover_text(format!(
                                        "{:016X} · {} bytes",
                                        section.address, section.size
                                    ))
                                    .clicked()
                                {
                                    if section.executable {
                                        jump = Some(section.address);
                                    } else {
                                        self.tab = Tab::Hex;
                                        self.hex_offset = section.file_offset as usize / 16 * 16;
                                    }
                                }
                            });
                        }
                    });
                ui.add_space(8.0);
                ui.separator();
                ui.add_space(5.0);
                label_heading(ui, &format!("SYMBOLS  /  {}", loaded.image.symbols.len()));
                ui.add(
                    egui::TextEdit::singleline(&mut self.filter)
                        .hint_text("Filter symbols / strings")
                        .desired_width(f32::INFINITY),
                );
                let needle = self.filter.to_lowercase();
                egui::ScrollArea::vertical()
                    .id_salt("symbols")
                    .show(ui, |ui| {
                        let mut shown = 0;
                        for symbol in &loaded.image.symbols {
                            if !needle.is_empty() && !symbol.name.to_lowercase().contains(&needle) {
                                continue;
                            }
                            if shown >= 1000 {
                                ui.label("Refine filter to see more symbols");
                                break;
                            }
                            shown += 1;
                            if ui
                                .selectable_label(
                                    self.selected == Some(symbol.address),
                                    RichText::new(&symbol.name)
                                        .monospace()
                                        .color(if symbol.is_function { ACCENT } else { MUTED }),
                                )
                                .on_hover_text(format!(
                                    "{:016X} · {} bytes",
                                    symbol.address, symbol.size
                                ))
                                .clicked()
                            {
                                jump = Some(symbol.address);
                            }
                        }
                        if shown == 0 {
                            ui.label(RichText::new("No matching symbols").color(MUTED));
                        }
                    });
            });
        if let Some(address) = jump {
            self.navigate(address);
        }
    }

    fn inspector(&mut self, ctx: &egui::Context) {
        let mut jump = None;
        egui::SidePanel::right("inspector").default_width(260.0).width_range(210.0..=450.0).resizable(true).show(ctx, |ui| {
            ui.add_space(10.0);
            label_heading(ui, "ANALYSIS");
            let Some(loaded) = &self.loaded else { ui.label(RichText::new("Import a file to begin").color(MUTED)); return; };
            if let Some(error) = &loaded.analysis_error { ui.colored_label(GOLD, error); }
            for warning in &loaded.image.warnings { ui.colored_label(GOLD, warning); }
            let Some(analysis) = &loaded.analysis else { return; };
            key_value(ui, "Instructions", &analysis.instructions.len().to_string());
            key_value(ui, "Basic blocks", &analysis.blocks.len().to_string());
            key_value(ui, "References", &analysis.references.len().to_string());
            if analysis.truncated { ui.colored_label(GOLD, "Instruction limit reached. Navigate to a later address to continue."); }
            ui.add_space(8.0);
            ui.label(RichText::new("Linear sweep of one code section. Data embedded in code may decode as instructions.").small().color(MUTED));
            ui.add_space(10.0); ui.separator(); ui.add_space(8.0);
            label_heading(ui, "SELECTED INSTRUCTION");
            if let Some(instruction) = self.selected.and_then(|a| analysis.instructions.iter().find(|i| i.address == a)) {
                ui.label(RichText::new(format!("{:016X}", instruction.address)).monospace().color(ACCENT));
                ui.label(RichText::new(&instruction.text).monospace().size(15.0));
                ui.label(RichText::new(&instruction.flow).small().color(MUTED));
                ui.add_space(8.0);
                if let Some(target) = instruction.target && ui.button(format!("Follow {target:016X}")).clicked() { jump = Some(target); }
                label_heading(ui, "INCOMING REFERENCES");
                let refs: Vec<_> = analysis.references.iter().filter(|r| r.to == instruction.address).collect();
                if refs.is_empty() { ui.label(RichText::new("None in this analysis range").small().color(MUTED)); }
                for reference in refs.iter().take(100) {
                    if ui.button(format!("{:016X}  {}", reference.from, reference.kind)).clicked() { jump = Some(reference.from); }
                }
            } else { ui.label(RichText::new("Select an instruction in the listing").color(MUTED)); }
        });
        if let Some(address) = jump {
            self.navigate(address);
        }
    }

    fn center(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            if self.loaded.is_none() {
                ui.vertical_centered(|ui| {
                    ui.add_space(ui.available_height() * 0.22);
                    ui.label(RichText::new("Explore the binary.").size(36.0).strong());
                    ui.add_space(10.0);
                    ui.label(
                        RichText::new("A native Rust workbench for static analysis.")
                            .size(17.0)
                            .color(MUTED),
                    );
                    ui.add_space(22.0);
                    if ui.button("Open a binary…").clicked() {
                        self.pick_file();
                    }
                    if ui.button("Explore the built-in sample").clicked() {
                        self.open(Input::Demo);
                    }
                    ui.add_space(28.0);
                    ui.label(
                        RichText::new("PE · ELF · Mach-O    /    x86 & x64 disassembly")
                            .color(ACCENT),
                    );
                    ui.label(
                        RichText::new("Desktop milestone. Decompiler and debugger are planned.")
                            .small()
                            .color(MUTED),
                    );
                });
                return;
            }
            ui.horizontal(|ui| {
                for (tab, label) in [
                    (Tab::Listing, "Disassembly"),
                    (Tab::Hex, "Hex"),
                    (Tab::Strings, "Strings"),
                    (Tab::Sections, "Sections"),
                    (Tab::Blocks, "Basic blocks"),
                ] {
                    ui.selectable_value(&mut self.tab, tab, label);
                }
            });
            ui.separator();
            ui.horizontal(|ui| {
                ui.label(RichText::new("ADDRESS").small().color(MUTED));
                let response = ui.add(
                    egui::TextEdit::singleline(&mut self.goto)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(160.0)
                        .hint_text("Hex address"),
                );
                let enter = response.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
                if ui.button("Go").clicked() || enter {
                    match u64::from_str_radix(
                        self.goto
                            .trim()
                            .trim_start_matches("0x")
                            .trim_start_matches("0X"),
                        16,
                    ) {
                        Ok(address) => self.navigate(address),
                        Err(_) => self.error = Some("Enter a hexadecimal virtual address".into()),
                    }
                }
                if ui.button("Entry point").clicked() {
                    self.navigate(self.loaded.as_ref().unwrap().image.entry);
                }
            });
            ui.separator();
            match self.tab {
                Tab::Listing => self.listing(ui),
                Tab::Hex => self.hex(ui),
                Tab::Strings => self.strings(ui),
                Tab::Sections => self.sections(ui),
                Tab::Blocks => self.blocks(ui),
            }
        });
    }

    fn listing(&mut self, ui: &mut egui::Ui) {
        let loaded = self.loaded.as_ref().unwrap();
        let Some(analysis) = &loaded.analysis else {
            ui.colored_label(
                GOLD,
                loaded
                    .analysis_error
                    .as_deref()
                    .unwrap_or("No analysis available"),
            );
            return;
        };
        ui.label(
            RichText::new(
                "VIRTUAL ADDRESS       BYTES                                      INSTRUCTION",
            )
            .monospace()
            .small()
            .color(MUTED),
        );
        let row_height = 22.0;
        let mut scroll = egui::ScrollArea::both()
            .id_salt("listing")
            .auto_shrink([false, false]);
        if let Some(index) = self.scroll_to.take() {
            scroll = scroll
                .vertical_scroll_offset(index as f32 * (row_height + ui.spacing().item_spacing.y));
        }
        scroll.show_rows(ui, row_height, analysis.instructions.len(), |ui, rows| {
            for index in rows {
                let instruction = &analysis.instructions[index];
                let bytes = instruction
                    .bytes
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let text = format!(
                    "{:016X}    {:<44}  {}",
                    instruction.address, bytes, instruction.text
                );
                let color = if instruction.target.is_some() {
                    GOLD
                } else {
                    Color32::from_rgb(205, 215, 228)
                };
                let response = ui.add_sized(
                    [ui.available_width().max(820.0), row_height],
                    egui::Button::new(RichText::new(text).monospace().color(color))
                        .selected(self.selected == Some(instruction.address))
                        .frame(false),
                );
                if response.clicked() {
                    self.selected = Some(instruction.address);
                }
                response.context_menu(|ui| {
                    if ui.button("Copy instruction").clicked() {
                        ui.ctx().copy_text(format!(
                            "{:016X}: {}",
                            instruction.address, instruction.text
                        ));
                        ui.close();
                    }
                    if ui.button("Copy address").clicked() {
                        ui.ctx().copy_text(format!("{:X}", instruction.address));
                        ui.close();
                    }
                });
            }
        });
    }

    fn hex(&mut self, ui: &mut egui::Ui) {
        let bytes = self.loaded.as_ref().unwrap().image.bytes();
        ui.horizontal(|ui| {
            ui.label(RichText::new("FILE OFFSET").small().color(MUTED));
            ui.add(
                egui::DragValue::new(&mut self.hex_offset)
                    .range(0..=bytes.len().saturating_sub(1))
                    .speed(16),
            );
            ui.label(
                RichText::new("decimal · page of 4 KiB")
                    .small()
                    .color(MUTED),
            );
        });
        self.hex_offset = self.hex_offset.min(bytes.len().saturating_sub(1)) / 16 * 16;
        egui::ScrollArea::both().id_salt("hex").show(ui, |ui| {
            for (index, chunk) in bytes[self.hex_offset..bytes.len().min(self.hex_offset + 4096)]
                .chunks(16)
                .enumerate()
            {
                let hex = chunk
                    .iter()
                    .map(|b| format!("{b:02X}"))
                    .collect::<Vec<_>>()
                    .join(" ");
                let ascii: String = chunk
                    .iter()
                    .map(|&b| {
                        if b.is_ascii_graphic() || b == b' ' {
                            b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                ui.label(
                    RichText::new(format!(
                        "{:08X}    {hex:<47}    {ascii}",
                        self.hex_offset + index * 16
                    ))
                    .monospace(),
                );
            }
        });
    }

    fn strings(&mut self, ui: &mut egui::Ui) {
        let image = &self.loaded.as_ref().unwrap().image;
        ui.horizontal(|ui| {
            ui.label(format!("{} printable ASCII strings", image.strings.len()));
            ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("Filter text"));
        });
        let needle = self.filter.to_lowercase();
        let filtered: Vec<_> = image
            .strings
            .iter()
            .filter(|s| needle.is_empty() || s.value.to_lowercase().contains(&needle))
            .collect();
        egui::ScrollArea::both().id_salt("strings").show_rows(
            ui,
            23.0,
            filtered.len(),
            |ui, rows| {
                for index in rows {
                    let string = filtered[index];
                    if ui
                        .selectable_label(
                            false,
                            RichText::new(format!(
                                "{:08X}    {}",
                                string.file_offset, string.value
                            ))
                            .monospace(),
                        )
                        .clicked()
                    {
                        self.hex_offset = string.file_offset as usize / 16 * 16;
                        self.tab = Tab::Hex;
                    }
                }
            },
        );
    }

    fn sections(&mut self, ui: &mut egui::Ui) {
        let mut jump = None;
        egui::ScrollArea::both().show(ui, |ui| {
            egui::Grid::new("sections_grid")
                .striped(true)
                .spacing([20.0, 12.0])
                .show(ui, |ui| {
                    for header in [
                        "Section",
                        "Virtual address",
                        "Memory size",
                        "File offset",
                        "File size",
                        "Code",
                    ] {
                        ui.label(RichText::new(header).color(MUTED));
                    }
                    ui.end_row();
                    for section in &self.loaded.as_ref().unwrap().image.sections {
                        if ui.selectable_label(false, &section.name).clicked() {
                            if section.executable {
                                jump = Some(section.address);
                            } else {
                                self.hex_offset = section.file_offset as usize / 16 * 16;
                                self.tab = Tab::Hex;
                            }
                        }
                        ui.monospace(format!("{:016X}", section.address));
                        ui.monospace(format!("{:X}", section.size));
                        ui.monospace(format!("{:X}", section.file_offset));
                        ui.monospace(format!("{:X}", section.file_size));
                        ui.label(if section.executable { "yes" } else { "" });
                        ui.end_row();
                    }
                });
        });
        if let Some(address) = jump {
            self.navigate(address);
        }
    }

    fn blocks(&mut self, ui: &mut egui::Ui) {
        let mut jump = None;
        ui.label(
            RichText::new(
                "Blocks and successor addresses recovered within the current linear sweep.",
            )
            .color(MUTED),
        );
        if let Some(analysis) = &self.loaded.as_ref().unwrap().analysis {
            egui::ScrollArea::both().id_salt("blocks").show_rows(
                ui,
                25.0,
                analysis.blocks.len(),
                |ui, rows| {
                    for index in rows {
                        let block = &analysis.blocks[index];
                        ui.horizontal(|ui| {
                            if ui
                                .selectable_label(
                                    false,
                                    RichText::new(format!(
                                        "{:016X} .. {:016X}",
                                        block.start, block.end
                                    ))
                                    .monospace()
                                    .color(ACCENT),
                                )
                                .clicked()
                            {
                                jump = Some(block.start);
                            }
                            ui.label("→");
                            if block.successors.is_empty() {
                                ui.label(RichText::new("exit / unresolved").color(MUTED));
                            }
                            for target in &block.successors {
                                if ui
                                    .link(RichText::new(format!("{target:016X}")).monospace())
                                    .clicked()
                                {
                                    jump = Some(*target);
                                }
                            }
                        });
                    }
                },
            );
        }
        if let Some(address) = jump {
            self.navigate(address);
        }
    }
}

impl eframe::App for Workbench {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll(ctx);
        if ctx.input_mut(|i| i.consume_key(egui::Modifiers::COMMAND, egui::Key::O)) {
            self.pick_file();
        }
        if let Some(path) = ctx.input(|i| i.raw.dropped_files.first().and_then(|f| f.path.clone()))
        {
            self.open(Input::Path(path));
        }
        self.toolbar(ctx);
        egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
            ui.horizontal(|ui| {
                if self.pending.is_some() {
                    ui.spinner();
                }
                ui.label(RichText::new(&self.status).small().color(MUTED));
            });
            if let Some(error) = self.error.clone() {
                ui.horizontal_wrapped(|ui| {
                    ui.colored_label(GOLD, error);
                    if ui.small_button("Dismiss").clicked() {
                        self.error = None;
                    }
                });
            }
        });
        self.sidebar(ctx);
        self.inspector(ctx);
        self.center(ctx);
    }
}

fn label_heading(ui: &mut egui::Ui, text: &str) {
    ui.label(RichText::new(text).small().strong().color(MUTED));
    ui.add_space(3.0);
}
fn key_value(ui: &mut egui::Ui, label: &str, value: &str) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(label).small().color(MUTED));
        ui.label(RichText::new(value).monospace().small());
    });
}
