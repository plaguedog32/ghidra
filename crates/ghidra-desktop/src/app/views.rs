use super::*;

impl Workbench {
    pub(super) fn annotation_editor(&mut self, ui: &mut egui::Ui) {
        label_heading(ui, "ANNOTATION");
        let Some(address) = self.selected else {
            ui.label("Select an address to annotate");
            return;
        };
        let Some(loaded) = &self.loaded else {
            return;
        };
        let mut annotation = loaded
            .metadata
            .annotations
            .get(&address)
            .cloned()
            .unwrap_or_default();
        ui.label(RichText::new("Label").small().color(MUTED));
        let label = ui.add(
            egui::TextEdit::singleline(&mut annotation.label)
                .char_limit(64)
                .desired_width(f32::INFINITY),
        );
        ui.label(RichText::new("Comment").small().color(MUTED));
        let comment = ui.add(
            egui::TextEdit::multiline(&mut annotation.comment)
                .char_limit(16_384)
                .desired_rows(5)
                .desired_width(f32::INFINITY),
        );
        let bookmark = ui.checkbox(&mut annotation.bookmarked, "Bookmark this address");
        if label.changed() || comment.changed() || bookmark.changed() {
            self.set_annotation(address, annotation);
        }
    }

    pub(super) fn set_annotation(&mut self, address: u64, annotation: Annotation) {
        if self.pending.is_some() {
            return;
        }
        let Some(loaded) = &mut self.loaded else {
            return;
        };
        if annotation.label.is_empty() && annotation.comment.is_empty() && !annotation.bookmarked {
            loaded.metadata.annotations.remove(&address);
        } else {
            if loaded.metadata.annotations.len() >= ghidra_project::MAX_ANNOTATIONS
                && !loaded.metadata.annotations.contains_key(&address)
            {
                self.error = Some("The project annotation limit has been reached".into());
                return;
            }
            loaded.metadata.annotations.insert(address, annotation);
        }
        self.dirty = true;
        self.revision = self.revision.wrapping_add(1);
    }

    pub(super) fn navigate_function(&mut self, entry: u64) {
        if self.pending.is_some() {
            return;
        }
        let function = self
            .loaded
            .as_ref()
            .and_then(|loaded| loaded.functions.functions.iter().find(|f| f.entry == entry))
            .cloned();
        if let Some(function) = function {
            self.selected = Some(entry);
            self.goto = format!("{entry:X}");
            self.scroll_to = Some(0);
            self.tab = Tab::Listing;
            self.status = format!(
                "{} · reachable code{}",
                function.name,
                if function.complete {
                    ""
                } else {
                    " · incomplete recovery"
                }
            );
            if let Some(loaded) = &mut self.loaded {
                loaded.analysis = Some(Analysis {
                    instructions: function.instructions,
                    blocks: function.blocks,
                    references: function.references,
                    truncated: !function.complete,
                });
                loaded.analysis_error = None;
                loaded.analysis_method = "recursive function";
            }
        } else {
            self.navigate(entry);
        }
    }

    pub(super) fn navigate_address(&mut self, address: u64) {
        if self.pending.is_some() {
            return;
        }
        let Some(loaded) = &self.loaded else {
            return;
        };
        if loaded
            .functions
            .functions
            .iter()
            .any(|f| f.entry == address)
        {
            self.navigate_function(address);
            return;
        }
        let section = loaded
            .image
            .sections
            .iter()
            .find(|s| address >= s.address && address - s.address < s.size);
        if let Some(section) = section {
            if section.executable {
                if loaded.image.supports_x86_disassembly() {
                    self.navigate(address);
                } else {
                    self.selected = Some(address);
                    self.goto = format!("{address:X}");
                    self.tab = Tab::Pcode;
                }
            } else if address - section.address < section.file_size {
                self.hex_offset =
                    (section.file_offset + address - section.address) as usize / 16 * 16;
                self.selected = Some(address);
                self.goto = format!("{address:X}");
                self.tab = Tab::Hex;
            } else {
                self.error =
                    Some("This address belongs to zero-filled memory with no file bytes".into());
            }
        } else {
            self.error = Some(format!("Address {address:X} is not mapped"));
        }
    }

    pub(super) fn functions(&mut self, ui: &mut egui::Ui) {
        let mut jump = None;
        let loaded = self.loaded.as_ref().unwrap();
        ui.horizontal(|ui| {
            ui.label(format!(
                "{} discovered functions",
                loaded.functions.functions.len()
            ));
            ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("Filter functions"));
        });
        ui.label(RichText::new("Follows direct calls and reachable branches. Indirect targets and shared tails may remain unresolved.").small().color(MUTED));
        for warning in loaded.functions.warnings.iter().take(6) {
            ui.colored_label(GOLD, warning);
        }
        let needle = self.filter.to_lowercase();
        let functions: Vec<_> = loaded
            .functions
            .functions
            .iter()
            .filter(|f| {
                f.name.to_lowercase().contains(&needle)
                    || loaded
                        .metadata
                        .annotations
                        .get(&f.entry)
                        .is_some_and(|a| a.label.to_lowercase().contains(&needle))
            })
            .collect();
        egui::ScrollArea::both().id_salt("functions").show_rows(ui, 25.0, functions.len(), |ui, rows| {
            for index in rows {
                let f = functions[index];
                let name = loaded.metadata.annotations.get(&f.entry).filter(|a| !a.label.is_empty()).map(|a| a.label.as_str()).unwrap_or(&f.name);
                if ui.selectable_label(false, RichText::new(format!("{:016X}   {:<32}  {:>5} instructions  {:>4} blocks  {:>3} callers{}",
                    f.entry, name, f.instructions.len(), f.blocks.len(), f.callers.len(), if f.complete { "" } else { "  [incomplete]" })).monospace()).clicked()
                { jump = Some(f.entry); }
            }
        });
        if let Some(entry) = jump {
            self.navigate_function(entry);
        }
    }

    pub(super) fn bookmarks(&mut self, ui: &mut egui::Ui) {
        let loaded = self.loaded.as_ref().unwrap();
        let mut jump = None;
        let annotations: Vec<_> = loaded
            .metadata
            .annotations
            .iter()
            .filter(|(_, a)| a.bookmarked)
            .collect();
        ui.label(format!("{} bookmarks", annotations.len()));
        egui::ScrollArea::both().show_rows(ui, 25.0, annotations.len(), |ui, rows| {
            for index in rows {
                let (address, annotation) = annotations[index];
                let first_line = annotation.comment.lines().next().unwrap_or_default();
                if ui
                    .selectable_label(
                        false,
                        RichText::new(format!(
                            "{address:016X}   {}   {first_line}",
                            annotation.label
                        ))
                        .monospace(),
                    )
                    .clicked()
                {
                    jump = Some(*address);
                }
            }
        });
        if let Some(address) = jump {
            self.navigate_address(address);
        }
    }

    pub(super) fn linkage(&mut self, ui: &mut egui::Ui) {
        let loaded = self.loaded.as_ref().unwrap();
        let linkage = &loaded.linkage;
        let mut jump = None;
        ui.horizontal(|ui| {
            ui.selectable_value(
                &mut self.linkage_mode,
                0,
                format!("Imports ({})", linkage.imports.len()),
            );
            ui.selectable_value(
                &mut self.linkage_mode,
                1,
                format!("Exports ({})", linkage.exports.len()),
            );
            ui.selectable_value(
                &mut self.linkage_mode,
                2,
                format!("Relocations ({})", linkage.relocations.len()),
            );
        });
        for warning in linkage.warnings.iter().take(6) {
            ui.colored_label(GOLD, warning);
        }
        ui.add(egui::TextEdit::singleline(&mut self.filter).hint_text("Filter linkage"));
        let needle = self.filter.to_lowercase();
        match self.linkage_mode {
            0 => {
                let entries: Vec<_> = linkage
                    .imports
                    .iter()
                    .filter(|i| {
                        i.name.to_lowercase().contains(&needle)
                            || i.library.to_lowercase().contains(&needle)
                    })
                    .collect();
                egui::ScrollArea::both().id_salt("imports").show_rows(
                    ui,
                    25.0,
                    entries.len(),
                    |ui, rows| {
                        for index in rows {
                            let import = entries[index];
                            let address = import
                                .address
                                .map(|a| format!("{a:016X}"))
                                .unwrap_or_else(|| "unresolved      ".into());
                            if ui
                                .selectable_label(
                                    false,
                                    RichText::new(format!(
                                        "{address}   {:<24}  {}",
                                        import.library, import.name
                                    ))
                                    .monospace(),
                                )
                                .clicked()
                            {
                                jump = import.address;
                            }
                        }
                    },
                );
            }
            1 => {
                let entries: Vec<_> = linkage
                    .exports
                    .iter()
                    .filter(|e| e.name.to_lowercase().contains(&needle))
                    .collect();
                egui::ScrollArea::both().id_salt("exports").show_rows(
                    ui,
                    25.0,
                    entries.len(),
                    |ui, rows| {
                        for index in rows {
                            let export = entries[index];
                            if ui
                                .selectable_label(
                                    false,
                                    RichText::new(format!(
                                        "{:016X}   {}",
                                        export.address, export.name
                                    ))
                                    .monospace(),
                                )
                                .clicked()
                            {
                                jump = Some(export.address);
                            }
                        }
                    },
                );
            }
            _ => {
                let entries: Vec<_> = linkage
                    .relocations
                    .iter()
                    .filter(|r| {
                        r.target.to_lowercase().contains(&needle)
                            || r.kind.to_lowercase().contains(&needle)
                    })
                    .collect();
                egui::ScrollArea::both().id_salt("relocations").show_rows(
                    ui,
                    25.0,
                    entries.len(),
                    |ui, rows| {
                        for index in rows {
                            let relocation = entries[index];
                            if ui
                                .selectable_label(
                                    false,
                                    RichText::new(format!(
                                        "{:016X}   {:>2} bit   {:<24}  {}  {:+}",
                                        relocation.address,
                                        relocation.size,
                                        relocation.kind,
                                        relocation.target,
                                        relocation.addend
                                    ))
                                    .monospace(),
                                )
                                .clicked()
                            {
                                jump = Some(relocation.address);
                            }
                        }
                    },
                );
            }
        }
        if let Some(address) = jump {
            self.navigate_address(address);
        }
    }
}
