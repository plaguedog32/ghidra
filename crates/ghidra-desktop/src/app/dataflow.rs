use super::*;
use crate::function_analysis::{
    FunctionRequest, FunctionResponse, FunctionView, FunctionWorker, RequestKey,
};
use ghidra_analysis::{AdaptedStatement, AppliedEffects};
use ghidra_cfg::NodeKind;
use std::sync::Arc;

mod constants;
mod expressions;
mod reduced;

/// Keep nested virtual lists finite inside the enclosing page scroll. A small
/// window may scroll the page to reach this area, but cannot squeeze it to zero.
fn inspection_panes<R>(
    ui: &mut egui::Ui,
    height: f32,
    contents: impl FnOnce(&mut egui::Ui) -> R,
) -> R {
    let height = height.max(180.0);
    ui.allocate_ui_with_layout(
        egui::vec2(ui.available_width(), height),
        egui::Layout::top_down(egui::Align::LEFT),
        |ui| {
            ui.set_min_height(height);
            contents(ui)
        },
    )
    .inner
}

/// Dataflow inspection modes over one completed function analysis.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum Inspect {
    #[default]
    ControlFlow,
    Storage,
    Expressions,
    Constants,
    Reduced,
}

#[derive(Default)]
pub(super) struct State {
    next_request: u64,
    waiting: Option<RequestKey>,
    /// Shared with the reduced-expression worker, which reads its existing
    /// constant facts and JSON without copying them.
    view: Option<(RequestKey, Arc<FunctionView>)>,
    error: Option<(RequestKey, String)>,
    worker: Option<FunctionWorker>,
    selected_node: usize,
    havoc_unknown: bool,
    inspect: Inspect,
    expression: expressions::Selection,
    constant: constants::Selection,
    reduced: reduced::State,
}

impl State {
    fn invalidate(&mut self) {
        self.next_request = self.next_request.wrapping_add(1);
        self.waiting = None;
        self.view = None;
        self.error = None;
        self.reduced.reset();
    }
    pub(super) fn clear(&mut self) {
        // Reuse the same worker across images. Its one-slot queue bounds stale
        // work instead of creating another compiling thread for every import.
        self.invalidate();
        self.selected_node = 0;
    }
    fn matches(key: RequestKey, fingerprint: (u64, u64)) -> bool {
        (key.generation, key.revision) == fingerprint
    }
    fn accept(&mut self, response: FunctionResponse, fingerprint: (u64, u64)) {
        if self.waiting != Some(response.key) {
            return;
        }
        self.waiting = None;
        if !Self::matches(response.key, fingerprint) {
            return;
        }
        match response.result {
            Ok(view) => {
                self.selected_node = view.analysis.ssa().entry();
                self.expression.value = 0;
                self.expression.operation = 0;
                self.constant.reset();
                self.reduced.reset();
                self.view = Some((response.key, Arc::new(view)));
                self.error = None;
            }
            Err(error) => {
                self.error = Some((response.key, error));
                self.view = None;
                self.reduced.reset();
            }
        }
    }
    pub(super) fn poll(&mut self, ctx: &egui::Context, fingerprint: (u64, u64)) {
        if self.waiting.is_some_and(|k| !Self::matches(k, fingerprint))
            || self
                .view
                .as_ref()
                .is_some_and(|(k, _)| !Self::matches(*k, fingerprint))
            || self
                .error
                .as_ref()
                .is_some_and(|(k, _)| !Self::matches(*k, fingerprint))
        {
            self.invalidate();
        }
        for _ in 0..4 {
            let response = match self.worker.as_ref().map(FunctionWorker::try_recv) {
                Some(Ok(Some(response))) => response,
                Some(Err(error)) => {
                    if let Some(key) = self.waiting.take() {
                        self.error = Some((key, error));
                    }
                    self.worker = None;
                    break;
                }
                _ => break,
            };
            self.accept(response, fingerprint);
        }
        self.reduced.poll(ctx, self.view.as_ref());
        if self.waiting.is_some() {
            ctx.request_repaint_after(Duration::from_millis(40));
        }
    }
}

impl Workbench {
    fn selected_function(&self) -> Option<u64> {
        let address = self.selected?;
        let functions = &self.loaded.as_ref()?.functions.functions;
        functions
            .iter()
            .find(|f| f.entry == address)
            .or_else(|| {
                functions.iter().find(|f| {
                    f.instructions
                        .binary_search_by_key(&address, |i| i.address)
                        .is_ok()
                })
            })
            .map(|f| f.entry)
    }

    pub(super) fn request_function_analysis(&mut self, entry: u64) {
        if self.pending.is_some() {
            return;
        }
        let Some(loaded) = self.loaded.as_ref() else {
            return;
        };
        self.dataflow.invalidate();
        let (generation, revision) = self.pcode.fingerprint();
        let key = RequestKey {
            id: self.dataflow.next_request,
            generation,
            revision,
            entry,
        };
        let config = match self.pcode.language_config() {
            Ok(config) => config,
            Err(error) => {
                self.dataflow.error = Some((key, error));
                return;
            }
        };
        let worker = self
            .dataflow
            .worker
            .get_or_insert_with(FunctionWorker::spawn);
        let result = worker.request(FunctionRequest {
            key,
            config,
            image: loaded.image.clone(),
            functions: loaded.functions.clone(),
            havoc_unknown: self.dataflow.havoc_unknown,
        });
        match result {
            Ok(()) => self.dataflow.waiting = Some(key),
            Err(error) => self.dataflow.error = Some((key, error)),
        }
    }

    pub(super) fn dataflow_view(&mut self, ui: &mut egui::Ui) {
        let viewport_height = ui.available_height();
        egui::ScrollArea::vertical()
            .id_salt("dataflow_page")
            .auto_shrink([false, false])
            .show(ui, |ui| self.dataflow_page(ui, viewport_height));
    }

    fn dataflow_page(&mut self, ui: &mut egui::Ui, viewport_height: f32) {
        let entry = self.selected_function();
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    entry.is_some(),
                    egui::Button::new("Analyze selected function"),
                )
                .clicked()
                && let Some(entry) = entry
            {
                self.request_function_analysis(entry);
            }
            if ui.button("Processor settings").clicked() {
                self.tab = Tab::Pcode;
            }
            if ui
                .checkbox(
                    &mut self.dataflow.havoc_unknown,
                    "Conservative unknown effects",
                )
                .changed()
            {
                self.dataflow.invalidate();
            }
            ui.separator();
            for (mode, label) in [
                (Inspect::ControlFlow, "CFG & SSA"),
                (Inspect::Storage, "Storage variables"),
                (Inspect::Expressions, "Expressions"),
                (Inspect::Constants, "Constants"),
                (Inspect::Reduced, "Reduced expressions"),
            ] {
                ui.selectable_value(&mut self.dataflow.inspect, mode, label);
            }
            if self.dataflow.waiting.is_some() {
                ui.spinner();
                ui.label("Analyzing function…");
            }
        });
        ui.label(RichText::new("Recovered x86/x64 functions with a matching catalog language. Unknown calls and userops require conservative effects; ABI and indirect targets remain unresolved.").small().color(MUTED));
        if entry.is_none() {
            ui.label("Select an instruction in a recovered function.");
        }
        if let Some((_, error)) = &self.dataflow.error {
            ui.colored_label(GOLD, error);
        }
        let Some((_, view)) = &self.dataflow.view else {
            ui.label("Analyze a function to inspect native control flow, SSA, typed P-code expressions, conservative constant facts and reduced expressions. Structured decompiled code is still in development.");
            return;
        };
        let analysis = Arc::clone(&view.analysis);
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(format!(
                    "{} · {:X} · {}",
                    view.name, view.entry, view.language_id
                ))
                .color(ACCENT),
            );
            if ui.button("Copy analysis JSON").clicked() {
                ui.ctx().copy_text(view.json.clone());
            }
        });
        ui.label(format!("{} native instructions · {} graph nodes · {} storage variables · {} SSA values · {} phis",
            view.native.len(), analysis.ssa().graph().node_count(), analysis.layout().variables().len(), analysis.ssa().values().len(), analysis.ssa().phi_count()));
        debug_assert!(Arc::ptr_eq(&analysis, view.expressions.analysis()));
        debug_assert!(Arc::ptr_eq(&view.expressions, view.constants.expressions()));
        let facts = Arc::clone(&view.constants);
        if !view.complete {
            ui.colored_label(GOLD, "Binary function recovery is incomplete. This result covers the recovered instructions.");
        }
        let placement = match analysis.ssa().placement() {
            ghidra_ssa::PhiPlacement::Unpruned => "Unpruned SSA.",
            ghidra_ssa::PhiPlacement::Pruned => "Liveness-pruned SSA.",
        };
        ui.label(RichText::new(format!("Instruction lengths and bytes checked; instruction-local temporaries start undefined. Memory dependencies use whole address spaces. {placement}")).small().color(MUTED));
        ui.separator();
        let pane_height = (viewport_height - (ui.cursor().top() - ui.min_rect().top())).max(180.0);
        if self.dataflow.inspect == Inspect::Expressions {
            let Some((_, view)) = &self.dataflow.view else {
                return;
            };
            if let Some(address) =
                expressions::panel(ui, &mut self.dataflow.expression, view, pane_height)
            {
                self.navigate_address(address);
            }
            return;
        }
        if self.dataflow.inspect == Inspect::Constants {
            let Some((_, view)) = &self.dataflow.view else {
                return;
            };
            if let Some(address) =
                constants::panel(ui, &mut self.dataflow.constant, view, pane_height)
            {
                self.navigate_address(address);
            }
            return;
        }
        if self.dataflow.inspect == Inspect::Reduced {
            let Some((key, view)) = &self.dataflow.view else {
                return;
            };
            let (key, view) = (*key, Arc::clone(view));
            // Only a cheap request is queued here; the worker simplifies.
            if self.pending.is_none() {
                self.dataflow.reduced.ensure(key, &view);
            }
            if let Some(address) =
                reduced::panel(ui, &mut self.dataflow.reduced, key, &view, pane_height)
            {
                self.navigate_address(address);
            }
            return;
        }
        inspection_panes(ui, pane_height, |ui| {
            if self.dataflow.inspect == Inspect::Storage {
                let variables = analysis.layout().variables();
                egui::ScrollArea::both()
                    .id_salt("dataflow_storage")
                    .show_rows(ui, 22.0, variables.len(), |ui, rows| {
                        for i in rows {
                            ui.monospace(format!(
                                "s{}  {:?}",
                                variables[i].id.0, variables[i].location
                            ));
                        }
                    });
                return;
            }
            let mut jump = None;
            ui.columns(2, |columns| {
                egui::ScrollArea::both()
                    .id_salt("dataflow_nodes")
                    .show_rows(
                        &mut columns[0],
                        23.0,
                        analysis.ssa().graph().node_count(),
                        |ui, rows| {
                            for node in rows {
                                let label = match analysis.cfg().node(node) {
                                    Some(NodeKind::Block(points)) => format!(
                                        "{node:>5}  {:X}:{}",
                                        points[0].address, points[0].operation_index
                                    ),
                                    Some(NodeKind::Exit(exit)) => {
                                        format!("{node:>5}  exit {:?}", exit.kind)
                                    }
                                    None => format!("{node:>5}  fresh temporaries"),
                                };
                                ui.selectable_value(
                                    &mut self.dataflow.selected_node,
                                    node,
                                    RichText::new(label).monospace(),
                                );
                            }
                        },
                    );
                let node = self.dataflow.selected_node;
                let ui = &mut columns[1];
                let Ok(block) = analysis.ssa().block(node) else {
                    return;
                };
                ui.label(format!(
                    "Node {node} · {} · constant propagation: {}",
                    if block.is_reachable() {
                        "reachable"
                    } else {
                        "unreachable"
                    },
                    match facts.is_node_executable(node) {
                        Ok(true) => constants::FEASIBLE,
                        Ok(false) => constants::NOT_FEASIBLE,
                        Err(_) => "unavailable",
                    }
                ));
                ui.label(format!(
                    "Successors: {:?}",
                    analysis.ssa().graph().successors(node).unwrap_or(&[])
                ));
                if let Some(NodeKind::Block(points)) = analysis.cfg().node(node)
                    && ui
                        .button(format!("Go to {:X}", points[0].address))
                        .clicked()
                {
                    jump = Some(points[0].address);
                }
                if let Some(renamed) = block.renamed() {
                    let mut incoming: Vec<_> = renamed
                        .incoming()
                        .iter()
                        .take(12)
                        .map(|p| match p {
                            ghidra_ssa::Predecessor::Entry => "entry".into(),
                            ghidra_ssa::Predecessor::Node(node) => format!("n{node}"),
                        })
                        .collect();
                    if renamed.incoming().len() > 12 {
                        incoming.push("…".into());
                    }
                    ui.label(format!("Incoming: {}", incoming.join(", ")));
                    let phis = renamed.phis();
                    if !phis.is_empty() {
                        ui.label("Phi values");
                        egui::ScrollArea::both()
                            .id_salt("dataflow_phis")
                            .max_height(180.0)
                            .show_rows(ui, 22.0, phis.len(), |ui, rows| {
                                for i in rows {
                                    let phi = &phis[i];
                                    ui.monospace(format!(
                                        "v{} = phi(s{}, {})",
                                        phi.value().0,
                                        phi.variable().0,
                                        ids(phi.operands().iter().map(|v| v.0))
                                    ));
                                }
                            });
                    }
                }
                ui.label("Operations");
                let raw = &analysis.raw().blocks[node];
                egui::ScrollArea::both()
                    .id_salt("dataflow_statements")
                    .show_rows(ui, 22.0, raw.len(), |ui, rows| {
                        for index in rows {
                            let id = ghidra_ssa::StatementId { node, index };
                            let label = match analysis.statement(id).expect("analysis statement") {
                                AdaptedStatement::Operation { point, effects, .. } => {
                                    let mnemonic = match analysis.cfg().statement(*point) {
                                        Some(ghidra_cfg::Statement::Operation(op)) => {
                                            op.opcode.mnemonic()
                                        }
                                        _ => "?",
                                    };
                                    format!(
                                        "{:X}:{} {}{}",
                                        point.address,
                                        point.operation_index,
                                        mnemonic,
                                        if matches!(effects, AppliedEffects::Conservative(_)) {
                                            " [opaque]"
                                        } else {
                                            ""
                                        }
                                    )
                                }
                                AdaptedStatement::NoOp { point } => {
                                    format!("{:X} no-op", point.address)
                                }
                                AdaptedStatement::UndefinedTemporaries { address, .. } => {
                                    format!("{address:X} fresh undefined temporaries")
                                }
                            };
                            let values = match analysis.ssa().statement(id) {
                                Ok(s) => format!(
                                    "defs [{}]  uses [{}]",
                                    ids(s.defs().iter().map(|v| v.0)),
                                    ids(s.uses().iter().map(|v| v.0))
                                ),
                                Err(_) => "unreachable".into(),
                            };
                            ui.monospace(format!("{label}   {values}"));
                        }
                    });
            });
            if let Some(address) = jump {
                self.navigate_address(address);
            }
        });
    }
}

fn ids(values: impl IntoIterator<Item = usize>) -> String {
    let mut values = values.into_iter();
    let mut result: Vec<_> = values.by_ref().take(12).map(|v| format!("v{v}")).collect();
    if values.next().is_some() {
        result.push("…".into());
    }
    result.join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: u64) -> RequestKey {
        RequestKey {
            id,
            generation: 7,
            revision: 3,
            entry: 0x1000,
        }
    }

    #[test]
    fn stale_function_ids_images_and_processor_revisions_cannot_replace_current_results() {
        let mut state = State {
            waiting: Some(key(2)),
            ..Default::default()
        };
        state.accept(
            FunctionResponse {
                key: key(1),
                result: Err("stale".into()),
            },
            (7, 3),
        );
        assert_eq!(state.waiting, Some(key(2)));
        assert!(state.error.is_none());
        state.accept(
            FunctionResponse {
                key: key(2),
                result: Err("old image".into()),
            },
            (8, 3),
        );
        assert!(state.error.is_none());
        state.waiting = Some(key(3));
        state.accept(
            FunctionResponse {
                key: key(3),
                result: Err("old processor".into()),
            },
            (7, 4),
        );
        assert!(state.error.is_none());
        state.waiting = Some(key(4));
        state.accept(
            FunctionResponse {
                key: key(4),
                result: Err("current".into()),
            },
            (7, 3),
        );
        assert_eq!(state.error.as_ref().unwrap().1, "current");
    }

    #[test]
    fn policy_edits_and_image_clear_invalidate_pending_results_without_spawning_more_workers() {
        let mut state = State {
            worker: Some(FunctionWorker::spawn()),
            waiting: Some(key(1)),
            havoc_unknown: true,
            ..Default::default()
        };
        state.invalidate();
        state.accept(
            FunctionResponse {
                key: key(1),
                result: Err("old policy".into()),
            },
            (7, 3),
        );
        assert!(state.error.is_none());
        state.waiting = Some(key(2));
        state.clear();
        assert!(state.waiting.is_none());
        assert!(state.worker.is_some());
    }

    #[test]
    fn completed_function_and_storage_views_render_without_mutating_project_state() {
        let fixture = crate::function_analysis::tests::fixture();
        let result = crate::function_analysis::tests::analyze(&fixture.request).unwrap();
        let loaded =
            crate::report::load_bytes("fixture".into(), fixture.request.image.bytes().to_vec())
                .unwrap();
        let mut app = Workbench::empty();
        app.selected = Some(result.entry);
        app.loaded = Some(loaded);
        let (generation, revision) = app.pcode.fingerprint();
        let key = RequestKey {
            id: 1,
            generation,
            revision,
            entry: result.entry,
        };
        app.dataflow.waiting = Some(key);
        app.dataflow.accept(
            FunctionResponse {
                key,
                result: Ok(result),
            },
            (generation, revision),
        );
        assert!(app.dataflow.view.is_some());
        let context = egui::Context::default();
        for storage in [Inspect::ControlFlow, Inspect::Storage] {
            app.dataflow.inspect = storage;
            let output = context.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1440.0, 900.0),
                    )),
                    ..Default::default()
                },
                |ctx| {
                    egui::CentralPanel::default().show(ctx, |ui| app.dataflow_view(ui));
                },
            );
            assert!(!output.shapes.is_empty());
        }
        assert!(!app.dirty);
        assert_eq!(app.revision, 0);
        app.dataflow.poll(&context, (generation + 1, revision));
        assert!(app.dataflow.view.is_none());
    }

    fn completed(result: FunctionView) -> (Workbench, (u64, u64)) {
        let loaded = crate::report::load_bytes(
            "fixture".into(),
            crate::function_analysis::tests::fixture()
                .request
                .image
                .bytes()
                .to_vec(),
        )
        .unwrap();
        let mut app = Workbench::empty();
        app.selected = Some(result.entry);
        app.loaded = Some(loaded);
        let fingerprint = app.pcode.fingerprint();
        let key = RequestKey {
            id: 1,
            generation: fingerprint.0,
            revision: fingerprint.1,
            entry: result.entry,
        };
        app.dataflow.waiting = Some(key);
        app.dataflow.accept(
            FunctionResponse {
                key,
                result: Ok(result),
            },
            fingerprint,
        );
        assert!(app.dataflow.view.is_some());
        (app, fingerprint)
    }

    fn render(app: &mut Workbench, context: &egui::Context) {
        let output = context.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1440.0, 900.0),
                )),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| app.dataflow_view(ui));
            },
        );
        assert!(!output.shapes.is_empty());
    }

    fn render_expression_rows(app: &mut Workbench, context: &egui::Context) {
        app.dataflow.inspect = Inspect::Expressions;
        let (values, operations) = {
            let view = &app.dataflow.view.as_ref().unwrap().1;
            (
                view.analysis.ssa().values().len(),
                view.expression_operations.len(),
            )
        };
        assert!(values > 0 && operations > 0);
        for rows in [expressions::Rows::Values, expressions::Rows::Operations] {
            app.dataflow.expression.rows = rows;
            // Selections from an older, larger view are clamped, not indexed.
            for selected in [0, 1, usize::MAX] {
                app.dataflow.expression.value = selected;
                app.dataflow.expression.operation = selected;
                render(app, context);
                match rows {
                    expressions::Rows::Values => assert!(app.dataflow.expression.value < values),
                    expressions::Rows::Operations => {
                        assert!(app.dataflow.expression.operation < operations)
                    }
                }
            }
        }
    }

    #[test]
    fn expression_mode_renders_values_operations_and_opaque_calls_without_mutation() {
        let fixture = crate::function_analysis::tests::fixture();
        let result = crate::function_analysis::tests::analyze(&fixture.request).unwrap();
        let (mut app, fingerprint) = completed(result);
        let context = egui::Context::default();
        render_expression_rows(&mut app, &context);
        // A new result resets expression selections.
        let result = crate::function_analysis::tests::analyze(&fixture.request).unwrap();
        app.dataflow.expression.value = 3;
        let key = RequestKey {
            id: 2,
            generation: fingerprint.0,
            revision: fingerprint.1,
            entry: result.entry,
        };
        app.dataflow.waiting = Some(key);
        app.dataflow.accept(
            FunctionResponse {
                key,
                result: Ok(result),
            },
            fingerprint,
        );
        assert_eq!(app.dataflow.expression.value, 0);
        // Conservative calls render as opaque operations and definitions.
        let source = std::fs::read_to_string(fixture.directory.path().join("test.slaspec"))
            .unwrap()
            .replace("rax = zext(imm);", "rax = zext(imm); call [rip];");
        std::fs::write(fixture.directory.path().join("test.slaspec"), source).unwrap();
        let mut request = fixture.request.clone();
        request.havoc_unknown = true;
        let result = crate::function_analysis::tests::analyze(&request).unwrap();
        let call = result
            .expression_operations
            .iter()
            .position(|s| {
                matches!(
                    result.expressions.operation(*s).unwrap().effects,
                    AppliedEffects::Conservative(_)
                )
            })
            .unwrap();
        let (mut app, fingerprint) = completed(result);
        render_expression_rows(&mut app, &context);
        app.dataflow.expression.rows = expressions::Rows::Operations;
        app.dataflow.expression.operation = call;
        render(&mut app, &context);
        assert_eq!(app.dataflow.expression.operation, call);
        assert!(!app.dirty);
        assert_eq!(app.revision, 0);
        assert!(app.loaded.as_ref().unwrap().metadata.annotations.is_empty());
        // Image/processor changes and policy edits drop the expression view.
        app.dataflow
            .poll(&context, (fingerprint.0 + 1, fingerprint.1));
        assert!(app.dataflow.view.is_none());
        render(&mut app, &context);
        assert_eq!(app.dataflow.inspect, Inspect::Expressions);
    }

    fn render_production(app: &mut Workbench, font_size: f32) {
        let context = egui::Context::default();
        context.style_mut(|style| {
            style.spacing.item_spacing = egui::vec2(10.0, 8.0);
            style.spacing.button_padding = egui::vec2(12.0, 7.0);
            for (text_style, font) in [
                (
                    egui::TextStyle::Monospace,
                    egui::FontId::monospace(font_size),
                ),
                (egui::TextStyle::Body, egui::FontId::proportional(font_size)),
                (
                    egui::TextStyle::Button,
                    egui::FontId::proportional(font_size),
                ),
            ] {
                style.text_styles.insert(text_style, font);
            }
        });
        let output = context.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1000.0, 650.0),
                )),
                ..Default::default()
            },
            |ctx| {
                egui::CentralPanel::default().show(ctx, |ui| app.dataflow_view(ui));
            },
        );
        assert!(!output.shapes.is_empty());
    }

    #[test]
    fn constant_mode_renders_every_row_kind_clamps_selections_and_never_mutates_the_project() {
        let fixture = crate::function_analysis::tests::fixture();
        let result = crate::function_analysis::tests::analyze(&fixture.request).unwrap();
        // The facts share the worker's expression and SSA allocations.
        assert!(Arc::ptr_eq(
            result.constants.expressions(),
            &result.expressions
        ));
        assert!(Arc::ptr_eq(result.constants.analysis(), &result.analysis));
        assert!(!result.constant_values.is_empty());
        let (mut app, fingerprint) = completed(result);
        let context = egui::Context::default();
        app.dataflow.inspect = Inspect::Constants;
        let limit = |app: &Workbench, rows| {
            let view = &app.dataflow.view.as_ref().unwrap().1;
            match rows {
                constants::Rows::Values => view.analysis.ssa().values().len(),
                constants::Rows::Known => view.constant_values.len(),
                constants::Rows::Edges => view.analysis.cfg().edges().len(),
                constants::Rows::Faults => view.constants.faults().len(),
            }
        };
        for rows in [
            constants::Rows::Values,
            constants::Rows::Known,
            constants::Rows::Edges,
            constants::Rows::Faults,
        ] {
            app.dataflow.constant.rows = rows;
            // Selections from an older, larger view are clamped, not indexed.
            for selected in [0, 1, usize::MAX] {
                let selection = &mut app.dataflow.constant;
                selection.value = selected;
                selection.known = selected;
                selection.edge = selected;
                selection.fault = selected;
                render(&mut app, &context);
                for font_size in [14.0, 28.0] {
                    render_production(&mut app, font_size);
                }
                let selection = &app.dataflow.constant;
                let current = match rows {
                    constants::Rows::Values => selection.value,
                    constants::Rows::Known => selection.known,
                    constants::Rows::Edges => selection.edge,
                    constants::Rows::Faults => selection.fault,
                };
                assert!(current < limit(&app, rows).max(1), "{rows:?} {current}");
            }
        }
        // The CFG view also reports conservative node feasibility.
        app.dataflow.inspect = Inspect::ControlFlow;
        render(&mut app, &context);
        app.dataflow.inspect = Inspect::Constants;
        // A new result resets selections but keeps the chosen row kind.
        app.dataflow.constant.rows = constants::Rows::Edges;
        app.dataflow.constant.edge = 3;
        let result = crate::function_analysis::tests::analyze(&fixture.request).unwrap();
        let key = RequestKey {
            id: 2,
            generation: fingerprint.0,
            revision: fingerprint.1,
            entry: result.entry,
        };
        app.dataflow.waiting = Some(key);
        app.dataflow.accept(
            FunctionResponse {
                key,
                result: Ok(result),
            },
            fingerprint,
        );
        assert_eq!(app.dataflow.constant.edge, 0);
        assert_eq!(app.dataflow.constant.rows, constants::Rows::Edges);
        render(&mut app, &context);
        assert!(!app.dirty);
        assert_eq!(app.revision, 0);
        assert!(app.loaded.as_ref().unwrap().metadata.annotations.is_empty());
        // Image/processor changes drop the facts with the rest of the view.
        app.dataflow
            .poll(&context, (fingerprint.0, fingerprint.1 + 1));
        assert!(app.dataflow.view.is_none());
        render(&mut app, &context);
        assert_eq!(app.dataflow.inspect, Inspect::Constants);
    }

    #[test]
    fn pending_project_operation_prevents_function_requests() {
        let mut app = Workbench::empty();
        let fixture = crate::function_analysis::tests::fixture();
        app.loaded = Some(
            crate::report::load_bytes("fixture".into(), fixture.request.image.bytes().to_vec())
                .unwrap(),
        );
        let (_sender, receiver) = mpsc::channel();
        app.pending = Some(receiver);
        app.request_function_analysis(fixture.request.key.entry);
        assert!(app.dataflow.worker.is_none());
        assert!(app.dataflow.waiting.is_none());
    }

    #[test]
    fn full_workbench_inspection_panes_remain_scrollable_at_small_sizes_and_large_fonts() {
        fn text_rect(output: &egui::FullOutput, needle: &str, exact: bool) -> Option<egui::Rect> {
            output.shapes.iter().find_map(|shape| {
                let egui::epaint::Shape::Text(text) = &shape.shape else {
                    return None;
                };
                let matches = if exact {
                    text.galley.text() == needle
                } else {
                    text.galley.text().starts_with(needle)
                };
                if !matches {
                    return None;
                }
                let visible = egui::Rect::from_min_size(text.pos, text.galley.size())
                    .intersect(shape.clip_rect)
                    .intersect(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1000.0, 650.0),
                    ));
                (visible.width() > 1.0 && visible.height() > 1.0).then_some(visible)
            })
        }
        fn frame(
            app: &mut Workbench,
            context: &egui::Context,
            time: &mut f64,
            events: Vec<egui::Event>,
        ) -> egui::FullOutput {
            *time += 1.0 / 30.0;
            context.run(
                egui::RawInput {
                    screen_rect: Some(egui::Rect::from_min_size(
                        egui::Pos2::ZERO,
                        egui::vec2(1000.0, 650.0),
                    )),
                    time: Some(*time),
                    events,
                    ..Default::default()
                },
                |ctx| {
                    app.toolbar(ctx);
                    egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
                        ui.label(RichText::new(&app.status).small());
                    });
                    app.sidebar(ctx);
                    app.inspector(ctx);
                    app.center(ctx);
                },
            )
        }
        fn scroll(
            app: &mut Workbench,
            context: &egui::Context,
            time: &mut f64,
            at: egui::Pos2,
        ) -> egui::FullOutput {
            let mut output = frame(
                app,
                context,
                time,
                vec![
                    egui::Event::PointerMoved(at),
                    egui::Event::MouseWheel {
                        unit: egui::MouseWheelUnit::Point,
                        delta: egui::vec2(0.0, -10000.0),
                        modifiers: egui::Modifiers::NONE,
                    },
                ],
            );
            for _ in 0..12 {
                output = frame(app, context, time, vec![]);
            }
            output
        }
        let fixture = crate::function_analysis::tests::fixture();
        let source =
            std::fs::read_to_string(fixture.directory.path().join("test.slaspec")).unwrap();
        assert!(source.contains("return [rip];"));
        std::fs::write(
            fixture.directory.path().join("test.slaspec"),
            source.replace("return [rip];", "rax = rax / 0; return [rip];"),
        )
        .unwrap();
        for font_size in [14.0, 28.0] {
            for rows in [
                constants::Rows::Values,
                constants::Rows::Known,
                constants::Rows::Edges,
                constants::Rows::Faults,
            ] {
                let view = crate::function_analysis::tests::analyze(&fixture.request).unwrap();
                let (mut app, _) = completed(view);
                app.tab = Tab::Dataflow;
                app.dataflow.inspect = Inspect::Constants;
                app.dataflow.constant.rows = rows;
                app.dataflow.constant.value =
                    app.dataflow.view.as_ref().unwrap().1.constant_values[0].0;
                let view = &app.dataflow.view.as_ref().unwrap().1;
                let c = view.constants.as_ref();
                assert!(!c.faults().is_empty());
                let spaces = c.analysis().cfg().spaces();
                let expected_row = match rows {
                    constants::Rows::Values => constants::value_row(c, spaces, 0).1,
                    constants::Rows::Known => {
                        constants::value_row(c, spaces, view.constant_values[0].0).1
                    }
                    constants::Rows::Edges => constants::edge_row(c, 0).1,
                    constants::Rows::Faults => constants::fault_row(c, 0).1,
                };
                let expected_address = match rows {
                    constants::Rows::Values => expressions::source_address(
                        &view.expressions,
                        ghidra_ssa::ValueId(app.dataflow.constant.value),
                    )
                    .unwrap(),
                    constants::Rows::Known => {
                        expressions::source_address(&view.expressions, view.constant_values[0])
                            .unwrap()
                    }
                    constants::Rows::Edges => c.analysis().cfg().edges()[0].source.address,
                    constants::Rows::Faults => {
                        view.expressions
                            .operation(c.faults()[0].statement)
                            .unwrap()
                            .point
                            .address
                    }
                };
                let context = egui::Context::default();
                context.style_mut(|style| {
                    style.spacing.item_spacing = egui::vec2(10.0, 8.0);
                    style.spacing.button_padding = egui::vec2(12.0, 7.0);
                    style.animation_time = 0.0;
                    for (kind, font) in [
                        (
                            egui::TextStyle::Monospace,
                            egui::FontId::monospace(font_size),
                        ),
                        (egui::TextStyle::Body, egui::FontId::proportional(font_size)),
                        (
                            egui::TextStyle::Button,
                            egui::FontId::proportional(font_size),
                        ),
                    ] {
                        style.text_styles.insert(kind, font);
                    }
                });
                let mut time = 0.0;
                let mut output = frame(&mut app, &context, &mut time, vec![]);
                for _ in 0..3 {
                    output = frame(&mut app, &context, &mut time, vec![]);
                }
                // Scroll on a header control so the page, rather than a nested
                // fact/detail list, receives the input. Its full production
                // toolbar and both 260-point side panels are present.
                let header = text_rect(&output, "Analyze selected function", false)
                    .expect("visible page header");
                output = scroll(&mut app, &context, &mut time, header.center());
                assert!(
                    text_rect(&output, &expected_row, true).is_some(),
                    "{font_size}, {rows:?}: no visible facts after page scroll"
                );
                {
                    // A long narrow detail panel must also allow its source
                    // navigation control to be reached by scrolling locally.
                    output = scroll(&mut app, &context, &mut time, egui::pos2(620.0, 600.0));
                    let button = text_rect(&output, "Go to ", false).unwrap_or_else(|| {
                        panic!("{font_size}, {rows:?}: source navigation inaccessible")
                    });
                    let at = button.center();
                    for pressed in [true, false] {
                        frame(
                            &mut app,
                            &context,
                            &mut time,
                            vec![
                                egui::Event::PointerMoved(at),
                                egui::Event::PointerButton {
                                    pos: at,
                                    button: egui::PointerButton::Primary,
                                    pressed,
                                    modifiers: egui::Modifiers::NONE,
                                },
                            ],
                        );
                    }
                    assert!(
                        matches!(app.tab, Tab::Listing),
                        "{font_size}, {rows:?}: source navigation did not run"
                    );
                    assert_eq!(
                        app.selected,
                        Some(expected_address),
                        "{font_size}, {rows:?}: wrong source address"
                    );
                }
                assert!(!app.dirty);
                assert_eq!(app.revision, 0);
                assert!(app.loaded.as_ref().unwrap().metadata.annotations.is_empty());
            }
        }
    }
}
