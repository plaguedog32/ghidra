use super::*;
use crate::function_analysis::reduced::{build, export};
use crate::function_analysis::tests::Fixture;
use ghidra_pcode::machine::ExecutionInput;
use ghidra_pcode::{PcodeInstruction, PcodeOperation, SpaceId, Varnode};
use std::time::Instant;

fn var(space: u32, offset: u64, size: u32) -> Varnode {
    Varnode {
        space: SpaceId(space),
        offset,
        size,
    }
}

fn op(opcode: Opcode, output: Option<Varnode>, inputs: Vec<Varnode>) -> PcodeOperation {
    PcodeOperation {
        opcode,
        output,
        inputs,
    }
}

/// A snapshot built by the command's own expression, fact and
/// simplification path.
fn snapshot(input: ExecutionInput, uniques: bool, havoc: bool) -> ReducedView {
    let terms = Arc::new(crate::analysis_cli::expressions_for(input, uniques, havoc));
    let facts = Arc::new(crate::constant_report::build(terms).unwrap());
    let reduced = ReducedView::new(facts.clone()).unwrap();
    assert!(Arc::ptr_eq(reduced.simplification.constants(), &facts));
    reduced
}

fn operations(s: &PcodeSimplification) -> Vec<StatementId> {
    s.expressions().operations().map(|o| o.statement).collect()
}

fn all_rows(snapshot: &ReducedView) -> Vec<(Color32, String)> {
    let s = &snapshot.simplification;
    let spaces = s.analysis().cfg().spaces();
    let mut rows: Vec<_> = (0..s.analysis().ssa().values().len())
        .map(|id| value_row(s, spaces, id))
        .collect();
    rows.extend((0..s.terms().len()).map(|id| term_row(s, spaces, id)));
    rows.extend(
        operations(s)
            .into_iter()
            .map(|statement| operation_row(s, spaces, statement)),
    );
    rows.extend((0..s.faults().len() + s.refused_folds().len()).map(|i| issue_row(s, i)));
    for (_, text) in &rows {
        assert!(text.chars().count() < 600, "{text}");
        assert!(!text.contains(['\r', '\n']), "{text}");
        let lower = text.to_lowercase();
        assert!(
            !lower.contains("decompil") && !lower.contains("optimi"),
            "{text}"
        );
    }
    rows
}

/// The canonical result of a value row: between `⇒` and the original
/// definition.
fn result(row: &str) -> &str {
    let start = row.find('⇒').expect("projected result");
    let end = row.rfind('←').expect("original definition");
    &row[start..end]
}

fn styled(font_size: f32) -> egui::Context {
    let context = egui::Context::default();
    context.style_mut(|style| {
        style.spacing.item_spacing = egui::vec2(10.0, 8.0);
        style.spacing.button_padding = egui::vec2(12.0, 7.0);
        style.animation_time = 0.0;
        // Each wheel event scrolls only the area under the pointer when it
        // arrives, so no remaining delta reaches a nested list later.
        style.scroll_animation = egui::style::ScrollAnimation::none();
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
    context
}

fn texts(output: &egui::FullOutput) -> Vec<String> {
    output
        .shapes
        .iter()
        .filter_map(|shape| match &shape.shape {
            egui::epaint::Shape::Text(text) => Some(text.galley.text().to_string()),
            _ => None,
        })
        .collect()
}

/// The visible part of the first text shape matching `needle`.
fn text_rect(output: &egui::FullOutput, needle: &str, exact: bool) -> Option<egui::Rect> {
    let screen = egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(1000.0, 650.0));
    visible_text(output, needle, exact, screen)
}

fn visible_text(
    output: &egui::FullOutput,
    needle: &str,
    exact: bool,
    screen: egui::Rect,
) -> Option<egui::Rect> {
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
            .intersect(screen);
        (visible.width() > 1.0 && visible.height() > 1.0).then_some(visible)
    })
}

/// Renders the snapshot panes in a window tall enough to show every detail
/// line, applying `events` to that frame.
fn render_contents(
    context: &egui::Context,
    selection: &mut Selection,
    snapshot: &ReducedView,
    operations: &[StatementId],
    events: Vec<egui::Event>,
) -> (egui::FullOutput, Option<u64>) {
    let mut jump = None;
    let output = context.run(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(1600.0, 3000.0),
            )),
            events,
            ..Default::default()
        },
        |ctx| {
            egui::CentralPanel::default().show(ctx, |ui| {
                jump = contents(ui, selection, snapshot, operations, 2800.0);
            });
        },
    );
    (output, jump)
}

fn click(at: egui::Pos2) -> Vec<egui::Event> {
    vec![
        egui::Event::PointerMoved(at),
        egui::Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed: true,
            modifiers: egui::Modifiers::NONE,
        },
        egui::Event::PointerButton {
            pos: at,
            button: egui::PointerButton::Primary,
            pressed: false,
            modifiers: egui::Modifiers::NONE,
        },
    ]
}

/// The single bit-vector value defined by `opcode` at `address`.
fn defined(s: &PcodeSimplification, address: u64, opcode: Opcode) -> (StatementId, ValueId) {
    let e = s.expressions();
    let operation = e
        .operations()
        .find(|o| o.point.address == address && o.opcode == opcode)
        .unwrap_or_else(|| panic!("{opcode:?} at {address:x}"));
    let defs = e
        .analysis()
        .ssa()
        .statement(operation.statement)
        .unwrap()
        .defs();
    let value = *defs
        .iter()
        .find(|v| matches!(e.value_type(**v), Ok(ExpressionType::Bits(_))))
        .unwrap();
    (operation.statement, value)
}

#[test]
fn rows_show_reductions_unreached_code_kept_faults_refusals_and_memory() {
    let snap = snapshot(crate::analysis_cli::tests::constant_program(), false, false);
    let s = &snap.simplification;
    let spaces = s.analysis().cfg().spaces();
    let rows = all_rows(&snap);
    assert!(!rows.is_empty());
    // 9 + 1 through the folded phi is the literal 10 for every use.
    let (add, sum) = defined(s, 0x1010, Opcode::IntAdd);
    let (color, row) = value_row(s, spaces, sum.0);
    assert_eq!(color, ACCENT);
    assert!(
        row.contains(" literal ") && row.contains("← INT_ADD("),
        "{row}"
    );
    assert!(result(&row).contains("0xa:4B"), "{row}");
    assert!(snap.reduced_values.contains(&sum));
    assert_eq!(status(s, sum).unwrap().0, Status::Literal);
    let (_, text) = operation_row(s, spaces, add);
    assert!(text.ends_with("[literal output]"), "{text}");
    assert!(text.contains("⇒ c") && text.contains("0xa:4B"), "{text}");
    // The skipped block is not simplified and never shows a literal result.
    let (copy, skipped) = defined(s, 0x1004, Opcode::Copy);
    let (color, row) = value_row(s, spaces, skipped.0);
    assert_eq!(color, MUTED);
    assert!(row.contains(" unreached "), "{row}");
    assert!(
        result(&row).contains("not simplified (never zero)"),
        "{row}"
    );
    assert!(!result(&row).contains("0x"), "{row}");
    assert!(!snap.reduced_values.contains(&skipped));
    let (color, text) = operation_row(s, spaces, copy);
    assert_eq!(color, MUTED);
    assert!(text.ends_with("[unreached: not simplified]"), "{text}");
    // The division keeps a distinct term that may fault; uses of its value
    // keep the SSA leaf rather than receiving the faulting term.
    let (division, quotient) = defined(s, 0x1010, Opcode::IntDiv);
    let (color, text) = operation_row(s, spaces, division);
    assert_eq!(color, GOLD);
    assert!(text.contains("INT_DIV(0x5:4B, 0x0:4B)"), "{text}");
    assert!(text.ends_with("[kept: may fault]"), "{text}");
    let (_, row) = value_row(s, spaces, quotient.0);
    assert!(row.contains(" leaf "), "{row}");
    assert!(
        result(&row).contains("(kept: definition may fault)"),
        "{row}"
    );
    // The load is a distinct read through the folded word-scaled pointer
    // that keeps its memory version.
    let (load, loaded) = defined(s, 0x1010, Opcode::Load);
    let (_, text) = operation_row(s, spaces, load);
    assert!(
        text.contains("read 4B LE ram[8B ptr 0x2000:8B × 1-byte words] of v"),
        "{text}"
    );
    assert!(text.ends_with("[memory read kept]"), "{text}");
    let (_, row) = value_row(s, spaces, loaded.0);
    assert!(
        result(&row).contains("(kept: definition reads memory)"),
        "{row}"
    );
    let read = s.operation(load).unwrap().unwrap().output().unwrap().0;
    let (color, text) = term_row(s, spaces, read);
    assert_eq!(color, GOLD);
    assert!(
        text.contains("[distinct, may fault here, reads memory]"),
        "{text}"
    );
    // A constant RETURN target is a projected control address operand.
    let ret = s
        .expressions()
        .operations()
        .find(|o| o.point.address == 0x1014)
        .unwrap()
        .statement;
    assert!(
        operation_row(s, spaces, ret).1.ends_with("⇒ (0x9000:8B)"),
        "{}",
        operation_row(s, spaces, ret).1
    );
    // The CBRANCH on an entry input keeps a comparison, not a literal.
    let branch = s
        .expressions()
        .operations()
        .find(|o| o.opcode == Opcode::Cbranch && o.point.address == 0x1010)
        .unwrap()
        .statement;
    let text = operation_row(s, spaces, branch).1;
    assert!(text.contains("⇒ (_, c") && text.ends_with(')'), "{text}");
    // The constant-propagation fault and the refused fold are separate.
    assert_eq!((s.faults().len(), s.refused_folds().len()), (1, 1));
    let (color, fault) = issue_row(s, 0);
    assert_eq!(color, GOLD);
    assert!(fault.starts_with("fault   ") && fault.contains("1010:1 INT_DIV"));
    assert!(
        fault.ends_with("constant-propagation evaluation fault: p-code division by zero"),
        "{fault}"
    );
    let (color, refused) = issue_row(s, 1);
    assert_eq!(color, PLAIN);
    assert!(refused.starts_with("refused ") && refused.contains("1010:1 INT_DIV"));
    assert!(
        refused.contains("literal fold refused, not a runtime fault: "),
        "{refused}"
    );
    // Out-of-range IDs are reported rather than indexed.
    assert!(value_row(s, spaces, usize::MAX).1.contains("unavailable"));
    assert!(term_row(s, spaces, usize::MAX).1.contains("unavailable"));
    assert!(issue_row(s, 2).1.contains("unavailable"));
}

#[test]
fn propagated_leaves_keep_undefined_and_opaque_identities_and_are_never_zero() {
    // A unique read before any write in instruction scope is a fresh
    // UNDEFINED temporary: entry state in the first instruction, a reset in
    // a later one with a single predecessor (a merge would be a phi leaf). The copy's uses receive that other value's leaf, never
    // zero, and keep its own UNDEFINED kind.
    for (instruction, address, kind, definition) in [
        (
            0,
            0x1000,
            "(UNDEFINED at entry)",
            "UNDEFINED at entry (never zero)",
        ),
        (
            3,
            0x1014,
            "(UNDEFINED reset)",
            "UNDEFINED fresh temporary at 1014",
        ),
    ] {
        let mut fresh = crate::analysis_cli::tests::constant_program();
        fresh.instructions[instruction]
            .ops
            .insert(0, op(Opcode::Copy, Some(var(2, 72, 4)), vec![var(3, 0, 4)]));
        let snap = snapshot(fresh, true, false);
        let s = &snap.simplification;
        let spaces = s.analysis().cfg().spaces();
        let copy = s
            .expressions()
            .operations()
            .find(|o| {
                o.point.address == address
                    && o.point.operation_index == 0
                    && o.opcode == Opcode::Copy
            })
            .unwrap()
            .statement;
        let copy = s.analysis().ssa().statement(copy).unwrap().defs()[0];
        let (color, row) = value_row(s, spaces, copy.0);
        assert_eq!(color, GOLD, "{row}");
        assert!(row.contains(" propagated "), "{row}");
        assert!(result(&row).contains(kind), "{row}");
        assert!(!result(&row).contains("0x"), "{row}");
        let TermKind::Leaf(undefined) = s.term(s.value_term(copy).unwrap()).unwrap().kind else {
            panic!("not a leaf");
        };
        assert_ne!(undefined, copy);
        assert!(snap.reduced_values.contains(&copy));
        // No UNDEFINED result is ever a literal.
        for (_, text) in all_rows(&snap) {
            if let (Some(start), Some(end)) = (text.find('⇒'), text.rfind('←'))
                && start < end
                && text[start..end].contains("UNDEFINED")
            {
                assert!(!text[start..end].contains("0x"), "{text}");
            }
        }
        // The detail names the other value's own UNDEFINED definition.
        let context = egui::Context::default();
        let operations = operations(s);
        let mut selection = Selection {
            value: copy.0,
            ..Default::default()
        };
        let (output, _) = render_contents(&context, &mut selection, &snap, &operations, vec![]);
        let shown = texts(&output);
        let expected = format!("Canonical leaf v{} = {definition}", undefined.0);
        assert!(
            shown.iter().any(|t| t.starts_with(&expected)),
            "{expected} in {shown:?}"
        );
    }

    let mut called = crate::analysis_cli::tests::constant_program();
    called.instructions[0]
        .ops
        .insert(0, op(Opcode::Call, None, vec![var(1, 0x8000, 8)]));
    let snap = snapshot(called, false, true);
    let s = &snap.simplification;
    let spaces = s.analysis().cfg().spaces();
    let call = s
        .expressions()
        .operations()
        .find(|o| o.opcode == Opcode::Call)
        .unwrap();
    let (color, text) = operation_row(s, spaces, call.statement);
    assert_eq!(color, GOLD);
    assert!(
        text.contains("OPAQUE") && text.ends_with("[definitions stay OPAQUE leaves]"),
        "{text}"
    );
    let defs = s
        .analysis()
        .ssa()
        .statement(call.statement)
        .unwrap()
        .defs()
        .to_vec();
    assert!(!defs.is_empty());
    for value in defs {
        let (color, row) = value_row(s, spaces, value.0);
        assert_eq!(color, GOLD, "{row}");
        assert!(row.contains(" leaf "), "{row}");
        assert!(result(&row).contains("(OPAQUE effect)"), "{row}");
        assert!(!snap.reduced_values.contains(&value));
    }
}

#[test]
fn details_clamp_invalid_selections_follow_term_references_and_name_return_targets() {
    let snap = snapshot(crate::analysis_cli::tests::constant_program(), false, false);
    let s = &snap.simplification;
    let operations = operations(s);
    let limit = |rows| match rows {
        Rows::Values => s.analysis().ssa().values().len(),
        Rows::Reductions => snap.reduced_values.len(),
        Rows::Terms => s.terms().len(),
        Rows::Operations => operations.len(),
        Rows::Issues => s.faults().len() + s.refused_folds().len(),
    };
    for font_size in [14.0, 28.0] {
        let context = styled(font_size);
        for rows in [
            Rows::Values,
            Rows::Reductions,
            Rows::Terms,
            Rows::Operations,
            Rows::Issues,
        ] {
            for selected in [0, 1, usize::MAX] {
                let mut selection = Selection {
                    rows,
                    value: selected,
                    reduction: selected,
                    term: selected,
                    operation: selected,
                    issue: selected,
                    reveal: true,
                };
                let (output, _) =
                    render_contents(&context, &mut selection, &snap, &operations, vec![]);
                let current = match rows {
                    Rows::Values => selection.value,
                    Rows::Reductions => selection.reduction,
                    Rows::Terms => selection.term,
                    Rows::Operations => selection.operation,
                    Rows::Issues => selection.issue,
                };
                assert!(current < limit(rows).max(1), "{rows:?} {current}");
                assert!(!selection.reveal);
                // Operations and issues always have a source instruction.
                if matches!(rows, Rows::Operations | Rows::Issues) {
                    assert!(
                        texts(&output).iter().any(|t| t.starts_with("Go to ")),
                        "{rows:?} {selected}"
                    );
                }
            }
        }
    }
    // Clicking the canonical result of a value inspects that term.
    let spaces = s.analysis().cfg().spaces();
    let (_, sum) = defined(s, 0x1010, Opcode::IntAdd);
    let term = s.value_term(sum).unwrap();
    let context = egui::Context::default();
    let mut selection = Selection {
        value: sum.0,
        ..Default::default()
    };
    let (output, _) = render_contents(&context, &mut selection, &snap, &operations, vec![]);
    let link = format!("c{} = {}", term.0, term_preview(s, spaces, term).1);
    let at = visible_text(&output, &link, true, egui::Rect::EVERYTHING)
        .unwrap_or_else(|| panic!("{link} in {:?}", texts(&output)))
        .center();
    render_contents(&context, &mut selection, &snap, &operations, click(at));
    assert_eq!((selection.rows, selection.term), (Rows::Terms, term.0));
    assert!(selection.reveal);
    let (output, _) = render_contents(&context, &mut selection, &snap, &operations, vec![]);
    assert!(!selection.reveal);
    let shown = texts(&output);
    assert!(
        shown
            .iter()
            .any(|t| t.starts_with(&format!("Canonical term c{} ·", term.0)))
    );
    assert!(
        shown.iter().any(|t| t == "Literal 0xa (4 bytes)"),
        "{shown:?}"
    );
    // A RETURN target is labelled a control address in the operation detail.
    let ret = operations
        .iter()
        .position(|statement| {
            s.expressions().operation(*statement).unwrap().point.address == 0x1014
        })
        .unwrap();
    let mut selection = Selection {
        rows: Rows::Operations,
        operation: ret,
        ..Default::default()
    };
    let (output, _) = render_contents(&context, &mut selection, &snap, &operations, vec![]);
    assert!(texts(&output).iter().any(|t| {
        t.starts_with("return target (control address, not an ABI return value): 0x9000:8B ⇒ c")
    }));
}

#[test]
fn empty_reductions_and_issue_lists_render_explicit_states() {
    let mut program = crate::analysis_cli::tests::constant_program();
    program.instructions = vec![PcodeInstruction {
        address: 0x1000,
        length: 4,
        ops: vec![op(Opcode::Return, None, vec![var(2, 0, 8)])],
    }];
    let snap = snapshot(program, false, false);
    let s = &snap.simplification;
    assert!(snap.reduced_values.is_empty());
    assert!(s.faults().is_empty() && s.refused_folds().is_empty());
    let operations = operations(s);
    let context = egui::Context::default();
    for (rows, empty) in [
        (
            Rows::Reductions,
            "No SSA value is reduced: every use keeps its own SSA identity.",
        ),
        (
            Rows::Issues,
            "No constant-propagation faults or refused folds.",
        ),
    ] {
        let mut selection = Selection {
            rows,
            reduction: usize::MAX,
            issue: usize::MAX,
            ..Default::default()
        };
        let (output, jump) = render_contents(&context, &mut selection, &snap, &operations, vec![]);
        assert!(jump.is_none());
        let shown = texts(&output);
        assert!(shown.iter().any(|t| t == empty), "{shown:?}");
        assert!(
            shown
                .iter()
                .any(|t| t.starts_with("Reductions: 0 literal values · 0 propagated values")),
            "{shown:?}"
        );
        let current = match rows {
            Rows::Reductions => selection.reduction,
            _ => selection.issue,
        };
        assert_eq!(current, 0);
    }
    // The entry-input return target stays its own SSA leaf.
    let spaces = s.analysis().cfg().spaces();
    let row = operation_row(s, spaces, operations[0]).1;
    assert!(row.ends_with("⇒ (v0)") || row.contains("⇒ (v"), "{row}");
}

#[test]
fn large_snapshots_format_only_visible_rows_each_frame() {
    let mut program = crate::analysis_cli::tests::constant_program();
    program.instructions = (0..600u64)
        .map(|i| PcodeInstruction {
            address: 0x1000 + i * 4,
            length: 4,
            ops: (0..8u64)
                .map(|j| {
                    op(
                        Opcode::IntAdd,
                        Some(var(2, (j * 8) % 128, 8)),
                        vec![var(2, ((j + 1) * 8) % 128, 8), var(0, i * 8 + j + 1, 8)],
                    )
                })
                .collect(),
        })
        .chain([PcodeInstruction {
            address: 0x1000 + 600 * 4,
            length: 4,
            ops: vec![op(Opcode::Return, None, vec![var(2, 0, 8)])],
        }])
        .collect();
    let snap = snapshot(program, false, false);
    let s = &snap.simplification;
    let operations = operations(s);
    assert!(s.terms().len() > 5000, "{}", s.terms().len());
    assert!(operations.len() > 4000);
    for rows in [
        Rows::Values,
        Rows::Reductions,
        Rows::Terms,
        Rows::Operations,
    ] {
        for font_size in [14.0, 28.0] {
            let context = styled(font_size);
            let mut selection = Selection {
                rows,
                term: 4000,
                value: 4000,
                operation: 4000,
                reduction: 2000,
                reveal: true,
                ..Default::default()
            };
            for _ in 0..3 {
                let before = FORMATTED.with(|count| count.get());
                let _ = context.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(1000.0, 650.0),
                        )),
                        ..Default::default()
                    },
                    |ctx| {
                        egui::CentralPanel::default().show(ctx, |ui| {
                            contents(ui, &mut selection, &snap, &operations, 500.0);
                        });
                    },
                );
                let formatted = FORMATTED.with(|count| count.get()) - before;
                assert!(
                    (1..=64).contains(&formatted),
                    "{rows:?} {font_size}: {formatted} rows formatted"
                );
            }
        }
    }
}

fn fixture_view() -> (Fixture, Arc<FunctionView>) {
    let fixture = crate::function_analysis::tests::fixture();
    let path = fixture.directory.path().join("test.slaspec");
    let source = std::fs::read_to_string(&path).unwrap();
    assert!(source.contains("return [rip];"));
    std::fs::write(
        &path,
        source.replace(
            "return [rip];",
            "rax = rax / 0; rax = rax + *:8 rip; return [rip];",
        ),
    )
    .unwrap();
    let view = Arc::new(crate::function_analysis::tests::analyze(&fixture.request).unwrap());
    (fixture, view)
}

fn key(view: &FunctionView) -> RequestKey {
    RequestKey {
        id: 1,
        generation: 7,
        revision: 3,
        entry: view.entry,
    }
}

/// Polls `state` inside frames until `done`, returning copied texts.
fn poll_until(
    state: &mut State,
    context: &egui::Context,
    view: Option<&(RequestKey, Arc<FunctionView>)>,
    done: impl Fn(&State) -> bool,
) -> Vec<String> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut copies = Vec::new();
    loop {
        let output = context.run(egui::RawInput::default(), |ctx| state.poll(ctx, view));
        copies.extend(copied(&output));
        if done(state) {
            return copies;
        }
        assert!(Instant::now() < deadline, "worker did not respond");
        std::thread::sleep(Duration::from_millis(2));
    }
}

fn copied(output: &egui::FullOutput) -> Vec<String> {
    output
        .platform_output
        .commands
        .iter()
        .filter_map(|command| match command {
            egui::OutputCommand::CopyText(text) => Some(text.clone()),
            _ => None,
        })
        .collect()
}

fn ready(state: &State) -> Arc<ReducedView> {
    match &state.build {
        Build::Ready(snapshot) => snapshot.clone(),
        other => panic!("not ready: {other:?}"),
    }
}

#[test]
fn snapshots_are_built_once_guarded_by_source_and_copied_exactly_once() {
    let (_fixture, view) = fixture_view();
    let key = key(&view);
    let current = (key, view.clone());
    let context = egui::Context::default();
    let mut state = State::default();
    state.ensure(key, &view);
    let Build::Waiting(first) = state.build else {
        panic!("build not queued");
    };
    // A pending or completed build is not requested again.
    state.ensure(key, &view);
    assert!(matches!(state.build, Build::Waiting(id) if id == first));
    assert!(poll_until(&mut state, &context, Some(&current), |s| !s.waiting()).is_empty());
    let snapshot = ready(&state);
    let s = &snapshot.simplification;
    assert!(Arc::ptr_eq(s.constants(), &view.constants));
    assert!(Arc::ptr_eq(s.expressions(), &view.expressions));
    assert!(Arc::ptr_eq(s.analysis(), &view.analysis));
    state.ensure(key, &view);
    assert!(Arc::ptr_eq(&ready(&state), &snapshot));

    // Late, mismatched or foreign results never replace the snapshot.
    let (_other_fixture, other) = fixture_view();
    let foreign = Arc::new(build(&other).unwrap());
    let built = |id, source, snapshot: &Arc<ReducedView>| ReducedResponse {
        id,
        source,
        outcome: ReducedOutcome::Built(Ok(snapshot.clone())),
    };
    state.accept(&context, built(first, key, &foreign), Some(&current));
    assert!(Arc::ptr_eq(&ready(&state), &snapshot));
    state.build = Build::Waiting(99);
    state.accept(&context, built(99, key, &foreign), Some(&current));
    assert!(matches!(&state.build, Build::Failed(e) if e == MISMATCH));
    state.build = Build::Waiting(100);
    let old = RequestKey { id: 0, ..key };
    state.accept(&context, built(100, old, &snapshot), Some(&current));
    assert!(matches!(&state.build, Build::Failed(e) if e == MISMATCH));
    state.build = Build::Waiting(101);
    state.accept(&context, built(101, key, &snapshot), None);
    assert!(matches!(&state.build, Build::Failed(e) if e == MISMATCH));

    // Stale or foreign exports are never copied.
    state.build = Build::Ready(snapshot.clone());
    let exported = |id, snapshot: &Arc<ReducedView>| ReducedResponse {
        id,
        source: key,
        outcome: ReducedOutcome::Exported {
            snapshot: snapshot.clone(),
            result: Ok("stale".into()),
        },
    };
    state.export = Export::Waiting(200);
    let output = context.run(egui::RawInput::default(), |ctx| {
        state.accept(ctx, exported(199, &snapshot), Some(&current));
        state.accept(ctx, exported(200, &foreign), Some(&current));
    });
    assert!(copied(&output).is_empty());
    assert!(matches!(&state.export, Export::Failed(e) if e == MISMATCH));

    // A requested copy serializes the command document once.
    let expected = export(&view, &snapshot, EXPORT_LIMIT).unwrap();
    state.export = Export::Idle;
    state.copy(key, &view);
    let Export::Waiting(copy) = state.export else {
        panic!("copy not queued");
    };
    state.copy(key, &view);
    assert!(matches!(state.export, Export::Waiting(id) if id == copy));
    let copies = poll_until(&mut state, &context, Some(&current), |s| !s.waiting());
    assert_eq!(copies, std::slice::from_ref(&expected));
    assert!(matches!(state.export, Export::Copied(n) if n == expected.len()));
    let output = context.run(egui::RawInput::default(), |ctx| {
        state.poll(ctx, Some(&current));
        state.accept(ctx, exported(copy, &snapshot), Some(&current));
    });
    assert!(copied(&output).is_empty());

    // An export-only size failure keeps the inspectable snapshot.
    state.export_limit = expected.len() - 1;
    state.copy(key, &view);
    let copies = poll_until(&mut state, &context, Some(&current), |s| !s.waiting());
    assert!(copies.is_empty());
    assert!(matches!(&state.export, Export::Failed(e) if e.contains("64 MiB")));
    assert!(Arc::ptr_eq(&ready(&state), &snapshot));
    state.export_limit = expected.len();
    state.copy(key, &view);
    let copies = poll_until(&mut state, &context, Some(&current), |s| !s.waiting());
    assert_eq!(copies, [expected]);

    // A copy in flight when the view changes is discarded.
    state.copy(key, &view);
    state.reset();
    assert!(matches!(state.build, Build::Idle) && matches!(state.export, Export::Idle));
    state.ensure(key, &view);
    let copies = poll_until(&mut state, &context, Some(&current), |s| !s.waiting());
    assert!(copies.is_empty());
    assert!(!Arc::ptr_eq(&ready(&state), &snapshot));
}

#[test]
fn stopped_and_panicking_workers_fail_recoverably() {
    let (_fixture, view) = fixture_view();
    let key = key(&view);
    let current = (key, view.clone());
    let context = egui::Context::default();
    let mut state = State {
        worker: Some(ReducedWorker::stopped()),
        build: Build::Waiting(1),
        export: Export::Waiting(2),
        ..Default::default()
    };
    let _ = context.run(egui::RawInput::default(), |ctx| {
        state.poll(ctx, Some(&current))
    });
    assert!(matches!(&state.build, Build::Failed(e) if e.contains("stopped")));
    assert!(matches!(&state.export, Export::Failed(e) if e.contains("stopped")));
    assert!(state.worker.is_none());
    // A stopped worker found when requesting is replaced on the next one.
    state.worker = Some(ReducedWorker::stopped());
    state.retry(key, &view);
    assert!(matches!(&state.build, Build::Failed(e) if e.contains("stopped")));
    assert!(state.worker.is_none());
    state.retry(key, &view);
    poll_until(&mut state, &context, Some(&current), |s| !s.waiting());
    ready(&state);
    // A panic is a reported failure, and the same worker keeps serving.
    let id = state.submit(key, &view, ReducedTask::Panic).unwrap();
    state.build = Build::Waiting(id);
    poll_until(&mut state, &context, Some(&current), |s| !s.waiting());
    assert!(matches!(&state.build, Build::Failed(e) if e.contains("panicked")));
    state.retry(key, &view);
    poll_until(&mut state, &context, Some(&current), |s| !s.waiting());
    ready(&state);
}

fn completed(fixture: &Fixture, view: Arc<FunctionView>) -> Workbench {
    let loaded =
        crate::report::load_bytes("fixture".into(), fixture.request.image.bytes().to_vec())
            .unwrap();
    let mut app = Workbench::empty();
    app.selected = Some(view.entry);
    app.loaded = Some(loaded);
    let (generation, revision) = app.pcode.fingerprint();
    let key = RequestKey {
        id: 1,
        generation,
        revision,
        entry: view.entry,
    };
    app.dataflow.view = Some((key, view));
    app
}

fn unchanged(app: &Workbench) {
    assert!(!app.dirty);
    assert_eq!(app.revision, 0);
    assert!(app.loaded.as_ref().unwrap().metadata.annotations.is_empty());
}

/// One full production frame: toolbar, status bar, both side panels and the
/// center, after the same polling as `update`.
struct Harness {
    app: Workbench,
    context: egui::Context,
    time: f64,
    copies: Vec<String>,
}

impl Harness {
    fn frame(&mut self, events: Vec<egui::Event>) -> egui::FullOutput {
        self.time += 1.0 / 30.0;
        let app = &mut self.app;
        let output = self.context.run(
            egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(
                    egui::Pos2::ZERO,
                    egui::vec2(1000.0, 650.0),
                )),
                time: Some(self.time),
                events,
                ..Default::default()
            },
            |ctx| {
                let fingerprint = app.pcode.fingerprint();
                app.dataflow.poll(ctx, fingerprint);
                app.toolbar(ctx);
                egui::TopBottomPanel::bottom("status").show(ctx, |ui| {
                    ui.label(RichText::new(&app.status).small());
                });
                app.sidebar(ctx);
                app.inspector(ctx);
                app.center(ctx);
            },
        );
        self.copies.extend(copied(&output));
        output
    }

    fn until(&mut self, done: impl Fn(&Workbench) -> bool) -> egui::FullOutput {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let output = self.frame(vec![]);
            if done(&self.app) {
                return output;
            }
            assert!(Instant::now() < deadline, "worker did not respond");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    fn click(&mut self, at: egui::Pos2) {
        for pressed in [true, false] {
            self.frame(vec![
                egui::Event::PointerMoved(at),
                egui::Event::PointerButton {
                    pos: at,
                    button: egui::PointerButton::Primary,
                    pressed,
                    modifiers: egui::Modifiers::NONE,
                },
            ]);
        }
    }

    fn scroll(&mut self, at: egui::Pos2, delta: f32) -> egui::FullOutput {
        let mut output = self.frame(vec![
            egui::Event::PointerMoved(at),
            egui::Event::MouseWheel {
                unit: egui::MouseWheelUnit::Point,
                delta: egui::vec2(0.0, delta),
                modifiers: egui::Modifiers::NONE,
            },
        ]);
        for _ in 0..12 {
            output = self.frame(vec![]);
        }
        output
    }
}

#[test]
fn reduced_mode_is_lazy_optional_and_never_touches_the_project() {
    let (fixture, view) = fixture_view();
    let mut harness = Harness {
        app: completed(&fixture, view.clone()),
        context: styled(14.0),
        time: 0.0,
        copies: vec![],
    };
    harness.app.tab = Tab::Dataflow;
    // Other modes never simplify.
    for mode in [
        Inspect::ControlFlow,
        Inspect::Storage,
        Inspect::Expressions,
        Inspect::Constants,
    ] {
        harness.app.dataflow.inspect = mode;
        harness.frame(vec![]);
    }
    assert!(matches!(harness.app.dataflow.reduced.build, Build::Idle));
    assert!(harness.app.dataflow.reduced.worker.is_none());
    // A pending project operation keeps the request back.
    let (sender, receiver) = mpsc::channel();
    harness.app.pending = Some(receiver);
    harness.app.dataflow.inspect = Inspect::Reduced;
    harness.frame(vec![]);
    assert!(matches!(harness.app.dataflow.reduced.build, Build::Idle));
    drop(sender);
    harness.app.pending = None;
    // Showing the mode simplifies the existing facts on the reduced worker;
    // the function worker never compiles, lifts or rebuilds SSA again.
    harness.frame(vec![]);
    assert!(matches!(
        harness.app.dataflow.reduced.build,
        Build::Waiting(_)
    ));
    harness.until(|app| !app.dataflow.reduced.waiting());
    let snapshot = ready(&harness.app.dataflow.reduced);
    assert!(harness.app.dataflow.worker.is_none());
    let shared = &harness.app.dataflow.view.as_ref().unwrap().1;
    assert!(Arc::ptr_eq(shared, &view));
    assert!(Arc::ptr_eq(
        snapshot.simplification.constants(),
        &view.constants
    ));
    // Mode toggles reuse the cached snapshot.
    for mode in [Inspect::Constants, Inspect::Reduced] {
        harness.app.dataflow.inspect = mode;
        harness.frame(vec![]);
    }
    assert!(Arc::ptr_eq(
        &ready(&harness.app.dataflow.reduced),
        &snapshot
    ));
    // An optional failure leaves every base mode usable, and retry is
    // explicit.
    harness.app.dataflow.reduced.build =
        Build::Failed("simplification limit exceeded: terms".into());
    for mode in [
        Inspect::ControlFlow,
        Inspect::Storage,
        Inspect::Expressions,
        Inspect::Constants,
        Inspect::Reduced,
    ] {
        harness.app.dataflow.inspect = mode;
        harness.frame(vec![]);
        assert!(harness.app.dataflow.view.is_some());
        assert!(harness.app.dataflow.error.is_none());
    }
    let output = harness.frame(vec![]);
    assert!(
        text_rect(
            &output,
            "Reduced expressions unavailable: simplification limit exceeded: terms",
            true
        )
        .is_some()
    );
    assert!(matches!(
        harness.app.dataflow.reduced.build,
        Build::Failed(_)
    ));
    let retry = text_rect(&output, "Retry reduction", true)
        .unwrap()
        .center();
    harness.click(retry);
    harness.until(|app| !app.dataflow.reduced.waiting());
    assert!(!Arc::ptr_eq(
        &ready(&harness.app.dataflow.reduced),
        &snapshot
    ));
    // Policy, image and processor changes drop the snapshot with the view.
    harness.app.dataflow.havoc_unknown = true;
    harness.app.dataflow.invalidate();
    assert!(matches!(harness.app.dataflow.reduced.build, Build::Idle));
    harness.app.dataflow.view = Some((
        RequestKey {
            id: 2,
            generation: harness.app.pcode.fingerprint().0,
            revision: harness.app.pcode.fingerprint().1,
            entry: view.entry,
        },
        view.clone(),
    ));
    harness.until(|app| matches!(app.dataflow.reduced.build, Build::Ready(_)));
    let (generation, revision) = harness.app.pcode.fingerprint();
    harness
        .app
        .dataflow
        .poll(&egui::Context::default(), (generation + 1, revision));
    assert!(harness.app.dataflow.view.is_none());
    assert!(matches!(harness.app.dataflow.reduced.build, Build::Idle));
    harness.frame(vec![]);
    assert!(matches!(harness.app.dataflow.reduced.build, Build::Idle));
    assert!(harness.copies.is_empty());
    unchanged(&harness.app);
}

#[test]
fn full_workbench_reduced_rows_scroll_select_navigate_and_copy_at_small_sizes() {
    let (fixture, view) = fixture_view();
    let reference = build(&view).unwrap();
    let s = &reference.simplification;
    let e = s.expressions().as_ref();
    let spaces = s.analysis().cfg().spaces();
    let expected_copy = export(&view, &reference, EXPORT_LIMIT).unwrap();
    // A known constant with a source instruction: `rax = zext(1)`.
    let literal = (0..s.analysis().ssa().values().len())
        .map(ValueId)
        .find(|v| {
            status(s, *v).unwrap().0 == Status::Literal
                && expressions::source_address(e, *v).is_some()
        })
        .unwrap();
    let literal_address = expressions::source_address(e, literal).unwrap();
    assert_eq!(literal_address, view.entry);
    // The division by zero: a fault, a refused fold and a distinct term.
    assert_eq!((s.faults().len(), s.refused_folds().len()), (1, 1));
    let fault = s.faults()[0];
    let fault_address = e.operation(fault.statement).unwrap().point.address;
    assert_ne!(fault_address, view.entry);
    let fault_operation = view
        .expression_operations
        .iter()
        .position(|statement| *statement == fault.statement)
        .unwrap();
    let reduction = reference
        .reduced_values
        .iter()
        .position(|v| *v == literal)
        .unwrap();
    // The function's memory read stays a distinct term.
    assert!((0..s.terms().len()).any(|id| term_row(s, spaces, id).1.contains("read 8B LE ram[")));
    for font_size in [14.0, 28.0] {
        for rows in [
            Rows::Values,
            Rows::Reductions,
            Rows::Terms,
            Rows::Operations,
            Rows::Issues,
        ] {
            let (target, row, address) = match rows {
                Rows::Values => (literal.0, value_row(s, spaces, literal.0), literal_address),
                Rows::Reductions => (reduction, value_row(s, spaces, literal.0), literal_address),
                Rows::Terms => (
                    fault.term.0,
                    term_row(s, spaces, fault.term.0),
                    fault_address,
                ),
                Rows::Operations => (
                    fault_operation,
                    operation_row(s, spaces, fault.statement),
                    fault_address,
                ),
                Rows::Issues => (0, issue_row(s, 0), fault_address),
            };
            let row = row.1;
            let mut harness = Harness {
                app: completed(&fixture, view.clone()),
                context: styled(font_size),
                time: 0.0,
                copies: vec![],
            };
            harness.app.tab = Tab::Dataflow;
            harness.app.dataflow.inspect = Inspect::Reduced;
            harness.frame(vec![]);
            harness.until(|app| !app.dataflow.reduced.waiting());
            ready(&harness.app.dataflow.reduced);
            let set = |app: &mut Workbench, index: usize| {
                let selection = &mut app.dataflow.reduced.selection;
                selection.rows = rows;
                *match rows {
                    Rows::Values => &mut selection.value,
                    Rows::Reductions => &mut selection.reduction,
                    Rows::Terms => &mut selection.term,
                    Rows::Operations => &mut selection.operation,
                    Rows::Issues => &mut selection.issue,
                } = index;
            };
            let selected = |app: &Workbench| {
                let selection = &app.dataflow.reduced.selection;
                match rows {
                    Rows::Values => selection.value,
                    Rows::Reductions => selection.reduction,
                    Rows::Terms => selection.term,
                    Rows::Operations => selection.operation,
                    Rows::Issues => selection.issue,
                }
            };
            set(&mut harness.app, target);
            harness.app.dataflow.reduced.selection.reveal = true;
            let mut output = harness.frame(vec![]);
            let header = text_rect(&output, "Analyze selected function", false)
                .expect("visible page header")
                .center();
            // Reach the copy action by scrolling the page from its header.
            let mut steps = 0;
            let copy = loop {
                if let Some(button) = text_rect(&output, "Copy reduced analysis JSON", true) {
                    break button.center();
                }
                assert!(steps < 20, "{font_size} {rows:?}: copy action unreachable");
                output = harness.scroll(header, -80.0);
                steps += 1;
            };
            harness.click(copy);
            harness.until(|app| !app.dataflow.reduced.waiting());
            assert_eq!(
                harness.copies,
                std::slice::from_ref(&expected_copy),
                "{font_size} {rows:?}"
            );
            // Select a different row, then scroll the page from its header
            // until the target's virtual row shows and click it. In compact
            // windows the page viewport can be shorter than the panes, so
            // the page is scrolled step by step rather than to its end.
            set(&mut harness.app, usize::MAX);
            output = harness.frame(vec![]);
            if selected(&harness.app) == target {
                set(&mut harness.app, 0);
                output = harness.frame(vec![]);
            }
            let mut steps = 0;
            let at = loop {
                if let Some(rect) = text_rect(&output, &row, true) {
                    break rect.center();
                }
                assert!(steps < 40, "{font_size} {rows:?}: row not visible: {row}");
                output = harness.scroll(header, -40.0);
                steps += 1;
            };
            harness.click(at);
            assert_eq!(selected(&harness.app), target, "{font_size} {rows:?}");
            // Back to the top over the page's own content, then scroll the
            // page from its header rather than a nested list.
            harness.scroll(header, 10000.0);
            harness.scroll(header, -10000.0);
            // Another instruction of the same function is selected first,
            // so the check below proves where navigation went.
            harness.app.selected = Some(if address == view.entry {
                fault_address
            } else {
                view.entry
            });
            // Scroll the narrow detail locally to its source navigation
            // where it is not already visible.
            let output = harness.frame(vec![]);
            let button = text_rect(&output, "Go to ", false)
                .or_else(|| {
                    let output = harness.scroll(egui::pos2(620.0, 600.0), -10000.0);
                    text_rect(&output, "Go to ", false)
                })
                .unwrap_or_else(|| panic!("{font_size} {rows:?}: source navigation inaccessible"));
            harness.click(button.center());
            assert!(
                matches!(harness.app.tab, Tab::Listing),
                "{font_size} {rows:?}"
            );
            assert_eq!(
                harness.app.selected,
                Some(address),
                "{font_size} {rows:?}: wrong source address"
            );
            // The copy happened exactly once and nothing was saved.
            assert_eq!(harness.copies.len(), 1);
            unchanged(&harness.app);
        }
    }
}
