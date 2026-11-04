//! Constant-propagation inspection for a completed function analysis. Rows
//! are virtualized over direct ID ranges, the fault slice, or the constant
//! value list collected once on the worker, so no frame scans every fact.
//! Previews show one term level with capped literals and inputs.
//!
//! "Feasible (conservative)" means statically feasible in the supplied CFG
//! under the documented policy. It does not prove that a path runs.
use super::expressions::{self, MAX_DETAIL_ROWS, MAX_ITEMS};
use super::*;
use ghidra_analysis::{ConstantFact, ExpressionDefinition, PcodeConstants, PcodeExpressions};
use ghidra_cfg::EdgeRole;
use ghidra_pcode::{AddressSpace, Value};
use ghidra_ssa::{Predecessor, ValueId, ValueOrigin};

pub(super) const KNOWN: &str = "known constant";
pub(super) const UNKNOWN: &str = "unknown";
pub(super) const UNREACHED: &str = "unreached";
pub(super) const FEASIBLE: &str = "feasible (conservative)";
pub(super) const NOT_FEASIBLE: &str = "not feasible";
/// Hexadecimal digits shown for a selected constant before eliding.
pub(super) const MAX_DETAIL_HEX_DIGITS: usize = 128;
/// Characters of an evaluation error shown in one row.
const MAX_ERROR_CHARS: usize = 160;

const PLAIN: Color32 = Color32::from_rgb(214, 222, 232);

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum Rows {
    #[default]
    Values,
    Known,
    Edges,
    Faults,
}

#[derive(Debug, Default)]
pub(super) struct Selection {
    pub rows: Rows,
    pub value: usize,
    pub known: usize,
    pub edge: usize,
    pub fault: usize,
}

impl Selection {
    pub(super) fn reset(&mut self) {
        *self = Self {
            rows: self.rows,
            ..Self::default()
        };
    }
}

fn fact_color(fact: ConstantFact<'_>) -> Color32 {
    match fact {
        ConstantFact::Constant(_) => ACCENT,
        ConstantFact::Unknown => PLAIN,
        ConstantFact::Unreached => MUTED,
    }
}

/// The lattice element with a bounded literal. Unknown and unreached are
/// named explicitly; neither is ever shown as a number.
pub(super) fn fact_text(fact: ConstantFact<'_>) -> String {
    match fact {
        ConstantFact::Constant(value) => format!("{KNOWN} {}", expressions::constant(value)),
        ConstantFact::Unknown => UNKNOWN.into(),
        ConstantFact::Unreached => UNREACHED.into(),
    }
}

/// A longer, still bounded, literal for the detail panel.
pub(super) fn detail_hex(value: &Value) -> String {
    // Values are at most 512 bytes, so this formatting is bounded.
    let digits = format!("{:x}", value.bits());
    if digits.len() <= MAX_DETAIL_HEX_DIGITS {
        format!("0x{digits} ({} bytes)", value.size())
    } else {
        format!(
            "0x{}… (+{} more hex digits; {} bytes)",
            &digits[..MAX_DETAIL_HEX_DIGITS],
            digits.len() - MAX_DETAIL_HEX_DIGITS,
            value.size()
        )
    }
}

fn feasible(live: bool) -> &'static str {
    if live { FEASIBLE } else { NOT_FEASIBLE }
}

/// A short reason tag for the value's definition, never its expansion.
fn origin_tag(e: &PcodeExpressions, value: ValueId) -> String {
    match e.definition(value) {
        Ok(ExpressionDefinition::Entry(ghidra_ssa::EntryState::Input)) => "entry input".into(),
        Ok(ExpressionDefinition::Entry(ghidra_ssa::EntryState::Undefined)) => {
            "entry UNDEFINED".into()
        }
        Ok(ExpressionDefinition::Phi(phi)) => format!("phi n{}", phi.node),
        Ok(ExpressionDefinition::Expression(root)) => format!("term t{}", root.0),
        Ok(ExpressionDefinition::Undefined { .. }) => "UNDEFINED reset".into(),
        Ok(ExpressionDefinition::Opaque { .. }) => "OPAQUE effect".into(),
        Err(_) => "unknown SSA value".into(),
    }
}

pub(super) fn value_row(
    c: &PcodeConstants,
    spaces: &[AddressSpace],
    id: usize,
) -> (Color32, String) {
    let e = c.expressions().as_ref();
    let value = ValueId(id);
    let ty = e
        .value_type(value)
        .map_or_else(|_| "?".into(), |ty| expressions::type_label(spaces, ty));
    let variable = e
        .analysis()
        .ssa()
        .value(value)
        .map_or(usize::MAX, |v| v.variable.0);
    let (color, fact) = match c.value(value) {
        Ok(fact) => (fact_color(fact), fact_text(fact)),
        Err(_) => (GOLD, "fact unavailable".into()),
    };
    (
        color,
        format!(
            "v{id:<6} {ty:<14} s{variable:<5} {fact}   ← {}",
            origin_tag(e, value)
        ),
    )
}

fn node_label(analysis: &ghidra_analysis::PcodeSsa, node: usize) -> String {
    match analysis.cfg().node(node) {
        Some(ghidra_cfg::NodeKind::Block(points)) => {
            format!("n{node} {:X}", points[0].address)
        }
        Some(ghidra_cfg::NodeKind::Exit(exit)) => format!("n{node} exit {:?}", exit.kind),
        None => format!("n{node} fresh temporaries"),
    }
}

/// "not feasible" with the reason the exposed facts establish, if any.
fn not_feasible(c: &PcodeConstants, edge: &ghidra_cfg::Edge) -> String {
    let reason = match c.is_node_executable(edge.from) {
        Ok(false) => "source unreached",
        Ok(true)
            if matches!(
                edge.role,
                EdgeRole::ConditionTrue | EdgeRole::ConditionFalse
            ) =>
        {
            "pruned by known constant condition"
        }
        _ => return NOT_FEASIBLE.into(),
    };
    format!("{NOT_FEASIBLE} ({reason})")
}

pub(super) fn edge_row(c: &PcodeConstants, id: usize) -> (Color32, String) {
    let analysis = c.analysis();
    let Some(edge) = analysis.cfg().edges().get(id) else {
        return (GOLD, format!("e{id} unavailable"));
    };
    let status = match c.is_cfg_edge_feasible(id) {
        Ok(true) => (PLAIN, FEASIBLE.to_string()),
        Ok(false) => (GOLD, not_feasible(c, edge)),
        Err(_) => (GOLD, "feasibility unavailable".into()),
    };
    (
        status.0,
        format!(
            "e{id:<5} {:X}:{:<3} {:<15} {} → {}   {}",
            edge.source.address,
            edge.source.operation_index,
            crate::analysis_cli::role(edge.role),
            node_label(analysis, edge.from),
            node_label(analysis, edge.to),
            status.1
        ),
    )
}

fn bounded_error(error: &ghidra_pcode::Error) -> String {
    let text = error.to_string().replace(['\r', '\n'], " ");
    if text.chars().count() <= MAX_ERROR_CHARS {
        text
    } else {
        let mut short: String = text.chars().take(MAX_ERROR_CHARS).collect();
        short.push('…');
        short
    }
}

pub(super) fn fault_row(c: &PcodeConstants, index: usize) -> (Color32, String) {
    let Some(fault) = c.faults().get(index) else {
        return (GOLD, format!("fault {index} unavailable"));
    };
    let point = c.expressions().operation(fault.statement).map_or_else(
        || "?".into(),
        |o| format!("{:X}:{}", o.point.address, o.point.operation_index),
    );
    (
        GOLD,
        format!(
            "n{}.{:<4} {point} {} t{} → {UNKNOWN} (evaluation fault: {})",
            fault.statement.node,
            fault.statement.index,
            fault.opcode.mnemonic(),
            fault.expression.0,
            bounded_error(&fault.error)
        ),
    )
}

fn fact_label(ui: &mut egui::Ui, fact: Result<ConstantFact<'_>, ghidra_analysis::ConstantError>) {
    match fact {
        Ok(ConstantFact::Constant(value)) => {
            ui.label(
                RichText::new(format!("{KNOWN} {}", detail_hex(value)))
                    .monospace()
                    .color(ACCENT),
            );
            ui.label(RichText::new("Every statically feasible definition yields exactly this bit pattern. The term itself is not rewritten.").small().color(MUTED));
        }
        Ok(ConstantFact::Unknown) => {
            ui.label(RichText::new(UNKNOWN).monospace().color(PLAIN));
            ui.label(RichText::new("No single known bit pattern: entry inputs, undefined state, memory, loads, opaque effects, evaluation faults or conflicting merges. Never assumed to be zero.").small().color(MUTED));
        }
        Ok(ConstantFact::Unreached) => {
            ui.label(RichText::new(UNREACHED).monospace().color(MUTED));
            ui.label(RichText::new("No definition is feasible in the supplied CFG. This is not a value and not zero.").small().color(MUTED));
        }
        Err(error) => {
            ui.colored_label(GOLD, format!("Fact unavailable: {error}"));
        }
    }
}

/// One level of term inputs with their facts; children are never expanded.
fn input_facts(ui: &mut egui::Ui, c: &PcodeConstants, root: ghidra_analysis::ExpressionId) {
    let e = c.expressions().as_ref();
    let Ok(node) = e.node(root) else {
        return;
    };
    let (inputs, total) = expressions::children(&node.kind);
    if inputs.is_empty() {
        return;
    }
    ui.label("Direct input facts (one level)");
    for child in inputs {
        let fact = c
            .expression(child)
            .map_or_else(|_| "fact unavailable".into(), fact_text);
        ui.monospace(format!(
            "t{} {} : {fact}",
            child.0,
            expressions::leaf(e, child)
        ));
    }
    if total > MAX_ITEMS {
        ui.monospace(format!("… +{} more", total - MAX_ITEMS));
    }
}

fn value_detail(
    ui: &mut egui::Ui,
    c: &PcodeConstants,
    spaces: &[AddressSpace],
    id: usize,
) -> Option<u64> {
    let e = c.expressions().as_ref();
    let value = ValueId(id);
    let ssa = e.analysis().ssa();
    let variable = ssa.value(value).ok()?.variable;
    let ty = e.value_type(value).ok()?;
    ui.label(
        RichText::new(format!(
            "v{id} · {} · storage s{}",
            expressions::type_label(spaces, ty),
            variable.0
        ))
        .color(ACCENT),
    );
    fact_label(ui, c.value(value));
    let (tone, definition) = expressions::definition(e, spaces, value);
    ui.label(RichText::new(definition).monospace().color(tone.color()));
    match ssa.value(value).ok()?.origin {
        ValueOrigin::Definition(site) => {
            if let Ok(live) = c.is_statement_executable(site.statement) {
                ui.label(format!(
                    "Defining statement n{}.{}: {}",
                    site.statement.node,
                    site.statement.index,
                    feasible(live)
                ));
            }
        }
        ValueOrigin::Phi(phi) => {
            if let Ok(live) = c.is_node_executable(phi.node) {
                ui.label(format!("Phi node n{}: {}", phi.node, feasible(live)));
            }
        }
        ValueOrigin::Entry(_) => {
            ui.label("Function-entry state. Entry values are unknown, never zero.");
        }
    }
    match *e.definition(value).ok()? {
        ExpressionDefinition::Expression(root) => {
            ui.monospace(format!(
                "Root t{} = {}",
                root.0,
                expressions::term(e, spaces, root)
            ));
            input_facts(ui, c, root);
        }
        ExpressionDefinition::Phi(phi) => {
            ui.label("Phi inputs by incoming edge (unreached inputs do not contribute).");
            if let (Ok(phi_value), Ok(block)) = (ssa.phi(phi), ssa.block(phi.node)) {
                let incoming = block.renamed().map_or(&[][..], |b| b.incoming());
                for (predecessor, operand) in incoming
                    .iter()
                    .zip(phi_value.operands())
                    .take(MAX_DETAIL_ROWS)
                {
                    let (from, edge) = match predecessor {
                        Predecessor::Entry => ("entry".to_string(), FEASIBLE),
                        Predecessor::Node(node) => (
                            format!("n{node}"),
                            c.is_edge_executable(*node, phi.node)
                                .map_or("feasibility unavailable", feasible),
                        ),
                    };
                    let fact = c
                        .value(*operand)
                        .map_or_else(|_| "fact unavailable".into(), fact_text);
                    ui.monospace(format!("from {from} ({edge}): v{} : {fact}", operand.0));
                }
                if phi_value.operands().len() > MAX_DETAIL_ROWS {
                    ui.monospace(format!(
                        "… +{} more",
                        phi_value.operands().len() - MAX_DETAIL_ROWS
                    ));
                }
            }
        }
        _ => {}
    }
    let address = expressions::source_address(e, value)?;
    ui.button(format!("Go to {address:X}"))
        .clicked()
        .then_some(address)
}

fn role_note(role: EdgeRole) -> Option<&'static str> {
    Some(match role {
        EdgeRole::ConditionTrue | EdgeRole::ConditionFalse => {
            "A known constant CBRANCH condition keeps only its taken outcome; an unknown condition keeps both."
        }
        EdgeRole::CallReturn | EdgeRole::CallNoReturn => {
            "Calls are not summarized: return and no-return outcomes both stay feasible."
        }
        EdgeRole::IndirectBranch => {
            "Indirect targets are not resolved; a known constant target adds no edges."
        }
        EdgeRole::Return => "A RETURN target is a control address, not an ABI return value.",
        _ => return None,
    })
}

fn edge_detail(ui: &mut egui::Ui, c: &PcodeConstants, id: usize) -> Option<u64> {
    let analysis = c.analysis();
    let edge = analysis.cfg().edges().get(id)?;
    ui.label(
        RichText::new(format!(
            "CFG edge e{id} · {} · {} → {}",
            crate::analysis_cli::role(edge.role),
            node_label(analysis, edge.from),
            node_label(analysis, edge.to)
        ))
        .color(ACCENT),
    );
    match c.is_cfg_edge_feasible(id) {
        Ok(true) => {
            ui.label(FEASIBLE);
        }
        Ok(false) => {
            ui.colored_label(GOLD, not_feasible(c, edge));
        }
        Err(error) => {
            ui.colored_label(GOLD, format!("Feasibility unavailable: {error}"));
        }
    }
    for (label, node) in [("Source", edge.from), ("Target", edge.to)] {
        if let Ok(live) = c.is_node_executable(node) {
            ui.label(format!("{label} n{node}: {}", feasible(live)));
        }
    }
    if matches!(
        edge.role,
        EdgeRole::ConditionTrue | EdgeRole::ConditionFalse
    ) && let Some(statement) = analysis.statement_id(edge.source)
        && let Some(operation) = c.expressions().operation(statement)
        && let Some(condition) = operation.operands.get(1).and_then(|o| o.expression())
    {
        let fact = c
            .expression(condition)
            .map_or_else(|_| "fact unavailable".into(), fact_text);
        ui.monospace(format!(
            "Condition {} : {fact}",
            expressions::leaf(c.expressions(), condition)
        ));
    }
    if let Some(note) = role_note(edge.role) {
        ui.label(RichText::new(note).small().color(MUTED));
    }
    ui.button(format!("Go to {:X}", edge.source.address))
        .clicked()
        .then_some(edge.source.address)
}

fn fault_detail(
    ui: &mut egui::Ui,
    c: &PcodeConstants,
    spaces: &[AddressSpace],
    index: usize,
) -> Option<u64> {
    let fault = c.faults().get(index)?;
    let e = c.expressions().as_ref();
    let operation = e.operation(fault.statement)?;
    ui.label(
        RichText::new(format!(
            "Evaluation fault · n{}.{} · {:X}:{} · {}",
            fault.statement.node,
            fault.statement.index,
            operation.point.address,
            operation.point.operation_index,
            fault.opcode.mnemonic()
        ))
        .color(ACCENT),
    );
    ui.colored_label(GOLD, bounded_error(&fault.error));
    ui.label(RichText::new("Every input is a known constant at the fixpoint, but evaluation failed. The result stays unknown, the term is unchanged, and control is not cut.").small().color(MUTED));
    ui.monospace(format!(
        "t{} = {}",
        fault.expression.0,
        expressions::term(e, spaces, fault.expression)
    ));
    input_facts(ui, c, fault.expression);
    ui.button(format!("Go to {:X}", operation.point.address))
        .clicked()
        .then_some(operation.point.address)
}

/// Virtualized rows over `count` items; `row` formats only visible ones.
fn rows(
    ui: &mut egui::Ui,
    salt: &str,
    selection: &mut usize,
    count: usize,
    mut row: impl FnMut(usize) -> (Color32, String),
) {
    *selection = (*selection).min(count.saturating_sub(1));
    let height = expressions::row_height(ui);
    egui::ScrollArea::both()
        .id_salt(salt)
        .show_rows(ui, height, count, |ui, range| {
            for index in range {
                let (color, text) = row(index);
                expressions::selectable_row(ui, selection, index, color, text);
            }
        });
}

/// Renders the constants mode and returns a requested source address.
pub(super) fn panel(
    ui: &mut egui::Ui,
    selection: &mut Selection,
    view: &FunctionView,
) -> Option<u64> {
    let c = view.constants.as_ref();
    debug_assert!(Arc::ptr_eq(c.expressions(), &view.expressions));
    let analysis = c.analysis();
    let spaces = analysis.cfg().spaces();
    let stats = c.stats();
    let policy = c.policy();
    ui.horizontal_wrapped(|ui| {
        ui.selectable_value(&mut selection.rows, Rows::Values, "SSA values");
        ui.selectable_value(&mut selection.rows, Rows::Known, "Known constants");
        ui.selectable_value(&mut selection.rows, Rows::Edges, "Control-flow edges");
        ui.selectable_value(&mut selection.rows, Rows::Faults, "Evaluation faults");
    });
    ui.label(RichText::new("Sparse conditional constant propagation over the typed terms. Feasible (conservative) means statically feasible in this recovered CFG, not proof that a path runs. Unknown and unreached are never zero. Terms are not rewritten; this is not decompiled code or optimization.").small().color(MUTED));
    ui.label(format!(
        "{} {KNOWN} · {} {UNKNOWN} · {} {UNREACHED} values · {}/{} graph nodes and {}/{} CFG edges {FEASIBLE} · {} evaluation faults",
        stats.constant_values,
        stats.unknown_values,
        stats.unreached_values,
        stats.executable_nodes,
        analysis.ssa().graph().node_count(),
        stats.feasible_cfg_edges,
        analysis.cfg().edges().len(),
        c.faults().len()
    ));
    let yes_no = |flag: bool, yes: &'static str, no: &'static str| if flag { yes } else { no };
    ui.label(
        RichText::new(format!(
            "Policy: {} · {} · {} · {} · {} · {}.",
            yes_no(
                policy.models_memory,
                "memory modeled",
                "memory and loads unknown"
            ),
            yes_no(
                policy.models_opaque_effects,
                "opaque effects modeled",
                "opaque effects unknown"
            ),
            yes_no(
                policy.prunes_constant_branches,
                "known constant CBRANCH conditions prune",
                "no branch pruning"
            ),
            yes_no(
                policy.resolves_indirect_targets,
                "indirect targets resolved",
                "indirect targets unresolved"
            ),
            yes_no(
                policy.summarizes_calls,
                "calls summarized",
                "call return and no-return both kept"
            ),
            yes_no(
                policy.faults_cut_control,
                "faults cut control",
                "faults do not cut control"
            ),
        ))
        .small()
        .color(MUTED),
    );
    let mut jump = None;
    ui.columns(2, |columns| match selection.rows {
        Rows::Values => {
            let count = analysis.ssa().values().len();
            rows(
                &mut columns[0],
                "constant_values",
                &mut selection.value,
                count,
                |id| value_row(c, spaces, id),
            );
            if count > 0 {
                jump = egui::ScrollArea::vertical()
                    .id_salt("constant_value_detail")
                    .show(&mut columns[1], |ui| {
                        value_detail(ui, c, spaces, selection.value)
                    })
                    .inner;
            }
        }
        Rows::Known => {
            let known = &view.constant_values;
            rows(
                &mut columns[0],
                "constant_known",
                &mut selection.known,
                known.len(),
                |index| value_row(c, spaces, known[index].0),
            );
            if let Some(value) = known.get(selection.known) {
                jump = egui::ScrollArea::vertical()
                    .id_salt("constant_known_detail")
                    .show(&mut columns[1], |ui| value_detail(ui, c, spaces, value.0))
                    .inner;
            } else {
                columns[1].label("No SSA value is a known constant.");
            }
        }
        Rows::Edges => {
            let count = analysis.cfg().edges().len();
            rows(
                &mut columns[0],
                "constant_edges",
                &mut selection.edge,
                count,
                |id| edge_row(c, id),
            );
            if count > 0 {
                jump = egui::ScrollArea::vertical()
                    .id_salt("constant_edge_detail")
                    .show(&mut columns[1], |ui| edge_detail(ui, c, selection.edge))
                    .inner;
            }
        }
        Rows::Faults => {
            let count = c.faults().len();
            rows(
                &mut columns[0],
                "constant_faults",
                &mut selection.fault,
                count,
                |index| fault_row(c, index),
            );
            if count > 0 {
                jump = egui::ScrollArea::vertical()
                    .id_salt("constant_fault_detail")
                    .show(&mut columns[1], |ui| {
                        fault_detail(ui, c, spaces, selection.fault)
                    })
                    .inner;
            } else {
                columns[1].label("No evaluation faults at the fixpoint.");
            }
        }
    });
    jump
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts(
        input: ghidra_pcode::machine::ExecutionInput,
        uniques: bool,
        havoc: bool,
    ) -> PcodeConstants {
        let terms = Arc::new(crate::analysis_cli::expressions_for(input, uniques, havoc));
        let facts = crate::constant_report::build(terms.clone()).unwrap();
        assert!(Arc::ptr_eq(facts.expressions(), &terms));
        facts
    }

    fn fixture() -> PcodeConstants {
        facts(crate::analysis_cli::tests::constant_program(), false, false)
    }

    /// Every row kind for a facts result, formatted exactly as the panel does.
    fn all_rows(c: &PcodeConstants) -> Vec<(Color32, String)> {
        let spaces = c.analysis().cfg().spaces();
        let mut rows: Vec<_> = (0..c.analysis().ssa().values().len())
            .map(|id| value_row(c, spaces, id))
            .collect();
        rows.extend((0..c.analysis().cfg().edges().len()).map(|id| edge_row(c, id)));
        rows.extend((0..c.faults().len()).map(|index| fault_row(c, index)));
        rows
    }

    fn assert_bounded(rows: &[(Color32, String)]) {
        for (_, text) in rows {
            assert!(text.chars().count() < 400, "{text}");
            let lower = text.to_lowercase();
            assert!(
                !lower.contains("decompil") && !lower.contains("optimi"),
                "{text}"
            );
            assert!(!text.contains(['\r', '\n']), "{text}");
        }
    }

    fn op(
        opcode: ghidra_pcode::Opcode,
        output: Option<(u32, u64, u32)>,
        inputs: &[(u32, u64, u32)],
    ) -> ghidra_pcode::PcodeOperation {
        let varnode = |(space, offset, size)| ghidra_pcode::Varnode {
            space: ghidra_pcode::SpaceId(space),
            offset,
            size,
        };
        ghidra_pcode::PcodeOperation {
            opcode,
            output: output.map(varnode),
            inputs: inputs.iter().copied().map(varnode).collect(),
        }
    }

    #[test]
    fn rows_name_known_unknown_unreached_feasibility_and_faults_explicitly() {
        let c = fixture();
        let rows = all_rows(&c);
        assert_bounded(&rows);
        let has = |needle: &str| rows.iter().any(|(_, text)| text.contains(needle));
        assert!(has("known constant 0x9:4B"));
        assert!(has("known constant 0xa:4B"));
        assert!(has("unknown   ← entry input"));
        assert!(has(UNREACHED));
        assert!(has(FEASIBLE));
        assert!(has("not feasible (pruned by known constant condition)"));
        assert!(has("not feasible (source unreached)"));
        let fault = fault_row(&c, 0).1;
        assert!(fault.contains("INT_DIV"), "{fault}");
        assert!(
            fault.contains("→ unknown (evaluation fault: p-code division by zero)"),
            "{fault}"
        );
        // Unreached and unknown value rows never print a literal.
        for (_, text) in &rows[..c.analysis().ssa().values().len()] {
            if !text.contains(KNOWN) {
                assert!(text.contains(UNKNOWN) || text.contains(UNREACHED), "{text}");
                assert!(!text.contains("0x"), "{text}");
            }
        }
        // Out-of-range IDs are reported rather than indexed.
        assert!(edge_row(&c, usize::MAX).1.contains("unavailable"));
        assert!(fault_row(&c, 7).1.contains("unavailable"));
    }

    #[test]
    fn literals_are_bounded_in_rows_and_details() {
        let wide = Value::from_le_bytes(&[0xcd; 512]).unwrap();
        let row = fact_text(ConstantFact::Constant(&wide));
        assert!(row.starts_with(KNOWN) && row.ends_with("…:512B"), "{row}");
        assert!(row.chars().count() <= KNOWN.len() + expressions::MAX_HEX_DIGITS + 10);
        let detail = detail_hex(&wide);
        assert!(
            detail.contains("(+896 more hex digits; 512 bytes)"),
            "{detail}"
        );
        assert!(detail.chars().count() < MAX_DETAIL_HEX_DIGITS + 64);
        assert_eq!(
            detail_hex(&Value::from_u64(4, 0x2a).unwrap()),
            "0x2a (4 bytes)"
        );
        assert_eq!(fact_text(ConstantFact::Unknown), UNKNOWN);
        assert_eq!(fact_text(ConstantFact::Unreached), UNREACHED);
    }

    #[test]
    fn resets_and_opaque_effects_render_as_unknown() {
        use ghidra_pcode::Opcode;
        // A unique read before any write in instruction scope is a fresh
        // undefined temporary, so the copy is unknown rather than zero.
        let mut fresh = crate::analysis_cli::tests::constant_program();
        fresh.instructions[0]
            .ops
            .insert(0, op(Opcode::Copy, Some((2, 72, 4)), &[(3, 0, 4)]));
        let c = facts(fresh, true, false);
        let rows = all_rows(&c);
        assert_bounded(&rows);
        assert!(
            rows.iter()
                .any(|(_, text)| text.contains("unknown   ← entry UNDEFINED")
                    || text.contains("unknown   ← UNDEFINED reset"))
        );
        assert!(
            !rows
                .iter()
                .any(|(_, text)| text.contains(KNOWN) && text.contains("UNDEFINED"))
        );
        let mut called = crate::analysis_cli::tests::constant_program();
        called.instructions[0]
            .ops
            .insert(0, op(Opcode::Call, None, &[(1, 0x8000, 8)]));
        let c = facts(called, false, true);
        let rows = all_rows(&c);
        assert_bounded(&rows);
        let opaque: Vec<_> = rows
            .iter()
            .filter(|(_, text)| text.contains("OPAQUE effect"))
            .collect();
        assert!(!opaque.is_empty());
        assert!(
            opaque
                .iter()
                .all(|(_, text)| text.contains(" unknown   ← OPAQUE"))
        );
        assert!(
            rows.iter()
                .any(|(_, text)| text.contains("call_no_return") && text.contains(FEASIBLE))
        );
    }

    #[test]
    fn constant_rows_keep_exact_single_line_geometry_under_production_style() {
        let c = fixture();
        let mut labels = all_rows(&c);
        labels.push((GOLD, "very long fault text\r\n".repeat(60)));
        for font_size in [14.0, 28.0] {
            for offset in [0.0, 400.0] {
                let ctx = egui::Context::default();
                ctx.style_mut(|style| {
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
                let mut seen = 0;
                let output = ctx.run(
                    egui::RawInput {
                        screen_rect: Some(egui::Rect::from_min_size(
                            egui::Pos2::ZERO,
                            egui::vec2(1000.0, 650.0),
                        )),
                        ..Default::default()
                    },
                    |ctx| {
                        egui::CentralPanel::default().show(ctx, |ui| {
                            ui.set_width(480.0);
                            let height = expressions::row_height(ui);
                            let pitch = height + ui.spacing().item_spacing.y;
                            let mut selection = usize::MAX;
                            let mut previous: Option<f32> = None;
                            let result = egui::ScrollArea::both()
                                .vertical_scroll_offset(offset)
                                .show_rows(ui, height, 100, |ui, range| {
                                    if offset > 0.0 {
                                        assert!(range.start > 0);
                                    }
                                    for index in range {
                                        let (color, text) = labels[index % labels.len()].clone();
                                        let response = expressions::selectable_row(
                                            ui,
                                            &mut selection,
                                            index,
                                            color,
                                            text,
                                        );
                                        assert!((response.rect.height() - height).abs() < 0.01);
                                        if let Some(top) = previous {
                                            assert!(
                                                (response.rect.top() - top - pitch).abs() < 0.01
                                            );
                                        }
                                        previous = Some(response.rect.top());
                                        seen += 1;
                                    }
                                });
                            assert!((result.content_size.y - (100.0 * pitch - 8.0)).abs() < 0.1);
                        });
                    },
                );
                assert!(seen > 1 && seen < 100);
                let galleys: Vec<_> = output
                    .shapes
                    .iter()
                    .filter_map(|shape| match &shape.shape {
                        egui::epaint::Shape::Text(text) => Some(text),
                        _ => None,
                    })
                    .collect();
                assert!(!galleys.is_empty());
                assert!(galleys.iter().all(|text| text.galley.rows.len() == 1));
            }
        }
    }
}
