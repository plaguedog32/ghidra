//! Expression inspection for a completed function analysis. Every preview
//! renders one term level with capped joins, operands and literals; children
//! are `tN` node, `vN` SSA value or literal references, never expansions.
use super::*;
use ghidra_analysis::{
    ExpressionAddress, ExpressionDefinition, ExpressionId, ExpressionKind, ExpressionOperand,
    ExpressionType, MemoryAccessKind, PcodeExpressions,
};
use ghidra_pcode::{AddressSpace, Endianness, Opcode, SpaceId, Value};
use ghidra_ssa::{StatementId, ValueId, ValueOrigin};

/// Items shown per join, operand, phi or definition list before eliding.
pub(super) const MAX_ITEMS: usize = 8;
/// Literal hexadecimal digits shown before eliding the remainder.
pub(super) const MAX_HEX_DIGITS: usize = 16;
pub(super) const MAX_DETAIL_ROWS: usize = 16;

// show_rows requires every row to have exactly this height, excluding spacing.
// Compact buttons remove vertical padding; the explicit font and minimum size
// keep the contract independent of the application's normal button padding.
pub(super) fn row_height(ui: &egui::Ui) -> f32 {
    ui.text_style_height(&egui::TextStyle::Monospace)
        .ceil()
        .max(22.0)
}

/// One compact, single-line, selectable virtual row of exactly `row_height`.
pub(super) fn selectable_row(
    ui: &mut egui::Ui,
    selection: &mut usize,
    index: usize,
    color: Color32,
    text: String,
) -> egui::Response {
    let text = text.replace(['\r', '\n'], " ");
    let response = ui.add(
        egui::Button::selectable(
            *selection == index,
            RichText::new(text)
                .text_style(egui::TextStyle::Monospace)
                .color(color),
        )
        .small()
        .wrap_mode(egui::TextWrapMode::Extend)
        .min_size(egui::vec2(0.0, row_height(ui))),
    );
    if response.clicked() {
        *selection = index;
    }
    response
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum Rows {
    #[default]
    Values,
    Operations,
}

#[derive(Debug, Default)]
pub(super) struct Selection {
    pub rows: Rows,
    pub value: usize,
    pub operation: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Tone {
    Plain,
    Undefined,
    Opaque,
}

impl Tone {
    pub(super) fn color(self) -> Color32 {
        match self {
            Self::Plain => Color32::from_rgb(214, 222, 232),
            Self::Undefined | Self::Opaque => GOLD,
        }
    }
}

pub(super) fn space_name(spaces: &[AddressSpace], id: SpaceId) -> String {
    spaces
        .iter()
        .find(|space| space.id == id)
        .map_or_else(|| format!("space{}", id.0), |space| space.name.clone())
}

pub(super) fn type_label(spaces: &[AddressSpace], ty: ExpressionType) -> String {
    match ty {
        ExpressionType::Bits(bytes) => format!("{bytes}B bits"),
        ExpressionType::Memory(space) => format!("{} memory", space_name(spaces, space)),
    }
}

pub(super) fn constant(value: &Value) -> String {
    match value.to_u64() {
        Some(small) => format!("0x{small:x}:{}B", value.size()),
        None => {
            // Values are at most 512 bytes, so this formatting is bounded.
            let digits = format!("{:x}", value.bits());
            format!("0x{}…:{}B", &digits[..MAX_HEX_DIGITS], value.size())
        }
    }
}

pub(super) fn capped(items: impl ExactSizeIterator<Item = String>, maximum: usize) -> String {
    let total = items.len();
    let mut text: Vec<String> = items.take(maximum).collect();
    if total > maximum {
        text.push(format!("… +{}", total - maximum));
    }
    text.join(", ")
}

pub(super) fn endian(endianness: Endianness) -> &'static str {
    match endianness {
        Endianness::Little => "LE",
        Endianness::Big => "BE",
    }
}

/// A child reference: SSA value, literal or node ID. Never recursive.
pub(super) fn leaf(e: &PcodeExpressions, id: ExpressionId) -> String {
    match e.node(id).map(|node| &node.kind) {
        Ok(ExpressionKind::SsaValue(value)) => format!("v{}", value.0),
        Ok(ExpressionKind::Constant(value)) => constant(value),
        Ok(_) => format!("t{}", id.0),
        Err(_) => format!("t{}?", id.0),
    }
}

fn address(e: &PcodeExpressions, address: &ExpressionAddress) -> String {
    match *address {
        ExpressionAddress::ByteOffset(offset) => format!("byte 0x{offset:x}"),
        ExpressionAddress::Pointer {
            value,
            word_size,
            address_size,
        } => format!(
            "{}B ptr {} × {word_size}-byte words",
            address_size,
            leaf(e, value)
        ),
    }
}

/// One level of the term at `id`, with bounded joins, inputs and literals.
pub(super) fn term(e: &PcodeExpressions, spaces: &[AddressSpace], id: ExpressionId) -> String {
    let Ok(node) = e.node(id) else {
        return format!("t{}?", id.0);
    };
    let bytes = match node.ty {
        ExpressionType::Bits(bytes) => bytes,
        ExpressionType::Memory(_) => 0,
    };
    match &node.kind {
        ExpressionKind::Constant(value) => constant(value),
        ExpressionKind::SsaValue(value) => format!("v{}", value.0),
        ExpressionKind::Join(pieces) => format!(
            "join lsb→msb({})",
            capped(
                pieces.iter().map(|piece| format!(
                    "{}@byte{}:{}B",
                    leaf(e, piece.value),
                    piece.lsb_byte,
                    piece.size
                )),
                MAX_ITEMS
            )
        ),
        ExpressionKind::Extract { value, lsb_byte } => {
            format!("slice({}, lsb byte {lsb_byte}, {bytes}B)", leaf(e, *value))
        }
        ExpressionKind::Pure { opcode, inputs } => format!(
            "{}({})",
            opcode.mnemonic(),
            capped(inputs.iter().map(|input| leaf(e, *input)), MAX_ITEMS)
        ),
        ExpressionKind::ReadMemory {
            space,
            version,
            address: at,
            endianness,
        } => format!(
            "read {bytes}B {} {}[{}] of v{}",
            endian(*endianness),
            space_name(spaces, *space),
            address(e, at),
            version.0
        ),
        ExpressionKind::WriteMemory {
            space,
            version,
            address: at,
            value,
            endianness,
        } => format!(
            "write {} {}[{}] ← {} into v{}",
            endian(*endianness),
            space_name(spaces, *space),
            address(e, at),
            leaf(e, *value),
            version.0
        ),
    }
}

/// Direct children of a term, in operand order, at most `MAX_ITEMS`.
pub(super) fn children(kind: &ExpressionKind) -> (Vec<ExpressionId>, usize) {
    let all: Vec<ExpressionId> = match kind {
        ExpressionKind::Constant(_) | ExpressionKind::SsaValue(_) => vec![],
        ExpressionKind::Join(pieces) => pieces.iter().take(MAX_ITEMS).map(|p| p.value).collect(),
        ExpressionKind::Extract { value, .. } => vec![*value],
        ExpressionKind::Pure { inputs, .. } => inputs.iter().take(MAX_ITEMS).copied().collect(),
        ExpressionKind::ReadMemory { address, .. } => match address {
            ExpressionAddress::Pointer { value, .. } => vec![*value],
            ExpressionAddress::ByteOffset(_) => vec![],
        },
        ExpressionKind::WriteMemory { address, value, .. } => match address {
            ExpressionAddress::Pointer { value: pointer, .. } => vec![*pointer, *value],
            ExpressionAddress::ByteOffset(_) => vec![*value],
        },
    };
    let total = match kind {
        ExpressionKind::Join(pieces) => pieces.len(),
        ExpressionKind::Pure { inputs, .. } => inputs.len(),
        _ => all.len(),
    };
    (all, total)
}

fn effect_class(e: &PcodeExpressions, statement: StatementId) -> String {
    match e.operation(statement).map(|o| o.effects) {
        Some(AppliedEffects::Conservative(class)) => format!("{class:?}"),
        _ => "unknown".into(),
    }
}

/// The definition of `value`, with undefined and opaque results marked.
pub(super) fn definition(
    e: &PcodeExpressions,
    spaces: &[AddressSpace],
    value: ValueId,
) -> (Tone, String) {
    let Ok(definition) = e.definition(value) else {
        return (Tone::Opaque, "unknown SSA value".into());
    };
    match *definition {
        ExpressionDefinition::Entry(ghidra_ssa::EntryState::Input) => {
            (Tone::Plain, "entry input (symbolic declaration)".into())
        }
        ExpressionDefinition::Entry(ghidra_ssa::EntryState::Undefined) => {
            (Tone::Undefined, "UNDEFINED at entry (never zero)".into())
        }
        ExpressionDefinition::Phi(phi) => {
            let operands = e
                .analysis()
                .ssa()
                .phi(phi)
                .map(|phi| {
                    capped(
                        phi.operands().iter().map(|v| format!("v{}", v.0)),
                        MAX_ITEMS,
                    )
                })
                .unwrap_or_default();
            (
                Tone::Plain,
                format!("phi n{}#{}({operands})", phi.node, phi.index),
            )
        }
        ExpressionDefinition::Expression(root) => (Tone::Plain, term(e, spaces, root)),
        ExpressionDefinition::Undefined {
            statement,
            instruction,
        } => (
            Tone::Undefined,
            format!(
                "UNDEFINED fresh temporary at {instruction:X} (reset n{}.{}, never zero)",
                statement.node, statement.index
            ),
        ),
        ExpressionDefinition::Opaque {
            statement,
            definition_slot,
        } => (
            Tone::Opaque,
            format!(
                "OPAQUE output of n{}.{} slot {definition_slot} ({} effect, no term)",
                statement.node,
                statement.index,
                effect_class(e, statement)
            ),
        ),
    }
}

fn role(opcode: Opcode, index: usize) -> String {
    match (opcode, index) {
        (Opcode::Return, 0) => "return target (control address, not an ABI return value)".into(),
        (Opcode::Branchind, 0) => "branch target".into(),
        (Opcode::Callind, 0) => "call target".into(),
        (Opcode::Cbranch, 1) => "condition".into(),
        (Opcode::Load | Opcode::Store, 1) => "pointer".into(),
        (Opcode::Store, 2) => "stored value".into(),
        _ => format!("input {index}"),
    }
}

/// One operand with its source role. Metadata is never shown as a value read.
pub(super) fn operand(
    e: &PcodeExpressions,
    spaces: &[AddressSpace],
    opcode: Opcode,
    index: usize,
    operand: &ExpressionOperand,
) -> String {
    match *operand {
        ExpressionOperand::Value(id) => format!("{}: {}", role(opcode, index), leaf(e, id)),
        ExpressionOperand::ConstantMetadata { value, .. } => {
            format!("metadata constant: {}", leaf(e, value))
        }
        ExpressionOperand::RelativeTarget(offset) => {
            format!("relative target: {offset:+} operations")
        }
        ExpressionOperand::DirectTarget(target) => format!(
            "direct target label: {}:0x{:x} (not a read)",
            space_name(spaces, target.space),
            target.offset
        ),
        ExpressionOperand::SpaceSelector(space) => {
            format!("space selector: {}", space_name(spaces, space))
        }
        ExpressionOperand::Userop(index) => format!("userop #{index}"),
        ExpressionOperand::OperationReference(source) => {
            format!("operation reference: 0x{:x}", source.offset)
        }
    }
}

pub(super) fn value_row(
    e: &PcodeExpressions,
    spaces: &[AddressSpace],
    id: usize,
) -> (Tone, String) {
    let value = ValueId(id);
    let ty = e
        .value_type(value)
        .map_or_else(|_| "?".into(), |ty| type_label(spaces, ty));
    let variable = e
        .analysis()
        .ssa()
        .value(value)
        .map_or(usize::MAX, |v| v.variable.0);
    let (tone, text) = definition(e, spaces, value);
    (tone, format!("v{id:<6} {ty:<14} s{variable:<5} = {text}"))
}

pub(super) fn operation_row(
    e: &PcodeExpressions,
    spaces: &[AddressSpace],
    statement: StatementId,
) -> (Tone, String) {
    let Some(operation) = e.operation(statement) else {
        return (
            Tone::Opaque,
            format!("n{}.{} unavailable", statement.node, statement.index),
        );
    };
    let operands = capped(
        operation
            .operands
            .iter()
            .enumerate()
            .map(|(i, o)| match o.expression() {
                Some(id) if matches!(o, ExpressionOperand::Value(_)) => leaf(e, id),
                _ => operand(e, spaces, operation.opcode, i, o),
            }),
        MAX_ITEMS,
    );
    let (tone, result) = match (operation.effects, operation.output) {
        (AppliedEffects::Conservative(class), _) => (Tone::Opaque, format!(" → OPAQUE {class:?}")),
        (_, Some(output)) => (Tone::Plain, format!(" → t{}", output.0)),
        (_, None) => (Tone::Plain, String::new()),
    };
    (
        tone,
        format!(
            "n{}.{:<4} {:X}:{} {} ({operands}){result}",
            statement.node,
            statement.index,
            operation.point.address,
            operation.point.operation_index,
            operation.opcode.mnemonic()
        ),
    )
}

/// The native instruction that produced `value`, where there is one.
pub(super) fn source_address(e: &PcodeExpressions, value: ValueId) -> Option<u64> {
    match e.definition(value).ok()? {
        ExpressionDefinition::Undefined { instruction, .. } => Some(*instruction),
        ExpressionDefinition::Opaque { statement, .. } => {
            Some(e.operation(*statement)?.point.address)
        }
        ExpressionDefinition::Expression(_) => match e.analysis().ssa().value(value).ok()?.origin {
            ValueOrigin::Definition(site) => Some(e.operation(site.statement)?.point.address),
            _ => None,
        },
        ExpressionDefinition::Phi(phi) => match e.analysis().cfg().node(phi.node) {
            Some(ghidra_cfg::NodeKind::Block(points)) => points.first().map(|p| p.address),
            _ => None,
        },
        ExpressionDefinition::Entry(_) => None,
    }
}

fn colored(ui: &mut egui::Ui, (tone, text): (Tone, String)) {
    ui.label(RichText::new(text).monospace().color(tone.color()));
}

fn term_inputs(
    ui: &mut egui::Ui,
    e: &PcodeExpressions,
    spaces: &[AddressSpace],
    root: ExpressionId,
) {
    let Ok(node) = e.node(root) else {
        return;
    };
    let (inputs, total) = children(&node.kind);
    if inputs.is_empty() {
        return;
    }
    ui.label("Direct inputs (one level)");
    for child in inputs {
        let ty = e
            .node(child)
            .map_or_else(|_| "?".into(), |n| type_label(spaces, n.ty));
        ui.monospace(format!("t{} {ty} = {}", child.0, term(e, spaces, child)));
    }
    if total > MAX_ITEMS {
        ui.monospace(format!("… +{} more", total - MAX_ITEMS));
    }
}

fn value_detail(
    ui: &mut egui::Ui,
    e: &PcodeExpressions,
    spaces: &[AddressSpace],
    id: usize,
) -> Option<u64> {
    let value = ValueId(id);
    let ssa = e.analysis().ssa();
    let variable = ssa.value(value).ok()?.variable;
    let location = e
        .analysis()
        .layout()
        .variables()
        .get(variable.0)
        .map(|v| format!("{:?}", v.location))
        .unwrap_or_default();
    let ty = e.value_type(value).ok()?;
    ui.label(
        RichText::new(format!(
            "v{id} · {} · storage s{} {location}",
            type_label(spaces, ty),
            variable.0
        ))
        .color(ACCENT),
    );
    colored(ui, definition(e, spaces, value));
    match *e.definition(value).ok()? {
        ExpressionDefinition::Expression(root) => {
            ui.label(format!("Root t{}", root.0));
            term_inputs(ui, e, spaces, root);
        }
        ExpressionDefinition::Phi(phi) => {
            ui.label("Phi inputs by incoming edge. Loop-carried values stay as references.");
            if let (Ok(phi), Ok(block)) = (ssa.phi(phi), ssa.block(phi.node)) {
                let incoming = block.renamed().map_or(&[][..], |b| b.incoming());
                for (predecessor, operand) in
                    incoming.iter().zip(phi.operands()).take(MAX_DETAIL_ROWS)
                {
                    let from = match predecessor {
                        ghidra_ssa::Predecessor::Entry => "entry".into(),
                        ghidra_ssa::Predecessor::Node(node) => format!("n{node}"),
                    };
                    ui.monospace(format!("from {from}: v{}", operand.0));
                }
                if phi.operands().len() > MAX_DETAIL_ROWS {
                    ui.monospace(format!(
                        "… +{} more",
                        phi.operands().len() - MAX_DETAIL_ROWS
                    ));
                }
            }
        }
        ExpressionDefinition::Undefined { .. } => {
            ui.colored_label(
                GOLD,
                "Instruction-local temporaries are fresh on native entry. This value is undefined, not zero.",
            );
        }
        ExpressionDefinition::Opaque { statement, .. } => {
            ui.colored_label(
                GOLD,
                format!(
                    "No term is reconstructed. Statement n{}.{} reads every observed storage value; see its SSA uses.",
                    statement.node, statement.index
                ),
            );
        }
        ExpressionDefinition::Entry(_) => {
            ui.label(
                RichText::new("Symbolic function-entry state; no concrete value is assumed.")
                    .small()
                    .color(MUTED),
            );
        }
    }
    let address = source_address(e, value)?;
    ui.button(format!("Go to {address:X}"))
        .clicked()
        .then_some(address)
}

fn operation_detail(
    ui: &mut egui::Ui,
    e: &PcodeExpressions,
    spaces: &[AddressSpace],
    statement: StatementId,
) -> Option<u64> {
    let operation = e.operation(statement)?;
    ui.label(
        RichText::new(format!(
            "n{}.{} · {:X}:{} · {}",
            statement.node,
            statement.index,
            operation.point.address,
            operation.point.operation_index,
            operation.opcode.mnemonic()
        ))
        .color(ACCENT),
    );
    let jump = ui
        .button(format!("Go to {:X}", operation.point.address))
        .clicked()
        .then_some(operation.point.address);
    match operation.effects {
        AppliedEffects::Explicit => {
            ui.label("Explicit P-code effects. Opcodes are not evaluated or folded.");
        }
        AppliedEffects::Conservative(class) => {
            ui.colored_label(
                GOLD,
                format!("Conservative {class:?} effect: every definition is OPAQUE."),
            );
        }
    }
    ui.label("Operands");
    for (index, input) in operation.operands.iter().enumerate().take(MAX_DETAIL_ROWS) {
        ui.monospace(operand(e, spaces, operation.opcode, index, input));
    }
    if operation.operands.len() > MAX_DETAIL_ROWS {
        ui.monospace(format!(
            "… +{} more",
            operation.operands.len() - MAX_DETAIL_ROWS
        ));
    }
    if let Some(memory) = &operation.indirect_memory {
        ui.monospace(format!(
            "{} {} memory version v{}",
            match memory.kind {
                MemoryAccessKind::Read => "reads",
                MemoryAccessKind::Write => "writes",
            },
            space_name(spaces, memory.space),
            memory.version.0
        ));
    }
    match (operation.effects, operation.output) {
        (AppliedEffects::Conservative(_), _) => {}
        (_, Some(output)) => {
            let ty = e
                .node(output)
                .map_or_else(|_| "?".into(), |n| type_label(spaces, n.ty));
            ui.monospace(format!(
                "Result t{} {ty} = {}",
                output.0,
                term(e, spaces, output)
            ));
            term_inputs(ui, e, spaces, output);
        }
        (_, None) => {
            ui.label(
                RichText::new("No bit result (store or control operation).")
                    .small()
                    .color(MUTED),
            );
        }
    }
    if let Ok(renamed) = e.analysis().ssa().statement(statement) {
        let defs = renamed.defs();
        if !defs.is_empty() {
            ui.label("Defines");
            for value in defs.iter().take(MAX_DETAIL_ROWS) {
                colored(ui, value_row(e, spaces, value.0));
            }
            if defs.len() > MAX_DETAIL_ROWS {
                ui.monospace(format!("… +{} more", defs.len() - MAX_DETAIL_ROWS));
            }
        }
    }
    jump
}

/// Renders the expression mode and returns a requested source address.
pub(super) fn panel(
    ui: &mut egui::Ui,
    selection: &mut Selection,
    view: &FunctionView,
    pane_height: f32,
) -> Option<u64> {
    let top = ui.cursor().top();
    let e = view.expressions.as_ref();
    let spaces = e.analysis().cfg().spaces();
    ui.horizontal(|ui| {
        ui.selectable_value(&mut selection.rows, Rows::Values, "SSA values");
        ui.selectable_value(&mut selection.rows, Rows::Operations, "Operations");
    });
    ui.label(RichText::new("Typed P-code terms over verified SSA, one level at a time. Loops and phis stay as vN references; tN names a term node. Undefined and opaque results are marked. This is not decompiled C, type recovery or an ABI model.").small().color(MUTED));
    ui.label(format!(
        "{} term nodes · {} operations · {} references · {} literal bytes",
        e.nodes().len(),
        view.expression_operations.len(),
        e.reference_count(),
        e.constant_bytes()
    ));
    let mut jump = None;
    super::inspection_panes(ui, pane_height - (ui.cursor().top() - top), |ui| {
        ui.columns(2, |columns| match selection.rows {
            Rows::Values => {
                let count = e.analysis().ssa().values().len();
                selection.value = selection.value.min(count.saturating_sub(1));
                let height = row_height(&columns[0]);
                egui::ScrollArea::both()
                    .id_salt("expression_values")
                    .show_rows(&mut columns[0], height, count, |ui, rows| {
                        for id in rows {
                            let (tone, text) = value_row(e, spaces, id);
                            selectable_row(ui, &mut selection.value, id, tone.color(), text);
                        }
                    });
                if count > 0 {
                    jump = egui::ScrollArea::vertical()
                        .id_salt("expression_value_detail")
                        .show(&mut columns[1], |ui| {
                            value_detail(ui, e, spaces, selection.value)
                        })
                        .inner;
                }
            }
            Rows::Operations => {
                let statements = &view.expression_operations;
                selection.operation = selection.operation.min(statements.len().saturating_sub(1));
                let height = row_height(&columns[0]);
                egui::ScrollArea::both()
                    .id_salt("expression_operations")
                    .show_rows(&mut columns[0], height, statements.len(), |ui, rows| {
                        for index in rows {
                            let (tone, text) = operation_row(e, spaces, statements[index]);
                            selectable_row(ui, &mut selection.operation, index, tone.color(), text);
                        }
                    });
                if let Some(&statement) = statements.get(selection.operation) {
                    jump = egui::ScrollArea::vertical()
                        .id_salt("expression_operation_detail")
                        .show(&mut columns[1], |ui| {
                            operation_detail(ui, e, spaces, statement)
                        })
                        .inner;
                }
            }
        });
    });
    jump
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_pcode::machine::ExecutionInput;

    fn sum_loop() -> ExecutionInput {
        serde_json::from_str(include_str!("../../../../../examples/pcode/sum-loop.json")).unwrap()
    }

    #[test]
    fn virtual_rows_match_geometry_with_production_spacing_and_long_labels() {
        let e = crate::expression_report::build(Arc::new(
            ghidra_analysis::PcodeSsa::new(
                Arc::new(
                    ghidra_cfg::Cfg::new(
                        {
                            let p = sum_loop();
                            ghidra_cfg::CfgInput::new(
                                p.spaces,
                                p.code_space,
                                p.entry,
                                p.instructions,
                            )
                        },
                        Default::default(),
                    )
                    .unwrap(),
                ),
                &[],
                ghidra_analysis::AnalysisOptions::native(),
                Default::default(),
            )
            .unwrap(),
        ))
        .unwrap();
        let spaces = e.analysis().cfg().spaces();
        let mut labels = vec![value_row(&e, spaces, 0)];
        labels.push(operation_row(
            &e,
            spaces,
            e.operations().next().unwrap().statement,
        ));
        labels.push((Tone::Undefined, "long space name\n".repeat(40)));
        for font_size in [14.0, 28.0] {
            for offset in [0.0, 500.0] {
                let ctx = egui::Context::default();
                ctx.style_mut(|style| {
                    style.spacing.item_spacing = egui::vec2(10.0, 8.0);
                    style.spacing.button_padding = egui::vec2(12.0, 7.0);
                    style.text_styles.insert(
                        egui::TextStyle::Monospace,
                        egui::FontId::monospace(font_size),
                    );
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
                            ui.set_width(350.0);
                            let height = row_height(ui);
                            let pitch = height + ui.spacing().item_spacing.y;
                            let result = egui::ScrollArea::both()
                                .vertical_scroll_offset(offset)
                                .show_rows(ui, height, 100, |ui, rows| {
                                    if offset > 0.0 {
                                        assert!(rows.start > 0);
                                    }
                                    let mut previous: Option<f32> = None;
                                    let mut selection = 0;
                                    for id in rows {
                                        let (tone, text) = &labels[id % labels.len()];
                                        let response = selectable_row(
                                            ui,
                                            &mut selection,
                                            id,
                                            tone.color(),
                                            text.clone(),
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
                let text_shapes: Vec<_> = output
                    .shapes
                    .iter()
                    .filter_map(|shape| {
                        if let egui::epaint::Shape::Text(text) = &shape.shape {
                            Some(text)
                        } else {
                            None
                        }
                    })
                    .collect();
                assert!(!text_shapes.is_empty());
                assert!(text_shapes.iter().all(|shape| shape.galley.rows.len() == 1));
            }
        }
    }

    fn rows_are_bounded(e: &PcodeExpressions) {
        let spaces = e.analysis().cfg().spaces();
        for id in 0..e.analysis().ssa().values().len() {
            let (_, text) = value_row(e, spaces, id);
            assert!(text.chars().count() < 600, "{text}");
            assert!(!text.to_lowercase().contains("decompil"));
        }
        for operation in e.operations() {
            let (_, text) = operation_row(e, spaces, operation.statement);
            assert!(text.chars().count() < 1200, "{text}");
        }
    }

    #[test]
    fn literal_and_join_previews_are_capped_without_recursive_expansion() {
        let wide = Value::from_le_bytes(&[0xab; 64]).unwrap();
        let text = constant(&wide);
        assert!(text.ends_with("…:64B"), "{text}");
        assert!(text.chars().count() <= MAX_HEX_DIGITS + 8);
        assert_eq!(constant(&Value::from_u64(4, 0x2a).unwrap()), "0x2a:4B");
        let mut program = sum_loop();
        let reg = |offset: u64, size: u32| ghidra_pcode::Varnode {
            space: SpaceId(2),
            offset,
            size,
        };
        let mut ops: Vec<_> = (0..16)
            .map(|byte| ghidra_pcode::PcodeOperation {
                opcode: Opcode::Copy,
                output: Some(reg(byte, 1)),
                inputs: vec![ghidra_pcode::Varnode {
                    space: SpaceId(0),
                    offset: byte,
                    size: 1,
                }],
            })
            .collect();
        ops.push(ghidra_pcode::PcodeOperation {
            opcode: Opcode::Copy,
            output: Some(reg(32, 16)),
            inputs: vec![reg(0, 16)],
        });
        program.instructions = vec![ghidra_pcode::PcodeInstruction {
            address: 0x1000,
            length: 4,
            ops,
        }];
        let e = crate::analysis_cli::expressions_for(program, false, false);
        let spaces = e.analysis().cfg().spaces();
        let join = e
            .nodes()
            .iter()
            .position(|n| matches!(&n.kind, ExpressionKind::Join(p) if p.len() == 16))
            .unwrap();
        let text = term(&e, spaces, ExpressionId(join));
        assert_eq!(text.matches("@byte").count(), MAX_ITEMS);
        assert!(text.ends_with("… +8)"), "{text}");
        // Join pieces are SSA references, not their defining terms.
        assert!(text.starts_with("join lsb→msb(v"), "{text}");
        let (inputs, total) = children(&e.nodes()[join].kind);
        assert_eq!((inputs.len(), total), (MAX_ITEMS, 16));
        rows_are_bounded(&e);
    }

    #[test]
    fn undefined_resets_and_opaque_effects_are_marked_and_return_targets_are_not_abi_values() {
        let mut looped = sum_loop();
        looped.instructions[0]
            .ops
            .push(ghidra_pcode::PcodeOperation {
                opcode: Opcode::Branch,
                output: None,
                inputs: vec![ghidra_pcode::Varnode {
                    space: SpaceId(1),
                    offset: 0x1000,
                    size: 8,
                }],
            });
        let e = crate::analysis_cli::expressions_for(looped, true, false);
        let spaces = e.analysis().cfg().spaces();
        let undefined = (0..e.analysis().ssa().values().len())
            .map(|id| definition(&e, spaces, ValueId(id)))
            .find(|(tone, _)| *tone == Tone::Undefined)
            .unwrap();
        assert!(undefined.1.contains("UNDEFINED") && undefined.1.contains("never zero"));
        rows_are_bounded(&e);

        let mut called = sum_loop();
        called.instructions[0].ops.insert(
            0,
            ghidra_pcode::PcodeOperation {
                opcode: Opcode::Call,
                output: None,
                inputs: vec![ghidra_pcode::Varnode {
                    space: SpaceId(1),
                    offset: 0x8000,
                    size: 8,
                }],
            },
        );
        called.instructions[0].ops.pop();
        let e = crate::analysis_cli::expressions_for(called, false, true);
        let spaces = e.analysis().cfg().spaces();
        let opaque = (0..e.analysis().ssa().values().len())
            .map(|id| definition(&e, spaces, ValueId(id)))
            .find(|(tone, _)| *tone == Tone::Opaque)
            .unwrap();
        assert!(
            opaque.1.contains("OPAQUE") && opaque.1.contains("Call"),
            "{}",
            opaque.1
        );
        let call = e.operations().find(|o| o.opcode == Opcode::Call).unwrap();
        let (tone, row) = operation_row(&e, spaces, call.statement);
        assert_eq!(tone, Tone::Opaque);
        assert!(
            row.contains("OPAQUE") && row.contains("not a read"),
            "{row}"
        );
        rows_are_bounded(&e);

        let alias: ExecutionInput = serde_json::from_str(include_str!(
            "../../../../../examples/pcode/alias-branch.json"
        ))
        .unwrap();
        let e = crate::analysis_cli::expressions_for(alias, false, false);
        let spaces = e.analysis().cfg().spaces();
        let ret = e.operations().find(|o| o.opcode == Opcode::Return).unwrap();
        let text = operand(&e, spaces, ret.opcode, 0, &ret.operands[0]);
        assert!(text.starts_with("return target"), "{text}");
        assert!(text.contains("not an ABI return value"), "{text}");
        let phi = (0..e.analysis().ssa().values().len())
            .map(|id| definition(&e, spaces, ValueId(id)).1)
            .find(|text| text.starts_with("phi n"))
            .unwrap();
        assert!(phi.contains("(v"), "{phi}");
        rows_are_bounded(&e);
    }
}
