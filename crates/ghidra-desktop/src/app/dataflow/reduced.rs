//! Reduced-expression inspection: the canonical value projection of one
//! completed function analysis. The snapshot is built lazily on a dedicated
//! worker from the view's existing constant facts, never in a frame. Rows are
//! virtualized over direct ID ranges or lists collected once on the worker,
//! and previews render one term level with capped operands and literals.
//!
//! `cN` names a canonical term, a namespace separate from expression nodes
//! `tN` and SSA values `vN`. The original operations remain the required
//! evaluation stream; nothing here is rewritten, pruned or decompiled.
use super::expressions::{self, MAX_DETAIL_ROWS, MAX_ITEMS};
use super::*;
use crate::function_analysis::reduced::{
    EXPORT_LIMIT, ReducedOutcome, ReducedRequest, ReducedResponse, ReducedTask, ReducedView,
    ReducedWorker,
};
use ghidra_analysis::{
    ConstantFact, ExpressionDefinition, ExpressionType, PcodeSimplification, Rule,
    SimplifiedOperation, SimplifyError, TermAddress, TermFault, TermId, TermIdentity, TermKind,
    TermOrigin,
};
use ghidra_pcode::{AddressSpace, Opcode};
use ghidra_ssa::{StatementId, ValueId};

const PLAIN: Color32 = Color32::from_rgb(214, 222, 232);
const MISMATCH: &str = "Simplification belongs to a different function snapshot";
const NOTE: &str = "Canonical value projection over the constant facts: cN is a canonical term, tN an original term node. The original operations still perform every read, effect, fault and branch; nothing is rewritten, pruned or decompiled, and no C, types or ABI are recovered. Phi, entry, UNDEFINED, OPAQUE and memory-state leaves are never zero; memory accesses and terms that may fault stay distinct.";

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) enum Rows {
    #[default]
    Values,
    Reductions,
    Terms,
    Operations,
    Issues,
}

#[derive(Debug, Default)]
pub(super) struct Selection {
    pub rows: Rows,
    pub value: usize,
    pub reduction: usize,
    pub term: usize,
    pub operation: usize,
    pub issue: usize,
    /// Scroll the current list to its selected row once.
    pub reveal: bool,
}

impl Selection {
    fn reset(&mut self) {
        *self = Self {
            rows: self.rows,
            ..Self::default()
        };
    }
}

/// The optional simplification of the current function view.
#[derive(Debug)]
pub(super) enum Build {
    /// Not requested for this view.
    Idle,
    Waiting(u64),
    Ready(Arc<ReducedView>),
    /// Kept until the view changes or an explicit retry.
    Failed(String),
}

#[derive(Debug)]
pub(super) enum Export {
    Idle,
    Waiting(u64),
    Copied(usize),
    Failed(String),
}

pub(super) struct State {
    next: u64,
    worker: Option<ReducedWorker>,
    pub build: Build,
    pub export: Export,
    pub selection: Selection,
    /// Bytes allowed for a reduced copy; the command's cap outside tests.
    pub export_limit: usize,
}

impl Default for State {
    fn default() -> Self {
        Self {
            next: 0,
            worker: None,
            build: Build::Idle,
            export: Export::Idle,
            selection: Selection::default(),
            export_limit: EXPORT_LIMIT,
        }
    }
}

impl State {
    /// Forgets the snapshot of a replaced or invalidated function view. The
    /// worker is kept, a queued request is dropped, and responses to earlier
    /// requests no longer match.
    pub(super) fn reset(&mut self) {
        self.next = self.next.wrapping_add(1);
        if let Some(worker) = &self.worker {
            worker.cancel();
        }
        self.build = Build::Idle;
        self.export = Export::Idle;
        self.selection.reset();
    }

    fn submit(
        &mut self,
        source: RequestKey,
        view: &Arc<FunctionView>,
        task: ReducedTask,
    ) -> Result<u64, String> {
        self.next = self.next.wrapping_add(1);
        let id = self.next;
        let worker = self.worker.get_or_insert_with(ReducedWorker::spawn);
        let result = worker.request(ReducedRequest {
            id,
            source,
            view: view.clone(),
            task,
        });
        if result.is_err() {
            // A later request spawns a fresh worker.
            self.worker = None;
        }
        result.map(|()| id)
    }

    /// Requests the simplification of `view` once; a result or failure is
    /// cached until the view changes.
    pub(super) fn ensure(&mut self, source: RequestKey, view: &Arc<FunctionView>) {
        if matches!(self.build, Build::Idle) {
            self.build = match self.submit(source, view, ReducedTask::Build) {
                Ok(id) => Build::Waiting(id),
                Err(error) => Build::Failed(error),
            };
        }
    }

    fn retry(&mut self, source: RequestKey, view: &Arc<FunctionView>) {
        self.build = Build::Idle;
        self.export = Export::Idle;
        self.ensure(source, view);
    }

    /// Serializes the current snapshot on the worker for one clipboard copy.
    fn copy(&mut self, source: RequestKey, view: &Arc<FunctionView>) {
        let Build::Ready(snapshot) = &self.build else {
            return;
        };
        if matches!(self.export, Export::Waiting(_)) {
            return;
        }
        let task = ReducedTask::Export {
            snapshot: snapshot.clone(),
            maximum: self.export_limit,
        };
        self.export = match self.submit(source, view, task) {
            Ok(id) => Export::Waiting(id),
            Err(error) => Export::Failed(error),
        };
    }

    pub(super) fn waiting(&self) -> bool {
        matches!(self.build, Build::Waiting(_)) || matches!(self.export, Export::Waiting(_))
    }

    pub(super) fn poll(
        &mut self,
        ctx: &egui::Context,
        view: Option<&(RequestKey, Arc<FunctionView>)>,
    ) {
        for _ in 0..4 {
            let response = match self.worker.as_ref().map(ReducedWorker::try_recv) {
                Some(Ok(Some(response))) => response,
                Some(Err(error)) => {
                    if matches!(self.build, Build::Waiting(_)) {
                        self.build = Build::Failed(error.clone());
                    }
                    if matches!(self.export, Export::Waiting(_)) {
                        self.export = Export::Failed(error);
                    }
                    self.worker = None;
                    break;
                }
                _ => break,
            };
            self.accept(ctx, response, view);
        }
        if self.waiting() {
            ctx.request_repaint_after(Duration::from_millis(40));
        }
    }

    /// Accepts only the response to the newest request for the current
    /// view, and only a snapshot of that view's own constant facts.
    fn accept(
        &mut self,
        ctx: &egui::Context,
        response: ReducedResponse,
        view: Option<&(RequestKey, Arc<FunctionView>)>,
    ) {
        let current = view
            .filter(|(key, _)| *key == response.source)
            .map(|(_, view)| view);
        match response.outcome {
            ReducedOutcome::Built(result) => {
                if !matches!(self.build, Build::Waiting(id) if id == response.id) {
                    return;
                }
                self.build = match (result, current) {
                    (Ok(snapshot), Some(view))
                        if Arc::ptr_eq(snapshot.simplification.constants(), &view.constants) =>
                    {
                        self.selection.reset();
                        Build::Ready(snapshot)
                    }
                    (Err(error), Some(_)) => Build::Failed(error),
                    _ => Build::Failed(MISMATCH.into()),
                };
            }
            ReducedOutcome::Exported { snapshot, result } => {
                if !matches!(self.export, Export::Waiting(id) if id == response.id) {
                    return;
                }
                let current_snapshot =
                    matches!(&self.build, Build::Ready(ready) if Arc::ptr_eq(ready, &snapshot));
                self.export = match result {
                    _ if current.is_none() || !current_snapshot => Export::Failed(MISMATCH.into()),
                    Ok(text) => {
                        let bytes = text.len();
                        ctx.copy_text(text);
                        Export::Copied(bytes)
                    }
                    Err(error) => Export::Failed(error),
                };
            }
        }
    }
}

#[cfg(test)]
thread_local! {
    /// Rows formatted on this thread, to check per-frame work.
    pub(super) static FORMATTED: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

fn formatted() {
    #[cfg(test)]
    FORMATTED.with(|count| count.set(count.get() + 1));
}

/// A child reference: a literal inline, a leaf as its SSA value, otherwise
/// the canonical term ID. Never recursive.
fn term_ref(s: &PcodeSimplification, id: TermId) -> String {
    match s.term(id).map(|term| &term.kind) {
        Ok(TermKind::Literal(value)) => expressions::constant(value),
        Ok(TermKind::Leaf(value)) => format!("v{}", value.0),
        Ok(_) => format!("c{}", id.0),
        Err(_) => format!("c{}?", id.0),
    }
}

/// What an SSA leaf stands for, from that value's own definition. A
/// propagated leaf of another value keeps that value's distinctions.
pub(super) fn leaf_kind(s: &PcodeSimplification, value: ValueId) -> (Color32, String) {
    let e = s.expressions();
    let (color, kind) = match e.definition(value) {
        Ok(ExpressionDefinition::Entry(ghidra_ssa::EntryState::Input)) => {
            (PLAIN, "entry input".to_string())
        }
        Ok(ExpressionDefinition::Entry(ghidra_ssa::EntryState::Undefined)) => {
            (GOLD, "UNDEFINED at entry".into())
        }
        Ok(ExpressionDefinition::Phi(phi)) => (PLAIN, format!("phi n{}", phi.node)),
        Ok(ExpressionDefinition::Undefined { .. }) => (GOLD, "UNDEFINED reset".into()),
        Ok(ExpressionDefinition::Opaque { .. }) => (GOLD, "OPAQUE effect".into()),
        Ok(ExpressionDefinition::Expression(root)) => {
            let reason = match (e.value_type(value), s.node_term(*root)) {
                (Ok(ExpressionType::Memory(_)), _) => "memory state",
                (_, Ok(Some(term))) => match s.term(term) {
                    Ok(term) if term.reads_memory => "kept: definition reads memory",
                    Ok(term) if term.may_fault() => "kept: definition may fault",
                    _ => "kept definition",
                },
                _ => "kept definition",
            };
            (PLAIN, reason.into())
        }
        Err(_) => (GOLD, "unknown SSA value".into()),
    };
    match s.constants().value(value) {
        Ok(ConstantFact::Unreached) => (
            if color == GOLD { GOLD } else { MUTED },
            format!("unreached {kind}"),
        ),
        _ => (color, kind),
    }
}

fn address(s: &PcodeSimplification, address: &TermAddress) -> String {
    match *address {
        TermAddress::ByteOffset(offset) => format!("byte 0x{offset:x}"),
        TermAddress::Pointer {
            term,
            word_size,
            address_size,
        } => format!(
            "{address_size}B ptr {} × {word_size}-byte words",
            term_ref(s, term)
        ),
    }
}

/// One level of a canonical term with bounded joins, inputs and literals.
pub(super) fn term_preview(
    s: &PcodeSimplification,
    spaces: &[AddressSpace],
    id: TermId,
) -> (Color32, String) {
    let Ok(term) = s.term(id) else {
        return (GOLD, format!("c{}?", id.0));
    };
    let bytes = match term.ty {
        ExpressionType::Bits(bytes) => bytes,
        ExpressionType::Memory(_) => 0,
    };
    let color = if term.fault == TermFault::Here {
        GOLD
    } else {
        PLAIN
    };
    match &term.kind {
        TermKind::Literal(value) => (ACCENT, expressions::constant(value)),
        TermKind::Leaf(value) => {
            let (color, kind) = leaf_kind(s, *value);
            (color, format!("v{} ({kind})", value.0))
        }
        TermKind::Join(pieces) => (
            color,
            format!(
                "join lsb→msb({})",
                expressions::capped(
                    pieces.iter().map(|piece| format!(
                        "{}@byte{}:{}B",
                        term_ref(s, piece.term),
                        piece.lsb_byte,
                        piece.size
                    )),
                    MAX_ITEMS
                )
            ),
        ),
        TermKind::Extract { term, lsb_byte } => (
            color,
            format!(
                "slice({}, lsb byte {lsb_byte}, {bytes}B)",
                term_ref(s, *term)
            ),
        ),
        TermKind::Apply { opcode, inputs } => (
            color,
            format!(
                "{}({})",
                opcode.mnemonic(),
                expressions::capped(inputs.iter().map(|input| term_ref(s, *input)), MAX_ITEMS)
            ),
        ),
        TermKind::ReadMemory {
            node,
            space,
            version,
            address: at,
            endianness,
        } => (
            color,
            format!(
                "read {bytes}B {} {}[{}] of v{} (t{})",
                expressions::endian(*endianness),
                expressions::space_name(spaces, *space),
                address(s, at),
                version.0,
                node.0
            ),
        ),
        TermKind::WriteMemory {
            node,
            space,
            version,
            address: at,
            value,
            endianness,
        } => (
            color,
            format!(
                "write {} {}[{}] ← {} into v{} (t{})",
                expressions::endian(*endianness),
                expressions::space_name(spaces, *space),
                address(s, at),
                term_ref(s, *value),
                version.0,
                node.0
            ),
        ),
    }
}

/// How uses of a value are projected.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Status {
    /// A known constant: uses receive its literal.
    Literal,
    /// Uses receive the definition's canonical term.
    Propagated,
    /// Uses keep the value's own SSA identity.
    Leaf,
    /// No definition is feasible; not simplified.
    Unreached,
}

impl Status {
    fn label(self) -> &'static str {
        match self {
            Self::Literal => "literal",
            Self::Propagated => "propagated",
            Self::Leaf => "leaf",
            Self::Unreached => "unreached",
        }
    }
}

pub(super) fn status(
    s: &PcodeSimplification,
    value: ValueId,
) -> Result<(Status, TermId), SimplifyError> {
    let term = s.value_term(value)?;
    let status = match s.constants().value(value)? {
        ConstantFact::Constant(_) => Status::Literal,
        ConstantFact::Unreached => Status::Unreached,
        ConstantFact::Unknown if s.is_propagated(value)? => Status::Propagated,
        ConstantFact::Unknown => Status::Leaf,
    };
    Ok((status, term))
}

pub(super) fn value_row(
    s: &PcodeSimplification,
    spaces: &[AddressSpace],
    id: usize,
) -> (Color32, String) {
    formatted();
    let e = s.expressions();
    let value = ValueId(id);
    let Ok((status, term)) = status(s, value) else {
        return (GOLD, format!("v{id} unavailable"));
    };
    let ty = e
        .value_type(value)
        .map_or_else(|_| "?".into(), |ty| expressions::type_label(spaces, ty));
    let (_, definition) = expressions::definition(e, spaces, value);
    let (color, result) = match status {
        Status::Unreached => (MUTED, "not simplified (never zero)".to_string()),
        _ => {
            let (color, preview) = term_preview(s, spaces, term);
            (color, format!("c{} {preview}", term.0))
        }
    };
    (
        color,
        format!(
            "v{id:<6} {ty:<12} {:<10} ⇒ {result}   ← {definition}",
            status.label()
        ),
    )
}

fn identity(identity: TermIdentity) -> &'static str {
    match identity {
        TermIdentity::Structural => "structural",
        TermIdentity::Distinct => "distinct",
        TermIdentity::Value => "value",
    }
}

fn origin(origin: TermOrigin) -> String {
    match origin {
        TermOrigin::Node(node) => format!("t{}", node.0),
        TermOrigin::Value(value) => format!("v{}", value.0),
    }
}

pub(super) fn term_row(
    s: &PcodeSimplification,
    spaces: &[AddressSpace],
    id: usize,
) -> (Color32, String) {
    formatted();
    let Ok(term) = s.term(TermId(id)) else {
        return (GOLD, format!("c{id} unavailable"));
    };
    let (color, preview) = term_preview(s, spaces, TermId(id));
    let mut tags = vec![identity(term.identity())];
    match term.fault {
        TermFault::Here => tags.push("may fault here"),
        TermFault::Subterm => tags.push("subterm may fault"),
        TermFault::None => {}
    }
    if term.reads_memory {
        tags.push("reads memory");
    }
    if term.boolean {
        tags.push("boolean");
    }
    (
        color,
        format!(
            "c{id:<6} {:<12} {preview}   [{}] {} ← {}",
            expressions::type_label(spaces, term.ty),
            tags.join(", "),
            term.rule.map_or("direct", Rule::name),
            origin(term.origin)
        ),
    )
}

/// Why an executed operation's output has its canonical term.
fn outcome(s: &PcodeSimplification, operation: SimplifiedOperation<'_>, output: TermId) -> String {
    let Ok(term) = s.term(output) else {
        return "unavailable".into();
    };
    let forwarded = (0..operation.source.operands.len().min(MAX_ITEMS))
        .any(|slot| operation.operand(slot) == Some(output));
    match &term.kind {
        TermKind::Literal(_) => "literal output".into(),
        TermKind::Leaf(_) => "forwarded".into(),
        _ if forwarded => "forwarded".into(),
        TermKind::ReadMemory { .. } => "memory read kept".into(),
        _ if term.fault == TermFault::Here => "kept: may fault".into(),
        _ => term
            .rule
            .map_or_else(|| "direct".into(), |rule| format!("rule {}", rule.name())),
    }
}

pub(super) fn operation_row(
    s: &PcodeSimplification,
    spaces: &[AddressSpace],
    statement: StatementId,
) -> (Color32, String) {
    formatted();
    let (tone, original) = expressions::operation_row(s.expressions(), spaces, statement);
    let Ok(Some(operation)) = s.operation(statement) else {
        return (GOLD, format!("{original}   [unavailable]"));
    };
    if !operation.executable {
        return (MUTED, format!("{original}   [unreached: not simplified]"));
    }
    if matches!(operation.source.effects, AppliedEffects::Conservative(_)) {
        return (
            GOLD,
            format!("{original}   [definitions stay OPAQUE leaves]"),
        );
    }
    match operation.output() {
        Some(output) => {
            let (color, preview) = term_preview(s, spaces, output);
            (
                color,
                format!(
                    "{original} ⇒ c{} {preview}   [{}]",
                    output.0,
                    outcome(s, operation, output)
                ),
            )
        }
        None => {
            let operands = expressions::capped(
                (0..operation.source.operands.len()).map(|slot| {
                    operation
                        .operand(slot)
                        .map_or("_".into(), |t| term_ref(s, t))
                }),
                MAX_ITEMS,
            );
            (tone.color(), format!("{original} ⇒ ({operands})"))
        }
    }
}

fn point(s: &PcodeSimplification, statement: StatementId) -> String {
    s.expressions().operation(statement).map_or_else(
        || "?".into(),
        |o| format!("{:X}:{}", o.point.address, o.point.operation_index),
    )
}

/// Constant-propagation faults first, then refused literal folds.
pub(super) fn issue_row(s: &PcodeSimplification, index: usize) -> (Color32, String) {
    formatted();
    let faults = s.faults();
    if let Some(fault) = faults.get(index) {
        let error = s
            .constants()
            .faults()
            .get(index)
            .map_or_else(|| "?".into(), |f| constants::bounded_error(&f.error));
        return (
            GOLD,
            format!(
                "fault   n{}.{:<4} {} {} t{} ⇒ c{} · constant-propagation evaluation fault: {error}",
                fault.statement.node,
                fault.statement.index,
                point(s, fault.statement),
                fault.opcode.mnemonic(),
                fault.node.0,
                fault.term.0
            ),
        );
    }
    let Some(refused) = index
        .checked_sub(faults.len())
        .and_then(|i| s.refused_folds().get(i))
    else {
        return (GOLD, format!("issue {index} unavailable"));
    };
    (
        PLAIN,
        format!(
            "refused n{}.{:<4} {} {} t{} ⇒ c{} · literal fold refused, not a runtime fault: {}",
            refused.statement.node,
            refused.statement.index,
            point(s, refused.statement),
            refused.opcode.mnemonic(),
            refused.node.0,
            refused.term.0,
            constants::bounded_error(&refused.error)
        ),
    )
}

/// A detail action: navigate to a source address or inspect a term.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Jump {
    Address(u64),
    Term(usize),
}

fn go_to(ui: &mut egui::Ui, address: u64) -> Option<Jump> {
    ui.button(format!("Go to {address:X}"))
        .clicked()
        .then_some(Jump::Address(address))
}

/// A clickable one-level reference to a canonical term.
fn term_link(
    ui: &mut egui::Ui,
    s: &PcodeSimplification,
    spaces: &[AddressSpace],
    prefix: &str,
    id: TermId,
) -> Option<Jump> {
    let (color, preview) = term_preview(s, spaces, id);
    ui.add(
        egui::Button::new(
            RichText::new(format!("{prefix}c{} = {preview}", id.0))
                .monospace()
                .color(color),
        )
        .wrap_mode(egui::TextWrapMode::Wrap),
    )
    .on_hover_text("Inspect this canonical term")
    .clicked()
    .then_some(Jump::Term(id.0))
}

fn muted(ui: &mut egui::Ui, text: impl Into<String>) {
    ui.label(RichText::new(text.into()).small().color(MUTED));
}

fn value_detail(
    ui: &mut egui::Ui,
    s: &PcodeSimplification,
    spaces: &[AddressSpace],
    value: ValueId,
) -> Option<Jump> {
    let e = s.expressions().as_ref();
    let variable = e.analysis().ssa().value(value).ok()?.variable;
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
            "v{} · {} · storage s{} {location}",
            value.0,
            expressions::type_label(spaces, ty),
            variable.0
        ))
        .color(ACCENT),
    );
    let fact = s
        .constants()
        .value(value)
        .map_or_else(|_| "unavailable".into(), constants::fact_text);
    ui.label(format!("Constant propagation: {fact}"));
    ui.label("Original definition");
    let (tone, definition) = expressions::definition(e, spaces, value);
    ui.label(RichText::new(definition).monospace().color(tone.color()));
    let (status, term) = status(s, value).ok()?;
    let mut jump = None;
    match status {
        Status::Literal => muted(
            ui,
            "Known constant: every use receives this literal. The defining operation still runs.",
        ),
        Status::Propagated => muted(
            ui,
            "Uses receive the definition's canonical term instead of this value.",
        ),
        Status::Leaf => muted(
            ui,
            format!(
                "Uses keep this value's own SSA identity ({}). Leaves are never expanded and never zero.",
                leaf_kind(s, value).1
            ),
        ),
        Status::Unreached => {
            ui.colored_label(MUTED, "Unreached: no definition is feasible in the supplied CFG, so this value is not simplified. It is not a value and not zero.");
        }
    }
    if status != Status::Unreached {
        ui.label("Canonical result");
        if let Some(action) = term_link(ui, s, spaces, "", term) {
            jump = Some(action);
        }
        // A propagated leaf of another value keeps that value's own
        // UNDEFINED, OPAQUE, entry or phi distinction.
        if let Ok(TermKind::Leaf(other)) = s.term(term).map(|t| &t.kind)
            && *other != value
        {
            let (tone, definition) = expressions::definition(e, spaces, *other);
            ui.label(
                RichText::new(format!("Canonical leaf v{} = {definition}", other.0))
                    .monospace()
                    .color(tone.color()),
            );
        }
    }
    if let Ok(ExpressionDefinition::Expression(root)) = e.definition(value) {
        match s.node_term(*root) {
            Ok(Some(defined)) => {
                if let Some(action) = term_link(
                    ui,
                    s,
                    spaces,
                    &format!("Definition t{} ⇒ ", root.0),
                    defined,
                ) {
                    jump = Some(action);
                }
            }
            Ok(None) => muted(
                ui,
                format!(
                    "Definition t{} is not simplified: its statement was not executed.",
                    root.0
                ),
            ),
            Err(_) => {}
        }
    }
    if let Some(address) = expressions::source_address(e, value)
        && let Some(action) = go_to(ui, address)
    {
        jump = Some(action);
    }
    jump
}

/// One level of a term's children with their roles.
fn children(kind: &TermKind) -> (Vec<(String, TermId)>, usize) {
    let pointer = |address: &TermAddress| match *address {
        TermAddress::Pointer { term, .. } => Some(("pointer: ".to_string(), term)),
        TermAddress::ByteOffset(_) => None,
    };
    match kind {
        TermKind::Literal(_) | TermKind::Leaf(_) => (vec![], 0),
        TermKind::Join(pieces) => (
            pieces
                .iter()
                .take(MAX_ITEMS)
                .map(|p| (format!("byte {} {}B: ", p.lsb_byte, p.size), p.term))
                .collect(),
            pieces.len(),
        ),
        TermKind::Extract { term, lsb_byte } => {
            (vec![(format!("source from byte {lsb_byte}: "), *term)], 1)
        }
        TermKind::Apply { inputs, .. } => (
            inputs
                .iter()
                .take(MAX_ITEMS)
                .enumerate()
                .map(|(i, t)| (format!("input {i}: "), *t))
                .collect(),
            inputs.len(),
        ),
        TermKind::ReadMemory { address, .. } => {
            let all: Vec<_> = pointer(address).into_iter().collect();
            let total = all.len();
            (all, total)
        }
        TermKind::WriteMemory { address, value, .. } => {
            let mut all: Vec<_> = pointer(address).into_iter().collect();
            all.push(("stored value: ".into(), *value));
            let total = all.len();
            (all, total)
        }
    }
}

fn term_detail(
    ui: &mut egui::Ui,
    snapshot: &ReducedView,
    operations: &[StatementId],
    spaces: &[AddressSpace],
    id: TermId,
) -> Option<Jump> {
    let s = &snapshot.simplification;
    let e = s.expressions().as_ref();
    let term = s.term(id).ok()?;
    ui.label(
        RichText::new(format!(
            "Canonical term c{} · {} · {} identity",
            id.0,
            expressions::type_label(spaces, term.ty),
            identity(term.identity())
        ))
        .color(ACCENT),
    );
    let (color, preview) = term_preview(s, spaces, id);
    ui.label(RichText::new(preview).monospace().color(color));
    match term.rule {
        Some(rule) => ui.label(format!("Produced by rule {}.", rule.name())),
        None => ui.label("Direct translation of the original term (no rewrite rule)."),
    };
    match term.fault {
        TermFault::Here => {
            ui.colored_label(GOLD, "May fault here (memory access or partial operation). Kept distinct: never shared, propagated or discarded.");
        }
        TermFault::Subterm => {
            ui.colored_label(
                GOLD,
                "A subterm may fault; the original operation stream still performs it.",
            );
        }
        TermFault::None => muted(ui, "Evaluating this term cannot fault."),
    }
    if term.reads_memory {
        muted(ui, "Reads memory directly or through a subterm.");
    }
    if term.boolean {
        muted(ui, "Proven boolean: one byte holding 0 or 1.");
    }
    let mut jump = None;
    let mut source = None;
    match &term.kind {
        TermKind::Literal(value) => {
            ui.label(
                RichText::new(format!("Literal {}", constants::detail_hex(value)))
                    .monospace()
                    .color(ACCENT),
            );
        }
        TermKind::Leaf(value) => {
            let (tone, definition) = expressions::definition(e, spaces, *value);
            ui.label(
                RichText::new(format!("v{} = {definition}", value.0))
                    .monospace()
                    .color(tone.color()),
            );
            let fact = s
                .constants()
                .value(*value)
                .map_or_else(|_| "unavailable".into(), constants::fact_text);
            ui.label(format!("Constant propagation: {fact}"));
            muted(
                ui,
                "An SSA leaf stands for the value's own identity. It is never expanded and never zero; loops stay value references.",
            );
            source = expressions::source_address(e, *value);
        }
        TermKind::ReadMemory {
            node,
            space,
            version,
            ..
        }
        | TermKind::WriteMemory {
            node,
            space,
            version,
            ..
        } => {
            let write = matches!(term.kind, TermKind::WriteMemory { .. });
            ui.label(format!(
                "Memory {} of {} memory version v{} (original node t{}). Never forwarded, shared or removed; the original operation performs the access.",
                if write { "write" } else { "read" },
                expressions::space_name(spaces, *space),
                version.0,
                node.0
            ));
        }
        _ => {}
    }
    let (inputs, total) = children(&term.kind);
    if !inputs.is_empty() {
        ui.label("Operands (one level)");
        for (role, child) in inputs {
            if let Some(action) = term_link(ui, s, spaces, &role, child) {
                jump = Some(action);
            }
        }
        if total > MAX_ITEMS {
            ui.monospace(format!("… +{} more", total - MAX_ITEMS));
        }
    }
    match term.origin {
        TermOrigin::Node(node) => {
            ui.monospace(format!(
                "Origin t{} = {}",
                node.0,
                expressions::term(e, spaces, node)
            ));
            if let Some(statement) = snapshot.node_statement(operations, node)
                && let Some(operation) = e.operation(statement)
            {
                muted(
                    ui,
                    format!(
                        "First appears in n{}.{} at {:X}:{} {}.",
                        statement.node,
                        statement.index,
                        operation.point.address,
                        operation.point.operation_index,
                        operation.opcode.mnemonic()
                    ),
                );
                source = source.or(Some(operation.point.address));
            }
        }
        TermOrigin::Value(value) => {
            ui.monospace(format!("Origin v{}", value.0));
            source = source.or_else(|| expressions::source_address(e, value));
        }
    }
    if let Some(address) = source
        && let Some(action) = go_to(ui, address)
    {
        jump = Some(action);
    }
    jump
}

fn operation_detail(
    ui: &mut egui::Ui,
    s: &PcodeSimplification,
    spaces: &[AddressSpace],
    statement: StatementId,
) -> Option<Jump> {
    let e = s.expressions().as_ref();
    let operation = s.operation(statement).ok()??;
    let source = operation.source;
    ui.label(
        RichText::new(format!(
            "n{}.{} · {:X}:{} · {}",
            statement.node,
            statement.index,
            source.point.address,
            source.point.operation_index,
            source.opcode.mnemonic()
        ))
        .color(ACCENT),
    );
    let mut jump = go_to(ui, source.point.address);
    if operation.executable {
        muted(
            ui,
            "Executed by constant propagation. The original operation still performs every read, effect and fault; the terms describe its values.",
        );
    } else {
        ui.colored_label(MUTED, "Unreached in the supplied CFG: no canonical terms. The original operation is unchanged and not simplified.");
    }
    if let AppliedEffects::Conservative(class) = source.effects {
        ui.colored_label(
            GOLD,
            format!("Conservative {class:?} effect: its definitions stay OPAQUE leaves."),
        );
    }
    ui.label("Operands (original ⇒ projected)");
    for (slot, input) in source.operands.iter().enumerate().take(MAX_DETAIL_ROWS) {
        let original = expressions::operand(e, spaces, source.opcode, slot, input);
        match operation.operand(slot) {
            Some(term) => {
                if let Some(action) = term_link(ui, s, spaces, &format!("{original} ⇒ "), term) {
                    jump = Some(action);
                }
            }
            None => {
                ui.monospace(original);
            }
        }
    }
    if source.operands.len() > MAX_DETAIL_ROWS {
        ui.monospace(format!(
            "… +{} more",
            source.operands.len() - MAX_DETAIL_ROWS
        ));
    }
    if source.opcode == Opcode::Cbranch
        && let Some(condition) = operation.operand(1)
        && let Ok(TermKind::Literal(_)) = s.term(condition).map(|t| &t.kind)
        && let Some(node) = source.operands.get(1).and_then(|o| o.expression())
        && !matches!(
            s.constants().expression(node),
            Ok(ConstantFact::Constant(_))
        )
    {
        muted(
            ui,
            "The condition is literal only in this projection. Constant-propagation feasibility is unchanged; no branch is pruned.",
        );
    }
    if let Some(memory) = &source.indirect_memory {
        ui.monospace(format!(
            "{} {} memory version v{}",
            match memory.kind {
                ghidra_analysis::MemoryAccessKind::Read => "Reads",
                ghidra_analysis::MemoryAccessKind::Write => "Writes",
            },
            expressions::space_name(spaces, memory.space),
            memory.version.0
        ));
    }
    match source.output {
        Some(node) => {
            let ty = e
                .node(node)
                .map_or_else(|_| "?".into(), |n| expressions::type_label(spaces, n.ty));
            ui.monospace(format!(
                "Original t{} {ty} = {}",
                node.0,
                expressions::term(e, spaces, node)
            ));
            match operation.output() {
                Some(output) => {
                    if let Some(action) = term_link(ui, s, spaces, "Projected ⇒ ", output) {
                        jump = Some(action);
                    }
                    muted(ui, outcome(s, operation, output));
                }
                None => muted(ui, "Not simplified: the statement was not executed."),
            }
        }
        None => muted(ui, "No bit result (store, control or opaque operation)."),
    }
    if operation.executable
        && let Ok(renamed) = e.analysis().ssa().statement(statement)
        && !renamed.defs().is_empty()
    {
        ui.label("Defines");
        for value in renamed.defs().iter().take(MAX_DETAIL_ROWS) {
            match status(s, *value) {
                Ok((Status::Unreached, _)) | Err(_) => {
                    ui.monospace(format!("v{} not simplified", value.0));
                }
                Ok((status, term)) => {
                    let prefix = format!("v{} {} ⇒ ", value.0, status.label());
                    if let Some(action) = term_link(ui, s, spaces, &prefix, term) {
                        jump = Some(action);
                    }
                }
            }
        }
        if renamed.defs().len() > MAX_DETAIL_ROWS {
            ui.monospace(format!(
                "… +{} more",
                renamed.defs().len() - MAX_DETAIL_ROWS
            ));
        }
    }
    jump
}

fn issue_detail(
    ui: &mut egui::Ui,
    s: &PcodeSimplification,
    spaces: &[AddressSpace],
    index: usize,
) -> Option<Jump> {
    let e = s.expressions().as_ref();
    let faults = s.faults();
    let (statement, node, term, opcode, fault) = match faults.get(index) {
        Some(f) => (f.statement, f.node, f.term, f.opcode, true),
        None => {
            let r = s.refused_folds().get(index.checked_sub(faults.len())?)?;
            (r.statement, r.node, r.term, r.opcode, false)
        }
    };
    let operation = e.operation(statement)?;
    ui.label(
        RichText::new(format!(
            "{} · n{}.{} · {:X}:{} · {}",
            if fault {
                "Constant-propagation evaluation fault"
            } else {
                "Refused literal fold"
            },
            statement.node,
            statement.index,
            operation.point.address,
            operation.point.operation_index,
            opcode.mnemonic()
        ))
        .color(ACCENT),
    );
    if fault {
        if let Some(original) = s.constants().faults().get(index) {
            ui.colored_label(GOLD, constants::bounded_error(&original.error));
        }
        muted(
            ui,
            "Every input is a known constant at the fixpoint, but evaluation failed. The result stays unknown, the canonical term stays a distinct application that may fault, and control is not cut.",
        );
    } else {
        let refused = &s.refused_folds()[index - faults.len()];
        ui.label(constants::bounded_error(&refused.error));
        muted(
            ui,
            "The evaluator refused to fold these literal inputs during analysis. This is not a claim that the program faults at run time and is reported separately from constant-propagation faults. The term stays an explicit application.",
        );
    }
    ui.monospace(format!(
        "Original t{} = {}",
        node.0,
        expressions::term(e, spaces, node)
    ));
    let mut jump = term_link(ui, s, spaces, "Canonical ⇒ ", term);
    if let Some(action) = go_to(ui, operation.point.address) {
        jump = Some(action);
    }
    jump
}

/// Virtualized rows over `count` items; `row` formats only visible ones.
fn rows(
    ui: &mut egui::Ui,
    salt: &str,
    selection: &mut usize,
    count: usize,
    reveal: bool,
    mut row: impl FnMut(usize) -> (Color32, String),
) {
    *selection = (*selection).min(count.saturating_sub(1));
    let height = expressions::row_height(ui);
    let mut area = egui::ScrollArea::both().id_salt(salt);
    if reveal {
        area =
            area.vertical_scroll_offset(*selection as f32 * (height + ui.spacing().item_spacing.y));
    }
    area.show_rows(ui, height, count, |ui, range| {
        for index in range {
            let (color, text) = row(index);
            expressions::selectable_row(ui, selection, index, color, text);
        }
    });
}

fn detail(
    ui: &mut egui::Ui,
    salt: &str,
    contents: impl FnOnce(&mut egui::Ui) -> Option<Jump>,
) -> Option<Jump> {
    egui::ScrollArea::vertical()
        .id_salt(salt)
        .show(ui, contents)
        .inner
}

fn summary(ui: &mut egui::Ui, s: &PcodeSimplification) {
    let stats = s.stats();
    ui.label(format!(
        "{} canonical terms ({} literal · {} leaf · {} distinct) for {} original term nodes · {} executed and {} unreached operations",
        stats.terms,
        stats.literal_terms,
        stats.leaf_terms,
        stats.distinct_terms,
        s.expressions().nodes().len(),
        stats.executed_operations,
        stats.skipped_operations
    ));
    ui.label(format!(
        "Reductions: {} literal values · {} propagated values · {} kept leaves · {} literal outputs · {} forwarded outputs · {} shared terms · {} newly literal conditions · {} evaluation faults · {} refused folds",
        stats.literal_values,
        stats.propagated_values,
        stats.leaf_values,
        stats.literal_outputs,
        stats.forwarded_outputs,
        stats.shared_terms,
        stats.new_literal_conditions,
        s.faults().len(),
        s.refused_folds().len()
    ));
    let fired: Vec<String> = Rule::ALL
        .iter()
        .filter(|rule| stats.rule(**rule) > 0)
        .map(|rule| format!("{} {}", rule.name(), stats.rule(*rule)))
        .collect();
    muted(
        ui,
        if fired.is_empty() {
            "No rewrite rule fired.".to_string()
        } else {
            format!("Rules fired: {}", fired.join(" · "))
        },
    );
}

/// Row kinds, the summary and the virtualized panes of one snapshot.
/// `operations` are the expression operation statements of the same view.
fn contents(
    ui: &mut egui::Ui,
    selection: &mut Selection,
    snapshot: &ReducedView,
    operations: &[StatementId],
    pane_height: f32,
) -> Option<u64> {
    let top = ui.cursor().top();
    let s = &snapshot.simplification;
    let spaces = s.analysis().cfg().spaces();
    ui.horizontal_wrapped(|ui| {
        for (rows, label) in [
            (Rows::Values, "SSA values"),
            (Rows::Reductions, "Reductions"),
            (Rows::Terms, "Canonical terms"),
            (Rows::Operations, "Operations"),
            (Rows::Issues, "Faults & refused folds"),
        ] {
            ui.selectable_value(&mut selection.rows, rows, label);
        }
    });
    muted(ui, NOTE);
    summary(ui, s);
    let reveal = std::mem::take(&mut selection.reveal);
    let mut jump = None;
    super::inspection_panes(ui, pane_height - (ui.cursor().top() - top), |ui| {
        ui.columns(2, |columns| match selection.rows {
            Rows::Values => {
                let count = s.analysis().ssa().values().len();
                rows(
                    &mut columns[0],
                    "reduced_values",
                    &mut selection.value,
                    count,
                    reveal,
                    |id| value_row(s, spaces, id),
                );
                if count > 0 {
                    jump = detail(&mut columns[1], "reduced_value_detail", |ui| {
                        value_detail(ui, s, spaces, ValueId(selection.value))
                    });
                }
            }
            Rows::Reductions => {
                let reduced = &snapshot.reduced_values;
                rows(
                    &mut columns[0],
                    "reduced_reductions",
                    &mut selection.reduction,
                    reduced.len(),
                    reveal,
                    |index| value_row(s, spaces, reduced[index].0),
                );
                match reduced.get(selection.reduction) {
                    Some(&value) => {
                        jump = detail(&mut columns[1], "reduced_reduction_detail", |ui| {
                            value_detail(ui, s, spaces, value)
                        });
                    }
                    None => {
                        columns[1].label(
                            "No SSA value is reduced: every use keeps its own SSA identity.",
                        );
                    }
                }
            }
            Rows::Terms => {
                let count = s.terms().len();
                rows(
                    &mut columns[0],
                    "reduced_terms",
                    &mut selection.term,
                    count,
                    reveal,
                    |id| term_row(s, spaces, id),
                );
                if count > 0 {
                    jump = detail(&mut columns[1], "reduced_term_detail", |ui| {
                        term_detail(ui, snapshot, operations, spaces, TermId(selection.term))
                    });
                } else {
                    columns[1].label("No canonical terms: no statement was executed.");
                }
            }
            Rows::Operations => {
                rows(
                    &mut columns[0],
                    "reduced_operations",
                    &mut selection.operation,
                    operations.len(),
                    reveal,
                    |index| operation_row(s, spaces, operations[index]),
                );
                match operations.get(selection.operation) {
                    Some(&statement) => {
                        jump = detail(&mut columns[1], "reduced_operation_detail", |ui| {
                            operation_detail(ui, s, spaces, statement)
                        });
                    }
                    None => {
                        columns[1].label("No expression operations.");
                    }
                }
            }
            Rows::Issues => {
                let count = s.faults().len() + s.refused_folds().len();
                rows(
                    &mut columns[0],
                    "reduced_issues",
                    &mut selection.issue,
                    count,
                    reveal,
                    |index| issue_row(s, index),
                );
                if count > 0 {
                    jump = detail(&mut columns[1], "reduced_issue_detail", |ui| {
                        issue_detail(ui, s, spaces, selection.issue)
                    });
                } else {
                    columns[1].label("No constant-propagation faults or refused folds.");
                }
            }
        });
    });
    match jump {
        Some(Jump::Address(address)) => Some(address),
        Some(Jump::Term(term)) => {
            selection.rows = Rows::Terms;
            selection.term = term;
            selection.reveal = true;
            None
        }
        None => None,
    }
}

/// Renders the reduced mode of `view` and returns a requested source
/// address. Building or failing leaves every other mode unaffected.
pub(super) fn panel(
    ui: &mut egui::Ui,
    state: &mut State,
    source: RequestKey,
    view: &Arc<FunctionView>,
    pane_height: f32,
) -> Option<u64> {
    let top = ui.cursor().top();
    let snapshot = match &state.build {
        Build::Ready(snapshot) => snapshot.clone(),
        Build::Idle | Build::Waiting(_) => {
            ui.horizontal(|ui| {
                if state.waiting() {
                    ui.spinner();
                    ui.label("Reducing expressions from the constant facts…");
                } else {
                    ui.label("Reduction starts after the current project operation.");
                }
            });
            muted(ui, NOTE);
            return None;
        }
        Build::Failed(error) => {
            let error = error.clone();
            ui.colored_label(GOLD, format!("Reduced expressions unavailable: {error}"));
            muted(
                ui,
                "The CFG & SSA, storage, expression and constant views of this analysis are unaffected.",
            );
            if ui.button("Retry reduction").clicked() {
                state.retry(source, view);
            }
            return None;
        }
    };
    let mut copy = false;
    ui.horizontal_wrapped(|ui| {
        copy = ui
            .add_enabled(
                !matches!(state.export, Export::Waiting(_)),
                egui::Button::new("Copy reduced analysis JSON"),
            )
            .on_hover_text("The function analysis document with its simplification field, as written by --analyze-function --simplify")
            .clicked();
        match &state.export {
            Export::Idle => {}
            Export::Waiting(_) => {
                ui.spinner();
                ui.label("Serializing…");
            }
            Export::Copied(bytes) => {
                ui.label(RichText::new(format!("Copied {bytes} bytes")).color(MUTED));
            }
            Export::Failed(error) => {
                ui.colored_label(GOLD, format!("Copy failed: {error}"));
            }
        }
    });
    if copy {
        state.copy(source, view);
    }
    let remaining = pane_height - (ui.cursor().top() - top);
    contents(
        ui,
        &mut state.selection,
        &snapshot,
        &view.expression_operations,
        remaining,
    )
}

#[cfg(test)]
mod tests;
