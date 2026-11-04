//! The walk over a decoded instruction's resolved semantics.
//!
//! One instruction's p-code is its root constructor's body with, spliced in,
//! the bodies of the sub-table operands it builds and of the instructions in
//! its delay slot. [`Traversal`] performs that splice: it visits the template
//! statements of each body in emission order and hands each one, resolved in
//! its [`Scope`], to a [`Visitor`].
//!
//! Every consumer of an instruction's semantics is a visitor over this one
//! walk — the owned AST is built by one, the streamed lowering runs a planner
//! and then an emitter as two — so the subtle parts (local id rebasing, label
//! scoping, `inst_next` in a delay slot, which child is built when) exist
//! once.

use pcode_types::streaming::StmtKind;

use crate::{
    instance::ConstructorInstance,
    objects::table::TableId,
    pmacro::{
        BodyTemplate,
        expression::LocalVarId,
        statement::{Ast, AstNode},
    },
    runtime::pcode::{
        RuntimeValue,
        view::{self, Scope, View, export},
    },
    semantics::EmitError,
    spec::Spec,
};

/// Receives each emitted statement of an instruction, in order.
pub(super) trait Visitor {
    fn statement(&mut self, statement: StmtKind<'_, View<'_>>) -> Result<(), EmitError>;

    /// Whether the visitor reads anything but labels and the targets of
    /// direct branches and calls. A planner does not, and resolving the
    /// operands of every other statement for it would be wasted work: it
    /// gets [`opaque_statement`](Self::opaque_statement) instead.
    fn wants_data_flow(&self) -> bool {
        true
    }

    /// A statement whose contents the visitor declined to see. It still
    /// counts as one: a label before it is not the instruction's last.
    fn opaque_statement(&mut self) -> Result<(), EmitError> {
        Ok(())
    }
}

/// Why a traversal stopped early.
///
/// The two are told apart because they are handled differently: a sub-table
/// operand that cannot be *expanded* is skipped when it is being pre-emitted,
/// as the eager expander always did, while a visitor's refusal always stops
/// the whole instruction.
pub(super) enum Interrupt {
    /// The semantics could not be resolved.
    Expansion(EmitError),
    /// The visitor rejected a statement.
    Visitor(EmitError),
}

impl From<Interrupt> for EmitError {
    fn from(interrupt: Interrupt) -> Self {
        match interrupt {
            Interrupt::Expansion(error) | Interrupt::Visitor(error) => error,
        }
    }
}

pub(super) struct Traversal<'spec, 'i> {
    spec: &'spec Spec,

    /// What sub-table operands export, as a stack: a body's exports sit above
    /// its parent's and are popped when the body is done, so the whole
    /// instruction shares one allocation rather than each body making its
    /// own. Exports are uncommon in the x86 semantics, so it usually stays
    /// empty.
    exports: Vec<(TableId, RuntimeValue)>,

    /// Local widths resolved from each spliced body's compile-time widths,
    /// keyed by the rebased id the emitted statements use.
    pub(super) local_sizes: pcode_types::LocalSizes,

    /// Cleared when a body's compile-time widths could not be resolved, so the
    /// consumer falls back to inferring them from the emitted statements.
    pub(super) widths_resolved: bool,

    /// Whether to resolve widths at all. A pass that runs after the plan is
    /// made has no use for them.
    collect_widths: bool,

    /// Monotonically increasing counter: next available `LocalVarId` for this decode.
    next_var_id: u32,
    /// Base offset added to each constructor's locals so different subtable
    /// invocations never share an ID.
    current_base: u32,

    /// `inst_next` as the semantic section sees it — past the delay slot. Swapped
    /// while a delayed instruction is spliced, since that instruction's body
    /// means its *own* `inst_next`.
    inst_next: u64,

    /// Address past the instruction after this one, when a constructor asked
    /// for it by reading `inst_next2`.
    inst_next2: Option<u64>,

    /// Instructions filling the current instruction's delay slot, spliced where
    /// its `delayslot` directive sits. Held here rather than looked up from the
    /// instance being emitted, because the directive may live in a
    /// sub-constructor while the delayed instructions belong to the root.
    delay_slots: &'i [ConstructorInstance],

    /// Label namespace for the body being emitted. `0` is the instruction's
    /// own; each spliced delay-slot instruction gets its own, so a label the
    /// delayed instruction declares cannot collide with one of the same name in
    /// the instruction that delayed it.
    label_scope: u32,

    /// Next unused value for [`Self::label_scope`].
    next_label_scope: u32,
}

impl<'spec, 'i> Traversal<'spec, 'i> {
    pub(super) fn new(spec: &'spec Spec, instance: &'i ConstructorInstance) -> Self {
        Self {
            spec,
            exports: Vec::new(),
            local_sizes: pcode_types::LocalSizes::default(),
            widths_resolved: true,
            collect_widths: true,
            next_var_id: 0,
            current_base: 0,
            inst_next: instance.semantic_inst_next(),
            inst_next2: instance.inst_next2,
            delay_slots: &instance.delay_slots,
            label_scope: 0,
            next_label_scope: 1,
        }
    }

    /// Reuses the export stack of an earlier walk over the same instruction,
    /// and skips resolving local widths, which that walk already did.
    pub(super) fn again(mut self, previous: Traversal<'_, '_>) -> Self {
        self.exports = previous.exports;
        self.exports.clear();
        self.collect_widths = false;
        self
    }

    /// Walks the whole instruction rooted at `instance`.
    pub(super) fn run(
        &mut self,
        instance: &ConstructorInstance,
        visitor: &mut impl Visitor,
    ) -> Result<(), Interrupt> {
        self.visit_instance(instance, visitor).map(|_| ())
    }

    /// Emits one delayed instruction's p-code in place of the directive.
    fn visit_delay_slot(
        &mut self,
        delayed: &ConstructorInstance,
        visitor: &mut impl Visitor,
    ) -> Result<(), Interrupt> {
        let base = self.next_var_id;
        self.next_var_id += delayed.constructor(self.spec).pmacro.local_var_count;

        let scope = self.next_label_scope;
        self.next_label_scope += 1;

        let old_base = std::mem::replace(&mut self.current_base, base);
        let old_scope = std::mem::replace(&mut self.label_scope, scope);
        let old_next = std::mem::replace(&mut self.inst_next, delayed.semantic_inst_next());
        let old_next2 = std::mem::replace(&mut self.inst_next2, delayed.inst_next2);

        let result = self.visit_instance(delayed, visitor);

        self.current_base = old_base;
        self.label_scope = old_scope;
        self.inst_next = old_next;
        self.inst_next2 = old_next2;

        result.map(|_| ())
    }

    fn visit_instance(
        &mut self,
        instance: &ConstructorInstance,
        visitor: &mut impl Visitor,
    ) -> Result<Option<RuntimeValue>, Interrupt> {
        let constructor = instance.constructor(self.spec);
        let pmacro = &constructor.pmacro;

        // SLEIGH prefix/wrapper constructors: delegate to their self-table child.
        if pmacro.body.is_empty() && pmacro.export.is_none() {
            let self_table = TableId::from(usize::from(instance.tree));
            if let Some(child) = instance.child_value(self.spec, self_table) {
                return self.visit_instance(child, visitor);
            }
        }

        let own_end = self.current_base + pmacro.local_var_count;
        if self.next_var_id < own_end {
            self.next_var_id = own_end;
        }

        self.visit_body(instance, pmacro.template(), visitor)
    }

    fn visit_body(
        &mut self,
        instance: &ConstructorInstance,
        template: BodyTemplate<'_>,
        visitor: &mut impl Visitor,
    ) -> Result<Option<RuntimeValue>, Interrupt> {
        let BodyTemplate {
            body,
            export,
            invalid,
            invalid_export,
            non_build_table_refs,
            local_widths,
            unsized_locals,
        } = template;
        let base = self.current_base;
        let exports = self.exports.len();
        let result = self.visit_body_inner(
            instance,
            body,
            invalid,
            non_build_table_refs,
            exports,
            visitor,
        );
        let result = result.and_then(|()| {
            // Resolve this body's widths now: a width naming a table operand
            // needs that operand's export, which only exists once the body
            // has been emitted.
            if self.collect_widths {
                self.resolve_local_widths(base, local_widths, unsized_locals, exports);
            }
            let Some(export) = export else {
                return Ok(None);
            };
            if let Some(error) = invalid_export {
                return Err(Interrupt::Expansion(error.clone()));
            }
            let scope = self.scope(instance, exports);
            view::export_value(&scope, export)
                .map(Some)
                .map_err(Interrupt::Expansion)
        });
        self.exports.truncate(exports);
        result
    }

    /// The statements of one body. `exports` is where this body's exports
    /// start on the stack.
    fn visit_body_inner(
        &mut self,
        instance: &ConstructorInstance,
        body: &[Ast],
        invalid: Option<&(usize, EmitError)>,
        non_build_table_refs: &[TableId],
        exports: usize,
        visitor: &mut impl Visitor,
    ) -> Result<(), Interrupt> {
        // Pre-emit all non-`build` subtable references. One that cannot be
        // expanded is left out, as it always was; only the visitor can stop
        // the instruction here.
        for &table_id in non_build_table_refs {
            if export(&self.exports[exports..], table_id).is_some() {
                continue;
            }
            match self.visit_child_scoped(instance, table_id, visitor) {
                Ok(Some(value)) => self.insert_export(exports, table_id, value),
                Ok(None) | Err(Interrupt::Expansion(_)) => {}
                Err(stop @ Interrupt::Visitor(_)) => return Err(stop),
            }
        }

        for (index, statement) in body.iter().enumerate() {
            if let Some((at, error)) = invalid
                && *at == index
            {
                return Err(Interrupt::Expansion(error.clone()));
            }
            self.visit_statement(instance, statement, exports, visitor)?;
        }
        Ok(())
    }

    fn insert_export(&mut self, exports: usize, table: TableId, value: RuntimeValue) {
        match self.exports[exports..]
            .iter_mut()
            .find(|(id, _)| *id == table)
        {
            Some(slot) => slot.1 = value,
            None => self.exports.push((table, value)),
        }
    }

    /// The scope of the body whose exports start at `exports`.
    fn scope<'a>(&'a self, instance: &'a ConstructorInstance, exports: usize) -> Scope<'a> {
        Scope {
            spec: self.spec,
            instance,
            base: self.current_base,
            inst_next: self.inst_next,
            inst_next2: self.inst_next2,
            exports: &self.exports[exports..],
            label_scope: self.label_scope,
        }
    }

    /// Rebases one body's compile-time widths into the ids its emitted
    /// statements use, resolving any that name an operand.
    fn resolve_local_widths(
        &mut self,
        base: u32,
        local_widths: &std::collections::HashMap<LocalVarId, pcode_types::SymbolicWidth>,
        unsized_locals: &[LocalVarId],
        exports: usize,
    ) {
        // A body with a local nothing can size leaves the widths incomplete,
        // whatever the rest of them resolved to.
        if !unsized_locals.is_empty() {
            self.widths_resolved = false;
        }
        for (id, width) in local_widths {
            let size = match width {
                pcode_types::SymbolicWidth::Fixed(size) => Some(*size),
                pcode_types::SymbolicWidth::SameAs(table) => {
                    export(&self.exports[exports..], *table).and_then(RuntimeValue::size)
                }
            };
            match size {
                Some(size) => {
                    self.local_sizes.insert(LocalVarId(base + id.0), size);
                }
                None => self.widths_resolved = false,
            }
        }
    }

    fn visit_statement(
        &mut self,
        instance: &ConstructorInstance,
        statement: &Ast,
        exports: usize,
        visitor: &mut impl Visitor,
    ) -> Result<(), Interrupt> {
        match &statement.ty {
            AstNode::Build(table_id) => {
                if let Some(value) = self.visit_child_scoped(instance, *table_id, visitor)? {
                    self.insert_export(exports, *table_id, value);
                }
                Ok(())
            }
            AstNode::DelaySlot(_) => {
                // The directive splices the delayed instructions' p-code where
                // it stands, not at the end: the manual's `beq` shape reads the
                // compared registers before the delayed instruction is free to
                // clobber them.
                for delayed in self.delay_slots {
                    self.visit_delay_slot(delayed, visitor)?;
                }
                Ok(())
            }
            AstNode::Export(_) => Ok(()),
            AstNode::Assignment { .. }
            | AstNode::LoadAssignment { .. }
            | AstNode::RangeAssignment { .. }
            | AstNode::BranchIndirect { .. }
            | AstNode::CallIndirect { .. }
            | AstNode::Return { .. }
            | AstNode::Expression(_)
                if !visitor.wants_data_flow() =>
            {
                visitor.opaque_statement().map_err(Interrupt::Visitor)
            }
            _ => {
                let scope = self.scope(instance, exports);
                visitor
                    .statement(view::statement(&scope, statement))
                    .map_err(Interrupt::Visitor)
            }
        }
    }

    /// Emit a child subtable with a fresh ID allocation scope.
    pub(super) fn visit_child_scoped(
        &mut self,
        instance: &ConstructorInstance,
        table_id: TableId,
        visitor: &mut impl Visitor,
    ) -> Result<Option<RuntimeValue>, Interrupt> {
        let child = instance.child_value(self.spec, table_id).ok_or_else(|| {
            Interrupt::Expansion(EmitError::new(format!(
                "failed to build semantic operand (table {}): no matched child constructor",
                usize::from(table_id)
            )))
        })?;

        let child_local_count = child.constructor(self.spec).pmacro.local_var_count;
        let child_base = self.next_var_id;
        self.next_var_id += child_local_count;

        let old_base = std::mem::replace(&mut self.current_base, child_base);
        let result = self.visit_instance(child, visitor);
        self.current_base = old_base;
        result
    }
}
