//! Resolution pass: walk a typed [`SleighFile`] and populate a [`SpecBuilder`].
//!
//! This is the Phase 3 step of the single-pass SLEIGH AST refactor. Given a
//! `SleighFile` produced by `build_sleigh_ast` (Phase 2), it performs all
//! name-to-ID resolution in declaration order — the same ordering invariants
//! as the old `RawSleighParser` — and returns a fully populated `SpecBuilder`
//! ready for `concretize()`.

use crate::{
    action::{Action, Atom, Expr as ActionExpr, GlobalSetAddr},
    builder::{Endian, SpecBuilder, SymbolId},
    constructor::DisplayElement,
    diagnostic::{BuildResult, Diagnostic, DiagnosticCode},
    objects::field::{FieldId, FieldParent, FieldType},
    pmacro::{
        PCodeMacro,
        expression::{
            Binop, Builtin, Expression, ExpressionTy, Ident, Load, LocalVarId, Range, SpaceRef,
            Unop,
        },
        statement::{Ast, AstNode, DelaySlotArg, LabelOrNode},
    },
    source::Span,
    syntax::{
        AttachStrDef, AttachValDef, AttachVarDef, BitRangeDef, ConstructorDef, ContextDef,
        MacroDef, RegisterDef, SleighFile, SleighItem, SpaceDef, TokenDef, UnresolvedAction,
        UnresolvedDisplayToken, UnresolvedExpr, WithBlockDef,
    },
};
use std::collections::HashMap;

type BSpan = (usize, usize);

/// Resolve a typed, unresolved [`SleighFile`] into a populated [`SpecBuilder`].
/// Resolves a file, returning the builder and any non-fatal findings.
///
/// Warnings are things the specification is accepted *despite* — where this
/// crate follows Ghidra into behaviour a reader would not expect. They are
/// surfaced by [`analyze`](crate::analyze); [`Compiler::compile`](crate::Compiler::compile)
/// returns only the specification and drops them.
pub(crate) fn resolve(
    file: &SleighFile,
) -> Result<(SpecBuilder, Vec<Diagnostic>), Vec<Diagnostic>> {
    let mut resolver = Resolver::new();
    resolver.resolve_file(file);
    if resolver.errors.is_empty() {
        Ok((resolver.ctx, resolver.warnings))
    } else {
        Err(resolver.errors)
    }
}

// ── Internal resolver state ───────────────────────────────────────────────────

struct Resolver {
    ctx: SpecBuilder,
    errors: Vec<Diagnostic>,
    /// Non-fatal findings: the specification compiles, but something in it is
    /// worth saying out loud.
    warnings: Vec<Diagnostic>,
    with_frames: Vec<WithFrame>,
    /// Per-pcode-block interner for implicit locals not interned during Phase 2.
    /// Reset at the start of each `resolve_pcode` call.
    local_interner: HashMap<Box<str>, LocalVarId>,
    local_next_id: u32,

    /// Disassembly-action locals whose name the shared symbol table cannot
    /// hold, because something else already owns it.
    ///
    /// Constructor-scoped, and consulted by *both* action resolution and
    /// p-code resolution: the action block writes the name and the semantic
    /// body reads it back, so one map has to be visible to both. Cleared at
    /// the start of each constructor.
    action_locals: HashMap<Box<str>, FieldId>,

    /// Table the constructor being resolved belongs to, if known.
    ///
    /// The table is only created once the constructor is added, *after* its
    /// actions are resolved — so the name is not in the symbol table yet when
    /// an action assigns it. Loongarch's `csr:` constructor collides that way
    /// round, and this is how the action sees it coming.
    action_scope_table: Option<Box<str>>,
}

struct WithFrame {
    default_name: Option<Box<str>>,
    constraint: crate::constraint::ConstraintAst,
    actions: Vec<Action>,
}

impl Resolver {
    fn new() -> Self {
        Self {
            ctx: SpecBuilder::new(),
            errors: Vec::new(),
            warnings: Vec::new(),
            with_frames: Vec::new(),
            local_interner: HashMap::new(),
            local_next_id: 0,
            action_locals: HashMap::new(),
            action_scope_table: None,
        }
    }

    /// Resolves a name written or read by a disassembly action.
    ///
    /// A constructor-scoped action local shadows the shared symbol table, which
    /// is what makes Loongarch's `csr` work: the name is a table there, and the
    /// action's `csr` is a different thing entirely.
    fn action_name(&self, name: &str) -> Option<FieldId> {
        if let Some(&id) = self.action_locals.get(name) {
            return Some(id);
        }
        self.ctx.try_get_field(name).map(|field| field.id)
    }

    /// Mints the field a disassembly action assigns to.
    ///
    /// Normally that is a named global, so the p-code body can read it back by
    /// name through the symbol table. When the name is already taken by
    /// something that is not a field, the global is minted unnamed and recorded
    /// in the constructor's own scope instead.
    fn mint_action_target(&mut self, name: &str, span: Span) -> BuildResult<FieldId> {
        let taken =
            self.ctx.symbols.contains_key(name) || self.action_scope_table.as_deref() == Some(name);
        if taken {
            let id = self.ctx.register_scoped_global(name);
            self.action_locals.insert(name.into(), id);
            return Ok(id);
        }

        match self.ctx.register_global(name) {
            Ok(field) => Ok(field.id),
            Err(mut d) => {
                d.primary = span;
                Err(d)
            }
        }
    }

    fn err(&self, message: impl Into<String>, span: Span) -> Diagnostic {
        Diagnostic::error(DiagnosticCode::Compile, message, span)
    }

    // ── File / item dispatch ──────────────────────────────────────────────────

    fn resolve_file(&mut self, file: &SleighFile) {
        for item in &file.items {
            self.resolve_item(item);
        }
    }

    fn resolve_item(&mut self, item: &SleighItem) {
        match item {
            SleighItem::Endianness(def) => {
                self.ctx.endian = if def.big_endian {
                    Endian::Big
                } else {
                    Endian::Little
                };
            }
            SleighItem::Alignment(def) => {
                self.ctx.alignment = def.alignment;
            }
            SleighItem::Space(def) => self.resolve_space(def),
            SleighItem::Register(def) => self.resolve_register(def),
            SleighItem::BitRange(def) => self.resolve_bitrange(def),
            SleighItem::PcodeOp(def) => {
                if let Err(mut d) = self.ctx.register_pcodeop(&def.name) {
                    d.primary = def.span;
                    self.errors.push(*d);
                }
            }
            SleighItem::Token(def) => self.resolve_token(def),
            SleighItem::Context(def) => self.resolve_context(def),
            SleighItem::Macro(def) => self.resolve_macro(def),
            SleighItem::AttachVar(def) => self.resolve_attach_var(def),
            SleighItem::AttachVal(def) => self.resolve_attach_val(def),
            SleighItem::AttachStr(def) => self.resolve_attach_str(def),
            SleighItem::WithBlock(def) => self.resolve_with_block(def),
            SleighItem::Constructor(def) => self.resolve_constructor(def),
        }
    }

    // ── Declaration handlers ──────────────────────────────────────────────────

    fn resolve_space(&mut self, def: &SpaceDef) {
        let mut space = match self.ctx.register_space(&def.name) {
            Ok(s) => s,
            Err(mut d) => {
                d.primary = def.span;
                self.errors.push(*d);
                return;
            }
        };
        space.ty = def.ty.clone();
        space.addr_size = def.addr_size;
        space.word_size = def.word_size;
        let space_id = space.id;
        if def.is_default {
            if self.ctx.default_space.is_some() {
                self.errors
                    .push(self.err("Attempting to redefine a default space", def.span));
                return;
            }
            self.ctx.default_space = Some(space_id);
        }
    }

    fn resolve_register(&mut self, def: &RegisterDef) {
        let space_id = match self.ctx.try_get_space(&def.space) {
            Some(s) => s.id,
            None => {
                self.errors
                    .push(self.err(format!("Undefined space `{}`", def.space), def.span));
                return;
            }
        };
        let mut offset = def.offset;
        for name_opt in &def.names {
            match name_opt {
                None => {
                    offset += def.size;
                }
                Some(name) => {
                    if let Err(mut d) = self.ctx.register_reg(name, space_id, offset, def.size) {
                        d.primary = def.span;
                        self.errors.push(*d);
                        return;
                    }
                    offset += def.size;
                }
            }
        }
    }

    fn resolve_bitrange(&mut self, def: &BitRangeDef) {
        for item in &def.items {
            let register_id = match self.ctx.try_get_register(&item.register) {
                Some(r) => r.id,
                None => {
                    self.errors.push(
                        self.err(format!("Undefined register `{}`", item.register), def.span),
                    );
                    return;
                }
            };
            if let Err(mut d) =
                self.ctx
                    .register_bitrange(&item.name, register_id, item.low, item.high)
            {
                d.primary = def.span;
                self.errors.push(*d);
                return;
            }
        }
    }

    fn resolve_token(&mut self, def: &TokenDef) {
        if def.size % 8 != 0 {
            self.errors.push(self.err(
                "Token size must be a multiple of 8 (it must fit in bytes)",
                def.span,
            ));
            return;
        }
        let endian = def
            .endian
            .map(|big| if big { Endian::Big } else { Endian::Little })
            .unwrap_or(self.ctx.endian);
        let token_id = match self.ctx.register_token(&def.name, def.size) {
            Ok(t) => {
                // Apply per-token endianness override.
                // `register_token` inherits ctx.endian; we override if different.
                let id = t.id;
                self.ctx.tokens[id].endian = endian;
                id
            }
            Err(mut d) => {
                d.primary = def.span;
                self.errors.push(*d);
                return;
            }
        };
        for field in &def.fields {
            if let Err(mut d) = self.ctx.register_field(
                &field.name,
                field.low,
                field.high,
                FieldParent::Token(token_id),
                field.signed,
            ) {
                d.primary = field.span;
                self.errors.push(*d);
                return;
            }
        }
    }

    fn resolve_context(&mut self, def: &ContextDef) {
        let reg_id = match self.ctx.try_get_register(&def.register) {
            Some(r) => r.id,
            None => {
                self.errors
                    .push(self.err(format!("Undefined register `{}`", def.register), def.span));
                return;
            }
        };

        if let Some(existing) = self.ctx.context_reg {
            if existing != reg_id {
                self.errors
                    .push(self.err("Attempting to redefine a context variable", def.span));
                return;
            }
        } else {
            self.ctx.context_reg = Some(reg_id);
        }

        for field in &def.fields {
            match self.ctx.register_field(
                &field.name,
                field.low,
                field.high,
                FieldParent::Context,
                field.signed,
            ) {
                Ok(registered) => registered.inner.noflow = field.noflow,
                Err(mut d) => {
                    d.primary = field.span;
                    self.errors.push(*d);
                    return;
                }
            }
        }
    }

    fn resolve_attach_var(&mut self, def: &AttachVarDef) {
        let registers: Result<Vec<_>, String> = def
            .registers
            .iter()
            .map(|opt| match opt {
                None => Ok(None),
                Some(name) => match self.ctx.try_get_register(name) {
                    Some(r) => Ok(Some(r.id)),
                    None => Err(format!("Undefined register `{name}`")),
                },
            })
            .collect();

        let registers = match registers {
            Ok(r) => r,
            Err(e) => {
                self.errors.push(self.err(e, def.span));
                return;
            }
        };

        let table_len = registers.len();
        let table_id = self.ctx.field_tables.add_register_table(registers);
        self.attach_fields(
            &def.fields,
            FieldType::Registers(table_id),
            table_len,
            def.span,
        );
    }

    fn resolve_attach_str(&mut self, def: &AttachStrDef) {
        let names = def.names.clone();
        let table_len = names.len();
        let table_id = self.ctx.field_tables.add_name_table(names);
        self.attach_fields(
            &def.fields,
            FieldType::String(table_id),
            table_len,
            def.span,
        );
    }

    fn resolve_attach_val(&mut self, def: &AttachValDef) {
        let table_len = def.values.len();
        let table_id = self.ctx.field_tables.add_value_table(def.values.clone());
        self.attach_fields(
            &def.fields,
            FieldType::Values(table_id),
            table_len,
            def.span,
        );
    }

    fn attach_fields(
        &mut self,
        field_names: &[Box<str>],
        ty: FieldType,
        table_size: usize,
        span: Span,
    ) {
        for name in field_names {
            let field = match self.ctx.try_get_mut_field(name) {
                Some(f) => f,
                None => {
                    self.errors
                        .push(self.err(format!("Undefined field `{name}`"), span));
                    return;
                }
            };
            // A field too wide to size cannot match any table, and saying so
            // beats reporting a bogus size.
            let field_width = field.width();
            let Some(field_size) = field.size() else {
                self.errors.push(self.err(
                    format!(
                        "Attempting to attach a table of size {table_size} to a field \
                         {field_width} bits wide"
                    ),
                    span,
                ));
                return;
            };
            if field_size != table_size as u64 {
                self.errors.push(self.err(
                    format!(
                        "Attempting to attach a table of size {table_size} to a field of size \
                         {field_size}"
                    ),
                    span,
                ));
                return;
            }
            field.attach(ty);
        }
    }

    fn resolve_macro(&mut self, def: &MacroDef) {
        let pmacro = match self.resolve_pcode(&def.pcode, def.span) {
            Ok(p) => p,
            Err(d) => {
                self.errors.push(*d);
                return;
            }
        };
        if let Err(mut d) = self.ctx.register_macro(&def.name, pmacro) {
            d.primary = def.span;
            self.errors.push(*d);
        }
    }

    fn resolve_constructor(&mut self, def: &ConstructorDef) {
        // Action locals are scoped to this constructor, and `resolve_pcode`
        // and the display below read them back by name.
        self.action_locals.clear();

        let table_name: Box<str> = def
            .table
            .clone()
            .or_else(|| self.get_table_name())
            .unwrap_or_else(|| "instruction".into());
        self.action_scope_table = Some(table_name.clone());

        let actions = self.resolve_actions(&def.actions, def.span);
        let actions = self.fold_with_actions(actions);
        let constraint = self.fold_with_constraints(def.constraint.clone());
        let display = resolve_display(&self.ctx, &self.action_locals, &def.display);

        let pmacro = match self.resolve_pcode(&def.pcode, def.span) {
            Ok(p) => p,
            Err(d) => {
                self.errors.push(*d);
                return;
            }
        };

        if let Err(mut d) =
            self.ctx
                .add_constructor(&table_name, constraint, display, actions, def.span, pmacro)
        {
            d.primary = def.span;
            self.errors.push(*d);
        }
    }

    fn resolve_with_block(&mut self, def: &WithBlockDef) {
        let actions = self.resolve_actions(&def.actions, def.span);
        self.with_frames.push(WithFrame {
            default_name: def.table.clone(),
            constraint: def.constraint.clone(),
            actions,
        });
        for item in &def.items {
            self.resolve_item(item);
        }
        self.with_frames.pop();
    }

    // ── With-frame helpers ────────────────────────────────────────────────────

    fn fold_with_constraints(
        &self,
        constraint: crate::constraint::ConstraintAst,
    ) -> crate::constraint::ConstraintAst {
        self.with_frames.iter().fold(constraint, |acc, frame| {
            let span = acc.span;
            frame.constraint.clone().and(acc, span)
        })
    }

    fn fold_with_actions(&self, actions: Vec<Action>) -> Vec<Action> {
        self.with_frames
            .iter()
            .flat_map(|f| &f.actions)
            .cloned()
            .chain(actions)
            .collect()
    }

    fn get_table_name(&self) -> Option<Box<str>> {
        self.with_frames.last().and_then(|f| f.default_name.clone())
    }

    // ── Action resolution ─────────────────────────────────────────────────────

    fn resolve_actions(&mut self, actions: &[UnresolvedAction], span: Span) -> Vec<Action> {
        let mut out = Vec::with_capacity(actions.len());
        for action in actions {
            match self.resolve_action(action, span) {
                Ok(a) => out.push(a),
                Err(d) => self.errors.push(*d),
            }
        }
        out
    }

    fn resolve_action(&mut self, action: &UnresolvedAction, span: Span) -> BuildResult<Action> {
        match action {
            UnresolvedAction::Assign { field, expr } => {
                let field_id = match self.action_name(field) {
                    Some(id) => id,
                    None => self.mint_action_target(field, span)?,
                };
                let expr = self.resolve_action_expr(expr, span)?;
                Ok(Action::Assign { field_id, expr })
            }

            UnresolvedAction::GlobalSet { addr, field } => {
                // Only a context variable can be committed: `globalset` writes
                // the context register, and a token or global field has no
                // representation there.
                let field_id = match self.ctx.try_get_field(field) {
                    Some(f) if f.parent == FieldParent::Context => f.id,
                    Some(_) => {
                        return Err(Box::new(self.err(
                            format!("`globalset` target `{field}` is not a context field"),
                            span,
                        )));
                    }
                    None => {
                        return Err(Box::new(self.err(
                            format!("Undefined context field `{field}` in `globalset`"),
                            span,
                        )));
                    }
                };
                let addr = self.resolve_globalset_addr(addr, span)?;
                Ok(Action::GlobalSet { addr, field_id })
            }
        }
    }

    /// Resolves the first argument of a `globalset`.
    ///
    /// It is normally an expression over fields (`inst_next` in the vast
    /// majority of the corpus), but SLEIGH also allows the bare name of a
    /// sub-table operand, whose exported address is the target. Sub-tables are
    /// routinely forward-referenced, so an otherwise unknown identifier is
    /// registered as a table exactly the way a constructor header would.
    fn resolve_globalset_addr(
        &mut self,
        addr: &UnresolvedExpr,
        span: Span,
    ) -> BuildResult<GlobalSetAddr> {
        let UnresolvedExpr::Ident(name) = addr else {
            return Ok(GlobalSetAddr::Expr(self.resolve_action_expr(addr, span)?));
        };

        if let Some(field_id) = self.action_name(name) {
            return Ok(GlobalSetAddr::Expr(ActionExpr::Atom(Atom::Ident(field_id))));
        }

        match self.ctx.symbols.get(name.as_ref()) {
            Some(&SymbolId::Table(id)) => Ok(GlobalSetAddr::Table(id)),
            Some(_) => Err(Box::new(self.err(
                format!("`globalset` address `{name}` is neither a field nor a table"),
                span,
            ))),
            None => match self.ctx.register_table(name) {
                Ok(table) => Ok(GlobalSetAddr::Table(table.id)),
                Err(mut d) => {
                    d.primary = span;
                    Err(d)
                }
            },
        }
    }

    fn resolve_action_expr(
        &mut self,
        expr: &UnresolvedExpr,
        span: Span,
    ) -> BuildResult<ActionExpr> {
        match expr {
            UnresolvedExpr::Binary { op, lhs, rhs } => Ok(ActionExpr::Binary {
                op: *op,
                lhs: Box::new(self.resolve_action_expr(lhs, span)?),
                rhs: Box::new(self.resolve_action_expr(rhs, span)?),
            }),
            UnresolvedExpr::Unary { op, expr } => Ok(ActionExpr::Unary {
                op: *op,
                expr: Box::new(self.resolve_action_expr(expr, span)?),
            }),
            UnresolvedExpr::Ident(name) => {
                if let Some(field_id) = self.action_name(name) {
                    return Ok(ActionExpr::Atom(Atom::Ident(field_id)));
                }

                // A register has no value at disassembly time. Ghidra models
                // one in a pattern expression as a `PatternlessSymbol`, whose
                // pattern expression is the constant zero, and specs rely on
                // it: avr32a computes `disp = ACBA + (disp4_8 << 2)` from the
                // control register `ACBA`, meaning "relative to whatever ACBA
                // holds". Matching that is the only way to compile the spec,
                // and matching it *silently* is the part worth knowing about —
                // see the handoff.
                if self.ctx.try_get_register(name).is_some() {
                    self.warnings.push(Diagnostic::warning(
                        DiagnosticCode::Compile,
                        format!(
                            "register `{name}` in a disassembly action reads as 0; \
                             it has no value until the instruction runs"
                        ),
                        span,
                    ));
                    return Ok(ActionExpr::Atom(Atom::Int(0)));
                }

                Err(Box::new(
                    self.err(format!("Undefined field `{name}`"), span),
                ))
            }
            UnresolvedExpr::Int(v) => Ok(ActionExpr::Atom(Atom::Int(*v))),
        }
    }

    // ── P-code resolution ─────────────────────────────────────────────────────

    fn resolve_pcode(&mut self, pmacro: &PCodeMacro, span: Span) -> BuildResult<PCodeMacro> {
        // Reset the per-block interner, starting IDs beyond what Phase 2 assigned.
        // Any Ident::Global that turns out not to be a spec symbol is an implicit
        // local; we intern it here so all references to the same name get the same ID.
        self.local_interner.clear();
        self.local_next_id = pmacro.local_var_count;

        let body = pmacro
            .body
            .iter()
            .map(|stmt| self.resolve_pcode_stmt(stmt, span))
            .collect::<Result<Vec<_>, _>>()?;

        let export = pmacro
            .export
            .as_ref()
            .map(|e| self.resolve_pcode_expr(e, span))
            .transpose()?;

        let mut resolved = PCodeMacro {
            args: pmacro.args.clone(),
            local_var_count: self.local_next_id,
            body,
            export,
            non_build_table_refs: Vec::new(),
            local_widths: std::collections::HashMap::new(),
            unsized_locals: Vec::new(),
            runtime: std::sync::OnceLock::new(),
        };
        resolved.refresh_runtime_metadata(&self.ctx.symbols, &[]);
        Ok(resolved)
    }

    fn resolve_pcode_stmt(&mut self, stmt: &Ast<BSpan>, span: Span) -> BuildResult<Ast<BSpan>> {
        let ty = match &stmt.ty {
            AstNode::DeferredBuild(name) => {
                let table_id = match self.ctx.symbols.get(name.as_ref()).copied() {
                    Some(SymbolId::Table(id)) => id,
                    _ => match self.ctx.register_table(name) {
                        Ok(t) => t.id,
                        Err(mut d) => {
                            d.primary = span;
                            return Err(d);
                        }
                    },
                };
                AstNode::Build(table_id)
            }
            // `delayslot(nwords)`: the argument names a field whose decoded
            // value is the byte count. Phase 2 parsed against an empty spec, so
            // this is the first point that can tell a field from a typo.
            AstNode::DelaySlot(DelaySlotArg::Deferred(name)) => {
                match self.ctx.try_get_field(name) {
                    Some(field) => AstNode::DelaySlot(DelaySlotArg::Field(field.id)),
                    None => {
                        return Err(Box::new(self.err(
                            format!(
                                "`delayslot({name})` argument is neither a constant nor a field"
                            ),
                            span,
                        )));
                    }
                }
            }
            AstNode::Assignment { lhs, size, rhs } => AstNode::Assignment {
                lhs: self.resolve_pcode_ident(lhs.clone(), span)?,
                size: *size,
                rhs: self.resolve_pcode_expr(rhs, span)?,
            },
            AstNode::LoadAssignment { lhs, size, rhs } => AstNode::LoadAssignment {
                lhs: self.resolve_pcode_load(lhs, span)?,
                size: *size,
                rhs: self.resolve_pcode_expr(rhs, span)?,
            },
            AstNode::RangeAssignment { lhs, size, rhs } => AstNode::RangeAssignment {
                lhs: Range {
                    value: Box::new(self.resolve_pcode_expr(&lhs.value, span)?),
                    start: lhs.start,
                    size: lhs.size,
                },
                size: *size,
                rhs: self.resolve_pcode_expr(rhs, span)?,
            },
            AstNode::Branch { target } => AstNode::Branch {
                target: self.resolve_pcode_target(target.clone(), span)?,
            },
            AstNode::ConditionalBranch { condition, target } => AstNode::ConditionalBranch {
                condition: self.resolve_pcode_expr(condition, span)?,
                target: self.resolve_pcode_target(target.clone(), span)?,
            },
            AstNode::BranchIndirect { target } => AstNode::BranchIndirect {
                target: self.resolve_pcode_expr(target, span)?,
            },
            AstNode::Call { target } => AstNode::Call {
                target: self.resolve_pcode_target(target.clone(), span)?,
            },
            AstNode::CallIndirect { target } => AstNode::CallIndirect {
                target: self.resolve_pcode_expr(target, span)?,
            },
            AstNode::Return { target } => AstNode::Return {
                target: self.resolve_pcode_expr(target, span)?,
            },
            AstNode::Export(expr) => AstNode::Export(self.resolve_pcode_expr(expr, span)?),
            AstNode::Expression(expr) => AstNode::Expression(self.resolve_pcode_expr(expr, span)?),
            // No deferred refs possible in these variants.
            other => other.clone(),
        };
        Ok(Ast {
            ty,
            span: stmt.span,
        })
    }

    fn resolve_pcode_expr(
        &mut self,
        expr: &Expression<BSpan>,
        span: Span,
    ) -> BuildResult<Expression<BSpan>> {
        let ty = match &expr.ty {
            ExpressionTy::Ident(ident) => {
                ExpressionTy::Ident(self.resolve_pcode_ident(ident.clone(), span)?)
            }
            ExpressionTy::Load(load) => ExpressionTy::Load(self.resolve_pcode_load(load, span)?),
            ExpressionTy::DeferredCall { name, args } => {
                let resolved_args = args
                    .iter()
                    .map(|a| self.resolve_pcode_expr(a, span))
                    .collect::<Result<Vec<_>, _>>()?;
                match self.ctx.symbols.get(name.as_ref()).copied() {
                    Some(SymbolId::PCodeOp(id)) => ExpressionTy::PcodeOp {
                        id,
                        args: resolved_args,
                    },
                    Some(SymbolId::Macro(id)) => ExpressionTy::MacroCall {
                        id,
                        args: resolved_args,
                    },
                    Some(SymbolId::Special) => ExpressionTy::FunctionCall {
                        builtin: Builtin::from_name(name)
                            .expect("Special symbol must be a builtin"),
                        args: resolved_args,
                    },
                    _ => {
                        return Err(Box::new(
                            self.err(format!("Unknown function or macro `{name}`"), span),
                        ));
                    }
                }
            }
            ExpressionTy::SubPieceMsb { src, count } => ExpressionTy::SubPieceMsb {
                src: Box::new(self.resolve_pcode_expr(src, span)?),
                count: *count,
            },
            ExpressionTy::SubPieceLsb { src, count } => ExpressionTy::SubPieceLsb {
                src: Box::new(self.resolve_pcode_expr(src, span)?),
                count: *count,
            },
            ExpressionTy::FunctionCall { builtin, args } => ExpressionTy::FunctionCall {
                builtin: *builtin,
                args: args
                    .iter()
                    .map(|a| self.resolve_pcode_expr(a, span))
                    .collect::<Result<Vec<_>, _>>()?,
            },
            ExpressionTy::PcodeOp { id, args } => ExpressionTy::PcodeOp {
                id: *id,
                args: args
                    .iter()
                    .map(|a| self.resolve_pcode_expr(a, span))
                    .collect::<Result<Vec<_>, _>>()?,
            },
            ExpressionTy::MacroCall { id, args } => ExpressionTy::MacroCall {
                id: *id,
                args: args
                    .iter()
                    .map(|a| self.resolve_pcode_expr(a, span))
                    .collect::<Result<Vec<_>, _>>()?,
            },
            ExpressionTy::Range(range) => ExpressionTy::Range(Range {
                value: Box::new(self.resolve_pcode_expr(&range.value, span)?),
                start: range.start,
                size: range.size,
            }),
            ExpressionTy::Unop(unop) => ExpressionTy::Unop(Unop {
                op: unop.op,
                e: Box::new(self.resolve_pcode_expr(&unop.e, span)?),
            }),
            ExpressionTy::Binop(binop) => ExpressionTy::Binop(Binop {
                op: binop.op,
                lhs: Box::new(self.resolve_pcode_expr(&binop.lhs, span)?),
                rhs: Box::new(self.resolve_pcode_expr(&binop.rhs, span)?),
            }),
            // SizedInt has no deferred references.
            other => other.clone(),
        };
        Ok(Expression {
            ty,
            size: expr.size,
            span: expr.span,
        })
    }

    fn resolve_pcode_ident(&mut self, ident: Ident, _span: Span) -> BuildResult<Ident> {
        let Ident::Global(name) = ident else {
            return Ok(ident);
        };
        // A disassembly-action local shadows the symbol table for the rest of
        // this constructor — Loongarch's `csr` body means the action's `csr`,
        // not the `csr` table it belongs to.
        if let Some(&id) = self.action_locals.get(name.as_ref()) {
            return Ok(Ident::Field(id));
        }

        Ok(match self.ctx.symbols.get(name.as_ref()).copied() {
            Some(SymbolId::Register(id)) => Ident::Register(id),
            Some(SymbolId::BitRangeField(id)) => Ident::BitRange(id),
            Some(SymbolId::Field(id)) => Ident::Field(id),
            Some(SymbolId::Table(id)) => Ident::Table(id),
            _ => {
                // Not a spec symbol — must be an implicit local temporary (e.g.
                // `tmp = *:4 reg2;`).  Phase 2 with an empty spec couldn't
                // distinguish locals from unresolved globals, so both became
                // Ident::Global.  Intern the name now so every reference in this
                // block gets a consistent LocalVarId.
                let id = if let Some(&id) = self.local_interner.get(name.as_ref()) {
                    id
                } else {
                    let id = LocalVarId(self.local_next_id);
                    self.local_next_id += 1;
                    self.local_interner.insert(name, id);
                    id
                };
                Ident::Named(id)
            }
        })
    }

    fn resolve_pcode_load(&mut self, load: &Load<BSpan>, span: Span) -> BuildResult<Load<BSpan>> {
        let space = load
            .space
            .as_ref()
            .map(|s| match s {
                SpaceRef::Resolved(id) => Ok(SpaceRef::Resolved(*id)),
                SpaceRef::Deferred(name) => self
                    .ctx
                    .try_get_space(name)
                    .map(|s| SpaceRef::Resolved(s.id))
                    .ok_or_else(|| Box::new(self.err(format!("Undefined space `{name}`"), span))),
            })
            .transpose()?;
        Ok(Load {
            space,
            size: load.size,
            ptr: Box::new(self.resolve_pcode_expr(&load.ptr, span)?),
        })
    }

    fn resolve_pcode_target(
        &mut self,
        target: LabelOrNode<BSpan>,
        span: Span,
    ) -> BuildResult<LabelOrNode<BSpan>> {
        match target {
            LabelOrNode::Label(_) | LabelOrNode::Node(_) => Ok(target),
            LabelOrNode::Expr(expr) => {
                let mut expr = self.resolve_pcode_expr(&expr, span)?;
                // A literal destination (`goto 0x0;`) is an address in the
                // default space, so it is that space's address width — the same
                // width `inst_next` resolves to. Lowering could not know it.
                if let ExpressionTy::SizedInt { size: None, .. } = &expr.ty
                    && let Some(default_space) = self.ctx.default_space
                {
                    let width = self.ctx.spaces[default_space].addr_size;
                    expr.size = Some(width);
                    if let ExpressionTy::SizedInt { size, .. } = &mut expr.ty {
                        *size = Some(width);
                    }
                }
                Ok(LabelOrNode::Expr(expr))
            }
        }
    }
}

// ── Display text parsing ──────────────────────────────────────────────────────

fn resolve_display(
    ctx: &SpecBuilder,
    action_locals: &HashMap<Box<str>, FieldId>,
    tokens: &[UnresolvedDisplayToken],
) -> Vec<DisplayElement> {
    use crate::builder::Symbol;
    tokens
        .iter()
        .map(|tok| match tok {
            // A constructor-scoped action local shadows the symbol table here
            // too, so `csr: csr is ...` displays the value the action computed.
            UnresolvedDisplayToken::Ident(name) if action_locals.contains_key(name.as_ref()) => {
                DisplayElement::Field(action_locals[name.as_ref()])
            }
            UnresolvedDisplayToken::Ident(name) => match ctx.get_symbol(name) {
                Symbol::Field(field) => DisplayElement::Field(field.id),
                Symbol::Table(table) => DisplayElement::Table(table.id),
                _ => DisplayElement::String(name.to_string()),
            },
            UnresolvedDisplayToken::Literal(text) => DisplayElement::String(text.to_string()),
        })
        .collect()
}
