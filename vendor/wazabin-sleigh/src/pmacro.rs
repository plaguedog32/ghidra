use crate::pcode_error::{PcodeError as Error, PcodeErrorTy as ErrorTy, PcodeResult as Result};
use crate::{
    builder::SymbolId,
    objects::{field::FieldId, table::TableId},
    pmacro::{
        expression::{Binop, Expression, ExpressionTy, Ident, Load, LocalVarId, Range, Unop},
        statement::{Ast, AstNode, DelaySlotArg, LabelOrNode},
    },
    semantics::EmitError,
};
use jstd::registry::Registry;
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    sync::OnceLock,
};

pub(crate) mod expression;
pub(crate) mod statement;
pub(crate) mod validate;

pub(crate) use pcode_types::{PMacroId, SymbolicWidth};

/// A compiled p-code macro definition, with per-statement byte spans for diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct PCodeMacro {
    pub(crate) args: Vec<LocalVarId>,
    pub(crate) local_var_count: u32,
    pub(crate) body: Vec<Ast<(usize, usize)>>,
    pub(crate) export: Option<Expression<(usize, usize)>>,
    pub(crate) non_build_table_refs: Vec<TableId>,
    /// Widths of this body's local variables, resolved when the specification
    /// was compiled. A `SameAs` width names an operand whose value only a
    /// decode supplies; the expander resolves those as it substitutes them.
    ///
    /// Resolving widths here rather than per decoded instruction is what lets
    /// an unsizable local be reported against its own source, and lets the
    /// per-instruction planner skip its fixed point entirely.
    pub(crate) local_widths: HashMap<LocalVarId, SymbolicWidth>,

    /// Locals this body uses that no width could be resolved for. Nothing a
    /// decode substitutes can give them one, so they are a defect in the
    /// specification; the expander falls back to per-instruction inference for
    /// any instruction that splices such a body.
    pub(crate) unsized_locals: Vec<LocalVarId>,
    /// The span-free copy the runtime p-code traversal walks. Kept out of the
    /// serialized specification: it is built lazily once per semantic body,
    /// then shared by every decoded instance of that constructor.
    #[serde(skip)]
    pub(crate) runtime: OnceLock<RuntimeBody>,
}

/// A semantic body as the runtime consumes it, checked once for the nodes it
/// cannot resolve so that no decode has to look for them.
///
/// The check is cached rather than repeated per decode because the streamed
/// lowering never looks at most of a body: its planning pass skips the
/// operands of data-flow statements, and its views reduce an unresolvable
/// node to a nameless marker for the emitter to reject. Reporting such a node
/// the way the eager expander did — by name, at the statement it sits in —
/// therefore has to happen once, over the template itself. See
/// [`validate`] for which nodes these are and why compilation never leaves
/// them behind.
#[derive(Debug, Clone)]
pub(crate) struct RuntimeBody {
    pub(crate) statements: Vec<Ast>,
    pub(crate) export: Option<Expression>,
    /// The first statement the runtime cannot expand, and why. The traversal
    /// reports it when it reaches that statement.
    pub(crate) invalid: Option<(usize, EmitError)>,
    /// Likewise for the export expression.
    pub(crate) invalid_export: Option<EmitError>,
}

/// One p-code body as the runtime traversal consumes it: its span-free
/// statements together with everything the specification resolved about them.
pub(crate) struct BodyTemplate<'a> {
    pub(crate) body: &'a [Ast],
    pub(crate) export: Option<&'a Expression>,
    pub(crate) invalid: Option<&'a (usize, EmitError)>,
    pub(crate) invalid_export: Option<&'a EmitError>,
    pub(crate) non_build_table_refs: &'a [TableId],
    pub(crate) local_widths: &'a HashMap<LocalVarId, SymbolicWidth>,
    pub(crate) unsized_locals: &'a [LocalVarId],
}

impl PCodeMacro {
    /// This body as the traversal consumes it.
    pub(crate) fn template(&self) -> BodyTemplate<'_> {
        let runtime = self.runtime();
        BodyTemplate {
            body: &runtime.statements,
            export: runtime.export.as_ref(),
            invalid: runtime.invalid.as_ref(),
            invalid_export: runtime.invalid_export.as_ref(),
            non_build_table_refs: &self.non_build_table_refs,
            local_widths: &self.local_widths,
            unsized_locals: &self.unsized_locals,
        }
    }

    pub(crate) fn empty() -> Self {
        Self {
            args: Vec::new(),
            local_var_count: 0,
            body: Vec::new(),
            export: None,
            non_build_table_refs: Vec::new(),
            local_widths: HashMap::new(),
            unsized_locals: Vec::new(),
            runtime: OnceLock::new(),
        }
    }

    /// Recompute the set of subtable operands that must be auto-built (emitted)
    /// even though the semantic body never `build`s or references them.
    ///
    /// `pattern_tables` lists the constructor's table operands in operand order.
    /// SLEIGH auto-builds *every* operand of a constructor; an operand that
    /// appears only in the `is` pattern (not the display, not the body, not an
    /// explicit `build`) still has its semantics emitted. Pure p-code macros
    /// have no pattern operands, so callers pass an empty slice there.
    pub(crate) fn refresh_runtime_metadata(
        &mut self,
        symbols: &HashMap<Box<str>, SymbolId>,
        pattern_tables: &[TableId],
    ) {
        self.non_build_table_refs =
            collect_non_build_table_refs(symbols, &self.body, self.export.as_ref(), pattern_tables);
    }

    pub(crate) fn expand_macros(&mut self, macros: &Registry<PMacroId, PCodeMacro>) -> Result<()> {
        let mut expander = MacroExpander {
            macros,
            stack: Vec::new(),
            next_id: self.local_var_count,
            expansions: 0,
        };

        let env = HashMap::new();

        self.body = expander.expand_body(&self.body, &env, 0, None)?;
        self.runtime = OnceLock::new();

        if let Some(export) = self.export.clone() {
            let (prefix, export) = expander.expand_expr(export, &env, 0)?;
            self.body.extend(prefix);
            self.export = Some(export);
        }

        self.local_var_count = expander.next_id;
        Ok(())
    }

    /// The `delayslot` directive in this body, if it has one.
    ///
    /// `finalize_pcode` rejects a body with two, so the first is the only one.
    pub(crate) fn delay_slot(&self) -> Option<&DelaySlotArg> {
        self.body.iter().find_map(|stmt| match &stmt.ty {
            AstNode::DelaySlot(arg) => Some(arg),
            _ => None,
        })
    }

    /// Does this body read `field` anywhere?
    ///
    /// Used to decide whether a decode has to look ahead: `inst_next2` is the
    /// address past the *next* instruction, which costs an extra decode to
    /// learn, and almost no constructor asks for it.
    ///
    /// `name` is the field's spelling, because a branch target keeps its name
    /// until emission (`LabelOrNode::Node`) — `goto inst_next2;` is a reference
    /// even though no `Ident::Field` was ever minted for it.
    pub(crate) fn references_field(&self, field: FieldId, name: &str) -> bool {
        self.body
            .iter()
            .any(|stmt| astnode_references_field(&stmt.ty, field, name))
            || self
                .export
                .as_ref()
                .is_some_and(|expr| expr_references_field(expr, field))
    }

    /// Strip all spans from body/export for use by the runtime.
    pub(crate) fn body_stripped(&self) -> impl Iterator<Item = Ast> + '_ {
        self.body.iter().map(|a| a.clone().strip_span())
    }

    pub(crate) fn export_stripped(&self) -> Option<Expression> {
        self.export.as_ref().map(|e| e.clone().strip_span())
    }

    /// The shared, span-free body the runtime traversal walks.
    fn runtime(&self) -> &RuntimeBody {
        self.runtime.get_or_init(|| {
            let statements: Vec<Ast> = self.body_stripped().collect();
            let export = self.export_stripped();
            let (invalid, invalid_export) = validate::body(&statements, export.as_ref());
            RuntimeBody {
                statements,
                export,
                invalid,
                invalid_export,
            }
        })
    }
}

fn collect_non_build_table_refs(
    symbols: &HashMap<Box<str>, SymbolId>,
    body: &[Ast<(usize, usize)>],
    export: Option<&Expression<(usize, usize)>>,
    pattern_tables: &[TableId],
) -> Vec<TableId> {
    let built: HashSet<TableId> = body
        .iter()
        .filter_map(|s| {
            if let AstNode::Build(table_id) = &s.ty {
                Some(*table_id)
            } else {
                None
            }
        })
        .collect();

    let mut refs = Vec::new();
    let mut seen = HashSet::new();

    for stmt in body {
        if !matches!(stmt.ty, AstNode::Build(_)) {
            collect_in_astnode(symbols, &stmt.ty, &mut refs, &mut seen);
        }
    }
    if let Some(expr) = export {
        collect_in_expr(expr, &mut refs, &mut seen);
    }

    // Table operands that appear only in the `is` pattern — never referenced in
    // the body/export and never explicitly built — are still auto-built by
    // SLEIGH, so their semantics must be emitted. Append them in operand order,
    // after the body-referenced ones, skipping any already collected.
    for &table_id in pattern_tables {
        if seen.insert(table_id) {
            refs.push(table_id);
        }
    }

    refs.retain(|id| !built.contains(id));
    refs
}

fn collect_in_astnode(
    symbols: &HashMap<Box<str>, SymbolId>,
    node: &AstNode<(usize, usize)>,
    refs: &mut Vec<TableId>,
    seen: &mut HashSet<TableId>,
) {
    match node {
        AstNode::Assignment { lhs, rhs, .. } => {
            if let Ident::Table(id) = lhs
                && seen.insert(*id)
            {
                refs.push(*id);
            }
            collect_in_expr(rhs, refs, seen);
        }
        AstNode::LoadAssignment { lhs, rhs, .. } => {
            collect_in_expr(&lhs.ptr, refs, seen);
            collect_in_expr(rhs, refs, seen);
        }
        AstNode::RangeAssignment { lhs, rhs, .. } => {
            collect_in_expr(&lhs.value, refs, seen);
            collect_in_expr(rhs, refs, seen);
        }
        AstNode::Build(_)
        | AstNode::DelaySlot(_)
        | AstNode::Label(_)
        | AstNode::DeferredBuild(_) => {}
        AstNode::Branch { target } | AstNode::Call { target } => {
            collect_in_target(symbols, target, refs, seen);
        }
        AstNode::ConditionalBranch { condition, target } => {
            collect_in_expr(condition, refs, seen);
            collect_in_target(symbols, target, refs, seen);
        }
        AstNode::BranchIndirect { target }
        | AstNode::CallIndirect { target }
        | AstNode::Return { target } => collect_in_expr(target, refs, seen),
        AstNode::Export(expr) | AstNode::Expression(expr) => {
            collect_in_expr(expr, refs, seen);
        }
    }
}

fn collect_in_target(
    symbols: &HashMap<Box<str>, SymbolId>,
    target: &LabelOrNode<(usize, usize)>,
    refs: &mut Vec<TableId>,
    seen: &mut HashSet<TableId>,
) {
    match target {
        LabelOrNode::Label(_) => {}
        LabelOrNode::Node(name) => {
            if let Some(SymbolId::Table(id)) = symbols.get(name.as_ref()).copied()
                && seen.insert(id)
            {
                refs.push(id);
            }
        }
        LabelOrNode::Expr(expr) => collect_in_expr(expr, refs, seen),
    }
}

fn collect_in_expr(
    expr: &Expression<(usize, usize)>,
    refs: &mut Vec<TableId>,
    seen: &mut HashSet<TableId>,
) {
    match &expr.ty {
        ExpressionTy::Ident(Ident::Table(id)) => {
            if seen.insert(*id) {
                refs.push(*id);
            }
        }
        ExpressionTy::Ident(_) | ExpressionTy::SizedInt { .. } => {}
        ExpressionTy::SubPieceMsb { src, .. } | ExpressionTy::SubPieceLsb { src, .. } => {
            collect_in_expr(src, refs, seen);
        }
        ExpressionTy::Load(load) => collect_in_expr(&load.ptr, refs, seen),
        ExpressionTy::Range(range) => collect_in_expr(&range.value, refs, seen),
        ExpressionTy::FunctionCall { args, .. }
        | ExpressionTy::PcodeOp { args, .. }
        | ExpressionTy::MacroCall { args, .. }
        | ExpressionTy::DeferredCall { args, .. } => {
            for arg in args {
                collect_in_expr(arg, refs, seen);
            }
        }
        ExpressionTy::Unop(unop) => collect_in_expr(&unop.e, refs, seen),
        ExpressionTy::Binop(binop) => {
            collect_in_expr(&binop.lhs, refs, seen);
            collect_in_expr(&binop.rhs, refs, seen);
        }
    }
}

struct MacroExpander<'a> {
    macros: &'a Registry<PMacroId, PCodeMacro>,
    stack: Vec<PMacroId>,
    /// Next available LocalVarId for newly inlined macro vars.
    next_id: u32,
    /// Number of macro expansions performed so far, used to give each one a
    /// distinct label scope.
    ///
    /// This cannot reuse `next_id`: a macro with no locals does not advance it,
    /// so two expansions of such a macro would share a scope.
    expansions: u32,
}

/// The label namespace a statement is being expanded into.
///
/// `None` is the constructor's own body, whose labels keep the names the
/// specification gave them. Each macro expansion gets its own numbered scope so
/// that expanding the same macro twice cannot produce two labels with the same
/// name.
type LabelScope = Option<u32>;

/// Qualifies a branch target with its expansion scope, leaving non-label
/// targets (computed addresses, `build` results) alone.
fn scope_target(target: LabelOrNode<BSpan>, scope: LabelScope) -> LabelOrNode<BSpan> {
    match target {
        LabelOrNode::Label(name) => LabelOrNode::Label(scoped_label(&name, scope)),
        other => other,
    }
}

/// Qualifies `name` with its expansion scope.
///
/// `#` cannot appear in a SLEIGH identifier, so a scoped name can never
/// collide with one written in a specification.
fn scoped_label(name: &str, scope: LabelScope) -> Box<str> {
    match scope {
        None => name.into(),
        Some(scope) => format!("{name}#{scope}").into(),
    }
}

type BSpan = (usize, usize);
type ExpandedExprList = (Vec<Ast<BSpan>>, Vec<Expression<BSpan>>);

impl<'a> MacroExpander<'a> {
    fn expand_body(
        &mut self,
        body: &[Ast<BSpan>],
        env: &HashMap<LocalVarId, Expression<BSpan>>,
        remap_base: u32,
        labels: LabelScope,
    ) -> Result<Vec<Ast<BSpan>>> {
        let mut out = Vec::new();
        for stmt in body {
            out.extend(self.expand_stmt(stmt.clone(), env, remap_base, labels)?);
        }
        Ok(out)
    }

    fn expand_stmt(
        &mut self,
        stmt: Ast<BSpan>,
        env: &HashMap<LocalVarId, Expression<BSpan>>,
        remap_base: u32,
        labels: LabelScope,
    ) -> Result<Vec<Ast<BSpan>>> {
        let span = stmt.span;
        let ty = match stmt.ty {
            AstNode::Assignment { lhs, size, rhs } => {
                let (mut prefix, rhs) = self.expand_expr(rhs, env, remap_base)?;
                // A parameter bound to a bit range (`shuffle_4(XmmReg1[0,32], ...)`)
                // or to a memory load is an lvalue in the caller: assigning to
                // it must write that lane or that memory, not a fresh local.
                if let Ident::Named(id) = &lhs {
                    match env.get(id) {
                        Some(Expression {
                            ty: ExpressionTy::Range(range),
                            ..
                        }) => {
                            prefix.push(Ast {
                                ty: AstNode::RangeAssignment {
                                    lhs: range.clone(),
                                    size,
                                    rhs,
                                },
                                span: (0, 0),
                            });
                            return Ok(prefix);
                        }
                        Some(Expression {
                            ty: ExpressionTy::Load(load),
                            ..
                        }) => {
                            prefix.push(Ast {
                                ty: AstNode::LoadAssignment {
                                    lhs: load.clone(),
                                    size,
                                    rhs,
                                },
                                span: (0, 0),
                            });
                            return Ok(prefix);
                        }
                        _ => {}
                    }
                }
                let lhs = self.substitute_lhs(lhs, env, remap_base);
                prefix.push(Ast {
                    ty: AstNode::Assignment { lhs, size, rhs },
                    span: (0, 0),
                });
                return Ok(prefix);
            }

            AstNode::LoadAssignment { lhs, size, rhs } => {
                let (mut prefix, ptr) = self.expand_expr(*lhs.ptr, env, remap_base)?;
                let (rhs_prefix, rhs) = self.expand_expr(rhs, env, remap_base)?;
                prefix.extend(rhs_prefix);
                prefix.push(Ast {
                    ty: AstNode::LoadAssignment {
                        lhs: Load {
                            ptr: Box::new(ptr),
                            ..lhs
                        },
                        size,
                        rhs,
                    },
                    span: (0, 0),
                });
                return Ok(prefix);
            }

            AstNode::RangeAssignment { lhs, size, rhs } => {
                let (mut prefix, value) = self.expand_expr(*lhs.value, env, remap_base)?;
                let (rhs_prefix, rhs) = self.expand_expr(rhs, env, remap_base)?;
                prefix.extend(rhs_prefix);
                prefix.push(Ast {
                    ty: AstNode::RangeAssignment {
                        lhs: Range {
                            value: Box::new(value),
                            ..lhs
                        },
                        size,
                        rhs,
                    },
                    span: (0, 0),
                });
                return Ok(prefix);
            }

            AstNode::ConditionalBranch { condition, target } => {
                let (mut prefix, condition) = self.expand_expr(condition, env, remap_base)?;
                let target = scope_target(target, labels);
                prefix.push(Ast {
                    ty: AstNode::ConditionalBranch { condition, target },
                    span: (0, 0),
                });
                return Ok(prefix);
            }

            AstNode::BranchIndirect { target } => {
                let (mut prefix, target) = self.expand_expr(target, env, remap_base)?;
                prefix.push(Ast {
                    ty: AstNode::BranchIndirect { target },
                    span: (0, 0),
                });
                return Ok(prefix);
            }
            AstNode::CallIndirect { target } => {
                let (mut prefix, target) = self.expand_expr(target, env, remap_base)?;
                prefix.push(Ast {
                    ty: AstNode::CallIndirect { target },
                    span: (0, 0),
                });
                return Ok(prefix);
            }

            AstNode::Return { target } => {
                let (mut prefix, target) = self.expand_expr(target, env, remap_base)?;
                prefix.push(Ast {
                    ty: AstNode::Return { target },
                    span: (0, 0),
                });
                return Ok(prefix);
            }

            AstNode::Expression(expr) => {
                if let ExpressionTy::MacroCall { id, args } = &expr.ty {
                    let expanded = self.expand_call(*id, &args.clone(), env, remap_base)?;
                    return Ok(expanded.body);
                }
                let (mut prefix, expr) = self.expand_expr(expr, env, remap_base)?;
                prefix.push(Ast {
                    ty: AstNode::Expression(expr),
                    span: (0, 0),
                });
                return Ok(prefix);
            }
            // A label, and a branch to one, are namespaced to the expansion
            // they came from. Without this, calling one macro twice in a
            // constructor emits its label twice under the same name, and a
            // consumer resolving branch targets by name binds both branches to
            // the same one — a silent control-flow miscompile.
            AstNode::Label(name) => AstNode::Label(scoped_label(&name, labels)),

            AstNode::Branch { target } => AstNode::Branch {
                target: scope_target(target, labels),
            },

            other => other,
        };
        Ok(vec![Ast { ty, span }])
    }

    fn expand_expr(
        &mut self,
        expr: Expression<BSpan>,
        env: &HashMap<LocalVarId, Expression<BSpan>>,
        remap_base: u32,
    ) -> Result<(Vec<Ast<BSpan>>, Expression<BSpan>)> {
        let size = expr.size;
        let ty = match expr.ty {
            ExpressionTy::Ident(Ident::Named(id)) => {
                if let Some(value) = env.get(&id) {
                    return Ok((Vec::new(), value.clone()));
                }
                return Ok((
                    Vec::new(),
                    Expression {
                        ty: ExpressionTy::Ident(Ident::Named(LocalVarId(id.0 + remap_base))),
                        size,
                        span: (0, 0),
                    },
                ));
            }

            ExpressionTy::SubPieceMsb { src, count } => {
                let (prefix, src) = self.expand_expr(*src, env, remap_base)?;
                return Ok((
                    prefix,
                    Expression {
                        ty: ExpressionTy::SubPieceMsb {
                            src: Box::new(src),
                            count,
                        },
                        size,
                        span: (0, 0),
                    },
                ));
            }

            ExpressionTy::SubPieceLsb { src, count } => {
                let (prefix, src) = self.expand_expr(*src, env, remap_base)?;
                return Ok((
                    prefix,
                    Expression {
                        ty: ExpressionTy::SubPieceLsb {
                            src: Box::new(src),
                            count,
                        },
                        size,
                        span: (0, 0),
                    },
                ));
            }
            ExpressionTy::Load(load) => {
                let (prefix, ptr) = self.expand_expr(*load.ptr, env, remap_base)?;
                return Ok((
                    prefix,
                    Expression {
                        ty: ExpressionTy::Load(Load {
                            ptr: Box::new(ptr),
                            ..load
                        }),
                        size,
                        span: (0, 0),
                    },
                ));
            }
            ExpressionTy::Range(range) => {
                let (prefix, value) = self.expand_expr(*range.value, env, remap_base)?;
                return Ok((
                    prefix,
                    Expression {
                        ty: ExpressionTy::Range(Range {
                            value: Box::new(value),
                            ..range
                        }),
                        size,
                        span: (0, 0),
                    },
                ));
            }
            ExpressionTy::FunctionCall { builtin, args } => {
                let (prefix, args) = self.expand_expr_list(args, env, remap_base)?;
                return Ok((
                    prefix,
                    Expression {
                        ty: ExpressionTy::FunctionCall { builtin, args },
                        size,
                        span: (0, 0),
                    },
                ));
            }
            ExpressionTy::PcodeOp { id, args } => {
                let (prefix, args) = self.expand_expr_list(args, env, remap_base)?;
                return Ok((
                    prefix,
                    Expression {
                        ty: ExpressionTy::PcodeOp { id, args },
                        size,
                        span: (0, 0),
                    },
                ));
            }
            ExpressionTy::MacroCall { id, args } => {
                let expanded = self.expand_call(id, &args, env, remap_base)?;
                let Some(export) = expanded.export else {
                    return Err(Error::spanless(ErrorTy::FunctionStatement));
                };
                return Ok((expanded.body, export));
            }
            ExpressionTy::DeferredCall { name, .. } => {
                return Err(Error::spanless(ErrorTy::UnknownMacro(name)));
            }
            ExpressionTy::Unop(unop) => {
                let (prefix, e) = self.expand_expr(*unop.e, env, remap_base)?;
                return Ok((
                    prefix,
                    Expression {
                        ty: ExpressionTy::Unop(Unop {
                            op: unop.op,
                            e: Box::new(e),
                        }),
                        size,
                        span: (0, 0),
                    },
                ));
            }
            ExpressionTy::Binop(binop) => {
                let (mut prefix, lhs) = self.expand_expr(*binop.lhs, env, remap_base)?;
                let (rhs_prefix, rhs) = self.expand_expr(*binop.rhs, env, remap_base)?;
                prefix.extend(rhs_prefix);
                return Ok((
                    prefix,
                    Expression {
                        ty: ExpressionTy::Binop(Binop {
                            op: binop.op,
                            lhs: Box::new(lhs),
                            rhs: Box::new(rhs),
                        }),
                        size,
                        span: (0, 0),
                    },
                ));
            }
            other => other,
        };
        Ok((
            Vec::new(),
            Expression {
                ty,
                size,
                span: (0, 0),
            },
        ))
    }

    fn expand_expr_list(
        &mut self,
        args: Vec<Expression<BSpan>>,
        env: &HashMap<LocalVarId, Expression<BSpan>>,
        remap_base: u32,
    ) -> Result<ExpandedExprList> {
        let mut prefix = Vec::new();
        let mut expanded_args = Vec::new();
        for arg in args {
            let (arg_prefix, arg) = self.expand_expr(arg, env, remap_base)?;
            prefix.extend(arg_prefix);
            expanded_args.push(arg);
        }
        Ok((prefix, expanded_args))
    }

    fn expand_call(
        &mut self,
        id: PMacroId,
        args: &[Expression<BSpan>],
        env: &HashMap<LocalVarId, Expression<BSpan>>,
        caller_remap: u32,
    ) -> Result<ExpandedMacro> {
        if self.stack.contains(&id) {
            return Err(Error::spanless(ErrorTy::UnknownMacro(
                "recursive macro".into(),
            )));
        }
        let macro_def = &self.macros[id];
        if macro_def.args.len() != args.len() {
            return Err(Error::spanless(ErrorTy::ArgumentCountMismatch {
                expected: macro_def.args.len(),
                actual: args.len(),
            }));
        }

        let macro_remap = self.next_id;
        self.next_id += macro_def.local_var_count;
        let scope = self.expansions;
        self.expansions += 1;

        let mut call_env: HashMap<LocalVarId, Expression<BSpan>> = HashMap::new();
        let mut prefix = Vec::new();
        for (&arg_id, arg) in macro_def.args.iter().zip(args.iter().cloned()) {
            let (arg_prefix, arg) = self.expand_expr(arg, env, caller_remap)?;
            prefix.extend(arg_prefix);
            call_env.insert(arg_id, arg);
        }

        self.stack.push(id);
        let mut body = self.expand_body(&macro_def.body, &call_env, macro_remap, Some(scope))?;
        let export = if let Some(export) = macro_def.export.clone() {
            let (export_prefix, export) = self.expand_expr(export, &call_env, macro_remap)?;
            body.extend(export_prefix);
            Some(export)
        } else {
            None
        };
        self.stack.pop();

        prefix.extend(body);
        Ok(ExpandedMacro {
            body: prefix,
            export,
        })
    }

    fn substitute_lhs(
        &self,
        lhs: Ident,
        env: &HashMap<LocalVarId, Expression<BSpan>>,
        remap_base: u32,
    ) -> Ident {
        match lhs {
            Ident::Named(id) => match env.get(&id) {
                Some(Expression {
                    ty: ExpressionTy::Ident(ident),
                    ..
                }) => ident.clone(),
                _ => Ident::Named(LocalVarId(id.0 + remap_base)),
            },
            other => other,
        }
    }
}

struct ExpandedMacro {
    body: Vec<Ast<BSpan>>,
    export: Option<Expression<BSpan>>,
}

fn astnode_references_field(node: &AstNode<(usize, usize)>, field: FieldId, name: &str) -> bool {
    let expr = |e: &Expression<(usize, usize)>| expr_references_field(e, field);
    let target = |t: &LabelOrNode<(usize, usize)>| match t {
        LabelOrNode::Expr(e) => expr_references_field(e, field),
        LabelOrNode::Node(node) => &**node == name,
        LabelOrNode::Label(_) => false,
    };

    match node {
        AstNode::Assignment { lhs, rhs, .. } => *lhs == Ident::Field(field) || expr(rhs),
        AstNode::LoadAssignment { lhs, rhs, .. } => expr(&lhs.ptr) || expr(rhs),
        AstNode::RangeAssignment { lhs, rhs, .. } => expr(&lhs.value) || expr(rhs),
        AstNode::Build(_)
        | AstNode::DeferredBuild(_)
        | AstNode::DelaySlot(_)
        | AstNode::Label(_) => false,
        AstNode::Branch { target: t } | AstNode::Call { target: t } => target(t),
        AstNode::ConditionalBranch {
            condition,
            target: t,
        } => expr(condition) || target(t),
        AstNode::BranchIndirect { target: t }
        | AstNode::CallIndirect { target: t }
        | AstNode::Return { target: t } => expr(t),
        AstNode::Export(e) | AstNode::Expression(e) => expr(e),
    }
}

fn expr_references_field(expr: &Expression<(usize, usize)>, field: FieldId) -> bool {
    let sub = |e: &Expression<(usize, usize)>| expr_references_field(e, field);
    match &expr.ty {
        ExpressionTy::Ident(ident) => *ident == Ident::Field(field),
        ExpressionTy::SizedInt { .. } => false,
        ExpressionTy::SubPieceMsb { src, .. } | ExpressionTy::SubPieceLsb { src, .. } => sub(src),
        ExpressionTy::Load(load) => sub(&load.ptr),
        ExpressionTy::Range(range) => sub(&range.value),
        ExpressionTy::FunctionCall { args, .. }
        | ExpressionTy::PcodeOp { args, .. }
        | ExpressionTy::MacroCall { args, .. }
        | ExpressionTy::DeferredCall { args, .. } => args.iter().any(sub),
        ExpressionTy::Unop(unop) => sub(&unop.e),
        ExpressionTy::Binop(binop) => sub(&binop.lhs) || sub(&binop.rhs),
    }
}
