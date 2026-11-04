//! Template nodes the runtime cannot resolve.
//!
//! Compilation removes every one of these from a body — a global name is
//! bound or becomes a local, a deferred call becomes a user operation, a
//! builtin or an inlined macro, a deferred `build` becomes a table, a space
//! name is looked up or rejected. A body that still carries one did not come
//! through the compiler: it was deserialized from a blob, or built by hand.
//! The runtime reports it as the old eager expander did, at the statement it
//! sits in and naming what was unresolved.
//!
//! The check lives here, with the template, because it is a property of the
//! template alone: [`PCodeMacro::runtime`](super::PCodeMacro) runs it once
//! per body and caches the verdict, so no decode looks for these nodes and
//! the runtime's views can treat them as unreachable.

use crate::{
    pmacro::{
        expression::{Expression, ExpressionTy, Ident, SpaceRef},
        statement::{Ast, AstNode, LabelOrNode},
    },
    semantics::EmitError,
};

/// Checks a body for nodes the runtime cannot resolve.
///
/// Returns the first offending statement with its error, and the export's
/// error if the export is unresolvable.
pub(super) fn body(
    statements: &[Ast],
    export: Option<&Expression>,
) -> (Option<(usize, EmitError)>, Option<EmitError>) {
    let invalid = statements
        .iter()
        .enumerate()
        .find_map(|(index, statement)| self::statement(statement).err().map(|e| (index, e)));
    let invalid_export = export.and_then(|expr| self::export(expr).err());
    (invalid, invalid_export)
}

fn statement(statement: &Ast) -> Result<(), EmitError> {
    let target = |target: &LabelOrNode| match target {
        LabelOrNode::Expr(expr) => self::expr(expr),
        LabelOrNode::Label(_) | LabelOrNode::Node(_) => Ok(()),
    };
    match &statement.ty {
        AstNode::Assignment { lhs, rhs, .. } => {
            expr(rhs)?;
            if let Ident::Global(name) = lhs {
                return Err(unresolved_global(name));
            }
            Ok(())
        }
        AstNode::LoadAssignment { lhs, rhs, .. } => {
            expr(&lhs.ptr)?;
            expr(rhs)
        }
        AstNode::RangeAssignment { lhs, rhs, .. } => {
            expr(&lhs.value)?;
            expr(rhs)
        }
        AstNode::DeferredBuild(name) => Err(EmitError::new(format!(
            "unresolved `build {name}` reached runtime"
        ))),
        AstNode::Build(_) | AstNode::DelaySlot(_) | AstNode::Label(_) | AstNode::Export(_) => {
            Ok(())
        }
        AstNode::Branch { target: t } | AstNode::Call { target: t } => target(t),
        AstNode::ConditionalBranch {
            condition,
            target: t,
        } => {
            expr(condition)?;
            target(t)
        }
        AstNode::BranchIndirect { target }
        | AstNode::CallIndirect { target }
        | AstNode::Return { target }
        | AstNode::Expression(target) => expr(target),
    }
}

/// An export is either a value or an address; an address must name a
/// resolved space and say how wide it is.
fn export(expr: &Expression) -> Result<(), EmitError> {
    if let ExpressionTy::Load(load) = &expr.ty {
        self::expr(&load.ptr)?;
        if let Some(SpaceRef::Deferred(name)) = &load.space {
            return Err(unresolved_space(name));
        }
        if load.size.is_none() {
            return Err(unsized_address_export());
        }
        return Ok(());
    }
    self::expr(expr)
}

fn expr(expr: &Expression) -> Result<(), EmitError> {
    match &expr.ty {
        ExpressionTy::SizedInt { .. } => Ok(()),
        ExpressionTy::Ident(Ident::Global(name)) => Err(unresolved_global(name)),
        ExpressionTy::Ident(_) => Ok(()),
        ExpressionTy::SubPieceMsb { src, .. } | ExpressionTy::SubPieceLsb { src, .. } => {
            self::expr(src)
        }
        ExpressionTy::Load(load) => self::expr(&load.ptr),
        ExpressionTy::Range(range) => self::expr(&range.value),
        ExpressionTy::FunctionCall { args, .. } | ExpressionTy::PcodeOp { args, .. } => {
            args.iter().try_for_each(self::expr)
        }
        ExpressionTy::MacroCall { .. } => Err(macro_call()),
        ExpressionTy::DeferredCall { name, .. } => Err(deferred_call(name)),
        ExpressionTy::Unop(unop) => self::expr(&unop.e),
        ExpressionTy::Binop(binop) => {
            self::expr(&binop.lhs)?;
            self::expr(&binop.rhs)
        }
    }
}

// The errors, shared with the runtime's views: a validated body never lets
// them reach a view, but the views still have to say what they would report.

pub(crate) fn unresolved_global(name: &str) -> EmitError {
    EmitError::new(format!("unresolved global `{name}` reached runtime"))
}

pub(crate) fn unresolved_space(name: &str) -> EmitError {
    EmitError::new(format!("unresolved space `{name}` reached runtime"))
}

/// Macros are inlined when the specification is compiled; a call that
/// survived has no body to splice in.
pub(crate) fn macro_call() -> EmitError {
    EmitError::new("p-code macro call reached runtime")
}

pub(crate) fn deferred_call(name: &str) -> EmitError {
    EmitError::new(format!("unresolved deferred p-code call `{name}`"))
}

pub(crate) fn unsized_address_export() -> EmitError {
    EmitError::new("address export must have an explicit load size")
}
