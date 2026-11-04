//! Guard the pinned lowerer's missing byte-to-word conversion for address-of.
//! The expanded AST loses fixed-symbol versus operand-handle provenance, so
//! refuse both forms on word storage instead of guessing a numeric correction.
use sleigh::{
    CompiledSpec, Instruction, PcodeAst, PcodeExpr, PcodeExprKind as E, PcodeIdent,
    PcodeStatementKind as S, PcodeTarget, PcodeUnaryOp,
};
use std::collections::BTreeSet;

use crate::Error;

// Bounds the additional AST audit, independent of payload widths/domains.
const MAX_AUDIT_NODES: usize = 131_072;

pub(super) fn lower(
    spec: &CompiledSpec,
    instruction: &Instruction<'_, '_>,
    word_spaces: &BTreeSet<sleigh::SpaceId>,
) -> Result<sleigh::InstructionPcode, Error> {
    let ast = instruction
        .pcode_ast()
        .map_err(|error| Error::Lower(error.to_string()))?;
    audit(spec, &ast, word_spaces)?;
    // Public bitrange_info reports byte geometry, while the dependency's
    // private lowering context retains exact bits. Reuse its actual lowerer
    // rather than recreate that context from lossy public metadata. The AST
    // preflight is released before the lowerer builds its own AST.
    drop(ast);
    instruction
        .pcode_ops()
        .map_err(|error| Error::Lower(error.to_string()))
}

struct Audit<'a> {
    pending: Vec<&'a PcodeExpr>,
    nodes: usize,
}

impl<'a> Audit<'a> {
    fn push(&mut self, expression: &'a PcodeExpr) -> Result<(), Error> {
        self.charge()?;
        self.pending.push(expression);
        Ok(())
    }
    fn charge(&mut self) -> Result<(), Error> {
        if self.nodes == MAX_AUDIT_NODES {
            return Err(Error::Unsupported(
                "word-space instruction exceeds 131072 AST audit nodes".into(),
            ));
        }
        self.nodes += 1;
        Ok(())
    }
    fn target(&mut self, target: &'a PcodeTarget) -> Result<(), Error> {
        match target {
            PcodeTarget::Expr(expression) => self.push(expression),
            // A sub-table export used as a direct target carries its pointer.
            PcodeTarget::Address(target) => self.push(&target.ptr),
            PcodeTarget::Label(_) | PcodeTarget::Node(_) => Ok(()),
        }
    }
}

fn audit(
    spec: &CompiledSpec,
    ast: &PcodeAst,
    word_spaces: &BTreeSet<sleigh::SpaceId>,
) -> Result<(), Error> {
    let mut audit = Audit {
        pending: Vec::new(),
        nodes: 0,
    };
    for statement in &ast.statements {
        audit.charge()?;
        match &statement.ty {
            S::Assignment { rhs, .. } | S::Export(rhs) | S::Expression(rhs) => audit.push(rhs)?,
            S::LoadAssignment { lhs, rhs, .. } => {
                audit.push(&lhs.ptr)?;
                audit.push(rhs)?;
            }
            S::RangeAssignment { lhs, rhs, .. } => {
                audit.push(&lhs.value)?;
                audit.push(rhs)?;
            }
            S::Branch { target } | S::Call { target } => audit.target(target)?,
            S::ConditionalBranch { condition, target } => {
                audit.push(condition)?;
                audit.target(target)?;
            }
            S::BranchIndirect { target } | S::CallIndirect { target } | S::Return { target } => {
                audit.push(target)?
            }
            S::Build(_) | S::DelaySlot(_) | S::DeferredBuild(_) | S::Label(_) => {}
        }
    }
    while let Some(expression) = audit.pending.pop() {
        match &expression.ty {
            E::Unop(unop) => {
                if matches!(unop.op, PcodeUnaryOp::AddressOf(_)) {
                    let storage = match unop.e.ty {
                        E::Ident(PcodeIdent::Register(id)) => spec.register_varnode(id),
                        E::Ident(PcodeIdent::BitRange(id)) => spec
                            .bitrange_info(id)
                            .and_then(|(id, _, _)| spec.register_varnode(id)),
                        _ => None,
                    };
                    if storage.is_some_and(|storage| word_spaces.contains(&storage.space)) {
                        return Err(Error::Unsupported(
                            "address-of word-space storage needs fixed-symbol/operand provenance and byte-to-word lowering".into()
                        ));
                    }
                }
                audit.push(&unop.e)?;
            }
            E::Binop(binop) => {
                audit.push(&binop.lhs)?;
                audit.push(&binop.rhs)?;
            }
            E::SubPieceMsb { src, .. } | E::SubPieceLsb { src, .. } => audit.push(src)?,
            E::Load(load) => audit.push(&load.ptr)?,
            E::Range(range) => audit.push(&range.value)?,
            E::FunctionCall { args, .. }
            | E::PcodeOp { args, .. }
            | E::MacroCall { args, .. }
            | E::DeferredCall { args, .. } => {
                for arg in args {
                    audit.push(arg)?;
                }
            }
            E::SizedInt { .. } | E::Ident(_) => {}
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_node_limit_is_checked_before_pending_growth() {
        let expression = E::SizedInt {
            value: 0,
            size: Some(1),
        }
        .with_size(1);
        let mut audit = Audit {
            pending: Vec::new(),
            nodes: MAX_AUDIT_NODES - 1,
        };
        audit.push(&expression).unwrap();
        assert_eq!(audit.pending.len(), 1);
        assert!(matches!(
            audit.push(&expression),
            Err(Error::Unsupported(_))
        ));
        assert_eq!(audit.pending.len(), 1);
        assert!(audit.charge().is_err());
    }
}
