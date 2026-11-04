//! Context changes a decoded instruction hands back to its caller.
//!
//! Decoding is pure: [`crate::Decoder::decode_one`] takes the context to decode
//! with and never mutates it. A SLEIGH disassembly action can nevertheless
//! affect *later* instructions, by committing a context variable at another
//! address with `globalset`. Those requests are collected here as
//! [`ContextEffect`]s and reported through
//! [`crate::Instruction::context_effects`]; [`crate::ContextDatabase`] is the
//! opt-in store that turns them back into decode contexts.
//!
//! A plain assignment inside an action block is **decode-local**: it steers the
//! rest of this instruction's own match and then goes away. Only `globalset`
//! propagates. That is Ghidra's model, and the corpus depends on it — avr8
//! wraps every instruction in `[ phase=1; ]` purely to switch its own
//! sub-constructor phase, and would wedge itself permanently if that leaked
//! into the next decode.

use std::borrow::Cow;

use crate::{
    action::{Action, GlobalSetAddr},
    instance::{ConstructorInstance, OperandValue},
    objects::field::{FieldId, FieldParent},
    pattern::{OperandId, OperandType},
    runtime::{
        DecodeError,
        pcode::exported_address,
        walker::{eval_action_expr, read_context, update_context},
    },
    spec::Spec,
};

/// Where a context change takes effect.
///
/// One variant today, because `globalset` is the only construct that escapes a
/// single decode. It stays an enum so the address is never mistaken for a bare
/// integer at a call site, and so a future SLEIGH scope has somewhere to land.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ContextScope {
    /// The value was committed for `addr` by a `globalset`.
    ///
    /// How long it lasts is the *field's* property, not the effect's: a
    /// `noflow` variable applies to the single instruction at `addr`, and
    /// anything else applies from `addr` onward until overridden.
    /// [`crate::ContextDatabase`] implements that split.
    At(u64),
}

/// One context change requested by a decoded instruction.
///
/// Only `globalset` produces these. A plain assignment in an action block is
/// decode-local and reports nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ContextEffect {
    /// The context field to change. Always a context field, never a token or
    /// global one.
    pub field: FieldId,

    /// The value the field takes, already narrowed to the field's width.
    ///
    /// This is the value the variable held *at the `globalset`*, which a later
    /// assignment in the same block may since have changed.
    pub value: u64,

    /// Where the change applies.
    pub scope: ContextScope,
}

/// Replays a matched instruction's disassembly actions to collect its effects.
///
/// Runs after the match, so `inst_next` and every sub-table operand are known —
/// neither is available while [`crate::runtime::walker::Walker`] is still
/// choosing constructors, which is why `globalset` is skipped there.
///
/// The replay threads one scratch context through the whole instruction, in the
/// order the matcher applied context actions: a constructor's own action block
/// first, then its sub-constructors in operand order. The scratch is what makes
/// assignments decode-local — it is read by the `globalset`s that follow them
/// and then dropped.
pub(crate) fn collect_context_effects(
    spec: &Spec,
    instance: &ConstructorInstance,
    input: &[u8],
) -> Result<Vec<ContextEffect>, DecodeError> {
    // Borrowed until an assignment actually writes the context, so an
    // instruction with no context actions — the overwhelming majority — copies
    // nothing.
    let mut scratch: Cow<'_, [u8]> = Cow::Borrowed(input);
    let mut effects = Vec::new();

    apply_instance(spec, instance, &mut scratch, &mut effects)?;

    Ok(effects)
}

fn apply_instance(
    spec: &Spec,
    instance: &ConstructorInstance,
    scratch: &mut Cow<'_, [u8]>,
    effects: &mut Vec<ContextEffect>,
) -> Result<(), DecodeError> {
    let constructor = instance.constructor(spec);

    for action in &constructor.actions {
        match action {
            Action::Assign { field_id, expr } => {
                let field = &spec.fields[*field_id];
                // Token and global assignments do not touch the context;
                // `Walker::resolve_globals` has already applied the latter.
                if field.parent != FieldParent::Context {
                    continue;
                }
                let value = eval_action_expr(
                    spec,
                    expr,
                    constructor,
                    &instance.global_values,
                    &instance.operand_values,
                    scratch,
                )
                .ok_or(DecodeError::InvalidAction)?;
                update_context(scratch.to_mut(), &field.range, value as u64);
            }

            Action::GlobalSet { addr, field_id } => {
                let addr = match addr {
                    GlobalSetAddr::Expr(expr) => eval_action_expr(
                        spec,
                        expr,
                        constructor,
                        &instance.global_values,
                        &instance.operand_values,
                        scratch,
                    )
                    .ok_or(DecodeError::InvalidAction)?
                        as u64,

                    GlobalSetAddr::Table(table_id) => {
                        exported_address(spec, instance, *table_id)
                            .ok_or(DecodeError::UnresolvedGlobalSetAddress)?
                    }
                };

                // The committed value is the one the variable holds *here*, not
                // the one it ends the action block with.
                let field = &spec.fields[*field_id];
                effects.push(ContextEffect {
                    field: *field_id,
                    value: read_context(scratch, &field.range),
                    scope: ContextScope::At(addr),
                });
            }
        }
    }

    // Defensive: replay only the operand `table_map` records as *the* instance
    // for its table (`ConstructorInstance::child_value`), so a sub-table
    // reachable through two operands cannot report its effects twice.
    //
    // The duplication this was written for is fixed — `concretize_table`'s
    // recursion placeholder was adding a self-operand that `build_operand` then
    // added again, giving avr8's `:^instruction is ... & instruction` two
    // `instruction` operands. Keeping the guard is cheap and the invariant it
    // relies on (one instance per table) is the one the rest of the runtime
    // already assumes.
    for (index, operand) in constructor.token_pattern.operands.iter().enumerate() {
        if let OperandType::Table(table_id) = operand.ty
            && constructor.table_map.get(&table_id) != Some(&(index as OperandId))
        {
            continue;
        }
        if let Some(OperandValue::Constructor(child)) = instance.operand_values.get(index) {
            apply_instance(spec, child, scratch, effects)?;
        }
    }

    Ok(())
}
