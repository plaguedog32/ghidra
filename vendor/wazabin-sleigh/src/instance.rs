use std::fmt::Write;

use crate::{
    constructor::{Constructor, ConstructorId, DisplayElement},
    objects::{
        field::{FieldId, FieldParent, FieldValue},
        table::TableId,
    },
    runtime::{ContextEffect, DecodeError},
    spec::Spec,
    tree::{Tree, TreeId},
};

/// A value for an operand decoded from raw bytes.
#[derive(Default, Debug, Clone)]
pub(crate) enum OperandValue {
    #[default]
    None,
    Int(i64),
    Constructor(ConstructorInstance),
}

/// A concretized constructor — the result of decoding a single instruction
/// from raw bytes using a [`Walker`].
#[derive(Debug, Clone)]
pub(crate) struct ConstructorInstance {
    pub tree: TreeId,
    pub id: ConstructorId,
    pub operand_values: Vec<OperandValue>,
    pub global_values: Vec<u64>,
    pub inst_start: u64,
    pub inst_next: u64,
    pub size: usize,

    /// Context changes this instruction requests, in the order its disassembly
    /// actions produced them. Only filled in on the root instance, once the
    /// whole instruction has matched.
    pub context_effects: Vec<ContextEffect>,

    /// Instructions decoded to fill this one's delay slot, in address order.
    /// Empty unless the matched tree carries a `delayslot` directive. Only
    /// filled in on the root instance.
    pub delay_slots: Vec<ConstructorInstance>,

    /// Total encoded length of [`Self::delay_slots`], in bytes.
    pub delay_slot_len: usize,

    /// Address past the instruction *following* this one, when a constructor in
    /// the matched tree reads `inst_next2`.
    pub inst_next2: Option<u64>,
}

impl ConstructorInstance {
    /// `inst_next` as the *semantic* section sees it.
    ///
    /// SLEIGH gives `inst_next` two meanings (manual §7.11): in a disassembly
    /// action it is the address right after this instruction, delay slot
    /// excluded; in the semantic section it is the address after the delay
    /// slot. MIPS depends on both — `:jal` writes `ra = inst_next` expecting
    /// the address past the slot, while `globalset(inst_next, ...)` must not
    /// skip it.
    pub(crate) fn semantic_inst_next(&self) -> u64 {
        self.inst_next + self.delay_slot_len as u64
    }
}

impl ConstructorInstance {
    pub(crate) fn tree<'spec>(&self, spec: &'spec Spec) -> &'spec Tree {
        &spec.trees[self.tree]
    }

    pub(crate) fn constructor<'spec>(&self, spec: &'spec Spec) -> &'spec Constructor {
        &self.tree(spec).constructors[self.id]
    }

    pub(crate) fn field_value(&self, spec: &Spec, field_id: FieldId) -> Option<i64> {
        let constructor = self.constructor(spec);
        let operand_id = *constructor.field_map.get(&field_id)?;
        if let &OperandValue::Int(value) = &self.operand_values[operand_id as usize] {
            Some(value)
        } else {
            None
        }
    }

    pub(crate) fn child_value(&self, spec: &Spec, table_id: TableId) -> Option<&Self> {
        let constructor = self.constructor(spec);
        let operand_id = *constructor.table_map.get(&table_id)?;
        if let OperandValue::Constructor(child) = &self.operand_values[operand_id as usize] {
            Some(child)
        } else {
            None
        }
    }

    /// Renders the instruction to its assembly display string.
    ///
    /// Returns [`DecodeError::UnresolvedDisplay`] when a display element names
    /// something this decode cannot supply a value for: a sub-table that did
    /// not become an operand, a field that is constrained by the pattern but
    /// not listed as an operand, or an attach-table entry that is out of range
    /// or an unattached `_`.
    pub(crate) fn try_to_string(&self, spec: &Spec) -> Result<String, DecodeError> {
        let constructor = self.constructor(spec);
        let mut res = String::new();

        for e in &constructor.display {
            match e {
                DisplayElement::String(s) => res.push_str(s),

                &DisplayElement::Table(table_id) => {
                    let child = self
                        .child_value(spec, table_id)
                        .ok_or(DecodeError::UnresolvedDisplay)?;
                    res.push_str(&child.try_to_string(spec)?);
                }

                &DisplayElement::Field(field_id) => {
                    let field = &spec.fields[field_id];

                    if field.parent == FieldParent::Global {
                        let idx = constructor.global_index(field_id);
                        let _ = write!(res, "{}", self.global_values[idx]);
                    } else {
                        let value = self
                            .field_value(spec, field_id)
                            .ok_or(DecodeError::UnresolvedDisplay)?;

                        let rendered = field
                            .value(&spec.field_tables, value as u64)
                            .ok_or(DecodeError::UnresolvedDisplay)?;

                        match rendered {
                            FieldValue::Int(v) => {
                                let _ = write!(res, "{v}");
                            }
                            FieldValue::UInt(v) => {
                                let _ = write!(res, "{v}");
                            }
                            FieldValue::Register(r) => res.push_str(&spec.registers[r].name),
                            FieldValue::String(s) => res.push_str(s),
                        }
                    }
                }
            }
        }

        Ok(res)
    }
}
