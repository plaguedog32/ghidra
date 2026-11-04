use crate::bitrange::BitRange;
use crate::{
    pattern::{OperandType, TokenPattern},
    token::TokenId,
};
use jstd::{
    Identifier,
    registry::{Identified, Registry},
};
use pcode_types::RegisterId;
use serde::{Deserialize, Serialize};

/// Identifies one attachment table — the list of registers, integers or names
/// bound to a field's values by an `attach variables`, `attach values` or
/// `attach names` statement.
#[derive(Identifier)]
pub struct FieldTableId(usize);

/// Identifies a field: a named bit range within a token or within the context
/// register, or one of the global pseudo-fields such as `inst_start`.
pub use pcode_types::FieldId;

pub(crate) const FIELD_INST_START: FieldId = FieldId::new(0);
pub(crate) const FIELD_INST_NEXT: FieldId = FieldId::new(1);

/// Address after the instruction *following* this one, whose length is taken
/// without its own delay slot. Used by skip instructions (Toy's `sk`).
pub(crate) const FIELD_INST_NEXT2: FieldId = FieldId::new(2);

/// What a field's bit range is measured against.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldParent {
    /// Bits of the named token, so the field is extracted from the
    /// instruction stream.
    Token(TokenId),

    /// Bits of the context register, so the field is read from the decode
    /// context rather than from the instruction.
    Context,

    /// A pseudo-field with no bits behind it: `inst_start`, `inst_next`,
    /// `inst_next2`, and the locals a constructor's disassembly action
    /// defines. Its value is supplied per decoded instruction instead of
    /// being extracted, and it may not appear in a bit pattern.
    Global,
}

/// How a field's extracted value is to be interpreted, as set by an `attach`
/// statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub(crate) enum FieldType {
    /// Unattached: the value is the number read out of the bits.
    Integer,

    /// `attach variables`: the value indexes a table of registers.
    Registers(FieldTableId),

    /// `attach values`: the value indexes a table of integers.
    Values(FieldTableId),

    /// `attach names`: the value indexes a table of display names, which have
    /// no meaning beyond the disassembly text.
    String(FieldTableId),
}

/// A field's value once any attachment has been applied.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum FieldValue<'a> {
    /// A signed integer.
    Int(i64),

    /// An unsigned integer.
    UInt(u64),

    /// A register, from an `attach variables` table.
    Register(RegisterId),

    /// A display name, from an `attach names` table.
    String(&'a str),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct Field {
    /// The name this field is declared under
    pub name: Box<str>,

    /// The bits this field occupies within its parent, numbered as SLEIGH
    /// numbers them for that parent. [`BitRange::end`] is inclusive.
    pub range: BitRange,

    /// Is this field signed
    pub signed: bool,

    /// Is this field marked `noflow`.
    ///
    /// Only meaningful for [`FieldParent::Context`] fields: a `noflow`
    /// variable's committed value applies to the single instruction at the
    /// address it was committed for, instead of persisting from there on.
    pub noflow: bool,

    /// The type of the field
    /// A field can be attached to a table to interpret its results in a
    /// particular way
    ty: FieldType,

    /// What the bit range is measured against: a token, the context
    /// register, or nothing at all for a global.
    pub parent: FieldParent,

    /// The size of the parent in bits; saturated to `Size::MAX` for a global,
    /// which has no parent to be bounded by.
    parent_size: crate::Size,
}

impl Field {
    /// Creates an unattached integer field spanning `range` of `parent`.
    ///
    /// `parent_size` is the parent's width in bits. Use [`Self::attach`] to
    /// give the field a table afterwards.
    pub(crate) fn new(
        name: impl Into<Box<str>>,
        parent: FieldParent,
        range: BitRange,
        parent_size: usize,
        signed: bool,
    ) -> Self {
        Self {
            name: name.into(),
            range,
            ty: FieldType::Integer,
            parent,
            parent_size: parent_size as crate::Size,
            signed,
            noflow: false,
        }
    }

    /// The number of bits in this field's parent
    pub(crate) fn parent_size(&self) -> usize {
        self.parent_size as usize
    }

    /// The number of bits in this field
    pub(crate) fn width(&self) -> usize {
        self.range.size()
    }

    /// The number of distinct values this field can hold (`2^width`).
    ///
    /// Returns `None` for a field 64 bits or wider, whose value count does not
    /// fit in a `u64` — callers must reject such a field rather than shift past
    /// the width of the type.
    pub(crate) fn size(&self) -> Option<u64> {
        let width = self.width();
        (width < u64::BITS as usize).then(|| 1u64 << width)
    }

    /// The corresponding mask for this field
    pub(crate) fn mask(&self) -> u64 {
        1u64.wrapping_shl(self.width() as crate::Size)
            .wrapping_sub(1)
            << self.range.start()
    }

    /// Does this field overlap another field
    ///
    /// [`BitRange::end`] is inclusive, so the comparisons are too: fields
    /// `(0,2)` and `(2,4)` share bit 2. Reading `end` as exclusive here let
    /// such a pair past the check, and a constraint comparing them bit by bit
    /// would then pin the shared bit to two values at once and compile to a
    /// pattern that silently matches nothing.
    pub(crate) fn overlaps(&self, other: &Self) -> bool {
        self.range.start() <= other.range.end() && other.range.start() <= self.range.end()
    }

    /// Retrieves the [`FieldValue`], using a field table if necessary.
    ///
    /// `value` is read out of the instruction, so it may fall outside an
    /// attached table, and a table entry may be an unattached `_` placeholder.
    /// Both yield `None` rather than an out-of-bounds index or an unwrap on a
    /// missing entry.
    pub(crate) fn value<'a>(
        &self,
        field_tables: &'a FieldTables,
        value: u64,
    ) -> Option<FieldValue<'a>> {
        // Only attached tables index by the value. Converting up front would
        // reject a sign-extended negative integer on 32-bit targets such as
        // wasm32, where it does not fit a `usize`.
        let index = || usize::try_from(value).ok();

        Some(match self.ty {
            // A `signed` field's value was sign-extended when it was read out
            // of the instruction, so rendering it unsigned prints a
            // twenty-digit number where the specification means `-2`.
            FieldType::Integer if self.signed => FieldValue::Int(value as i64),
            FieldType::Integer => FieldValue::UInt(value),

            // `attach values` may bind negative numbers, stored here in
            // two's complement. Ghidra reads an attached value as signed.
            FieldType::Values(table_id) => {
                FieldValue::Int((*field_tables.values[table_id].get(index()?)?)? as i64)
            }

            FieldType::Registers(table_id) => {
                FieldValue::Register((*field_tables.registers[table_id].get(index()?)?)?)
            }

            FieldType::String(table_id) => {
                FieldValue::String(field_tables.names[table_id].get(index()?)?.as_deref()?)
            }
        })
    }

    /// Whether an `attach` statement gives the field's value a meaning
    /// beyond the integer read out of its bits.
    pub(crate) fn is_attached(&self) -> bool {
        self.ty != FieldType::Integer
    }

    /// How this field's raw bits are to be interpreted.
    pub(crate) fn field_type(&self) -> FieldType {
        self.ty
    }

    /// Adds a table to this field
    pub(crate) fn attach(&mut self, ty: FieldType) {
        self.ty = ty;
    }
}

/// Converts this field into a [`TokenPattern`] with an [`Operand`]
pub(crate) fn field_pattern(field: Identified<FieldId, &Field>) -> TokenPattern {
    match field.parent {
        FieldParent::Token(tok) => TokenPattern::from_insn(tok),

        FieldParent::Context => TokenPattern::default(),

        FieldParent::Global => unreachable!("Global fields cannot appear in patterns"),
    }
    .with_operand(OperandType::Field(field.id))
}

/// Tables that link numeric values to other types
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct FieldTables {
    /// Tables declared by `attach variables`
    registers: Registry<FieldTableId, Vec<Option<RegisterId>>>,

    /// Tables declared by `attach names`
    names: Registry<FieldTableId, Vec<Option<Box<str>>>>,

    /// Tables declared by `attach values`
    values: Registry<FieldTableId, Vec<Option<u64>>>,
}

impl FieldTables {
    /// The `attach variables` table `id` names.
    pub(crate) fn register_table(&self, id: FieldTableId) -> &[Option<RegisterId>] {
        &self.registers[id]
    }

    /// The `attach names` table `id` names.
    #[cfg(feature = "unstable-introspect")]
    pub(crate) fn name_table(&self, id: FieldTableId) -> &[Option<Box<str>>] {
        &self.names[id]
    }

    /// The `attach values` table `id` names.
    #[cfg(feature = "unstable-introspect")]
    pub(crate) fn value_table(&self, id: FieldTableId) -> &[Option<u64>] {
        &self.values[id]
    }

    /// Registers an `attach variables` table, indexed by field value.
    ///
    /// A `_` entry in the attach list is stored as `None`, meaning that value
    /// has nothing attached to it.
    pub(crate) fn add_register_table(&mut self, table: Vec<Option<RegisterId>>) -> FieldTableId {
        self.registers.push(table)
    }

    /// Registers an `attach names` table, indexed by field value. `_` entries
    /// are stored as `None`.
    pub(crate) fn add_name_table(&mut self, table: Vec<Option<Box<str>>>) -> FieldTableId {
        self.names.push(table)
    }

    /// Registers an `attach values` table, indexed by field value. `_` entries
    /// are stored as `None`.
    pub(crate) fn add_value_table(&mut self, table: Vec<Option<u64>>) -> FieldTableId {
        self.values.push(table)
    }
}
