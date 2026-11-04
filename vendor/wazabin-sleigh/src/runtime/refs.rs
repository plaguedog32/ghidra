use crate::{
    builder::SymbolId,
    objects::{
        field::{Field, FieldId},
        table::TableId,
    },
    token::{Token, TokenId},
    tree::Tree,
};
use pcode_types::{Register, RegisterId, Space, SpaceId};

/// Read-only register reference.
#[derive(Clone, Copy)]
pub struct RegisterRef<'spec> {
    /// Stable register id.
    pub id: RegisterId,
    register: &'spec Register,
}

impl<'spec> RegisterRef<'spec> {
    pub(super) fn new(id: RegisterId, register: &'spec Register) -> Self {
        Self { id, register }
    }

    /// Register name.
    pub fn name(&self) -> &str {
        &self.register.name
    }

    /// Byte offset in the register space.
    pub fn offset(&self) -> usize {
        self.register.offset
    }

    /// Register size in bytes.
    pub fn size(&self) -> usize {
        self.register.size
    }

    /// The space this register lives in (normally the `register` space).
    pub fn space(&self) -> SpaceId {
        self.register.space
    }
}

/// Read-only field reference.
#[derive(Clone, Copy)]
pub struct FieldRef<'spec> {
    /// Stable field id.
    pub id: FieldId,
    field: &'spec Field,
}

impl<'spec> FieldRef<'spec> {
    pub(super) fn new(id: FieldId, field: &'spec Field) -> Self {
        Self { id, field }
    }

    /// Field name.
    pub fn name(&self) -> &str {
        &self.field.name
    }

    /// Field width in bits.
    pub fn width(&self) -> usize {
        self.field.width()
    }
}

/// Read-only token reference.
#[derive(Clone, Copy)]
pub struct TokenRef<'spec> {
    /// Stable token id.
    pub id: TokenId,
    token: &'spec Token,
}

impl<'spec> TokenRef<'spec> {
    pub(super) fn new(id: TokenId, token: &'spec Token) -> Self {
        Self { id, token }
    }

    /// Token name.
    pub fn name(&self) -> &str {
        &self.token.name
    }

    /// Token size in bits.
    pub fn size(&self) -> usize {
        self.token.size()
    }
}

/// Read-only space reference.
#[derive(Clone, Copy)]
pub struct SpaceRef<'spec> {
    /// Stable space id.
    pub id: SpaceId,
    space: &'spec Space,
}

impl<'spec> SpaceRef<'spec> {
    pub(super) fn new(id: SpaceId, space: &'spec Space) -> Self {
        Self { id, space }
    }

    /// Space name, if it has one.
    pub fn name(&self) -> Option<&str> {
        self.space.name.as_deref()
    }

    /// Address size in bytes.
    pub fn address_size(&self) -> usize {
        self.space.addr_size
    }

    /// Word size in bytes.
    pub fn word_size(&self) -> usize {
        self.space.word_size
    }

    /// The underlying space definition.
    pub fn space(&self) -> &'spec Space {
        self.space
    }
}

/// Read-only constructor table reference.
#[derive(Clone, Copy)]
pub struct TableRef<'spec> {
    /// Stable table id.
    pub id: TableId,
    table: &'spec Tree,
}

impl<'spec> TableRef<'spec> {
    pub(super) fn new(id: TableId, table: &'spec Tree) -> Self {
        Self { id, table }
    }

    /// Table name.
    pub fn name(&self) -> &str {
        &self.table.name
    }

    /// Number of constructors in this table.
    pub fn constructor_count(&self) -> usize {
        self.table.constructors.len()
    }

    /// Maximum encoded length of any constructor in this table.
    pub fn max_len(&self) -> usize {
        self.table
            .constructors
            .iter()
            .map(|constructor| constructor.min_size())
            .max()
            .unwrap_or(0)
    }
}

/// Public symbol category.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SymbolKind {
    /// Register symbol.
    Register,
    /// Bitorange field symbol.
    BitRangeField,
    /// Memory space symbol.
    Space,
    /// Token symbol.
    Token,
    /// Field symbol.
    Field,
    /// P-code macro symbol.
    Macro,
    /// Constructor table symbol.
    Table,
    /// User-defined p-code op symbol.
    PCodeOp,
    /// Reserved builtin.
    Special,
}

impl From<SymbolId> for SymbolKind {
    fn from(value: SymbolId) -> Self {
        match value {
            SymbolId::Register(_) => Self::Register,
            SymbolId::BitRangeField(_) => Self::BitRangeField,
            SymbolId::Space(_) => Self::Space,
            SymbolId::Token(_) => Self::Token,
            SymbolId::Field(_) => Self::Field,
            SymbolId::Macro(_) => Self::Macro,
            SymbolId::Table(_) => Self::Table,
            SymbolId::PCodeOp(_) => Self::PCodeOp,
            SymbolId::Special => Self::Special,
        }
    }
}

/// Read-only symbol metadata.
#[derive(Debug, Clone, Copy)]
pub struct SymbolRef<'spec> {
    /// Symbol name.
    pub name: &'spec str,

    /// Symbol category.
    pub kind: SymbolKind,
}
