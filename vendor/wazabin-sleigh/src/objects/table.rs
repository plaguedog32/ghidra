use crate::{
    constructor::{ConstructorBuilder, ConstructorId},
    pattern::{CombinedPattern, TokenPattern},
};
use jstd::registry::{Identified, Registry};

pub(crate) use pcode_types::TableId;

/// A reference to a [`Table`] with its id
pub(crate) type TableRef<'b> = Identified<TableId, &'b Table>;

/// A mutable reference to a [`Table`] with its id
pub(crate) type TableMutRef<'b> = Identified<TableId, &'b mut Table>;

#[derive(Debug)]
pub(crate) struct Table {
    pub name: Box<str>,
    pub constructors: Registry<ConstructorId, ConstructorBuilder>,
    pub pattern: Option<TokenPattern>,
    pub building: bool,
}

impl Table {
    /// Creates a new table
    pub(crate) fn new(name: Box<str>) -> Self {
        Self {
            name,
            constructors: Default::default(),
            pattern: None,
            building: false,
        }
    }

    /// The maximum length of any constructor in this table
    pub(crate) fn max_len(&self) -> usize {
        self.constructors
            .iter()
            .flat_map(|constructor| constructor.pattern.unwrap_pattern().combined_patterns())
            .map(CombinedPattern::max_len)
            .max()
            .unwrap_or(0)
    }
}
