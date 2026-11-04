use crate::TypeId;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    Types,
    Fields,
    References,
    NameLength,
    NameBytes,
    AlignmentEntries,
    Depth,
    TypeBytes,
    Work,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_types: usize,
    pub max_fields: usize,
    pub max_references: usize,
    pub max_name_length: usize,
    pub max_name_bytes: usize,
    pub max_alignment_entries: usize,
    pub max_depth: usize,
    /// Includes aligned lengths and field extents. No payload bytes are allocated.
    pub max_type_bytes: u64,
    pub max_work: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_types: 100_000,
            max_fields: 1_000_000,
            max_references: 1_000_000,
            max_name_length: 1024,
            max_name_bytes: 16 * 1024 * 1024,
            max_alignment_entries: 100_000,
            max_depth: 100_000,
            max_type_bytes: i32::MAX as u64,
            max_work: 32_000_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    #[error("datatype layout limit exceeded: {0:?}")]
    Limit(Resource),
    #[error("invalid data organization: {0}")]
    InvalidOrganization(&'static str),
    #[error("invalid datatype {ty:?}: {reason}")]
    InvalidType { ty: TypeId, reason: &'static str },
    #[error("datatype {owner:?} refers to nonexistent {target:?}")]
    InvalidReference { owner: TypeId, target: TypeId },
    #[error("by-value cycle from {owner:?} to {target:?}")]
    ByValueCycle { owner: TypeId, target: TypeId },
    #[error("datatype {owner:?} has an unsized or void field at index {field}")]
    InvalidField { owner: TypeId, field: usize },
    #[error("array {owner:?} has an unsized or void element {element:?}")]
    InvalidElement { owner: TypeId, element: TypeId },
    #[error("datatype {owner:?} has an invalid bitfield at index {field}: {reason}")]
    InvalidBitfield {
        owner: TypeId,
        field: usize,
        reason: &'static str,
    },
    /// Bitfield storage depends on byte order, which is never guessed from
    /// the host or inferred from the data organization.
    #[error("datatype {owner:?} declares bitfield {field}, but no byte order was supplied")]
    EndiannessRequired { owner: TypeId, field: usize },
    #[error("layout arithmetic overflow in datatype {0:?}")]
    Overflow(TypeId),
    #[error("datatype index {0:?} is out of range")]
    UnknownType(TypeId),
}

pub type Result<T> = std::result::Result<T, Error>;

pub(crate) struct Budget {
    pub(crate) limits: Limits,
    pub(crate) work: u64,
}

impl Budget {
    pub(crate) fn charge(&mut self, amount: u64) -> Result<()> {
        self.work = self
            .work
            .checked_add(amount)
            .filter(|n| *n <= self.limits.max_work)
            .ok_or(Error::Limit(Resource::Work))?;
        Ok(())
    }

    pub(crate) fn bytes(&self, bytes: u64) -> Result<u64> {
        if bytes > self.limits.max_type_bytes {
            return Err(Error::Limit(Resource::TypeBytes));
        }
        Ok(bytes)
    }
}

pub(crate) fn count(total: &mut usize, add: usize, limit: usize, resource: Resource) -> Result<()> {
    *total = total
        .checked_add(add)
        .filter(|n| *n <= limit)
        .ok_or(Error::Limit(resource))?;
    Ok(())
}
