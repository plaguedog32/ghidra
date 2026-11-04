use thiserror::Error;

use crate::{AbiSpace, BindingSite, RegisterId};

pub type AbiResult<T> = Result<T, AbiError>;

/// Every construction/resolution call has its own budget. No input name is
/// copied into an error in full, and a budget failure returns no partial result.
#[derive(Clone, Copy, Debug)]
pub struct AbiLimits {
    pub max_spaces: usize,
    pub max_registers: usize,
    pub max_models: usize,
    pub max_bindings: usize,
    pub max_space_bases: usize,
    pub max_join_pieces: usize,
    pub max_total_pieces: usize,
    pub max_name_length: usize,
    /// Name bytes visited/copied during this call, including lookup spellings.
    pub max_name_bytes: usize,
    pub max_work: u64,
}

impl Default for AbiLimits {
    fn default() -> Self {
        Self {
            max_spaces: 256,
            max_registers: 100_000,
            max_models: 16_384,
            max_bindings: 100_000,
            max_space_bases: 4096,
            max_join_pieces: 1024,
            max_total_pieces: 1_000_000,
            max_name_length: 1024,
            max_name_bytes: 16 * 1024 * 1024,
            max_work: 100_000_000,
        }
    }
}

#[derive(Debug, Error)]
pub enum AbiError {
    #[error("compiler storage limit exceeded: {0}")]
    Limit(&'static str),
    #[error("invalid language layout: {0}")]
    InvalidLayout(&'static str),
    #[error("invalid storage declaration: {0}")]
    InvalidStorage(&'static str),
    #[error("unknown register `{0}`")]
    UnknownRegister(String),
    #[error("unknown address space `{0}`")]
    UnknownSpace(String),
    #[error("unknown register ID {0:?}")]
    UnknownRegisterId(RegisterId),
    #[error("invalid address extent in {space:?}: offset {offset:#x}, size {size:?}")]
    AddressRange {
        space: AbiSpace,
        offset: u64,
        size: Option<u32>,
    },
    #[error("storage size {actual} is smaller than parameter maximum {required}")]
    TooSmall { actual: u32, required: u32 },
    #[error("at {site:?}: {source}")]
    At {
        site: BindingSite,
        source: Box<AbiError>,
    },
}

pub(crate) fn label(text: &str) -> String {
    let mut end = text.len().min(64);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut result = text[..end].to_owned();
    if end != text.len() {
        result.push('…');
    }
    result
}

pub(crate) struct Budget {
    pub limits: AbiLimits,
    pub work: u64,
    pub name_bytes: usize,
    pub pieces: usize,
}

impl Budget {
    pub fn new(limits: AbiLimits) -> Self {
        Self {
            limits,
            work: 0,
            name_bytes: 0,
            pieces: 0,
        }
    }
    pub fn work(&mut self, count: usize) -> AbiResult<()> {
        self.work = self
            .work
            .checked_add(u64::try_from(count).map_err(|_| AbiError::Limit("work"))?)
            .filter(|&n| n <= self.limits.max_work)
            .ok_or(AbiError::Limit("work"))?;
        Ok(())
    }
    pub fn name(&mut self, name: &str) -> AbiResult<()> {
        if name.is_empty() || name.len() > self.limits.max_name_length {
            return Err(AbiError::Limit("name length"));
        }
        add(
            &mut self.name_bytes,
            name.len(),
            self.limits.max_name_bytes,
            "name bytes",
        )?;
        self.work(name.len())
    }
    pub fn lookup(&mut self, length: usize, bytes: usize) -> AbiResult<()> {
        let cost = (usize::BITS - length.leading_zeros()) as usize + 1;
        self.work(
            cost.checked_mul(bytes.max(1))
                .ok_or(AbiError::Limit("work"))?,
        )
    }
    pub fn pieces(&mut self, count: usize) -> AbiResult<()> {
        add(
            &mut self.pieces,
            count,
            self.limits.max_total_pieces,
            "storage pieces",
        )?;
        self.work(count)
    }
}

pub(crate) fn add(
    count: &mut usize,
    amount: usize,
    maximum: usize,
    resource: &'static str,
) -> AbiResult<()> {
    *count = count
        .checked_add(amount)
        .filter(|&n| n <= maximum)
        .ok_or(AbiError::Limit(resource))?;
    Ok(())
}
