use ghidra_languages::{JoinPiece, StackGrowth, StackPointer, Storage};
use ghidra_pcode::{SpaceId, SpaceKind};
use serde::Serialize;

use crate::error::Budget;
use crate::{AbiError, AbiLimits, AbiResult, RegisterFile, RegisterId};

/// Compiler-only spaces are distinct from language space IDs. No synthetic
/// numeric ID is invented that could alias a real register or memory space.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub enum AbiSpace {
    Language(SpaceId),
    Stack,
    Other,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct AbiAddress {
    pub space: AbiSpace,
    /// Byte offset. Stack offsets use normalized sign-extended Java-long bits.
    pub offset: u64,
}

impl AbiAddress {
    pub fn signed_stack_offset(&self) -> Option<i64> {
        (self.space == AbiSpace::Stack).then_some(self.offset as i64)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StorageRange {
    pub address: AbiAddress,
    /// None is an address without a declared width, not a zero-byte value.
    pub size: Option<u32>,
    /// Present only when this declaration named a register directly.
    pub register: Option<RegisterId>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum JoinKind {
    Concatenation,
    FloatExtension,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolvedPiece {
    pub storage: StorageRange,
    /// Concatenation byte significance. A floating extension is a format
    /// conversion, so it deliberately has no bit-slice offset.
    pub lsb_byte: Option<u32>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum ResolvedStorage {
    Single(StorageRange),
    Join {
        kind: JoinKind,
        logical_size: u32,
        physical_size: u32,
        pieces: Vec<ResolvedPiece>,
    },
}

impl ResolvedStorage {
    pub fn size(&self) -> Option<u32> {
        match self {
            Self::Single(range) => range.size,
            Self::Join { logical_size, .. } => Some(*logical_size),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StackProperties {
    pub pointer: Option<RegisterId>,
    pub backing_space: AbiSpace,
    pub address_size: u8,
    pub word_size: u32,
    pub growth: StackGrowth,
    pub reverse_justify: bool,
}

#[derive(Clone, Copy)]
pub(crate) struct SpaceProperties {
    pub space: AbiSpace,
    pub address_size: u8,
    pub word_size: u32,
    pub signed: bool,
    pub constant: bool,
}

impl SpaceProperties {
    fn capacity(self) -> u128 {
        ((1_u128 << (8 * u32::from(self.address_size))) * u128::from(self.word_size))
            .min(u128::from(u64::MAX) + 1)
    }
    pub fn normalize(self, raw: u64, size: Option<u32>) -> AbiResult<AbiAddress> {
        let capacity = self.capacity() as i128;
        let raw_signed = i128::from(raw as i64);
        let value = if self.signed {
            let minimum = -capacity / 2;
            let maximum = capacity / 2 - 1;
            if raw_signed >= minimum && raw_signed <= maximum {
                raw_signed
            } else if raw_signed > maximum && raw_signed < capacity {
                raw_signed - capacity
            } else {
                return Err(self.range_error(raw, size));
            }
        } else if capacity == 1_i128 << 64 {
            i128::from(raw)
        } else if raw_signed >= 0 && raw_signed < capacity {
            raw_signed
        } else if raw_signed < 0 && raw_signed >= -capacity {
            raw_signed + capacity
        } else {
            return Err(self.range_error(raw, size));
        };
        let maximum = if self.signed {
            capacity / 2 - 1
        } else {
            capacity - 1
        };
        // Constant space denotes literal values rather than memory extents.
        if !self.constant
            && let Some(size) = size
            && (size == 0 || value + i128::from(size) - 1 > maximum)
        {
            return Err(self.range_error(raw, Some(size)));
        }
        Ok(AbiAddress {
            space: self.space,
            offset: value as u64,
        })
    }
    fn range_error(self, offset: u64, size: Option<u32>) -> AbiError {
        AbiError::AddressRange {
            space: self.space,
            offset,
            size,
        }
    }
}

/// Resolve one declaration. `default_size` is for a genuinely sized use of an
/// unsized address; parameter-pool capacity is a separate compiler constraint.
pub fn resolve_storage(
    file: &RegisterFile,
    pointer: Option<&StackPointer>,
    storage: &Storage,
    default_size: Option<u32>,
    limits: AbiLimits,
) -> AbiResult<ResolvedStorage> {
    let mut resolver = Resolver::new(file, pointer, limits)?;
    resolver.resolve(storage, default_size)
}

pub(crate) struct Resolver<'a> {
    pub file: &'a RegisterFile,
    pub stack: StackProperties,
    pub budget: Budget,
}

impl<'a> Resolver<'a> {
    pub fn new(
        file: &'a RegisterFile,
        pointer: Option<&StackPointer>,
        limits: AbiLimits,
    ) -> AbiResult<Self> {
        let mut budget = Budget::new(limits);
        let (register, backing, address_size, word_size, growth, reverse_justify) =
            if let Some(pointer) = pointer {
                let id = file.find_register(&pointer.register, &mut budget)?;
                let backing = Self::language_space(file, &pointer.space, &mut budget)?;
                let register = file.register(id)?;
                let size = register.size.min(u32::from(backing.address_size)) as u8;
                (
                    Some(id),
                    backing.space,
                    size,
                    backing.word_size,
                    pointer.growth,
                    pointer.reverse_justify,
                )
            } else {
                let space = file
                    .space(file.default_space())
                    .ok_or(AbiError::InvalidLayout("default space"))?;
                (
                    None,
                    AbiSpace::Language(space.id),
                    space.address_size,
                    space.word_size,
                    StackGrowth::Negative,
                    false,
                )
            };
        if address_size == 0
            || (1_u128 << (8 * u32::from(address_size))) * u128::from(word_size) > 1_u128 << 64
        {
            return Err(AbiError::InvalidStorage(
                "stack exceeds the 64-bit byte-address domain",
            ));
        }
        Ok(Self {
            file,
            stack: StackProperties {
                pointer: register,
                backing_space: backing,
                address_size,
                word_size,
                growth,
                reverse_justify,
            },
            budget,
        })
    }

    fn language_space(
        file: &RegisterFile,
        name: &str,
        budget: &mut Budget,
    ) -> AbiResult<SpaceProperties> {
        if name == "OTHER" {
            budget.name(name)?;
            return Ok(SpaceProperties {
                space: AbiSpace::Other,
                address_size: 8,
                word_size: 1,
                signed: false,
                constant: false,
            });
        }
        let space = file.find_space(name, budget)?;
        Ok(SpaceProperties {
            space: AbiSpace::Language(space.id),
            address_size: space.address_size,
            word_size: space.word_size,
            signed: space.kind == SpaceKind::Constant,
            constant: space.kind == SpaceKind::Constant,
        })
    }

    pub fn space(&mut self, name: &str) -> AbiResult<SpaceProperties> {
        if name == "stack" {
            self.budget.name(name)?;
            Ok(SpaceProperties {
                space: AbiSpace::Stack,
                address_size: self.stack.address_size,
                word_size: self.stack.word_size,
                signed: true,
                constant: false,
            })
        } else if name == "join" {
            Err(AbiError::InvalidStorage(
                "numeric join-space offsets need a join record",
            ))
        } else {
            Self::language_space(self.file, name, &mut self.budget)
        }
    }

    pub fn register(&mut self, name: &str) -> AbiResult<StorageRange> {
        let id = self.file.find_register(name, &mut self.budget)?;
        let register = self.file.register(id)?;
        Ok(StorageRange {
            address: AbiAddress {
                space: AbiSpace::Language(register.space),
                offset: register.offset,
            },
            size: Some(register.size),
            register: Some(id),
        })
    }

    fn location(&mut self, space: &str, offset: u64, size: Option<u32>) -> AbiResult<StorageRange> {
        let properties = self.space(space)?;
        let address = properties.normalize(offset, size)?;
        Ok(StorageRange {
            address,
            size,
            register: None,
        })
    }

    pub fn resolve(
        &mut self,
        storage: &Storage,
        default_size: Option<u32>,
    ) -> AbiResult<ResolvedStorage> {
        self.budget.work(1)?;
        match storage {
            Storage::Register { name } => {
                self.budget.pieces(1)?;
                Ok(ResolvedStorage::Single(self.register(name)?))
            }
            Storage::Varnode {
                space,
                offset,
                size,
            } => {
                if *size == 0 {
                    return Err(AbiError::InvalidStorage("zero-sized varnode"));
                }
                self.budget.pieces(1)?;
                Ok(ResolvedStorage::Single(self.location(
                    space,
                    *offset,
                    Some(*size),
                )?))
            }
            Storage::Address {
                space,
                offset,
                size,
            } => {
                let size = size.filter(|n| *n != 0).or(default_size);
                if size == Some(0) {
                    return Err(AbiError::InvalidStorage("zero default size"));
                }
                self.budget.pieces(1)?;
                Ok(ResolvedStorage::Single(
                    self.location(space, *offset, size)?,
                ))
            }
            Storage::Join {
                pieces,
                logical_size,
            } => self.join(pieces, *logical_size),
        }
    }

    fn join(&mut self, source: &[JoinPiece], logical: Option<u32>) -> AbiResult<ResolvedStorage> {
        if source.is_empty() {
            return Err(AbiError::InvalidStorage("empty join"));
        }
        if source.len() > self.budget.limits.max_join_pieces {
            return Err(AbiError::Limit("join pieces"));
        }
        self.budget.pieces(source.len())?;
        let mut pieces = Vec::with_capacity(source.len());
        let mut physical_size = 0_u32;
        for piece in source {
            self.budget.work(1)?;
            let storage = match piece {
                JoinPiece::Register { name } => self.register(name)?,
                JoinPiece::Varnode {
                    space,
                    offset,
                    size,
                } => {
                    if *size == 0 {
                        return Err(AbiError::InvalidStorage("zero join piece size"));
                    }
                    self.location(space, *offset, Some(*size))?
                }
            };
            physical_size = physical_size
                .checked_add(
                    storage
                        .size
                        .ok_or(AbiError::InvalidStorage("unsized join piece"))?,
                )
                .ok_or(AbiError::Limit("join bytes"))?;
            pieces.push(ResolvedPiece {
                storage,
                lsb_byte: None,
            });
        }
        let logical_size = logical.filter(|n| *n != 0).unwrap_or(physical_size);
        let kind = if logical_size != physical_size {
            if pieces.len() != 1 {
                return Err(AbiError::InvalidStorage(
                    "logical size override requires one join piece",
                ));
            }
            JoinKind::FloatExtension
        } else {
            if pieces.len() == 1 {
                let space = pieces[0].storage.address.space;
                let constant = match space {
                    AbiSpace::Language(id) => self
                        .file
                        .space(id)
                        .is_some_and(|s| s.kind == SpaceKind::Constant),
                    _ => false,
                };
                if !constant {
                    return Err(AbiError::InvalidStorage(
                        "single physical join requires a distinct logical size",
                    ));
                }
            }
            let mut remaining = physical_size;
            for piece in &mut pieces {
                self.budget.work(1)?;
                remaining -= piece
                    .storage
                    .size
                    .ok_or(AbiError::InvalidStorage("unsized join piece"))?;
                piece.lsb_byte = Some(remaining);
            }
            JoinKind::Concatenation
        };
        Ok(ResolvedStorage::Join {
            kind,
            logical_size,
            physical_size,
            pieces,
        })
    }
}
