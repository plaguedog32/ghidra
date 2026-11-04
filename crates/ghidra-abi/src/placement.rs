//! Place one value in a declared parameter pool. Resource consumption and
//! datatype/model-rule selection belong to a caller, not to this pure query.
use ghidra_languages::{Extension, StackGrowth};
use ghidra_pcode::{Endianness, SpaceKind};
use serde::Serialize;
use thiserror::Error;

use crate::{
    AbiAddress, AbiSpace, BindingSite, CompilerStorage, JoinKind, ResolvedStorage, StorageRange,
};

#[derive(Clone, Copy, Debug)]
pub struct PlacementLimits {
    pub max_source_pieces: usize,
    pub max_output_pieces: usize,
    pub max_work: u64,
}

impl Default for PlacementLimits {
    fn default() -> Self {
        Self {
            max_source_pieces: 1024,
            max_output_pieces: 1024,
            max_work: 100_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub enum Justification {
    /// Left for little endian, right for big endian; a big-endian stack's
    /// reverse-justify attribute changes the default to left.
    #[default]
    Default,
    Left,
    Right,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct PlacementRequest {
    pub size: u32,
    /// Aligned pools count used slots, not bytes or resource IDs. For an
    /// exclusion pool only zero is usable; successful placement leaves it zero.
    pub used_slots: u64,
    /// Alignment relative to the pool's slot origin, not an absolute address.
    pub type_alignment: u32,
    pub justification: Justification,
}

impl PlacementRequest {
    pub fn new(size: u32) -> Self {
        Self {
            size,
            used_slots: 0,
            type_alignment: 1,
            justification: Justification::Default,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum NoFit {
    BelowMinimum,
    AboveCapacity,
    ExclusionUsed,
    SlotsExhausted,
    /// The selected value would leave the address domain. A declared pool's
    /// capacity need not itself fit, but every actual placement must fit.
    AddressDomain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum PieceRole {
    Storage,
    /// Retained join padding. This is neither writable storage nor a known
    /// value; the constant-space offset is preserved only as provenance.
    Padding,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlacedPiece {
    pub storage: StorageRange,
    /// Significance in the selected value, in bytes from its least significant end.
    pub lsb_byte: u32,
    /// Index in the original most-significant-first join (zero for a single pool).
    pub source_piece: usize,
    pub source_byte_offset: u32,
    pub role: PieceRole,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum PlacedStorage {
    /// Pieces stay most-significant-first, even when a slice has only one piece.
    Bits { pieces: Vec<PlacedPiece> },
    /// A format conversion, not an integer slice or an evaluated conversion.
    /// The full physical container remains present regardless of logical width.
    FloatConversion {
        container: StorageRange,
        logical_size: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlacedValue {
    pub size: u32,
    /// The declaration's extension policy. Sign, zero and inttype are recorded,
    /// not executed, and do not make the unused container bytes known.
    pub extension: Extension,
    pub storage: PlacedStorage,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum PlacementOutcome {
    Placed(PlacedValue),
    NoFit(NoFit),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct Placement {
    pub site: BindingSite,
    /// Includes alignment holes, even when there were not enough slots left.
    /// An error, unlike NoFit, returns no updated cursor.
    pub next_slot: u64,
    pub source_pieces: usize,
    pub work: u64,
    pub outcome: PlacementOutcome,
}

#[derive(Debug, Error)]
pub enum PlacementError {
    #[error("parameter placement limit exceeded: {0}")]
    Limit(&'static str),
    #[error("invalid parameter placement request: {0}")]
    InvalidRequest(&'static str),
    #[error("invalid parameter placement at {site:?}: {reason}")]
    Invalid {
        site: BindingSite,
        reason: &'static str,
    },
    #[error("unsupported parameter placement at {site:?}: {reason}")]
    Unsupported {
        site: BindingSite,
        reason: &'static str,
    },
}

struct Budget {
    limits: PlacementLimits,
    work: u64,
}

impl Budget {
    fn charge(&mut self, amount: usize) -> Result<(), PlacementError> {
        self.work = self
            .work
            .checked_add(u64::try_from(amount).map_err(|_| PlacementError::Limit("work"))?)
            .filter(|w| *w <= self.limits.max_work)
            .ok_or(PlacementError::Limit("work"))?;
        Ok(())
    }
    fn lookup(&mut self, count: usize) -> Result<(), PlacementError> {
        self.charge((usize::BITS - count.leading_zeros()) as usize + 1)
    }
    fn output(&mut self, count: usize) -> Result<(), PlacementError> {
        if count > self.limits.max_output_pieces {
            return Err(PlacementError::Limit("output pieces"));
        }
        self.charge(count)
    }
}

#[derive(Clone, Copy)]
struct Geometry {
    minimum: i128,
    maximum: i128,
    endian: Endianness,
    padding: bool,
}

fn geometry(
    storage: &CompilerStorage,
    space: AbiSpace,
    site: BindingSite,
    budget: &mut Budget,
) -> Result<Geometry, PlacementError> {
    budget.lookup(storage.register_file().spaces().len())?;
    let file = storage.register_file();
    let language = |id| {
        file.space(id).ok_or(PlacementError::Invalid {
            site,
            reason: "unknown physical address space",
        })
    };
    let (capacity, endian, signed, padding) = match space {
        AbiSpace::Language(id) => {
            let s = language(id)?;
            (
                (1_u128 << (8 * u32::from(s.address_size))) * u128::from(s.word_size),
                s.endianness,
                false,
                s.kind == SpaceKind::Constant,
            )
        }
        AbiSpace::Stack => {
            let stack = storage.stack();
            let id = match stack.backing_space {
                AbiSpace::Language(id) => id,
                AbiSpace::Other => file.default_space(),
                AbiSpace::Stack => {
                    return Err(PlacementError::Invalid {
                        site,
                        reason: "stack cannot back itself",
                    });
                }
            };
            (
                (1_u128 << (8 * u32::from(stack.address_size))) * u128::from(stack.word_size),
                language(id)?.endianness,
                true,
                false,
            )
        }
        AbiSpace::Other => (
            1_u128 << 64,
            language(file.default_space())?.endianness,
            false,
            false,
        ),
    };
    if capacity == 0 || capacity > 1_u128 << 64 {
        return Err(PlacementError::Invalid {
            site,
            reason: "invalid physical address domain",
        });
    }
    let capacity = capacity as i128;
    Ok(Geometry {
        minimum: if signed { -capacity / 2 } else { 0 },
        maximum: if signed {
            capacity / 2 - 1
        } else {
            capacity - 1
        },
        endian,
        padding,
    })
}

fn physical_slice(
    storage: &CompilerStorage,
    source: &StorageRange,
    displacement: u64,
    size: u32,
    site: BindingSite,
    budget: &mut Budget,
) -> Result<Option<(StorageRange, PieceRole)>, PlacementError> {
    let g = geometry(storage, source.address.space, site, budget)?;
    // Constant-space join components describe padding, not literal bytes to
    // extract. Keep their declared offset rather than add a byte displacement.
    let offset = if g.padding {
        source.address.offset
    } else {
        let base = if source.address.space == AbiSpace::Stack {
            i128::from(source.address.offset as i64)
        } else {
            i128::from(source.address.offset)
        };
        let first = base + i128::from(displacement);
        if first < g.minimum || first + i128::from(size) - 1 > g.maximum {
            return Ok(None);
        }
        first as u64
    };
    Ok(Some((
        StorageRange {
            address: AbiAddress {
                offset,
                ..source.address
            },
            size: Some(size),
            // This is declaration provenance, not a claim that a register
            // with this exact sliced width/name exists.
            register: source.register,
        },
        if g.padding {
            PieceRole::Padding
        } else {
            PieceRole::Storage
        },
    )))
}

/// Pure placement in one input/output entry. This neither chooses the entry
/// by datatype nor reserves its resource groups. A later allocation pass must
/// consume exclusion groups explicitly; `next_slot == 0` is not a free result.
pub fn place_parameter(
    storage: &CompilerStorage,
    site: BindingSite,
    request: PlacementRequest,
    limits: PlacementLimits,
) -> Result<Placement, PlacementError> {
    if request.size == 0 || request.type_alignment == 0 {
        return Err(PlacementError::InvalidRequest(
            "size and type alignment must be positive",
        ));
    }
    let invalid = |reason| PlacementError::Invalid { site, reason };
    let unsupported = |reason| PlacementError::Unsupported { site, reason };
    let mut budget = Budget { limits, work: 0 };
    budget.charge(1)?;
    let model = match site {
        BindingSite::Input { model, .. } | BindingSite::Output { model, .. } => model,
        _ => return Err(invalid("site is not a parameter entry")),
    };
    let prototype = storage
        .source()
        .prototypes
        .get(model)
        .ok_or_else(|| invalid("unknown model"))?;
    if !prototype.is_complete() {
        return Err(invalid("prototype has incomplete declarations"));
    }
    budget.lookup(storage.bindings().len())?;
    let binding = storage
        .binding(site)
        .ok_or_else(|| invalid("unknown parameter entry"))?;
    let p = binding
        .parameter
        .as_ref()
        .ok_or_else(|| invalid("missing parameter constraints"))?;
    if p.min_size == 0
        || p.max_size < p.min_size
        || p.max_size > i32::MAX as u32
        || p.alignment > i32::MAX as u32
    {
        return Err(invalid("invalid parameter size/alignment"));
    }
    let count = match &binding.storage {
        ResolvedStorage::Single(_) => 1,
        ResolvedStorage::Join { pieces, .. } => pieces.len(),
    };
    if count == 0 {
        return Err(invalid("empty physical storage"));
    }
    if count > limits.max_source_pieces {
        return Err(PlacementError::Limit("source pieces"));
    }
    let finish = |outcome, next_slot, budget: &Budget| Placement {
        site,
        next_slot,
        source_pieces: count,
        work: budget.work,
        outcome,
    };
    let fail = |reason, next_slot, budget: &Budget| {
        Ok(finish(PlacementOutcome::NoFit(reason), next_slot, budget))
    };
    if request.size < p.min_size {
        return fail(NoFit::BelowMinimum, request.used_slots, &budget);
    }
    let (cursor, next_slot, span, start) = if p.alignment == 0 {
        if request.used_slots != 0 {
            return fail(NoFit::ExclusionUsed, request.used_slots, &budget);
        }
        if request.size > p.max_size {
            return fail(NoFit::AboveCapacity, request.used_slots, &budget);
        }
        (0, 0, p.max_size, 0)
    } else {
        if storage.stack().growth == StackGrowth::Positive && p.max_size % p.alignment != 0 {
            return Err(invalid(
                "positive growth requires a whole number of pool slots",
            ));
        }
        // Exact relative alignment, including nondividing alignments. Retained
        // getAddrBySlot uses floor division that can leave such requests
        // misaligned; conventional divisible alignments have identical results.
        let mut a = u64::from(p.alignment);
        let mut b = u64::from(request.type_alignment);
        while b != 0 {
            budget.charge(1)?;
            (a, b) = (b, a % b);
        }
        let period = u64::from(request.type_alignment) / a;
        let remainder = request.used_slots % period;
        let cursor = request
            .used_slots
            .checked_add(if remainder == 0 {
                0
            } else {
                period - remainder
            })
            .ok_or(PlacementError::InvalidRequest("slot alignment overflows"))?;
        let used = u64::from(request.size).div_ceil(u64::from(p.alignment));
        let next = cursor
            .checked_add(used)
            .ok_or(PlacementError::InvalidRequest("slot count overflows"))?;
        let capacity = u64::from(p.max_size / p.alignment);
        if next > capacity {
            return fail(NoFit::SlotsExhausted, cursor, &budget);
        }
        let index = if storage.stack().growth == StackGrowth::Positive {
            capacity - next
        } else {
            cursor
        };
        // Both are bounded by p.max_size after the capacity test.
        (
            cursor,
            next,
            (used * u64::from(p.alignment)) as u32,
            index * u64::from(p.alignment),
        )
    };
    let pool_endian = match &binding.storage {
        ResolvedStorage::Single(range) => {
            let g = geometry(storage, range.address.space, site, &mut budget)?;
            if range.address.space == AbiSpace::Stack
                && storage.stack().reverse_justify
                && g.endian == Endianness::Little
            {
                return Err(unsupported(
                    "native little-endian reverse stack justification",
                ));
            }
            g.endian
        }
        ResolvedStorage::Join { .. } => {
            // A synthetic join uses the translator's default byte order; its
            // physical byte traversal below uses the first piece's order.
            geometry(
                storage,
                AbiSpace::Language(storage.register_file().default_space()),
                site,
                &mut budget,
            )?
            .endian
        }
    };
    let force_left = matches!(&binding.storage, ResolvedStorage::Single(r) if r.address.space == AbiSpace::Stack)
        && storage.stack().reverse_justify;
    let right = match request.justification {
        Justification::Default => pool_endian == Endianness::Big && !force_left,
        Justification::Left => false,
        Justification::Right => true,
    };
    if let ResolvedStorage::Join {
        kind: JoinKind::FloatExtension,
        logical_size,
        pieces,
        ..
    } = &binding.storage
    {
        if p.alignment != 0 || request.size != *logical_size || pieces.len() != 1 {
            return Err(unsupported("partial or aligned floating join conversion"));
        }
        budget.output(1)?;
        let source = &pieces[0].storage;
        let physical = source
            .size
            .ok_or_else(|| invalid("unsized floating container"))?;
        let Some((container, role)) =
            physical_slice(storage, source, 0, physical, site, &mut budget)?
        else {
            return fail(NoFit::AddressDomain, cursor, &budget);
        };
        if role == PieceRole::Padding {
            return Err(unsupported("floating conversion of constant padding"));
        }
        return Ok(finish(
            PlacementOutcome::Placed(PlacedValue {
                size: request.size,
                extension: p.extension,
                storage: PlacedStorage::FloatConversion {
                    container,
                    logical_size: request.size,
                },
            }),
            next_slot,
            &budget,
        ));
    }
    if p.alignment == 0 && p.extension == Extension::Float && request.size != p.max_size {
        let ResolvedStorage::Single(source) = &binding.storage else {
            return Err(unsupported("floating conversion of a concatenated join"));
        };
        budget.output(1)?;
        let Some((container, role)) =
            physical_slice(storage, source, 0, p.max_size, site, &mut budget)?
        else {
            return fail(NoFit::AddressDomain, cursor, &budget);
        };
        if role == PieceRole::Padding {
            return Err(unsupported("floating conversion of constant padding"));
        }
        return Ok(finish(
            PlacementOutcome::Placed(PlacedValue {
                size: request.size,
                extension: p.extension,
                storage: PlacedStorage::FloatConversion {
                    container,
                    logical_size: request.size,
                },
            }),
            next_slot,
            &budget,
        ));
    }
    let displacement = start
        + if right {
            u64::from(span - request.size)
        } else {
            0
        };
    let pieces = match &binding.storage {
        ResolvedStorage::Single(source) => {
            budget.output(1)?;
            let Some((range, role)) = physical_slice(
                storage,
                source,
                displacement,
                request.size,
                site,
                &mut budget,
            )?
            else {
                return fail(NoFit::AddressDomain, cursor, &budget);
            };
            vec![PlacedPiece {
                storage: range,
                lsb_byte: 0,
                source_piece: 0,
                source_byte_offset: u32::try_from(displacement)
                    .map_err(|_| invalid("slice offset exceeds pool"))?,
                role,
            }]
        }
        ResolvedStorage::Join { pieces, .. } => {
            let first = geometry(storage, pieces[0].storage.address.space, site, &mut budget)?;
            // Work in logical byte coordinates without expanding any payload
            // bytes, then keep source (most-significant-first) piece order.
            let total = pieces.iter().try_fold(0_u64, |n, piece| {
                budget.charge(1)?;
                let size = piece
                    .storage
                    .size
                    .filter(|s| *s != 0)
                    .ok_or_else(|| invalid("unsized join piece"))?;
                n.checked_add(u64::from(size))
                    .ok_or_else(|| invalid("join size overflow"))
            })?;
            let end = displacement + u64::from(request.size);
            if end > total {
                return Err(invalid("slice exceeds join's physical size"));
            }
            let mut coordinate = if first.endian == Endianness::Big {
                0
            } else {
                total
            };
            let mut selected = 0;
            for piece in pieces {
                budget.charge(1)?;
                let size = u64::from(piece.storage.size.expect("validated join piece"));
                let base = if first.endian == Endianness::Big {
                    coordinate
                } else {
                    coordinate - size
                };
                selected += usize::from(displacement < base + size && base < end);
                coordinate = if first.endian == Endianness::Big {
                    coordinate + size
                } else {
                    base
                };
            }
            budget.output(selected)?;
            let mut output = Vec::with_capacity(selected);
            coordinate = if first.endian == Endianness::Big {
                0
            } else {
                total
            };
            let mut remaining = request.size;
            for (index, piece) in pieces.iter().enumerate() {
                budget.charge(1)?;
                let size = u64::from(piece.storage.size.expect("validated join piece"));
                let base = if first.endian == Endianness::Big {
                    coordinate
                } else {
                    coordinate - size
                };
                coordinate = if first.endian == Endianness::Big {
                    coordinate + size
                } else {
                    base
                };
                let left = displacement.max(base);
                let right = end.min(base + size);
                if left >= right {
                    continue;
                }
                let length = (right - left) as u32;
                let Some((range, role)) = physical_slice(
                    storage,
                    &piece.storage,
                    left - base,
                    length,
                    site,
                    &mut budget,
                )?
                else {
                    return fail(NoFit::AddressDomain, cursor, &budget);
                };
                remaining -= length;
                output.push(PlacedPiece {
                    storage: range,
                    lsb_byte: remaining,
                    source_piece: index,
                    source_byte_offset: (left - base) as u32,
                    role,
                });
            }
            if remaining != 0 {
                return Err(invalid("join slice did not cover value"));
            }
            output
        }
    };
    Ok(finish(
        PlacementOutcome::Placed(PlacedValue {
            size: request.size,
            extension: p.extension,
            storage: PlacedStorage::Bits { pieces },
        }),
        next_slot,
        &budget,
    ))
}
