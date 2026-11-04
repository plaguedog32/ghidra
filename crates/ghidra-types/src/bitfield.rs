//! Compiler-specific layout of composites that declare at least one bitfield.
//!
//! Structures follow the retained `AlignedComponentPacker` state machine and
//! `AlignedStructurePacker` final rounding. Unions follow
//! `UnionDataType.getBitFieldAllocation`/`adjustBitField` and
//! `CompositeAlignmentHelper`. Field metadata follows `BitFieldDataType` and
//! the getters of `BitFieldPackingImpl`. A bitfield-free composite never
//! reaches this module; ordinary members here use the same member rules as
//! `layout::composite`, which a crate test cross-checks.
//!
//! Java `int` state is replaced by checked `u64` arithmetic. Java's `-1`
//! sentinels are `None`: an inactive group offset, and the alignment of an
//! MS zero-width bitfield that the packer ignores.

use ghidra_languages::{Endianness, ResolvedDataOrganization};

use crate::error::Budget;
use crate::layout::{align_up, lcm, primitive, sized};
use crate::{
    BitfieldLayout, Builtin, Composite, Error, Field, FieldLayout, Geometry, MinimumAlignment,
    Packing, Result, TypeId, TypeKind, TypeLayout,
};

/// `BitFieldDataType.isValidBaseDataType`: an `AbstractIntegerDataType`
/// (char and bool included; wide chars and floats excluded), an enum, or a
/// typedef chain to either.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum BaseClass {
    Ineligible,
    Integer,
    Enum,
}

/// An alias inherits its already-computed target's class, so the class of a
/// long alias chain costs O(1) per alias rather than a walk per bitfield.
pub(crate) fn classify(kind: &TypeKind, classes: &[BaseClass]) -> BaseClass {
    match kind {
        TypeKind::Integer { .. } => BaseClass::Integer,
        TypeKind::Enum { .. } => BaseClass::Enum,
        TypeKind::Builtin(
            Builtin::WChar | Builtin::Float | Builtin::Double | Builtin::LongDouble,
        ) => BaseClass::Ineligible,
        TypeKind::Builtin(_) => BaseClass::Integer,
        TypeKind::Alias(target) => classes[target.0],
        _ => BaseClass::Ineligible,
    }
}

pub(crate) struct Context<'a> {
    pub(crate) id: TypeId,
    pub(crate) layouts: &'a [Option<TypeLayout>],
    pub(crate) classes: &'a [BaseClass],
    pub(crate) org: &'a ResolvedDataOrganization,
    pub(crate) endianness: Endianness,
}

#[derive(Debug, Clone, Copy)]
struct Base {
    /// `getBaseTypeSize()`: the declared base's raw length.
    bytes: u64,
    /// `getBaseDataType().getAlignment()`; an alias uses its target's.
    alignment: u32,
    /// `getPrimitiveBaseDataType().getAlignment()`. An enum uses the unsigned
    /// integer of its length, whose alignment can differ from the enum's.
    primitive_alignment: u32,
}

#[derive(Debug, Clone, Copy)]
enum Member {
    Ordinary {
        bytes: u64,
        alignment: u32,
    },
    Bitfield {
        declared: u32,
        effective: u32,
        base: Base,
    },
}

/// The mutable component state the retained packer reads back.
#[derive(Debug, Clone, Copy)]
struct Slot {
    member: Member,
    offset: u64,
    length: u64,
    bit_offset: u8,
}

impl Slot {
    fn bitfield(&self) -> Option<(u32, Base)> {
        match self.member {
            Member::Bitfield {
                effective, base, ..
            } => Some((effective, base)),
            Member::Ordinary { .. } => None,
        }
    }

    /// `isZeroBitFieldComponent`: the effective width is zero.
    fn is_zero(&self) -> bool {
        matches!(self.member, Member::Bitfield { effective: 0, .. })
    }
}

/// `CompositeAlignmentHelper.getPackedAlignment`.
fn packed(alignment: u32, packing: Packing) -> u32 {
    match packing {
        Packing::Explicit(cap) if cap < alignment => cap,
        _ => alignment,
    }
}

fn member(
    cx: &Context<'_>,
    index: usize,
    field: &Field,
    packing: Packing,
    budget: &mut Budget,
) -> Result<Member> {
    let g = cx.layouts[field.ty.0]
        .as_ref()
        .expect("computed field dependency")
        .geometry;
    let Some(declared) = field.bit_width else {
        // The ordinary member rules of layout::composite.
        let width = g
            .aligned_length
            .filter(|n| *n > 0)
            .ok_or(Error::InvalidField {
                owner: cx.id,
                field: index,
            })?;
        return Ok(Member::Ordinary {
            bytes: if g.is_zero_length() { 0 } else { width },
            alignment: packed(g.alignment, packing),
        });
    };
    let class = cx.classes[field.ty.0];
    let bytes = g.size.filter(|_| class != BaseClass::Ineligible);
    let Some(bytes) = bytes else {
        return Err(Error::InvalidBitfield {
            owner: cx.id,
            field: index,
            reason: "base must be an integer, enum, or alias chain to one",
        });
    };
    let primitive_alignment = if class == BaseClass::Enum {
        let width = u32::try_from(bytes).map_err(|_| Error::Overflow(cx.id))?;
        primitive(cx.id, width, cx.org, budget)?.alignment
    } else {
        g.alignment
    };
    // BitFieldDataType.getEffectiveBitSize.
    let effective = u64::from(declared).min(bytes.saturating_mul(8)) as u32;
    Ok(Member::Bitfield {
        declared,
        effective,
        base: Base {
            bytes,
            alignment: g.alignment,
            primitive_alignment,
        },
    })
}

pub(crate) fn composite(
    cx: &Context<'_>,
    c: &Composite,
    is_union: bool,
    budget: &mut Budget,
) -> Result<(Geometry, Vec<FieldLayout>)> {
    let mut members = Vec::with_capacity(c.fields.len()); // Preflight bounded total fields.
    for (index, field) in c.fields.iter().enumerate() {
        budget.charge(1)?;
        members.push(member(cx, index, field, c.packing, budget)?);
    }
    let minimum = match c.minimum_alignment {
        MinimumAlignment::Default => 1,
        MinimumAlignment::Machine => cx.org.machine_alignment,
        MinimumAlignment::Explicit(n) => n,
    };
    if is_union {
        union(cx, c, &members, minimum, budget)
    } else {
        structure(cx, c, members, minimum, budget)
    }
}

fn structure(
    cx: &Context<'_>,
    c: &Composite,
    members: Vec<Member>,
    minimum: u32,
    budget: &mut Budget,
) -> Result<(Geometry, Vec<FieldLayout>)> {
    let ms = cx.org.use_ms_bitfield_convention;
    let zero_bit_offset = match cx.endianness {
        Endianness::Big => 7,
        Endianness::Little => 0,
    };
    let slots = members
        .into_iter()
        .map(|member| Slot {
            member,
            offset: 0,
            length: 0,
            bit_offset: zero_bit_offset,
        })
        .collect();
    let mut packer = Packer {
        id: cx.id,
        ms,
        endianness: cx.endianness,
        // BitFieldPackingImpl getters force these under the MS convention.
        type_alignment_enabled: ms || cx.org.bitfield_type_alignment_enabled,
        zero_length_boundary: if ms {
            0
        } else {
            cx.org.bitfield_zero_length_boundary
        },
        packing: c.packing,
        slots,
        last: None,
        group: None,
        last_alignment: Some(1),
        zero_alignment: None,
        pending_zero: None,
        default_alignment: 1,
        budget,
    };
    let count = packer.slots.len();
    for index in 0..count {
        packer.add_component(index, index + 1 == count)?;
    }
    let length = packer.length()?;
    // AlignedStructurePacker: the minimum raises, but never lowers, alignment.
    let alignment = packer.default_alignment.max(minimum);
    let bytes = packer.budget.bytes(align_up(length, alignment, cx.id)?)?;
    let fields = c
        .fields
        .iter()
        .zip(&packer.slots)
        .map(|(field, slot)| match slot.member {
            Member::Ordinary { alignment, .. } => FieldLayout {
                ty: field.ty,
                offset: slot.offset,
                bytes: slot.length,
                alignment,
                bitfield: None,
            },
            Member::Bitfield {
                declared,
                effective,
                base,
            } => FieldLayout {
                ty: field.ty,
                offset: slot.offset,
                bytes: slot.length,
                alignment: packed(base.alignment, c.packing),
                bitfield: Some(BitfieldLayout {
                    declared_bits: declared,
                    effective_bits: effective,
                    base_bytes: base.bytes,
                    storage_bytes: if effective == 0 { 1 } else { slot.length },
                    bit_offset: slot.bit_offset,
                }),
            },
        })
        .collect();
    Ok((sized(bytes, bytes.max(1), bytes.max(1), alignment), fields))
}

/// `AlignedComponentPacker`, one method per retained method.
struct Packer<'b> {
    id: TypeId,
    ms: bool,
    endianness: Endianness,
    type_alignment_enabled: bool,
    zero_length_boundary: u32,
    packing: Packing,
    slots: Vec<Slot>,
    /// `lastComponent`; `initGroup` clears it before placing a group's first member.
    last: Option<usize>,
    /// `groupOffset`; `None` is Java's `-1`.
    group: Option<u64>,
    /// `lastAlignment`; `None` is the `-1` of an ignored MS zero-width bitfield.
    last_alignment: Option<u32>,
    /// `zeroAlignment` imposed on the successor of a deferred zero-width bitfield.
    zero_alignment: Option<u32>,
    /// A zero-width bitfield whose placement awaits its successor.
    pending_zero: Option<usize>,
    /// `defaultAlignment`, the LCM of conveyed alignments.
    default_alignment: u32,
    budget: &'b mut Budget,
}

impl Packer<'_> {
    fn add(&self, a: u64, b: u64) -> Result<u64> {
        a.checked_add(b).ok_or(Error::Overflow(self.id))
    }

    fn align(&self, alignment: u32, offset: u64) -> Result<u64> {
        align_up(offset, alignment, self.id)
    }

    fn last_is_zero(&self) -> bool {
        self.last.is_some_and(|last| self.slots[last].is_zero())
    }

    fn group(&self) -> u64 {
        self.group
            .expect("the member after a group start has an active group offset")
    }

    /// `addComponent`.
    fn add_component(&mut self, index: usize, is_last: bool) -> Result<()> {
        self.budget.charge(1)?;
        if !self.pack_component(index)? {
            self.init_group(index, is_last)?;
        }
        self.last = Some(index);
        // getComponentAlignmentLCM. Java's -1 is neutral in its LCM helper;
        // zero cannot occur because every alignment input is positive.
        if let Some(alignment) = self.last_alignment {
            let alignment = packed(alignment, self.packing);
            self.default_alignment = lcm(self.default_alignment, alignment, self.id, self.budget)?;
        }
        Ok(())
    }

    /// `getLength`. An MS bitfield group reserves its allocation unit; GCC
    /// ends at the last component, rounded after a trailing zero-width one.
    fn length(&self) -> Result<u64> {
        let Some(last) = self.last else {
            return Ok(0);
        };
        let slot = self.slots[last];
        if let (true, Some(group), Some((_, base))) = (self.ms, self.group, slot.bitfield()) {
            return self.add(group, base.bytes);
        }
        let end = self.add(slot.offset, slot.length)?;
        match slot.bitfield() {
            Some((0, base)) if !self.ms => self.align(base.alignment, end),
            _ => Ok(end),
        }
    }

    /// `getBitFieldAlignment`: GCC places packed bitfields at any byte.
    fn bitfield_alignment(&self, base: Base) -> u32 {
        if !self.ms && matches!(self.packing, Packing::Explicit(_)) {
            1
        } else {
            packed(base.alignment, self.packing)
        }
    }

    /// `getZeroBitFieldAlignment`; `None` is an ignored MS zero-width bitfield.
    fn zero_field_alignment(&self, base: Base, is_last: bool) -> Option<u32> {
        // isIgnoredZeroBitField: MS ignores one without a preceding bitfield.
        let after_bitfield = self
            .last
            .is_some_and(|last| self.slots[last].bitfield().is_some());
        if self.ms && !after_bitfield {
            return None;
        }
        if !self.type_alignment_enabled {
            return Some(self.zero_length_boundary.max(1));
        }
        // GCC ignores packing for an interior zero-width bitfield.
        let packing = if !self.ms && !is_last {
            Packing::Default
        } else {
            self.packing
        };
        Some(packed(base.alignment, packing))
    }

    /// The retained packer never re-places a non-final zero-width bitfield
    /// whose successor is also zero-width; Java keeps its previous,
    /// history-dependent offset. Policy: use the offset it receives under
    /// declaration-order construction, where it was last laid out as the
    /// trailing member. GCC's next group offset is read from this offset.
    fn settle_pending_zero(&mut self) -> Result<()> {
        let Some(index) = self.pending_zero.take() else {
            return Ok(());
        };
        let (_, base) = self.slots[index]
            .bitfield()
            .expect("a pending member is a zero-width bitfield");
        let offset = self.align(base.alignment, self.group())?;
        self.budget.bytes(offset)?;
        self.slots[index].offset = offset;
        Ok(())
    }

    /// `initGroup`.
    fn init_group(&mut self, index: usize, is_last: bool) -> Result<()> {
        self.settle_pending_zero()?;
        let group = self.length()?;
        self.group = Some(group);
        self.last_alignment = Some(1);
        match self.slots[index].member {
            Member::Bitfield {
                effective: 0, base, ..
            } => {
                let alignment = self.zero_field_alignment(base, is_last);
                if is_last {
                    // A trailing zero-width bitfield uses its natural base
                    // alignment for placement, regardless of packing.
                    let offset = self.align(base.alignment, group)?;
                    self.update(index, offset, 0, Some(alignment.unwrap_or(1)))?;
                    self.group = None;
                } else {
                    // Deferred: the successor fixes this offset.
                    self.zero_alignment = alignment;
                    if self.ms {
                        self.last_alignment = alignment;
                    }
                    self.pending_zero = Some(index);
                }
            }
            Member::Bitfield {
                effective, base, ..
            } => {
                self.last = None;
                self.pack_bitfield(index, effective, base)?;
            }
            Member::Ordinary { bytes, alignment } => {
                self.last = None;
                self.pack_ordinary(index, bytes, alignment, group)?;
            }
        }
        Ok(())
    }

    /// `adjustZeroLengthBitField`: the zero-width bitfield and its successor
    /// share the later of the two aligned offsets.
    fn adjust_zero(&mut self, minimum: Option<u32>) -> Result<()> {
        let index = self.last.expect("a zero-width bitfield precedes");
        let group = self.group();
        let natural = match minimum {
            Some(alignment) => self.align(alignment, group)?,
            None => group,
        };
        let forced = match self.zero_alignment {
            Some(alignment) => self.align(alignment, group)?,
            None => group,
        };
        let group = natural.max(forced);
        self.group = Some(group);
        self.pending_zero = None;
        self.update(index, group, 0, minimum)
    }

    /// `packComponent`; `false` starts a new group.
    fn pack_component(&mut self, index: usize) -> Result<bool> {
        let Some(last) = self.last else {
            return Ok(false);
        };
        let slot = self.slots[index];
        if slot.is_zero() {
            return Ok(false);
        }
        let previous = self.slots[last];
        let after_zero = previous.is_zero();
        match slot.member {
            Member::Bitfield {
                effective, base, ..
            } => {
                if !after_zero && self.ms {
                    match previous.bitfield() {
                        None => return Ok(false),
                        // Only the base byte size groups MS bitfields.
                        Some((_, previous_base)) if previous_base.bytes != base.bytes => {
                            return Ok(false);
                        }
                        Some(_) => (),
                    }
                }
                self.pack_bitfield(index, effective, base)?;
            }
            Member::Ordinary { bytes, alignment } => {
                if !after_zero && self.ms {
                    return Ok(false);
                }
                let offset = if after_zero {
                    self.group()
                } else {
                    self.add(previous.offset, previous.length)?
                };
                self.pack_ordinary(index, bytes, alignment, offset)?;
            }
        }
        Ok(true)
    }

    /// `alignAndPackNonBitfieldComponent`.
    fn pack_ordinary(
        &mut self,
        index: usize,
        bytes: u64,
        alignment: u32,
        minimum_offset: u64,
    ) -> Result<()> {
        let offset = if self.last_is_zero() {
            self.adjust_zero(Some(alignment))?;
            self.group()
        } else {
            let offset = self.align(alignment, minimum_offset)?;
            if self.last.is_none() {
                self.group = Some(offset);
            }
            offset
        };
        self.update(index, offset, bytes, Some(alignment))
    }

    /// `alignAndPackBitField` and `setBitFieldDataType`.
    fn pack_bitfield(&mut self, index: usize, effective: u32, base: Base) -> Result<()> {
        if self.last_is_zero() {
            let minimum = if self.ms {
                Some(self.bitfield_alignment(base))
            } else {
                self.zero_alignment
            };
            self.adjust_zero(minimum)?;
        }
        // The packed primitive alignment is conveyed even if placement uses less.
        let mut alignment = packed(base.primitive_alignment, self.packing);
        self.last_alignment = self.last_alignment.max(Some(alignment));
        let effective = u64::from(effective);
        let (offset, consumed) = match self.last {
            None => {
                let offset = self.align(alignment, self.group())?;
                self.group = Some(offset);
                (offset, 0)
            }
            Some(last) if self.slots[last].is_zero() => (self.group(), 0),
            Some(last) => {
                alignment = self.bitfield_alignment(base);
                self.continuation(effective, base, alignment, self.slots[last])?
            }
        };
        let storage = (effective + consumed).div_ceil(8);
        let bit_offset = match self.endianness {
            Endianness::Big => 8 * storage - effective - consumed,
            Endianness::Little => consumed,
        };
        self.slots[index].bit_offset =
            u8::try_from(bit_offset).expect("minimal storage leaves at most seven spare bits");
        self.update(index, offset, storage, Some(alignment))
    }

    /// Placement after a nonzero component: returns the byte offset and the
    /// bits of that byte already consumed.
    fn continuation(
        &mut self,
        effective: u64,
        base: Base,
        alignment: u32,
        previous: Slot,
    ) -> Result<(u64, u64)> {
        let (mut offset, mut consumed, previous_unit) = match previous.bitfield() {
            Some((previous_bits, previous_base)) => {
                // getEndOffset of a nonzero bitfield: its last storage byte.
                let end = self.add(previous.offset, previous.length - 1)?;
                let consumed = match self.endianness {
                    // Filled left to right; 8 means the byte is full.
                    Endianness::Big => 8 - u64::from(previous.bit_offset),
                    // Filled right to left; 0 means the byte is full.
                    Endianness::Little => {
                        (u64::from(previous_bits) + u64::from(previous.bit_offset)) % 8
                    }
                };
                if consumed == 0 || consumed == 8 {
                    (self.add(end, 1)?, 0, Some(previous_base.bytes))
                } else {
                    (end, consumed, Some(previous_base.bytes))
                }
            }
            None => (self.add(previous.offset, previous.length)?, 0, None),
        };
        let tentative = (effective + consumed).div_ceil(8);
        let mut end = self.add(offset, tentative - 1)?;
        let step = u64::from(alignment);
        if offset % step != 0 || tentative > base.bytes {
            // Java tests end >= align(offset) - alignment + baseSize, whose
            // left base can be negative; add the alignment to both sides.
            let unit_end = self.add(self.align(alignment, offset)?, base.bytes)?;
            if self.add(end, step)? >= unit_end {
                offset = self.align(alignment, self.add(offset, 1)?)?;
                // The tentative size is retained here, as in the source.
                end = self.add(offset, tentative - 1)?;
                consumed = 0;
            }
        }
        let crossed = match (self.group, previous_unit) {
            (Some(group), Some(unit)) => end >= self.add(group, unit)?,
            _ => false,
        };
        if crossed {
            // MS starts a new allocation unit here; GCC clears the marker.
            self.group = if self.ms { Some(offset) } else { None };
        }
        Ok((offset, consumed))
    }

    /// `updateComponent`.
    fn update(
        &mut self,
        index: usize,
        offset: u64,
        length: u64,
        alignment: Option<u32>,
    ) -> Result<()> {
        self.budget.bytes(self.add(offset, length)?)?;
        let slot = &mut self.slots[index];
        slot.offset = offset;
        slot.length = length;
        self.last_alignment = self.last_alignment.max(alignment);
        Ok(())
    }
}

/// Union members share offset zero. Bitfields keep minimal normalized storage
/// but contribute a compiler-specific allocation to the union length.
fn union(
    cx: &Context<'_>,
    c: &Composite,
    members: &[Member],
    minimum: u32,
    budget: &mut Budget,
) -> Result<(Geometry, Vec<FieldLayout>)> {
    let ms = cx.org.use_ms_bitfield_convention;
    let mut fields = Vec::with_capacity(members.len());
    let mut length = 0;
    let mut alignment = 1;
    for (field, member) in c.fields.iter().zip(members) {
        budget.charge(1)?;
        let (layout, allocation, imparts) = match *member {
            Member::Ordinary {
                bytes,
                alignment: field_alignment,
            } => {
                let layout = FieldLayout {
                    ty: field.ty,
                    offset: 0,
                    bytes,
                    alignment: field_alignment,
                    bitfield: None,
                };
                (layout, bytes, true)
            }
            Member::Bitfield {
                declared,
                effective,
                base,
            } => {
                let bits = u64::from(effective);
                // UnionDataType.adjustBitField: offset zero, minimal storage.
                let storage = bits.div_ceil(8).max(1);
                let bit_offset = match cx.endianness {
                    Endianness::Little => 0,
                    Endianness::Big if effective == 0 => 7,
                    Endianness::Big => 8 * storage - bits,
                };
                // getBitFieldAllocation.
                let allocation = if ms {
                    // MS allocates the whole base, even for zero width.
                    base.bytes
                } else if effective == 0 {
                    0
                } else {
                    match c.packing {
                        // Literally LCM(minimal storage, pack), per source.
                        Packing::Explicit(cap) if base.bytes > u64::from(cap) => {
                            lcm64(storage, u64::from(cap), cx.id, budget)?
                        }
                        _ => base.bytes,
                    }
                };
                let layout = FieldLayout {
                    ty: field.ty,
                    offset: 0,
                    bytes: if effective == 0 { 0 } else { storage },
                    alignment: packed(base.alignment, c.packing),
                    bitfield: Some(BitfieldLayout {
                        declared_bits: declared,
                        effective_bits: effective,
                        base_bytes: base.bytes,
                        storage_bytes: storage,
                        bit_offset: u8::try_from(bit_offset)
                            .expect("minimal storage leaves at most seven spare bits"),
                    }),
                };
                // GCC unions ignore a zero-width bitfield's alignment.
                (layout, allocation, ms || effective != 0)
            }
        };
        if imparts {
            alignment = lcm(alignment, layout.alignment, cx.id, budget)?;
        }
        // Every allocation covers its member's minimal storage.
        length = length.max(budget.bytes(allocation)?);
        fields.push(layout);
    }
    alignment = lcm(alignment, minimum, cx.id, budget)?;
    if cx.org.absolute_max_alignment != 0 {
        alignment = alignment.min(cx.org.absolute_max_alignment);
    }
    let bytes = budget.bytes(align_up(length, alignment, cx.id)?)?;
    Ok((sized(bytes, bytes.max(1), bytes.max(1), alignment), fields))
}

fn lcm64(first: u64, second: u64, id: TypeId, budget: &mut Budget) -> Result<u64> {
    let (mut a, mut b) = (first, second);
    while b != 0 {
        budget.charge(1)?;
        (a, b) = (b, a % b);
    }
    (first / a).checked_mul(second).ok_or(Error::Overflow(id))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ghidra_languages::{DataOrganization, SizeAlignment};

    use crate::layout::FORCE_BITFIELD_PACKER;
    use crate::{
        Builtin, Composite, Endianness, Field, Limits, MinimumAlignment, Packing, TypeDefinition,
        TypeId, TypeKind, TypeLayouts,
    };

    struct Deterministic(u64);

    impl Deterministic {
        fn pick(&mut self, bound: usize) -> usize {
            self.0 = self
                .0
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            ((self.0 >> 24) % bound as u64) as usize
        }
    }

    fn map(entries: &[(u32, u32)]) -> Vec<SizeAlignment> {
        entries
            .iter()
            .map(|&(size, alignment)| SizeAlignment { size, alignment })
            .collect()
    }

    /// Includes nonpower, descending, capped and empty size maps, where the
    /// GCC running-maximum and MS per-member conveyance differ.
    fn profiles() -> Vec<crate::ResolvedDataOrganization> {
        let conventional = DataOrganization::default().resolve(8);
        let mut nonpower = conventional.clone();
        nonpower.size_alignment_map = map(&[(1, 1), (2, 2), (3, 3), (4, 4), (6, 6)]);
        let mut descending = conventional.clone();
        descending.absolute_max_alignment = 8;
        descending.size_alignment_map = map(&[(1, 8), (4, 2), (8, 1), (16, 16)]);
        let mut capped = conventional.clone();
        capped.absolute_max_alignment = 4;
        capped.machine_alignment = 16;
        let mut empty = conventional.clone();
        empty.size_alignment_map.clear();
        empty.default_alignment = 8;
        vec![conventional, nonpower, descending, capped, empty]
    }

    fn graph(random: &mut Deterministic) -> Vec<TypeDefinition> {
        let mut kinds = Vec::new();
        for bytes in [1, 2, 3, 4, 5, 6, 8, 12, 16] {
            kinds.push(TypeKind::Integer {
                bytes,
                signed: false,
            });
            kinds.push(TypeKind::Opaque { bytes });
        }
        for bytes in 1..=8 {
            kinds.push(TypeKind::Enum {
                bytes,
                signed: true,
            });
        }
        kinds.push(TypeKind::Builtin(Builtin::LongDouble));
        kinds.push(TypeKind::Pointer {
            target: TypeId(0),
            bytes: None,
        });
        kinds.push(TypeKind::Pointer {
            target: TypeId(0),
            bytes: Some(3),
        });
        for minimum in [MinimumAlignment::Default, MinimumAlignment::Explicit(16)] {
            kinds.push(TypeKind::Structure(Composite {
                minimum_alignment: minimum,
                ..Default::default()
            }));
        }
        kinds.push(TypeKind::Array {
            element: TypeId(2),
            count: 0,
        });
        let packs = [None, Some(1), Some(2), Some(3), Some(4), Some(8)];
        let minima = [
            MinimumAlignment::Default,
            MinimumAlignment::Machine,
            MinimumAlignment::Explicit(3),
            MinimumAlignment::Explicit(8),
        ];
        for _ in 0..4 {
            let available = kinds.len();
            for _ in 0..16 {
                let kind = match random.pick(5) {
                    0 => TypeKind::Alias(TypeId(random.pick(available))),
                    1 => TypeKind::Array {
                        element: TypeId(random.pick(available)),
                        count: random.pick(4) as u64,
                    },
                    choice => {
                        let composite = Composite {
                            fields: (0..random.pick(8))
                                .map(|_| Field::new("", TypeId(random.pick(available))))
                                .collect(),
                            packing: packs[random.pick(packs.len())]
                                .map_or(Packing::Default, Packing::Explicit),
                            minimum_alignment: minima[random.pick(minima.len())],
                        };
                        if choice == 2 {
                            TypeKind::Union(composite)
                        } else {
                            TypeKind::Structure(composite)
                        }
                    }
                };
                kinds.push(kind);
            }
        }
        kinds
            .into_iter()
            .map(|kind| TypeDefinition::new("", kind))
            .collect()
    }

    /// Ordinary members in the bitfield packer must reproduce the unchanged
    /// ordinary path, so a correction to one cannot silently miss the other.
    #[test]
    fn bitfield_packer_reproduces_the_ordinary_path_without_bitfields() {
        let mut composites = 0;
        for (profile, organization) in profiles().into_iter().enumerate() {
            for ms in [false, true] {
                let mut org = organization.clone();
                org.use_ms_bitfield_convention = ms;
                let mut random = Deterministic(0x0bd1_7f1e ^ (profile as u64) << 1 ^ u64::from(ms));
                for _ in 0..24 {
                    let definitions: Arc<[TypeDefinition]> = graph(&mut random).into();
                    let build = |force: bool| {
                        FORCE_BITFIELD_PACKER.with(|flag| flag.set(force));
                        let layouts = TypeLayouts::new_with_endianness(
                            definitions.clone(),
                            org.clone(),
                            Endianness::Little,
                            Limits::default(),
                        );
                        FORCE_BITFIELD_PACKER.with(|flag| flag.set(false));
                        layouts.unwrap()
                    };
                    assert_eq!(
                        build(true).layouts(),
                        build(false).layouts(),
                        "profile {profile}, MS={ms}"
                    );
                    composites += definitions
                        .iter()
                        .filter(|d| matches!(d.kind, TypeKind::Structure(_) | TypeKind::Union(_)))
                        .count();
                }
            }
        }
        assert!(composites > 5_000, "{composites}");
    }
}
