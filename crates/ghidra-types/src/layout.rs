use std::sync::Arc;

use ghidra_languages::{Endianness, ResolvedDataOrganization};

use crate::bitfield::{self, BaseClass};
use crate::error::{Budget, count};
use crate::{
    Builtin, Composite, Error, Field, FieldLayout, Geometry, Limits, MAX_BITFIELD_BITS,
    MinimumAlignment, Packing, Resource, Result, TypeDefinition, TypeId, TypeKind, TypeLayout,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LayoutStats {
    pub types: usize,
    pub fields: usize,
    pub references: usize,
    pub name_bytes: usize,
    /// Maximum active by-value dependency stack, including the current type.
    pub depth: usize,
    pub work: u64,
}

/// An immutable layout of the entire input graph. Every input, including an
/// unreferenced type, is validated. The supplied definitions remain unchanged.
#[derive(Debug, Clone)]
pub struct TypeLayouts {
    definitions: Arc<[TypeDefinition]>,
    organization: ResolvedDataOrganization,
    endianness: Option<Endianness>,
    layouts: Vec<TypeLayout>,
    stats: LayoutStats,
    limits: Limits,
}

impl TypeLayouts {
    /// Lays out a graph without a byte order. A declared bitfield fails with
    /// [`Error::EndiannessRequired`]; ordinary graphs are unaffected.
    pub fn new(
        definitions: Arc<[TypeDefinition]>,
        organization: ResolvedDataOrganization,
        limits: Limits,
    ) -> Result<Self> {
        Self::build(definitions, organization, None, limits)
    }

    /// Lays out a graph with the program's byte order, which determines
    /// normalized bitfield bit offsets. The caller supplies it explicitly; it
    /// is never taken from the host or the compiler specification.
    pub fn new_with_endianness(
        definitions: Arc<[TypeDefinition]>,
        organization: ResolvedDataOrganization,
        endianness: Endianness,
        limits: Limits,
    ) -> Result<Self> {
        Self::build(definitions, organization, Some(endianness), limits)
    }

    fn build(
        definitions: Arc<[TypeDefinition]>,
        organization: ResolvedDataOrganization,
        endianness: Option<Endianness>,
        limits: Limits,
    ) -> Result<Self> {
        let mut budget = Budget { limits, work: 0 };
        let mut stats = validate(&definitions, &organization, endianness, &mut budget)?;
        // Counts have been bounded before any node-indexed output is allocated.
        let mut layouts: Vec<Option<TypeLayout>> = vec![None; definitions.len()];
        // Bitfield-base classes propagate through aliases in dependency order,
        // so no bitfield walks an alias chain.
        let mut classes = vec![BaseClass::Ineligible; definitions.len()];
        let mut states = vec![0u8; definitions.len()];
        let mut stack = Vec::new();
        for root in 0..definitions.len() {
            budget.charge(1)?;
            if states[root] != 0 {
                continue;
            }
            push(
                TypeId(root),
                &mut stack,
                &mut states,
                &mut stats,
                &mut budget,
            )?;
            while let Some((id, next)) = stack.last_mut() {
                budget.charge(1)?;
                if let Some(child) = dependency(&definitions[id.0].kind, *next) {
                    *next += 1;
                    match states[child.0] {
                        0 => push(child, &mut stack, &mut states, &mut stats, &mut budget)?,
                        1 => {
                            return Err(Error::ByValueCycle {
                                owner: *id,
                                target: child,
                            });
                        }
                        _ => (),
                    }
                } else {
                    let id = *id;
                    let kind = &definitions[id.0].kind;
                    let layout = compute(
                        id,
                        kind,
                        &layouts,
                        &classes,
                        &organization,
                        endianness,
                        &mut budget,
                    )?;
                    classes[id.0] = bitfield::classify(kind, &classes);
                    layouts[id.0] = Some(layout);
                    states[id.0] = 2;
                    stack.pop();
                }
            }
        }
        budget.charge(definitions.len() as u64)?;
        let layouts = layouts
            .into_iter()
            .map(|n| n.expect("each validated node was visited"))
            .collect();
        stats.work = budget.work;
        Ok(Self {
            definitions,
            organization,
            endianness,
            layouts,
            stats,
            limits,
        })
    }

    pub fn definitions(&self) -> &[TypeDefinition] {
        &self.definitions
    }
    pub fn shared_definitions(&self) -> Arc<[TypeDefinition]> {
        self.definitions.clone()
    }
    pub fn organization(&self) -> &ResolvedDataOrganization {
        &self.organization
    }
    /// The byte order supplied at construction, if any.
    pub fn endianness(&self) -> Option<Endianness> {
        self.endianness
    }
    pub fn layouts(&self) -> &[TypeLayout] {
        &self.layouts
    }
    pub fn layout(&self, id: TypeId) -> Result<&TypeLayout> {
        self.layouts.get(id.0).ok_or(Error::UnknownType(id))
    }
    pub fn definition(&self, id: TypeId) -> Result<&TypeDefinition> {
        self.definitions.get(id.0).ok_or(Error::UnknownType(id))
    }
    pub fn stats(&self) -> LayoutStats {
        self.stats
    }
    pub fn limits(&self) -> Limits {
        self.limits
    }
}

fn push(
    id: TypeId,
    stack: &mut Vec<(TypeId, usize)>,
    states: &mut [u8],
    stats: &mut LayoutStats,
    budget: &mut Budget,
) -> Result<()> {
    budget.charge(1)?;
    if stack.len() >= budget.limits.max_depth {
        return Err(Error::Limit(Resource::Depth));
    }
    states[id.0] = 1;
    stack.push((id, 0));
    stats.depth = stats.depth.max(stack.len());
    Ok(())
}

/// Pointer targets and function signatures do not determine their own widths.
fn dependency(kind: &TypeKind, index: usize) -> Option<TypeId> {
    match kind {
        TypeKind::Alias(id) if index == 0 => Some(*id),
        TypeKind::Array { element, .. } if index == 0 => Some(*element),
        TypeKind::Structure(c) | TypeKind::Union(c) => c.fields.get(index).map(|f| f.ty),
        _ => None,
    }
}

fn validate(
    defs: &[TypeDefinition],
    org: &ResolvedDataOrganization,
    endianness: Option<Endianness>,
    budget: &mut Budget,
) -> Result<LayoutStats> {
    let mut stats = LayoutStats::default();
    count(
        &mut stats.types,
        defs.len(),
        budget.limits.max_types,
        Resource::Types,
    )?;
    if org.size_alignment_map.len() > budget.limits.max_alignment_entries {
        return Err(Error::Limit(Resource::AlignmentEntries));
    }
    // All geometry is explicitly supplied, not host-dependent. A malformed
    // hand-built map is rejected rather than fed to binary search.
    for n in [
        org.machine_alignment,
        org.default_alignment,
        org.default_pointer_alignment,
        org.pointer_size,
        org.char_size,
        org.wchar_size,
        org.short_size,
        org.integer_size,
        org.long_size,
        org.long_long_size,
        org.float_size,
        org.double_size,
        org.long_double_size,
    ] {
        budget.charge(1)?;
        if n == 0 {
            return Err(Error::InvalidOrganization("zero size or alignment"));
        }
    }
    let mut previous = None;
    for entry in &org.size_alignment_map {
        budget.charge(1)?;
        if entry.size == 0 || entry.alignment == 0 {
            return Err(Error::InvalidOrganization("zero size-map key or alignment"));
        }
        if previous.is_some_and(|p| p >= entry.size) {
            return Err(Error::InvalidOrganization(
                "size map must be strictly increasing",
            ));
        }
        previous = Some(entry.size);
    }
    // Length-only preflight precedes reading field/parameter contents.
    for def in defs {
        budget.charge(1)?;
        match &def.kind {
            TypeKind::Structure(c) | TypeKind::Union(c) => {
                count(
                    &mut stats.fields,
                    c.fields.len(),
                    budget.limits.max_fields,
                    Resource::Fields,
                )?;
                count(
                    &mut stats.references,
                    c.fields.len(),
                    budget.limits.max_references,
                    Resource::References,
                )?;
            }
            TypeKind::Function { parameters, .. } => {
                count(
                    &mut stats.references,
                    1,
                    budget.limits.max_references,
                    Resource::References,
                )?;
                count(
                    &mut stats.references,
                    parameters.len(),
                    budget.limits.max_references,
                    Resource::References,
                )?;
            }
            TypeKind::Pointer { .. } | TypeKind::Array { .. } | TypeKind::Alias(_) => {
                count(
                    &mut stats.references,
                    1,
                    budget.limits.max_references,
                    Resource::References,
                )?;
            }
            _ => (),
        }
    }
    for (index, def) in defs.iter().enumerate() {
        budget.charge(1)?;
        let id = TypeId(index);
        name(&def.name, &mut stats, budget)?;
        let reference = |target: TypeId| {
            if target.0 < defs.len() {
                Ok(())
            } else {
                Err(Error::InvalidReference { owner: id, target })
            }
        };
        match &def.kind {
            TypeKind::Integer { bytes, .. }
            | TypeKind::Float { bytes }
            | TypeKind::Opaque { bytes } => {
                if *bytes == 0 {
                    return Err(invalid(id, "zero-width scalar"));
                }
            }
            TypeKind::Enum { bytes, .. } => {
                if !(1..=8).contains(bytes) {
                    return Err(invalid(id, "enum width must be 1..=8"));
                }
            }
            TypeKind::Pointer { target, bytes } => {
                if *bytes == Some(0) {
                    return Err(invalid(id, "zero-width pointer"));
                }
                budget.charge(1)?;
                reference(*target)?;
            }
            TypeKind::Array { element, .. } | TypeKind::Alias(element) => {
                budget.charge(1)?;
                reference(*element)?;
            }
            TypeKind::Function {
                result, parameters, ..
            } => {
                budget.charge(1)?;
                reference(*result)?;
                for target in parameters {
                    budget.charge(1)?;
                    reference(*target)?;
                }
            }
            TypeKind::Structure(c) | TypeKind::Union(c) => {
                if c.packing == Packing::Explicit(0) {
                    return Err(invalid(id, "zero explicit packing"));
                }
                if c.minimum_alignment == MinimumAlignment::Explicit(0) {
                    return Err(invalid(id, "zero explicit minimum alignment"));
                }
                for (index, field) in c.fields.iter().enumerate() {
                    budget.charge(1)?;
                    name(&field.name, &mut stats, budget)?;
                    reference(field.ty)?;
                    bitfield_declaration(id, index, field, endianness)?;
                }
            }
            _ => (),
        }
    }
    Ok(stats)
}

/// Width and byte-order checks need no other type. Base eligibility is checked
/// during layout from the propagated class.
fn bitfield_declaration(
    owner: TypeId,
    field: usize,
    declaration: &Field,
    endianness: Option<Endianness>,
) -> Result<()> {
    let Some(bits) = declaration.bit_width else {
        return Ok(());
    };
    if bits > MAX_BITFIELD_BITS {
        return Err(Error::InvalidBitfield {
            owner,
            field,
            reason: "declared width exceeds 255 bits",
        });
    }
    if endianness.is_none() {
        return Err(Error::EndiannessRequired { owner, field });
    }
    Ok(())
}

fn name(name: &str, stats: &mut LayoutStats, budget: &Budget) -> Result<()> {
    if name.len() > budget.limits.max_name_length {
        return Err(Error::Limit(Resource::NameLength));
    }
    count(
        &mut stats.name_bytes,
        name.len(),
        budget.limits.max_name_bytes,
        Resource::NameBytes,
    )
}

fn invalid(ty: TypeId, reason: &'static str) -> Error {
    Error::InvalidType { ty, reason }
}

fn compute(
    id: TypeId,
    kind: &TypeKind,
    layouts: &[Option<TypeLayout>],
    classes: &[BaseClass],
    org: &ResolvedDataOrganization,
    endianness: Option<Endianness>,
    budget: &mut Budget,
) -> Result<TypeLayout> {
    budget.charge(1)?;
    let mut array_stride = None;
    let mut fields = Vec::new();
    let child = |id: TypeId| {
        layouts[id.0]
            .as_ref()
            .expect("by-value dependency was computed")
            .geometry
    };
    let geometry = match kind {
        TypeKind::Void => sized(0, 0, 0, 1),
        TypeKind::Incomplete | TypeKind::Function { .. } => Geometry {
            size: None,
            length: None,
            aligned_length: None,
            alignment: 1,
        },
        TypeKind::Builtin(builtin) => primitive(id, builtin_size(*builtin, org), org, budget)?,
        TypeKind::Integer { bytes, .. }
        | TypeKind::Float { bytes }
        | TypeKind::Opaque { bytes } => primitive(id, *bytes, org, budget)?,
        TypeKind::Enum { bytes, .. } => {
            let bytes = budget.bytes(u64::from(*bytes))?;
            sized(bytes, bytes, bytes, size_alignment(bytes, org, budget)?)
        }
        TypeKind::Pointer { bytes, .. } => {
            let bytes = bytes.unwrap_or(org.pointer_size);
            budget.bytes(u64::from(bytes))?;
            lookup_work(org, budget)?;
            let alignment = if org.alignment_for_size(bytes).is_some() {
                size_alignment(u64::from(bytes), org, budget)?
            } else {
                // Deliberately not clamped by absolute_max_alignment.
                org.default_pointer_alignment
            };
            sized(
                u64::from(bytes),
                u64::from(bytes),
                u64::from(bytes),
                alignment,
            )
        }
        TypeKind::Alias(target) => child(*target),
        TypeKind::Array { element, count } => {
            let element_geometry = child(*element);
            let stride = element_geometry.aligned_length.filter(|n| *n > 0).ok_or(
                Error::InvalidElement {
                    owner: id,
                    element: *element,
                },
            )?;
            array_stride = Some(stride);
            let bytes = budget.bytes(stride.checked_mul(*count).ok_or(Error::Overflow(id))?)?;
            sized(
                bytes,
                bytes.max(1),
                bytes.max(1),
                element_geometry.alignment,
            )
        }
        TypeKind::Structure(c) | TypeKind::Union(c) => {
            let is_union = matches!(kind, TypeKind::Union(_));
            // A bitfield-free composite keeps the ordinary path below.
            let (g, f) = if uses_bitfield_packer(c) {
                let context = bitfield::Context {
                    id,
                    layouts,
                    classes,
                    org,
                    endianness: endianness.expect("validation requires a byte order"),
                };
                bitfield::composite(&context, c, is_union, budget)?
            } else {
                composite(id, c, is_union, layouts, org, budget)?
            };
            fields = f;
            g
        }
    };
    // In particular, the one-byte display placeholder is also bounded.
    for length in [geometry.size, geometry.length, geometry.aligned_length]
        .into_iter()
        .flatten()
    {
        budget.bytes(length)?;
    }
    Ok(TypeLayout {
        geometry,
        fields,
        array_stride,
    })
}

#[cfg(test)]
thread_local! {
    /// Test hook: also route bitfield-free composites through the bitfield
    /// packer, so a crate test can require both paths to agree.
    pub(crate) static FORCE_BITFIELD_PACKER: std::cell::Cell<bool> =
        const { std::cell::Cell::new(false) };
}

fn uses_bitfield_packer(c: &Composite) -> bool {
    #[cfg(test)]
    if FORCE_BITFIELD_PACKER.with(std::cell::Cell::get) {
        return true;
    }
    c.fields.iter().any(Field::is_bitfield)
}

pub(crate) fn sized(size: u64, length: u64, aligned_length: u64, alignment: u32) -> Geometry {
    Geometry {
        size: Some(size),
        length: Some(length),
        aligned_length: Some(aligned_length),
        alignment,
    }
}

pub(crate) fn primitive(
    id: TypeId,
    bytes: u32,
    org: &ResolvedDataOrganization,
    budget: &mut Budget,
) -> Result<Geometry> {
    let bytes = budget.bytes(u64::from(bytes))?;
    let first_alignment = size_alignment(bytes, org, budget)?;
    let aligned_length = budget.bytes(align_up(bytes, first_alignment, id)?)?;
    let alignment = size_alignment(aligned_length, org, budget)?;
    Ok(sized(bytes, bytes, aligned_length, alignment))
}

fn builtin_size(builtin: Builtin, org: &ResolvedDataOrganization) -> u32 {
    match builtin {
        Builtin::Bool => 1,
        Builtin::Char | Builtin::SignedChar | Builtin::UnsignedChar => org.char_size,
        Builtin::WChar => org.wchar_size,
        Builtin::Short | Builtin::UnsignedShort => org.short_size,
        Builtin::Int | Builtin::UnsignedInt => org.integer_size,
        Builtin::Long | Builtin::UnsignedLong => org.long_size,
        Builtin::LongLong | Builtin::UnsignedLongLong => org.long_long_size,
        Builtin::Float => org.float_size,
        Builtin::Double => org.double_size,
        Builtin::LongDouble => org.long_double_size,
    }
}

fn lookup_work(org: &ResolvedDataOrganization, budget: &mut Budget) -> Result<()> {
    budget.charge(if org.size_alignment_map.is_empty() {
        1
    } else {
        u64::from(org.size_alignment_map.len().ilog2()) + 2
    })
}

/// Unlike ResolvedDataOrganization::alignment_for_size's exact lookup, the
/// datatype API uses the greatest size-map key <= the requested size.
fn size_alignment(bytes: u64, org: &ResolvedDataOrganization, budget: &mut Budget) -> Result<u32> {
    lookup_work(org, budget)?;
    let position = org
        .size_alignment_map
        .partition_point(|e| u64::from(e.size) <= bytes);
    let alignment = position.checked_sub(1).map_or(org.default_alignment, |i| {
        org.size_alignment_map[i].alignment
    });
    Ok(if org.absolute_max_alignment == 0 {
        alignment
    } else {
        alignment.min(org.absolute_max_alignment)
    })
}

pub(crate) fn align_up(bytes: u64, alignment: u32, id: TypeId) -> Result<u64> {
    let alignment = u64::from(alignment);
    let remainder = bytes % alignment;
    bytes
        .checked_add(if remainder == 0 {
            0
        } else {
            alignment - remainder
        })
        .ok_or(Error::Overflow(id))
}

pub(crate) fn lcm(mut a: u32, mut b: u32, id: TypeId, budget: &mut Budget) -> Result<u32> {
    let product_a = a;
    let product_b = b;
    while b != 0 {
        budget.charge(1)?;
        (a, b) = (b, a % b);
    }
    (product_a / a)
        .checked_mul(product_b)
        .ok_or(Error::Overflow(id))
}

fn composite(
    id: TypeId,
    c: &Composite,
    is_union: bool,
    layouts: &[Option<TypeLayout>],
    org: &ResolvedDataOrganization,
    budget: &mut Budget,
) -> Result<(Geometry, Vec<FieldLayout>)> {
    let mut fields = Vec::with_capacity(c.fields.len()); // Preflight bounded total fields.
    let mut bytes = 0;
    let mut alignment = 1;
    let mut group_alignment = 1;
    for (index, field) in c.fields.iter().enumerate() {
        budget.charge(1)?;
        let g = layouts[field.ty.0]
            .as_ref()
            .expect("computed field dependency")
            .geometry;
        let width = g
            .aligned_length
            .filter(|n| *n > 0)
            .ok_or(Error::InvalidField {
                owner: id,
                field: index,
            })?;
        let field_bytes = if g.is_zero_length() { 0 } else { width };
        let field_alignment = match c.packing {
            Packing::Default => g.alignment,
            Packing::Explicit(cap) => g.alignment.min(cap),
        };
        // GCC retains one ordinary-component group; its running maximum is
        // conveyed after each field. MS starts a fresh group per ordinary field.
        // This differs from a direct LCM only for non-power-of-two alignments.
        group_alignment = if is_union || org.use_ms_bitfield_convention {
            field_alignment
        } else {
            group_alignment.max(field_alignment)
        };
        alignment = lcm(alignment, group_alignment, id, budget)?;
        let offset = if is_union {
            0
        } else {
            align_up(bytes, field_alignment, id)?
        };
        let end = budget.bytes(offset.checked_add(field_bytes).ok_or(Error::Overflow(id))?)?;
        bytes = if is_union { bytes.max(end) } else { end };
        fields.push(FieldLayout {
            ty: field.ty,
            offset,
            bytes: field_bytes,
            alignment: field_alignment,
            bitfield: None,
        });
    }
    let minimum = match c.minimum_alignment {
        MinimumAlignment::Default => 1,
        MinimumAlignment::Machine => org.machine_alignment,
        MinimumAlignment::Explicit(n) => n,
    };
    if is_union {
        alignment = lcm(alignment, minimum, id, budget)?;
        if org.absolute_max_alignment != 0 {
            alignment = alignment.min(org.absolute_max_alignment);
        }
    } else {
        alignment = alignment.max(minimum);
    }
    bytes = budget.bytes(align_up(bytes, alignment, id)?)?;
    Ok((sized(bytes, bytes.max(1), bytes.max(1), alignment), fields))
}
