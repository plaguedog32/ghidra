//! A converted native decompiler datatype graph, separate from Java layout facts.
//!
//! This models the declared layout as transported by `PcodeDataTypeManager` and
//! decoded by the retained C++ `TypeFactory` (`type.cc`), not direct C++
//! constructors and not a reinterpretation of Java `TypeKind`s. Each source
//! `TypeId(i)` converts to at most one native object `NativeTypeId(i)`; objects
//! synthesized by the decoder follow the source objects. See the crate README.
use std::collections::BTreeMap;
use std::sync::Arc;

use ghidra_languages::MetaType;
use ghidra_types::{
    Builtin, Endianness, TypeDefinition, TypeId, TypeKind, TypeLayout, TypeLayouts,
};

use crate::{NativeAlignmentError, NativeAlignmentMap};

/// The largest native `int4` value. Native sizes, counts and offsets above it
/// are explicit conversion/arithmetic errors, never wrapped.
pub const NATIVE_INT_MAX: u32 = i32::MAX as u32;

/// Index of a native object. `NativeTypeId(i)` for `i < source_count` is the
/// conversion of source `TypeId(i)`; larger indices are decoder-synthesized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NativeTypeId(pub usize);

/// Where a native object came from. Identity is the `NativeTypeId`, never a
/// width or structural comparison.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeOrigin {
    /// The decoded form of this source object. Distinct source IDs always
    /// produce distinct native objects, including aliases and equal widths.
    Source(TypeId),
    /// `TypeFactory::getBase(size, meta)` for a resized byte-range structure
    /// bitfield. `meta` is Int, Uint or Unknown. Interned by `(size, meta)`
    /// among synthetic objects only.
    SyntheticBase { size: u32, meta: MetaType },
    /// `getBase` above `max_basetype_size`: an array of the synthetic
    /// `SyntheticBase { size: 1, meta: Unknown }` element, interned by count.
    SyntheticByteArray { count: u32 },
    /// A union bitfield component, transported as an opaque datatype of its
    /// storage width. One object per declared union field.
    UnionBitfield { owner: TypeId, field: usize },
}

/// One decoded native object. Aliases are typedef clones: they copy meta-type
/// and geometry, keep their own identity and share their target's shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeType {
    pub origin: NativeOrigin,
    /// Decoded `type_metatype`. Only Void, Unknown, Int, Uint, Bool, Code, Float,
    /// Ptr, Array, Struct and Union occur; enum transport tags become Int/Uint.
    pub meta: MetaType,
    /// `getSize()`: raw native size.
    pub size: u32,
    /// `getAlignSize()`.
    pub aligned_size: u32,
    /// `getAlignment()`, always at least one.
    pub alignment: u32,
    /// Decoded `TypeEnum` (enum sub-meta), including through aliases.
    pub enumeration: bool,
    /// Immediate typedef target (`typedefImm`) of a converted source alias.
    pub alias_of: Option<NativeTypeId>,
    /// First non-alias object in the alias chain; itself for non-aliases.
    pub canonical: NativeTypeId,
}

/// Contiguous range into the graph's shared field or bitfield storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NativeRange {
    pub start: usize,
    pub end: usize,
}

impl NativeRange {
    pub fn len(self) -> usize {
        self.end - self.start
    }
    pub fn is_empty(self) -> bool {
        self.start == self.end
    }
}

/// Normalized traversal category. Aliases carry their canonical target's
/// shape, whose ranges point into shared storage (no per-alias field copy).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeShape {
    /// Void, Unknown, Int, Uint, Bool, Float, Code and enums.
    Leaf,
    /// The target is a source reference, not a by-value dependency; it may be
    /// unconverted (for example incomplete) without affecting this pointer.
    Pointer {
        target: TypeId,
    },
    /// Element is the native object of the declared element (alias kept).
    Array {
        element: NativeTypeId,
        count: u32,
    },
    /// Visible fields (including byte-range bitfields) and the separate
    /// non-byte bitfield list, which primitive extraction never visits.
    Structure {
        fields: NativeRange,
        bitfields: NativeRange,
    },
    Union {
        fields: NativeRange,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeFieldKind {
    Ordinary,
    /// A structure bitfield whose bit range is byte aligned. The field type is
    /// the declared base when the native size matches, else synthetic.
    ByteRangeBitfield {
        bits: u32,
    },
    /// A union bitfield transported as an opaque datatype of this many bytes.
    UnionBitfield {
        storage_bytes: u32,
    },
}

/// One visible field (`TypeStruct::field`/`TypeUnion::field`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeField {
    pub offset: u32,
    pub ty: NativeTypeId,
    /// Index of the declaration in the source composite.
    pub source_field: usize,
    pub kind: NativeFieldKind,
}

/// A non-byte structure bitfield (`TypeStruct::bitfield`), after decoding.
/// Its metadata is retained for later consumers; extraction ignores it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeBitfield {
    pub source_field: usize,
    pub byte_offset: u32,
    pub byte_size: u32,
    pub least_significant_bit: u32,
    pub bits: u32,
    pub base: NativeTypeId,
}

/// A field the native decoder discards with an overlap warning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeDroppedField {
    pub owner: TypeId,
    pub source_field: usize,
    pub bitfield: bool,
}

/// Array facts derived from the canonical shape; stride is the element's
/// native aligned size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeArray {
    pub element: NativeTypeId,
    pub count: u32,
    pub stride: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeTypeOptions {
    /// `Architecture::max_basetype_size` (architecture.cc resetDefaultsInternal,
    /// default 10). Resized bitfield bases wider than this become arrays of the
    /// Unknown size-one base. Must be in `8..=i32::MAX` ("needs to be 8 or
    /// bigger"); smaller values would depend on core-type cache contents.
    pub max_basetype_size: u32,
}

impl Default for NativeTypeOptions {
    fn default() -> Self {
        Self {
            max_basetype_size: 10,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeTypeLimits {
    /// Source definitions, checked before node-indexed allocation.
    pub max_types: usize,
    /// Source composite declarations recorded by the layout snapshot.
    pub max_fields: usize,
    /// Source references recorded by the layout snapshot.
    pub max_references: usize,
    /// Decoder-synthesized objects, checked before each is allocated.
    pub max_synthetic: usize,
    /// Active by-value dependency stack during conversion.
    pub max_depth: usize,
    /// One construction work budget; queries charge no construction work.
    pub max_work: u64,
}

impl Default for NativeTypeLimits {
    fn default() -> Self {
        Self {
            max_types: 100_000,
            max_fields: 1_000_000,
            max_references: 1_000_000,
            max_synthetic: 1_000_000,
            max_depth: 100_000,
            max_work: 64_000_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NativeTypeStats {
    pub source_types: usize,
    pub converted: usize,
    pub failed: usize,
    pub synthetic: usize,
    pub fields: usize,
    pub bitfields: usize,
    pub dropped_fields: usize,
    pub references: usize,
    pub unloadable: usize,
    pub depth: usize,
    pub work: u64,
}

/// Why one source object has no decoded native form. Conversion failures are
/// per type: they propagate to by-value dependents but not through pointers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NativeConversionError {
    #[error("incomplete datatype {0:?} has no native transport")]
    Incomplete(TypeId),
    #[error("datatype {ty:?} size {size} is outside the native signed-int range")]
    SizeRange { ty: TypeId, size: u64 },
    #[error("datatype {ty:?} alignment {alignment} is outside the native signed-int range")]
    AlignmentRange { ty: TypeId, alignment: u64 },
    #[error("array {ty:?} count {count} exceeds the native signed-int range")]
    ArrayCount { ty: TypeId, count: u64 },
    #[error(
        "array {ty:?} encodes size {encoded_size}, but {count} native elements of aligned size {element_aligned_size} need {expected}"
    )]
    ArraySizeMismatch {
        ty: TypeId,
        count: u32,
        element_aligned_size: u32,
        encoded_size: u32,
        expected: u64,
    },
    #[error("datatype {ty:?} native {operation} exceeds the signed-int range")]
    Arithmetic { ty: TypeId, operation: &'static str },
    #[error("field {field} of {owner:?} has offset {offset} outside the native signed-int range")]
    FieldOffset {
        owner: TypeId,
        field: usize,
        offset: u64,
    },
    #[error("field {field} of {owner:?} is out of order for the native decoder")]
    FieldOutOfOrder { owner: TypeId, field: usize },
    #[error("field {field} of {owner:?} does not fit its native composite")]
    FieldDoesNotFit { owner: TypeId, field: usize },
    #[error("field {field} of {owner:?} has a void native type")]
    VoidField { owner: TypeId, field: usize },
    #[error("bitfield {field} of {owner:?} has a non-integer native base")]
    NonIntegerBitfieldBase { owner: TypeId, field: usize },
    #[error("bitfield {field} of {owner:?} has no byte order")]
    MissingByteOrder { owner: TypeId, field: usize },
    #[error("datatype {ty:?} depends by value on {dependency:?}, which failed at {root:?}")]
    Dependency {
        ty: TypeId,
        dependency: TypeId,
        root: TypeId,
    },
}

impl NativeConversionError {
    /// The source object whose own conversion failed first.
    pub fn root(self) -> TypeId {
        use NativeConversionError::*;
        match self {
            Incomplete(ty)
            | SizeRange { ty, .. }
            | AlignmentRange { ty, .. }
            | ArrayCount { ty, .. }
            | ArraySizeMismatch { ty, .. }
            | Arithmetic { ty, .. } => ty,
            FieldOffset { owner, .. }
            | FieldOutOfOrder { owner, .. }
            | FieldDoesNotFit { owner, .. }
            | VoidField { owner, .. }
            | NonIntegerBitfieldBase { owner, .. }
            | MissingByteOrder { owner, .. } => owner,
            Dependency { root, .. } => root,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NativeTypeError {
    #[error("native type graph limit exceeded: {0}")]
    Limit(&'static str),
    #[error("invalid native type options: {0}")]
    InvalidOptions(&'static str),
    #[error("unknown source datatype {0:?}")]
    UnknownSource(TypeId),
    #[error("unknown native datatype {0:?}")]
    UnknownNative(NativeTypeId),
    #[error(transparent)]
    Conversion(#[from] NativeConversionError),
}

type Result<T> = std::result::Result<T, NativeTypeError>;
type Converted<T> = std::result::Result<T, NativeConversionError>;
/// A decoded object, its shape and its inert-subtree facts.
type Decoded = (NativeType, NativeShape, Option<Inert>);

/// Offset-independent facts for a subtree that emits nothing and sets no flag
/// when entered: a fieldless structure, or an array of such subtrees.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Inert {
    /// Extra nesting levels entered below this type.
    pub(crate) depth: usize,
    /// Largest relative offset entered below this type.
    pub(crate) reach: u64,
}

#[derive(Debug, Clone, Copy)]
enum Slot {
    Native {
        ty: NativeType,
        shape: NativeShape,
        inert: Option<Inert>,
    },
    Failed(NativeConversionError),
}

/// Bounded, immutable decoded view of one `TypeLayouts` snapshot. It retains
/// the original layouts, so Java facts and native facts can be compared.
#[derive(Debug, Clone)]
pub struct NativeTypeGraph {
    layouts: Arc<TypeLayouts>,
    alignments: NativeAlignmentMap,
    options: NativeTypeOptions,
    limits: NativeTypeLimits,
    slots: Vec<Slot>,
    fields: Vec<NativeField>,
    bitfields: Vec<NativeBitfield>,
    dropped: Vec<NativeDroppedField>,
    /// Per source: the failed source object reachable through any reference.
    blockers: Vec<Option<TypeId>>,
    stats: NativeTypeStats,
}

impl NativeTypeGraph {
    /// Convert every source object. Resource limits and invalid options are
    /// errors; a per-type conversion failure is recorded and returned only when
    /// that type (or a by-value dependent) is queried.
    ///
    /// `alignments` is explicit: `NativeAlignmentMap::from_organization` of the
    /// layouts' organization models the Java bridge, `NativeAlignmentMap::new`
    /// a standalone native decode.
    pub fn new(
        layouts: Arc<TypeLayouts>,
        alignments: &NativeAlignmentMap,
        options: NativeTypeOptions,
        limits: NativeTypeLimits,
    ) -> Result<Self> {
        if !(8..=NATIVE_INT_MAX).contains(&options.max_basetype_size) {
            return Err(NativeTypeError::InvalidOptions(
                "max_basetype_size must be in 8..=i32::MAX",
            ));
        }
        let count = layouts.definitions().len();
        let layout_stats = layouts.stats();
        if count > limits.max_types {
            return Err(NativeTypeError::Limit("types"));
        }
        if layout_stats.fields > limits.max_fields {
            return Err(NativeTypeError::Limit("fields"));
        }
        if layout_stats.references > limits.max_references {
            return Err(NativeTypeError::Limit("references"));
        }
        let mut builder = Builder {
            definitions: layouts.definitions(),
            layouts: layouts.layouts(),
            endianness: layouts.endianness(),
            char_signed: layouts.organization().char_signed,
            alignments,
            options,
            limits,
            work: 0,
            slots: vec![None; count],
            fields: Vec::new(),
            bitfields: Vec::new(),
            dropped: Vec::new(),
            interned: BTreeMap::new(),
            journal: Vec::new(),
            depth: 0,
        };
        builder.convert_all()?;
        let blockers = builder.loadability()?;
        let Builder {
            work,
            slots,
            fields,
            bitfields,
            dropped,
            depth,
            ..
        } = builder;
        let slots: Vec<Slot> = slots
            .into_iter()
            .map(|slot| slot.expect("every source and synthetic slot was converted"))
            .collect();
        let failed = slots[..count]
            .iter()
            .filter(|slot| matches!(slot, Slot::Failed(_)))
            .count();
        let stats = NativeTypeStats {
            source_types: count,
            converted: count - failed,
            failed,
            synthetic: slots.len() - count,
            fields: fields.len(),
            bitfields: bitfields.len(),
            dropped_fields: dropped.len(),
            references: layout_stats.references,
            unloadable: blockers.iter().filter(|b| b.is_some()).count(),
            depth,
            work,
        };
        Ok(Self {
            layouts,
            alignments: alignments.clone(),
            options,
            limits,
            slots,
            fields,
            bitfields,
            dropped,
            blockers,
            stats,
        })
    }

    pub fn layouts(&self) -> &Arc<TypeLayouts> {
        &self.layouts
    }
    pub fn alignments(&self) -> &NativeAlignmentMap {
        &self.alignments
    }
    pub fn options(&self) -> NativeTypeOptions {
        self.options
    }
    pub fn limits(&self) -> NativeTypeLimits {
        self.limits
    }
    pub fn stats(&self) -> NativeTypeStats {
        self.stats
    }
    pub fn source_count(&self) -> usize {
        self.stats.source_types
    }
    /// Source slots (converted or failed) plus synthetic objects.
    pub fn native_count(&self) -> usize {
        self.slots.len()
    }

    /// The native object of a source object, or its typed conversion failure.
    pub fn native(&self, source: TypeId) -> Result<NativeTypeId> {
        match self.slots.get(source.0) {
            Some(Slot::Native { .. }) if source.0 < self.source_count() => {
                Ok(NativeTypeId(source.0))
            }
            Some(Slot::Failed(error)) => Err(NativeTypeError::Conversion(*error)),
            _ => Err(NativeTypeError::UnknownSource(source)),
        }
    }

    pub fn get(&self, id: NativeTypeId) -> Result<&NativeType> {
        match self.slots.get(id.0) {
            Some(Slot::Native { ty, .. }) => Ok(ty),
            Some(Slot::Failed(error)) => Err(NativeTypeError::Conversion(*error)),
            None => Err(NativeTypeError::UnknownNative(id)),
        }
    }

    pub fn shape(&self, id: NativeTypeId) -> Result<NativeShape> {
        match self.slots.get(id.0) {
            Some(Slot::Native { shape, .. }) => Ok(*shape),
            Some(Slot::Failed(error)) => Err(NativeTypeError::Conversion(*error)),
            None => Err(NativeTypeError::UnknownNative(id)),
        }
    }

    /// Visible fields of a structure/union (or alias of one); empty otherwise.
    pub fn fields(&self, id: NativeTypeId) -> Result<&[NativeField]> {
        Ok(match self.shape(id)? {
            NativeShape::Structure { fields, .. } | NativeShape::Union { fields } => {
                &self.fields[fields.start..fields.end]
            }
            _ => &[],
        })
    }

    /// Non-byte structure bitfields, invisible to primitive extraction.
    pub fn bitfields(&self, id: NativeTypeId) -> Result<&[NativeBitfield]> {
        Ok(match self.shape(id)? {
            NativeShape::Structure { bitfields, .. } => {
                &self.bitfields[bitfields.start..bitfields.end]
            }
            _ => &[],
        })
    }

    pub fn array(&self, id: NativeTypeId) -> Result<Option<NativeArray>> {
        Ok(match self.shape(id)? {
            NativeShape::Array { element, count } => Some(NativeArray {
                element,
                count,
                stride: self.get(element)?.aligned_size,
            }),
            _ => None,
        })
    }

    /// Fields discarded by the native decoder's overlap rule, in conversion order.
    pub fn dropped_fields(&self) -> &[NativeDroppedField] {
        &self.dropped
    }

    /// Source objects whose own conversion failed, in source order.
    pub fn failures(&self) -> impl Iterator<Item = (TypeId, NativeConversionError)> + '_ {
        self.slots[..self.source_count()]
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| match slot {
                Slot::Failed(error) => Some((TypeId(index), *error)),
                Slot::Native { .. } => None,
            })
    }

    /// `None` when this object and every object reachable through by-value,
    /// pointer-target and function-signature references converted. Otherwise a
    /// failed source object it reaches. A queryable pointer can be unloadable.
    /// Loadable here does not prove a real TypeFactory accepts the stream: names,
    /// native IDs and factory interning are not modeled.
    pub fn load_blocker(&self, source: TypeId) -> Result<Option<TypeId>> {
        self.blockers
            .get(source.0)
            .copied()
            .ok_or(NativeTypeError::UnknownSource(source))
    }

    /// True when no source object failed conversion.
    pub fn is_fully_converted(&self) -> bool {
        self.stats.failed == 0
    }

    pub(crate) fn inert(&self, id: NativeTypeId) -> Option<Inert> {
        match self.slots[id.0] {
            Slot::Native { inert, .. } => inert,
            Slot::Failed(_) => None,
        }
    }

    pub(crate) fn field_slice(&self, range: NativeRange) -> &[NativeField] {
        &self.fields[range.start..range.end]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum SyntheticKey {
    Base { size: u32, meta: u8 },
    ByteArray { count: u32 },
}

fn meta_code(meta: MetaType) -> u8 {
    match meta {
        MetaType::Int => 0,
        MetaType::Uint => 1,
        _ => 2,
    }
}

struct Builder<'a> {
    definitions: &'a [TypeDefinition],
    layouts: &'a [TypeLayout],
    endianness: Option<Endianness>,
    char_signed: bool,
    alignments: &'a NativeAlignmentMap,
    options: NativeTypeOptions,
    limits: NativeTypeLimits,
    work: u64,
    slots: Vec<Option<Slot>>,
    fields: Vec<NativeField>,
    bitfields: Vec<NativeBitfield>,
    dropped: Vec<NativeDroppedField>,
    interned: BTreeMap<SyntheticKey, NativeTypeId>,
    /// Keys interned by the conversion in progress, removed if it fails.
    journal: Vec<SyntheticKey>,
    depth: usize,
}

impl Builder<'_> {
    fn charge(&mut self, amount: u64) -> Result<()> {
        self.work = self
            .work
            .checked_add(amount)
            .filter(|n| *n <= self.limits.max_work)
            .ok_or(NativeTypeError::Limit("work"))?;
        Ok(())
    }

    /// Iterative post-order over by-value transport dependencies, which the
    /// layout snapshot has already proven acyclic.
    fn convert_all(&mut self) -> Result<()> {
        let count = self.definitions.len();
        let mut visited = vec![false; count];
        let mut stack: Vec<(usize, usize)> = Vec::new();
        for root in 0..count {
            self.charge(1)?;
            if visited[root] {
                continue;
            }
            self.push(root, &mut stack, &mut visited)?;
            while let Some((id, cursor)) = stack.last_mut() {
                let id = *id;
                let mut next = *cursor;
                let dependency = self.dependency(id, &mut next)?;
                stack.last_mut().expect("current node").1 = next;
                if let Some(child) = dependency {
                    if !visited[child] {
                        self.push(child, &mut stack, &mut visited)?;
                    }
                } else {
                    self.charge(1)?;
                    let fields = self.fields.len();
                    let bitfields = self.bitfields.len();
                    let dropped = self.dropped.len();
                    let synthetic = self.slots.len();
                    self.journal.clear();
                    let slot = match self.convert(id)? {
                        Ok((ty, shape, inert)) => Slot::Native { ty, shape, inert },
                        Err(error) => {
                            // A failed decode leaves no partial fields or new
                            // synthetic objects behind.
                            self.fields.truncate(fields);
                            self.bitfields.truncate(bitfields);
                            self.dropped.truncate(dropped);
                            self.slots.truncate(synthetic);
                            for key in self.journal.drain(..) {
                                self.interned.remove(&key);
                            }
                            Slot::Failed(error)
                        }
                    };
                    self.slots[id] = Some(slot);
                    stack.pop();
                }
            }
        }
        Ok(())
    }

    fn push(
        &mut self,
        id: usize,
        stack: &mut Vec<(usize, usize)>,
        visited: &mut [bool],
    ) -> Result<()> {
        self.charge(1)?;
        if stack.len() >= self.limits.max_depth {
            return Err(NativeTypeError::Limit("depth"));
        }
        visited[id] = true;
        stack.push((id, 0));
        self.depth = self.depth.max(stack.len());
        Ok(())
    }

    /// Next transported by-value dependency at or after `cursor`. Zero-count
    /// arrays (opaque transport), zero-byte components (skipped by the bridge)
    /// and union bitfields (opaque transport) have none.
    fn dependency(&mut self, id: usize, cursor: &mut usize) -> Result<Option<usize>> {
        let definitions = self.definitions;
        let layouts = self.layouts;
        match &definitions[id].kind {
            TypeKind::Alias(target) if *cursor == 0 => {
                *cursor = 1;
                Ok(Some(target.0))
            }
            TypeKind::Array { element, count } if *cursor == 0 && *count != 0 => {
                *cursor = 1;
                Ok(Some(element.0))
            }
            TypeKind::Structure(c) | TypeKind::Union(c) => {
                let union = matches!(definitions[id].kind, TypeKind::Union(_));
                while let Some(field) = c.fields.get(*cursor) {
                    self.charge(1)?;
                    let layout = &layouts[id].fields[*cursor];
                    *cursor += 1;
                    if layout.bytes == 0 || (union && layout.bitfield.is_some()) {
                        continue;
                    }
                    return Ok(Some(field.ty.0));
                }
                Ok(None)
            }
            _ => Ok(None),
        }
    }

    fn native_of(&self, owner: usize, source: TypeId) -> Converted<(NativeTypeId, NativeType)> {
        match self.slots[source.0].expect("dependency converted first") {
            Slot::Native { ty, .. } => Ok((NativeTypeId(source.0), ty)),
            Slot::Failed(error) => Err(NativeConversionError::Dependency {
                ty: TypeId(owner),
                dependency: source,
                root: error.root(),
            }),
        }
    }

    fn primitive(
        &self,
        id: usize,
        origin: NativeOrigin,
        meta: MetaType,
        size: u64,
    ) -> Converted<NativeType> {
        let geometry = self
            .alignments
            .primitive_geometry(size)
            .map_err(|error| match error {
                NativeAlignmentError::InvalidSize(size) => NativeConversionError::SizeRange {
                    ty: TypeId(id),
                    size,
                },
                _ => NativeConversionError::Arithmetic {
                    ty: TypeId(id),
                    operation: "primitive padding",
                },
            })?;
        Ok(NativeType {
            origin,
            meta,
            size: geometry.size,
            aligned_size: geometry.aligned_size,
            alignment: geometry.alignment,
            enumeration: false,
            alias_of: None,
            canonical: NativeTypeId(id),
        })
    }

    /// `encodeOpaqueDataType`: below 16 bytes an Unknown primitive, otherwise a
    /// fieldless structure with no alignment attribute (alignment one).
    fn opaque(&self, id: usize, origin: NativeOrigin, bytes: u64) -> Converted<Decoded> {
        if bytes < 16 {
            let ty = self.primitive(id, origin, MetaType::Unknown, bytes)?;
            return Ok((ty, NativeShape::Leaf, None));
        }
        let size = int4_size(id, bytes)?;
        Ok((
            NativeType {
                origin,
                meta: MetaType::Struct,
                size,
                aligned_size: size,
                alignment: 1,
                enumeration: false,
                alias_of: None,
                canonical: NativeTypeId(id),
            },
            NativeShape::Structure {
                fields: NativeRange::default(),
                bitfields: NativeRange::default(),
            },
            Some(Inert { depth: 0, reach: 0 }),
        ))
    }

    fn convert(&mut self, id: usize) -> Result<Converted<Decoded>> {
        let definitions = self.definitions;
        let layouts = self.layouts;
        let origin = NativeOrigin::Source(TypeId(id));
        let layout = &layouts[id];
        let leaf = |ty: Converted<NativeType>| ty.map(|ty| (ty, NativeShape::Leaf, None));
        Ok(match &definitions[id].kind {
            TypeKind::Void => Ok((
                NativeType {
                    origin,
                    meta: MetaType::Void,
                    size: 0,
                    aligned_size: 0,
                    alignment: 1,
                    enumeration: false,
                    alias_of: None,
                    canonical: NativeTypeId(id),
                },
                NativeShape::Leaf,
                None,
            )),
            TypeKind::Incomplete => Err(NativeConversionError::Incomplete(TypeId(id))),
            TypeKind::Function { .. } => Ok((
                NativeType {
                    origin,
                    meta: MetaType::Code,
                    size: 1,
                    aligned_size: 1,
                    alignment: 1,
                    enumeration: false,
                    alias_of: None,
                    canonical: NativeTypeId(id),
                },
                NativeShape::Leaf,
                None,
            )),
            TypeKind::Builtin(builtin) => {
                let meta = match builtin {
                    Builtin::Bool => MetaType::Bool,
                    Builtin::Float | Builtin::Double | Builtin::LongDouble => MetaType::Float,
                    Builtin::UnsignedChar
                    | Builtin::UnsignedShort
                    | Builtin::UnsignedInt
                    | Builtin::UnsignedLong
                    | Builtin::UnsignedLongLong => MetaType::Uint,
                    Builtin::Char if !self.char_signed => MetaType::Uint,
                    _ => MetaType::Int,
                };
                leaf(self.primitive(id, origin, meta, raw_size(layout)))
            }
            TypeKind::Integer { signed, .. } => {
                let meta = if *signed {
                    MetaType::Int
                } else {
                    MetaType::Uint
                };
                leaf(self.primitive(id, origin, meta, raw_size(layout)))
            }
            TypeKind::Float { .. } => {
                leaf(self.primitive(id, origin, MetaType::Float, raw_size(layout)))
            }
            TypeKind::Enum { signed, .. } => {
                // type.cc:1572 stores enum_int/enum_uint transport as Int/Uint.
                let meta = if *signed {
                    MetaType::Int
                } else {
                    MetaType::Uint
                };
                leaf(
                    self.primitive(id, origin, meta, raw_size(layout))
                        .map(|mut ty| {
                            ty.enumeration = true;
                            ty
                        }),
                )
            }
            TypeKind::Pointer { target, .. } => self
                .primitive(id, origin, MetaType::Ptr, raw_size(layout))
                .map(|ty| (ty, NativeShape::Pointer { target: *target }, None)),
            TypeKind::Opaque { bytes } => self.opaque(id, origin, u64::from(*bytes)),
            TypeKind::Alias(target) => self.native_of(id, *target).map(|(target_id, target)| {
                let Some(Slot::Native { shape, inert, .. }) = self.slots[target_id.0] else {
                    unreachable!("converted target has a native slot");
                };
                (
                    NativeType {
                        origin,
                        alias_of: Some(target_id),
                        ..target
                    },
                    shape,
                    inert,
                )
            }),
            TypeKind::Array { element, count } => self.array(id, layout, *element, *count),
            TypeKind::Structure(_) => self.structure(id)?,
            TypeKind::Union(_) => self.union(id)?,
        })
    }

    fn array(
        &self,
        id: usize,
        layout: &TypeLayout,
        element: TypeId,
        count: u64,
    ) -> Converted<Decoded> {
        let origin = NativeOrigin::Source(TypeId(id));
        let encoded = layout.geometry.length.expect("arrays have a public length");
        if count == 0 {
            // encodeArray sends zero-element arrays as opaque data of getLength().
            return self.opaque(id, origin, encoded);
        }
        let encoded_size = int4_size(id, encoded)?;
        let count = u32::try_from(count)
            .ok()
            .filter(|n| *n <= NATIVE_INT_MAX)
            .ok_or(NativeConversionError::ArrayCount {
                ty: TypeId(id),
                count,
            })?;
        let (element_id, element_type) = self.native_of(id, element)?;
        let expected = u64::from(count) * u64::from(element_type.aligned_size);
        if expected > u64::from(NATIVE_INT_MAX) {
            // TypeArray::decode multiplies in int4; do not emulate overflow.
            return Err(NativeConversionError::Arithmetic {
                ty: TypeId(id),
                operation: "array count times element aligned size",
            });
        }
        if expected != u64::from(encoded_size) {
            return Err(NativeConversionError::ArraySizeMismatch {
                ty: TypeId(id),
                count,
                element_aligned_size: element_type.aligned_size,
                encoded_size,
                expected,
            });
        }
        let inert = match self.slots[element_id.0] {
            Some(Slot::Native {
                inert: Some(inner), ..
            }) => inner.depth.checked_add(1).map(|depth| Inert {
                depth,
                reach: u64::from(count - 1) * u64::from(element_type.aligned_size) + inner.reach,
            }),
            _ => None,
        };
        Ok((
            NativeType {
                origin,
                meta: MetaType::Array,
                size: encoded_size,
                aligned_size: encoded_size,
                alignment: element_type.alignment,
                enumeration: false,
                alias_of: None,
                canonical: NativeTypeId(id),
            },
            NativeShape::Array {
                element: element_id,
                count,
            },
            inert,
        ))
    }

    /// Public size and explicit Java alignment, with native aligned size.
    fn composite_geometry(&self, id: usize, meta: MetaType) -> Converted<NativeType> {
        let geometry = self.layouts[id].geometry;
        let size = int4_size(
            id,
            geometry.length.expect("composites have a public length"),
        )?;
        let alignment = geometry.alignment;
        if alignment == 0 || alignment > NATIVE_INT_MAX {
            return Err(NativeConversionError::AlignmentRange {
                ty: TypeId(id),
                alignment: u64::from(alignment),
            });
        }
        let aligned = u64::from(size).div_ceil(u64::from(alignment)) * u64::from(alignment);
        if aligned > u64::from(NATIVE_INT_MAX) {
            return Err(NativeConversionError::Arithmetic {
                ty: TypeId(id),
                operation: "composite alignment padding",
            });
        }
        Ok(NativeType {
            origin: NativeOrigin::Source(TypeId(id)),
            meta,
            size,
            aligned_size: aligned as u32,
            alignment,
            enumeration: false,
            alias_of: None,
            canonical: NativeTypeId(id),
        })
    }

    /// `encodeStructure` followed by `TypeStruct::decodeFields`, including
    /// `decodeField`/`decodeBitField` order, overlap and fit rules.
    fn structure(&mut self, id: usize) -> Result<Converted<Decoded>> {
        let definitions = self.definitions;
        let layouts = self.layouts;
        let TypeKind::Structure(composite) = &definitions[id].kind else {
            unreachable!("structure conversion");
        };
        let ty = match self.composite_geometry(id, MetaType::Struct) {
            Ok(ty) => ty,
            Err(error) => return Ok(Err(error)),
        };
        let field_start = self.fields.len();
        let bitfield_start = self.bitfields.len();
        let owner = TypeId(id);
        let mut calc_size: u64 = 0;
        let mut last_offset: Option<u32> = None;
        let mut previous_bits: Option<BitRange> = None;
        for (index, (declaration, layout)) in
            composite.fields.iter().zip(&layouts[id].fields).enumerate()
        {
            self.charge(1)?;
            if layout.bytes == 0 {
                continue; // encodeStructure skips zero-length components.
            }
            let offset = match u32::try_from(layout.offset)
                .ok()
                .filter(|n| *n <= NATIVE_INT_MAX)
            {
                Some(offset) => offset,
                None => {
                    return Ok(Err(NativeConversionError::FieldOffset {
                        owner,
                        field: index,
                        offset: layout.offset,
                    }));
                }
            };
            let (base_id, base) = match self.native_of(id, declaration.ty) {
                Ok(found) => found,
                Err(error) => return Ok(Err(error)),
            };
            let out_of_order = last_offset.is_some_and(|last| offset < last);
            if let Some(bits) = layout.bitfield {
                if !matches!(base.meta, MetaType::Int | MetaType::Uint | MetaType::Bool) {
                    return Ok(Err(NativeConversionError::NonIntegerBitfieldBase {
                        owner,
                        field: index,
                    }));
                }
                let Some(endianness) = self.endianness else {
                    return Ok(Err(NativeConversionError::MissingByteOrder {
                        owner,
                        field: index,
                    }));
                };
                let mut range = BitRange::decoded(
                    offset,
                    u32::from(bits.bit_offset),
                    bits.effective_bits,
                    endianness == Endianness::Big,
                );
                if out_of_order {
                    return Ok(Err(NativeConversionError::FieldOutOfOrder {
                        owner,
                        field: index,
                    }));
                }
                if u64::from(offset) < calc_size
                    && previous_bits.is_none_or(|previous| previous.overlap_test(&range) != -1)
                {
                    self.dropped.push(NativeDroppedField {
                        owner,
                        source_field: index,
                        bitfield: true,
                    });
                    continue;
                }
                last_offset = Some(offset);
                calc_size = u64::from(offset) + u64::from(range.byte_size);
                if calc_size > u64::from(NATIVE_INT_MAX) {
                    return Ok(Err(NativeConversionError::Arithmetic {
                        ty: owner,
                        operation: "bitfield end offset",
                    }));
                }
                if calc_size > u64::from(ty.size) {
                    return Ok(Err(NativeConversionError::FieldDoesNotFit {
                        owner,
                        field: index,
                    }));
                }
                if range.is_byte_range() {
                    range.minimize_container();
                    let field_type = if base.size == range.byte_size {
                        base_id
                    } else {
                        let meta = match base.meta {
                            MetaType::Int | MetaType::Uint => base.meta,
                            _ => MetaType::Unknown,
                        };
                        match self.synthetic_base(id, range.byte_size, meta)? {
                            Ok(found) => found,
                            Err(error) => return Ok(Err(error)),
                        }
                    };
                    self.fields.push(NativeField {
                        offset: range.byte_offset,
                        ty: field_type,
                        source_field: index,
                        kind: NativeFieldKind::ByteRangeBitfield { bits: range.bits },
                    });
                } else {
                    self.bitfields.push(NativeBitfield {
                        source_field: index,
                        byte_offset: range.byte_offset,
                        byte_size: range.byte_size,
                        least_significant_bit: range.least_significant_bit,
                        bits: range.bits,
                        base: base_id,
                    });
                    previous_bits = Some(range);
                }
            } else {
                if base.meta == MetaType::Void {
                    return Ok(Err(NativeConversionError::VoidField {
                        owner,
                        field: index,
                    }));
                }
                if out_of_order {
                    return Ok(Err(NativeConversionError::FieldOutOfOrder {
                        owner,
                        field: index,
                    }));
                }
                if u64::from(offset) < calc_size {
                    self.dropped.push(NativeDroppedField {
                        owner,
                        source_field: index,
                        bitfield: false,
                    });
                    continue;
                }
                last_offset = Some(offset);
                calc_size = u64::from(offset) + u64::from(base.size);
                if calc_size > u64::from(NATIVE_INT_MAX) {
                    return Ok(Err(NativeConversionError::Arithmetic {
                        ty: owner,
                        operation: "field end offset",
                    }));
                }
                if calc_size > u64::from(ty.size) {
                    return Ok(Err(NativeConversionError::FieldDoesNotFit {
                        owner,
                        field: index,
                    }));
                }
                self.fields.push(NativeField {
                    offset,
                    ty: base_id,
                    source_field: index,
                    kind: NativeFieldKind::Ordinary,
                });
            }
        }
        let fields = NativeRange {
            start: field_start,
            end: self.fields.len(),
        };
        let bitfields = NativeRange {
            start: bitfield_start,
            end: self.bitfields.len(),
        };
        let inert = fields.is_empty().then_some(Inert { depth: 0, reach: 0 });
        Ok(Ok((
            ty,
            NativeShape::Structure { fields, bitfields },
            inert,
        )))
    }

    /// `encodeUnion` followed by `TypeUnion::decodeFields`.
    fn union(&mut self, id: usize) -> Result<Converted<Decoded>> {
        let definitions = self.definitions;
        let layouts = self.layouts;
        let TypeKind::Union(composite) = &definitions[id].kind else {
            unreachable!("union conversion");
        };
        let ty = match self.composite_geometry(id, MetaType::Union) {
            Ok(ty) => ty,
            Err(error) => return Ok(Err(error)),
        };
        let owner = TypeId(id);
        let start = self.fields.len();
        for (index, (declaration, layout)) in
            composite.fields.iter().zip(&layouts[id].fields).enumerate()
        {
            self.charge(1)?;
            if layout.bytes == 0 {
                continue;
            }
            let offset = match u32::try_from(layout.offset)
                .ok()
                .filter(|n| *n <= NATIVE_INT_MAX)
            {
                Some(offset) => offset,
                None => {
                    return Ok(Err(NativeConversionError::FieldOffset {
                        owner,
                        field: index,
                        offset: layout.offset,
                    }));
                }
            };
            let (field_type, kind, size) = if layout.bitfield.is_some() {
                // The bitfield wrapper's typeref resolves to opaque transport
                // of its component length; its declared base is not sent.
                let storage = layout.bytes;
                let synthetic = match self.union_bitfield(id, index, storage)? {
                    Ok(found) => found,
                    Err(error) => return Ok(Err(error)),
                };
                let size = self.slot_type(synthetic).size;
                (
                    synthetic,
                    NativeFieldKind::UnionBitfield {
                        storage_bytes: size,
                    },
                    size,
                )
            } else {
                match self.native_of(id, declaration.ty) {
                    Ok((found, native)) => (found, NativeFieldKind::Ordinary, native.size),
                    Err(error) => return Ok(Err(error)),
                }
            };
            let end = u64::from(offset) + u64::from(size);
            if end > u64::from(NATIVE_INT_MAX) {
                return Ok(Err(NativeConversionError::Arithmetic {
                    ty: owner,
                    operation: "union field end offset",
                }));
            }
            if end > u64::from(ty.size) {
                return Ok(Err(NativeConversionError::FieldDoesNotFit {
                    owner,
                    field: index,
                }));
            }
            self.fields.push(NativeField {
                offset,
                ty: field_type,
                source_field: index,
                kind,
            });
        }
        let fields = NativeRange {
            start,
            end: self.fields.len(),
        };
        Ok(Ok((ty, NativeShape::Union { fields }, None)))
    }

    fn slot_type(&self, id: NativeTypeId) -> NativeType {
        match self.slots[id.0] {
            Some(Slot::Native { ty, .. }) => ty,
            _ => unreachable!("synthetic slots are native"),
        }
    }

    fn allocate_synthetic(&mut self, slot: Slot) -> Result<NativeTypeId> {
        let synthetic = self.slots.len() - self.definitions.len();
        if synthetic >= self.limits.max_synthetic {
            return Err(NativeTypeError::Limit("synthetic types"));
        }
        self.charge(1)?;
        self.slots.push(Some(slot));
        Ok(NativeTypeId(self.slots.len() - 1))
    }

    fn intern_charge(&mut self) -> Result<()> {
        let entries = self.interned.len().max(1);
        self.charge(1 + u64::from(usize::BITS - entries.leading_zeros()))
    }

    /// `TypeFactory::getBase(size, meta)` for meta Int/Uint/Unknown.
    fn synthetic_base(
        &mut self,
        owner: usize,
        size: u32,
        meta: MetaType,
    ) -> Result<Converted<NativeTypeId>> {
        if size > self.options.max_basetype_size {
            return self.synthetic_byte_array(owner, size);
        }
        let key = SyntheticKey::Base {
            size,
            meta: meta_code(meta),
        };
        self.intern_charge()?;
        if let Some(found) = self.interned.get(&key) {
            return Ok(Ok(*found));
        }
        let index = self.slots.len();
        let ty = match self.primitive(
            index,
            NativeOrigin::SyntheticBase { size, meta },
            meta,
            u64::from(size),
        ) {
            Ok(ty) => ty,
            Err(_) => {
                return Ok(Err(NativeConversionError::Arithmetic {
                    ty: TypeId(owner),
                    operation: "synthetic base padding",
                }));
            }
        };
        let id = self.allocate_synthetic(Slot::Native {
            ty,
            shape: NativeShape::Leaf,
            inert: None,
        })?;
        self.interned.insert(key, id);
        self.journal.push(key);
        Ok(Ok(id))
    }

    /// `getTypeArray(size, typecache[1][TYPE_UNKNOWN])`: the native array
    /// geometry of the Unknown size-one base, not a flat `size` width.
    fn synthetic_byte_array(
        &mut self,
        owner: usize,
        count: u32,
    ) -> Result<Converted<NativeTypeId>> {
        let key = SyntheticKey::ByteArray { count };
        self.intern_charge()?;
        if let Some(found) = self.interned.get(&key) {
            return Ok(Ok(*found));
        }
        let element = match self.synthetic_base(owner, 1, MetaType::Unknown)? {
            Ok(element) => element,
            Err(error) => return Ok(Err(error)),
        };
        let element_type = self.slot_type(element);
        let size = u64::from(count) * u64::from(element_type.aligned_size);
        if size > u64::from(NATIVE_INT_MAX) {
            return Ok(Err(NativeConversionError::Arithmetic {
                ty: TypeId(owner),
                operation: "synthetic byte-array size",
            }));
        }
        let index = self.slots.len();
        let id = self.allocate_synthetic(Slot::Native {
            ty: NativeType {
                origin: NativeOrigin::SyntheticByteArray { count },
                meta: MetaType::Array,
                size: size as u32,
                aligned_size: size as u32,
                alignment: element_type.alignment,
                enumeration: false,
                alias_of: None,
                canonical: NativeTypeId(index),
            },
            shape: NativeShape::Array { element, count },
            inert: None,
        })?;
        self.interned.insert(key, id);
        self.journal.push(key);
        Ok(Ok(id))
    }

    fn union_bitfield(
        &mut self,
        owner: usize,
        field: usize,
        storage: u64,
    ) -> Result<Converted<NativeTypeId>> {
        let index = self.slots.len();
        let origin = NativeOrigin::UnionBitfield {
            owner: TypeId(owner),
            field,
        };
        let (ty, shape, inert) = match self.opaque(index, origin, storage) {
            Ok(found) => found,
            Err(_) => {
                return Ok(Err(NativeConversionError::Arithmetic {
                    ty: TypeId(owner),
                    operation: "union bitfield opaque size",
                }));
            }
        };
        self.allocate_synthetic(Slot::Native { ty, shape, inert })
            .map(Ok)
    }

    /// Reverse reachability from failed source objects over every transported
    /// reference, including pointer targets and function signatures.
    fn loadability(&mut self) -> Result<Vec<Option<TypeId>>> {
        let definitions = self.definitions;
        let layouts = self.layouts;
        let count = definitions.len();
        let mut incoming = vec![0usize; count + 1];
        let mut edges = 0usize;
        for id in 0..count {
            self.charge(1)?;
            for target in references(&definitions[id].kind, &layouts[id]) {
                self.charge(1)?;
                incoming[target.0 + 1] += 1;
                edges += 1;
            }
        }
        for index in 0..count {
            incoming[index + 1] += incoming[index];
        }
        self.charge(count as u64)?;
        let mut fill = incoming.clone();
        let mut referrers = vec![0usize; edges];
        for id in 0..count {
            for target in references(&definitions[id].kind, &layouts[id]) {
                self.charge(1)?;
                referrers[fill[target.0]] = id;
                fill[target.0] += 1;
            }
        }
        let mut blockers = vec![None; count];
        let mut queue = Vec::new();
        for (id, blocker) in blockers.iter_mut().enumerate() {
            self.charge(1)?;
            if let Some(Slot::Failed(error)) = self.slots[id] {
                *blocker = Some(error.root());
                queue.push(id);
            }
        }
        let mut next = 0;
        while let Some(&target) = queue.get(next) {
            next += 1;
            let blocker = blockers[target];
            for &referrer in &referrers[incoming[target]..incoming[target + 1]] {
                self.charge(1)?;
                if blockers[referrer].is_none() {
                    blockers[referrer] = blocker;
                    queue.push(referrer);
                }
            }
        }
        Ok(blockers)
    }
}

/// Every reference whose target the transport would also encode.
fn references<'a>(kind: &'a TypeKind, layout: &'a TypeLayout) -> impl Iterator<Item = TypeId> + 'a {
    let single = match kind {
        TypeKind::Alias(target) | TypeKind::Pointer { target, .. } => Some(*target),
        TypeKind::Array { element, count } if *count != 0 => Some(*element),
        TypeKind::Function { result, .. } => Some(*result),
        _ => None,
    };
    let parameters: &[TypeId] = match kind {
        TypeKind::Function { parameters, .. } => parameters,
        _ => &[],
    };
    let (fields, union) = match kind {
        TypeKind::Structure(c) => (&c.fields[..], false),
        TypeKind::Union(c) => (&c.fields[..], true),
        _ => (&[][..], false),
    };
    single.into_iter().chain(parameters.iter().copied()).chain(
        fields
            .iter()
            .zip(&layout.fields)
            .filter(move |(_, layout)| layout.bytes != 0 && !(union && layout.bitfield.is_some()))
            .map(|(field, _)| field.ty),
    )
}

fn raw_size(layout: &TypeLayout) -> u64 {
    layout.geometry.size.expect("sized scalar layout")
}

fn int4_size(id: usize, size: u64) -> Converted<u32> {
    u32::try_from(size)
        .ok()
        .filter(|n| *n <= NATIVE_INT_MAX)
        .ok_or(NativeConversionError::SizeRange {
            ty: TypeId(id),
            size,
        })
}

/// The decoded `BitRange` of a `<bitfield>` element (address.cc). Values are
/// small: offsets are int4-checked and widths are at most 255 bits.
#[derive(Debug, Clone, Copy)]
struct BitRange {
    byte_offset: u32,
    byte_size: u32,
    least_significant_bit: u32,
    bits: u32,
    big_endian: bool,
}

impl BitRange {
    fn decoded(byte_offset: u32, least_significant_bit: u32, bits: u32, big_endian: bool) -> Self {
        Self {
            byte_offset,
            byte_size: (least_significant_bit + bits).div_ceil(8),
            least_significant_bit,
            bits,
            big_endian,
        }
    }

    fn is_byte_range(&self) -> bool {
        self.bits & 7 == 0 && self.least_significant_bit & 7 == 0
    }

    fn minimize_container(&mut self) {
        let truncate = self.least_significant_bit / 8;
        if self.big_endian {
            self.byte_size -= truncate;
        } else {
            self.byte_offset += truncate;
        }
        self.least_significant_bit &= 7;
        let needed = (self.least_significant_bit + self.bits).div_ceil(8);
        if self.byte_size > needed {
            let excess = self.byte_size - needed;
            if self.big_endian {
                self.byte_offset += excess;
            }
            self.byte_size -= excess;
        }
    }

    /// `BitRange::overlapTest`; -1 means `self` comes strictly before `other`.
    fn overlap_test(&self, other: &Self) -> i32 {
        let this_least = i64::from(self.least_significant_bit);
        let other_least = if self.big_endian {
            let this_end = i64::from(self.byte_offset) + i64::from(self.byte_size);
            let other_end = i64::from(other.byte_offset) + i64::from(other.byte_size);
            i64::from(other.least_significant_bit) + 8 * (this_end - other_end)
        } else {
            i64::from(other.least_significant_bit)
                + 8 * (i64::from(other.byte_offset) - i64::from(self.byte_offset))
        };
        let this_most = this_least + i64::from(self.bits);
        let other_most = other_least + i64::from(other.bits);
        if self.big_endian {
            if this_least >= other_most {
                return -1;
            }
            if other_least >= this_most {
                return 1;
            }
        } else {
            if this_most <= other_least {
                return -1;
            }
            if other_most <= this_least {
                return 1;
            }
        }
        if this_least == other_least && this_most == other_most {
            0
        } else if other_least <= this_least && other_most >= this_most {
            2
        } else if this_least <= other_least && this_most >= other_most {
            3
        } else {
            4
        }
    }
}

#[cfg(test)]
mod tests {
    use super::BitRange;

    fn range(offset: u32, size: u32, least: u32, bits: u32, big: bool) -> BitRange {
        BitRange {
            byte_offset: offset,
            byte_size: size,
            least_significant_bit: least,
            bits,
            big_endian: big,
        }
    }

    /// address.cc minimizeContainer: little endian moves the offset past
    /// truncated low bytes; big endian keeps it and shrinks from the end.
    #[test]
    fn minimize_container_follows_byte_order() {
        let mut little = BitRange::decoded(4, 8, 16, false);
        assert_eq!(little.byte_size, 3);
        assert!(little.is_byte_range());
        little.minimize_container();
        assert_eq!(
            (
                little.byte_offset,
                little.byte_size,
                little.least_significant_bit
            ),
            (5, 2, 0)
        );
        let mut big = BitRange::decoded(4, 8, 16, true);
        big.minimize_container();
        assert_eq!(
            (big.byte_offset, big.byte_size, big.least_significant_bit),
            (4, 2, 0)
        );
        // An oversized big-endian container drops leading bytes.
        let mut wide = range(4, 4, 0, 8, true);
        wide.minimize_container();
        assert_eq!((wide.byte_offset, wide.byte_size), (7, 1));
        let mut wide = range(4, 4, 0, 8, false);
        wide.minimize_container();
        assert_eq!((wide.byte_offset, wide.byte_size), (4, 1));
        assert!(!BitRange::decoded(0, 4, 8, false).is_byte_range());
        assert!(!BitRange::decoded(0, 0, 12, false).is_byte_range());
    }

    /// address.cc overlapTest codes, little and big endian.
    #[test]
    fn overlap_test_codes() {
        let le = |a: (u32, u32, u32, u32), b: (u32, u32, u32, u32)| {
            range(a.0, a.1, a.2, a.3, false).overlap_test(&range(b.0, b.1, b.2, b.3, false))
        };
        assert_eq!(le((0, 1, 0, 4), (0, 2, 4, 12)), -1);
        assert_eq!(le((0, 2, 4, 12), (0, 1, 0, 4)), 1);
        assert_eq!(le((0, 1, 0, 4), (0, 1, 0, 4)), 0);
        assert_eq!(le((0, 1, 2, 3), (0, 1, 0, 8)), 2);
        assert_eq!(le((0, 1, 0, 8), (0, 1, 2, 3)), 3);
        assert_eq!(le((0, 1, 0, 6), (0, 1, 4, 4)), 4);
        // Different containers translate the other range's bits.
        assert_eq!(le((0, 1, 0, 8), (1, 1, 0, 8)), -1);
        assert_eq!(le((1, 1, 0, 8), (0, 2, 4, 8)), 4);
        let be = |a: (u32, u32, u32, u32), b: (u32, u32, u32, u32)| {
            range(a.0, a.1, a.2, a.3, true).overlap_test(&range(b.0, b.1, b.2, b.3, true))
        };
        // Big endian: an earlier field occupies more significant bits.
        assert_eq!(be((0, 1, 4, 4), (0, 2, 0, 12)), -1);
        assert_eq!(be((0, 2, 0, 12), (0, 1, 4, 4)), 1);
        assert_eq!(be((0, 1, 0, 8), (1, 1, 0, 8)), -1);
        assert_eq!(be((0, 1, 4, 4), (0, 1, 4, 4)), 0);
        assert_eq!(be((0, 1, 2, 2), (0, 1, 0, 8)), 2);
        assert_eq!(be((0, 1, 0, 6), (0, 1, 4, 4)), 4);
    }
}
