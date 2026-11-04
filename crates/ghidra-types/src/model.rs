/// Stable index into a snapshot's original definition array.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeId(pub usize);

/// A name is metadata; duplicate and empty names are permitted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeDefinition {
    pub name: String,
    pub kind: TypeKind,
}

impl TypeDefinition {
    pub fn new(name: impl Into<String>, kind: TypeKind) -> Self {
        Self {
            name: name.into(),
            kind,
        }
    }
}

/// References use IDs rather than recursive Rust ownership. This permits
/// pointer-recursive types without recursive traversal or recursive drop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TypeKind {
    Void,
    /// No storage layout has been declared yet.
    Incomplete,
    Builtin(Builtin),
    Integer {
        bytes: u32,
        signed: bool,
    },
    Float {
        bytes: u32,
    },
    /// Fixed-size storage with no inferred meaning; uses primitive alignment.
    Opaque {
        bytes: u32,
    },
    /// Only enum storage is modeled, not enumerator names or values.
    Enum {
        bytes: u32,
        signed: bool,
    },
    Pointer {
        target: TypeId,
        bytes: Option<u32>,
    },
    Array {
        element: TypeId,
        count: u64,
    },
    Alias(TypeId),
    Structure(Composite),
    Union(Composite),
    /// A signature is unsized. References are validated but are not by-value
    /// layout dependencies; no calling convention or C validity is inferred.
    Function {
        result: TypeId,
        parameters: Vec<TypeId>,
        variadic: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Builtin {
    Bool,
    Char,
    SignedChar,
    UnsignedChar,
    WChar,
    Short,
    UnsignedShort,
    Int,
    UnsignedInt,
    Long,
    UnsignedLong,
    LongLong,
    UnsignedLongLong,
    Float,
    Double,
    LongDouble,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Packing {
    /// Automatic native layout with uncapped member alignments.
    #[default]
    Default,
    /// Automatic layout with this positive cap on member alignments.
    Explicit(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MinimumAlignment {
    #[default]
    Default,
    Machine,
    Explicit(u32),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Field {
    pub name: String,
    pub ty: TypeId,
}

impl Field {
    pub fn new(name: impl Into<String>, ty: TypeId) -> Self {
        Self {
            name: name.into(),
            ty,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Composite {
    pub fields: Vec<Field>,
    pub packing: Packing,
    pub minimum_alignment: MinimumAlignment,
}

/// Three lengths are deliberately distinct. For primitives `size` and `length`
/// are the raw storage width; `aligned_length` may include padding. Empty
/// composites/zero-count arrays have logical `size=0`, but a display `length`
/// and array-compatible `aligned_length` of 1, as in the retained datatype API.
/// Functions/incomplete types have no lengths; void has three zero lengths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Geometry {
    pub size: Option<u64>,
    pub length: Option<u64>,
    pub aligned_length: Option<u64>,
    pub alignment: u32,
}

impl Geometry {
    /// Test mathematical logical size, including void's zero size. This is not
    /// Java DataType.isZeroLength's special component classification; void still
    /// has no embeddable storage and is rejected as a field/array element.
    pub fn is_zero_length(self) -> bool {
        self.size == Some(0)
    }
}

/// One result for one declared field, in declaration order. Padding occupies
/// no field record; field sizes are aligned lengths, or zero for logical zeros.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FieldLayout {
    pub ty: TypeId,
    pub offset: u64,
    pub bytes: u64,
    pub alignment: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TypeLayout {
    pub geometry: Geometry,
    /// Only direct structure/union definitions have fields. An alias copies
    /// geometry, never an expanded copy of the target's field array.
    pub fields: Vec<FieldLayout>,
    /// Present only on direct arrays. Aliases preserve geometry but do not copy
    /// this detail; follow the alias target to inspect its array stride.
    pub array_stride: Option<u64>,
}
