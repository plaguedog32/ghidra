//! `.cspec` compiler specification: data organization, stack pointer, return address,
//! prototype models (calling conventions) and the other ABI declarations Ghidra reads in
//! `BasicCompilerSpec.restoreXml`.
//!
//! What this module does and does not do:
//! - Every element Ghidra reads is captured in typed fields, in document order. Parameter
//!   entries keep their order, `<group>` membership and join pieces (in piece-number
//!   order). Model rules keep their filter, qualifiers, action and side effects.
//! - Nothing is resolved against a SLEIGH language. Register names stay names; register
//!   offsets and sizes, address-space sizes and register overlap are unknown here. So
//!   Ghidra's resource group numbers (which depend on overlap between entries), the
//!   endian/justification flags of each entry, and join-overlap checks are not computed.
//! - Nothing is executed. Model rules, `pointermax`, hidden-return handling and p-code
//!   injection bodies are data for a later calling-convention resolver. This crate does
//!   not assign parameters to storage.
//! - Where Ghidra would reject a file (bad sizes, ordering violations, unknown storage
//!   classes, ...) an [`Severity::Error`] diagnostic is recorded instead. A record that
//!   cannot be built is dropped; a record that is built but breaks a consistency rule is
//!   kept. Either way the enclosing prototype is marked [`ModelStatus::Incomplete`].
//! - Recognised elements that are not turned into typed data are listed in
//!   [`CompilerSpec::unmodeled`].
//!
//! Ghidra checks that need the language and are therefore *not* made here: that named
//! registers and address spaces exist, that a `<pentry>` maxsize fits its register, that
//! offsets fit their space, that overlapping entries nest legally, that a join overlaps
//! an earlier entry, and the `spacebase`/`stackpointer` register lookups.
//!
//! A successfully returned [`CompilerSpec`] means the file was parsed.
//! [`CompilerSpec::is_fully_modeled`] says whether every ABI declaration in it was captured
//! without errors. Neither means the ABI can be executed.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::pspec::{self, ContextSet, Property, TrackedSet};
use crate::xml::{self, Element};
use crate::{Diagnostic, DiagnosticKind, Error, Limits, Severity};

/// Name Ghidra gives the implicit `this`-call model.
pub const THISCALL: &str = "__thiscall";

/// Name of Ghidra's join address space.
pub const JOIN_SPACE: &str = "join";

/// Name of the stack address space created from `<stackpointer>`.
pub const STACK_SPACE: &str = "stack";

// ---------------------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------------------

/// One physical piece of a join.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum JoinPiece {
    /// A register by name (`pieceN="r0"`). Its size comes from the SLEIGH register map.
    Register { name: String },
    /// `pieceN="space:offset:size"`.
    Varnode {
        space: String,
        offset: u64,
        size: u32,
    },
}

/// A storage location as written in the spec.
///
/// Offsets are kept as the 64-bit pattern Ghidra's `SpecXmlUtils.decodeLong` produces, so
/// a negative stack offset such as `-2` is stored as `0xffff_ffff_ffff_fffe`. Use
/// [`Storage::signed_offset`] for stack offsets. Truncation to the address-space size
/// needs the language and is not done here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Storage {
    /// `<register name=".."/>`. Offset and size are not known without the language.
    Register { name: String },
    /// `<varnode space offset size/>`.
    Varnode {
        space: String,
        offset: u64,
        size: u32,
    },
    /// `<addr space offset [size]/>`. In a `<pentry>` the size is usually omitted and the
    /// entry's `maxsize` applies.
    Address {
        space: String,
        offset: u64,
        size: Option<u32>,
    },
    /// `<addr space="join" piece1=.. piece2=.. [size]/>`. Pieces are in piece-number
    /// order (`piece1` first), which is Ghidra's most-significant-first order. They are
    /// never flattened or reordered.
    Join {
        pieces: Vec<JoinPiece>,
        /// Explicit `size` attribute (the logical size). Absent means the sum of pieces.
        logical_size: Option<u32>,
    },
}

impl Storage {
    /// Address space name, when the storage names one directly.
    pub fn space(&self) -> Option<&str> {
        match self {
            Storage::Varnode { space, .. } | Storage::Address { space, .. } => Some(space),
            Storage::Join { .. } => Some(JOIN_SPACE),
            Storage::Register { .. } => None,
        }
    }

    /// True for storage in the `stack` space.
    pub fn is_stack(&self) -> bool {
        self.space() == Some(STACK_SPACE)
    }

    pub fn register_name(&self) -> Option<&str> {
        match self {
            Storage::Register { name } => Some(name),
            _ => None,
        }
    }

    /// Offset as a signed value (Ghidra's stack space has signed offsets).
    pub fn signed_offset(&self) -> Option<i64> {
        match self {
            Storage::Varnode { offset, .. } | Storage::Address { offset, .. } => {
                Some(*offset as i64)
            }
            _ => None,
        }
    }

    /// Size in bytes when it is known without the language: a varnode size, an explicit
    /// address size, a join's logical size, or the sum of join pieces when every piece is
    /// a sized varnode.
    pub fn known_size(&self) -> Option<u32> {
        match self {
            Storage::Varnode { size, .. } => Some(*size),
            Storage::Address { size, .. } => size.filter(|s| *s != 0),
            Storage::Join {
                logical_size: Some(size),
                ..
            } => Some(*size),
            Storage::Join { pieces, .. } => pieces.iter().try_fold(0u32, |sum, p| match p {
                JoinPiece::Varnode { size, .. } => sum.checked_add(*size),
                JoinPiece::Register { .. } => None,
            }),
            Storage::Register { .. } => None,
        }
    }
}

/// An inclusive address range. A missing bound is open (Ghidra uses offset 0 and the
/// space maximum).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AddressRange {
    pub space: String,
    pub first: Option<u64>,
    pub last: Option<u64>,
}

/// A `<range>` or `<register>` tag in `<global>`, `<localrange>` and similar lists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MemoryTag {
    Range(AddressRange),
    /// The bytes of a register. Not resolvable without the language.
    Register {
        name: String,
    },
}

// ---------------------------------------------------------------------------------------
// Data organization
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SizeAlignment {
    pub size: u32,
    pub alignment: u32,
}

/// `<bitfield_packing>` as declared.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BitfieldPacking {
    pub use_ms_convention: Option<bool>,
    pub type_alignment_enabled: Option<bool>,
    pub zero_length_boundary: Option<u32>,
}

/// `<data_organization>` exactly as declared. `None` means the element was absent and
/// Ghidra's default applies; see [`DataOrganization::resolve`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DataOrganization {
    pub absolute_max_alignment: Option<u32>,
    pub machine_alignment: Option<u32>,
    pub default_alignment: Option<u32>,
    pub default_pointer_alignment: Option<u32>,
    pub pointer_size: Option<u32>,
    pub pointer_shift: Option<u32>,
    pub char_signed: Option<bool>,
    pub char_size: Option<u32>,
    pub wchar_size: Option<u32>,
    pub short_size: Option<u32>,
    pub integer_size: Option<u32>,
    pub long_size: Option<u32>,
    pub long_long_size: Option<u32>,
    pub float_size: Option<u32>,
    pub double_size: Option<u32>,
    pub long_double_size: Option<u32>,
    /// `<size_alignment_map>` entries in document order (duplicates included).
    pub size_alignment_map: Vec<SizeAlignment>,
    pub bitfield_packing: Option<BitfieldPacking>,
}

/// Data organization with Ghidra's defaults filled in
/// (`DataOrganizationImpl.getDefaultOrganization` then `restoreXml`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedDataOrganization {
    /// 0 means no maximum.
    pub absolute_max_alignment: u32,
    pub machine_alignment: u32,
    pub default_alignment: u32,
    pub default_pointer_alignment: u32,
    pub pointer_size: u32,
    pub pointer_shift: u32,
    pub char_signed: bool,
    pub char_size: u32,
    pub wchar_size: u32,
    pub short_size: u32,
    pub integer_size: u32,
    pub long_size: u32,
    pub long_long_size: u32,
    pub float_size: u32,
    pub double_size: u32,
    pub long_double_size: u32,
    /// Sorted by size. Ghidra seeds 1/2/4/8 → 1/2/4/8 and the spec's entries override
    /// or extend that map (later duplicates win).
    pub size_alignment_map: Vec<SizeAlignment>,
    pub use_ms_bitfield_convention: bool,
    pub bitfield_type_alignment_enabled: bool,
    pub bitfield_zero_length_boundary: u32,
}

impl ResolvedDataOrganization {
    /// Alignment for a primitive of `size` bytes from the size map, if listed.
    pub fn alignment_for_size(&self, size: u32) -> Option<u32> {
        self.size_alignment_map
            .iter()
            .find(|e| e.size == size)
            .map(|e| e.alignment)
    }
}

impl DataOrganization {
    /// Apply Ghidra's defaults. `language_pointer_size` is the default address space's
    /// pointer size, which Ghidra uses when `<pointer_size>` is absent; it needs the
    /// language, so the caller supplies it.
    pub fn resolve(&self, language_pointer_size: u32) -> ResolvedDataOrganization {
        let mut map: Vec<SizeAlignment> = [1, 2, 4, 8]
            .into_iter()
            .map(|n| SizeAlignment {
                size: n,
                alignment: n,
            })
            .collect();
        for entry in &self.size_alignment_map {
            match map.iter_mut().find(|e| e.size == entry.size) {
                Some(existing) => existing.alignment = entry.alignment,
                None => map.push(*entry),
            }
        }
        map.sort_by_key(|e| e.size);
        let bits = self.bitfield_packing.clone().unwrap_or_default();
        ResolvedDataOrganization {
            absolute_max_alignment: self.absolute_max_alignment.unwrap_or(0),
            machine_alignment: self.machine_alignment.unwrap_or(8),
            default_alignment: self.default_alignment.unwrap_or(1),
            default_pointer_alignment: self.default_pointer_alignment.unwrap_or(4),
            pointer_size: self.pointer_size.unwrap_or(language_pointer_size),
            pointer_shift: self.pointer_shift.unwrap_or(0),
            char_signed: self.char_signed.unwrap_or(true),
            char_size: self.char_size.unwrap_or(1),
            wchar_size: self.wchar_size.unwrap_or(2),
            short_size: self.short_size.unwrap_or(2),
            integer_size: self.integer_size.unwrap_or(4),
            long_size: self.long_size.unwrap_or(4),
            long_long_size: self.long_long_size.unwrap_or(8),
            float_size: self.float_size.unwrap_or(4),
            double_size: self.double_size.unwrap_or(8),
            long_double_size: self.long_double_size.unwrap_or(8),
            size_alignment_map: map,
            use_ms_bitfield_convention: bits.use_ms_convention.unwrap_or(false),
            bitfield_type_alignment_enabled: bits.type_alignment_enabled.unwrap_or(true),
            bitfield_zero_length_boundary: bits.zero_length_boundary.unwrap_or(0),
        }
    }
}

// ---------------------------------------------------------------------------------------
// Stack pointer and other global declarations
// ---------------------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StackGrowth {
    Negative,
    Positive,
}

/// `<stackpointer register space [growth] [reversejustify]/>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StackPointer {
    pub register: String,
    /// The space the stack lives in (e.g. `ram`).
    pub space: String,
    /// `negative` when absent.
    pub growth: StackGrowth,
    /// Ghidra reads this as true only for `1` or `true` (any case).
    pub reverse_justify: bool,
    pub line: u32,
}

/// `<spacebase name register space/>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpaceBase {
    pub name: String,
    pub register: String,
    pub space: String,
    pub line: u32,
}

/// `<deadcodedelay space delay/>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeadCodeDelay {
    pub space: String,
    pub delay: i32,
}

/// Parameter of a p-code injection (`<input>`/`<output>` in `<pcode>`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InjectParameter {
    pub name: String,
    pub size: Option<u32>,
}

/// A `<pcode>` payload. The body is SLEIGH-style p-code source; it is kept verbatim and
/// not compiled here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PcodeSnippet {
    pub param_shift: Option<i32>,
    pub dynamic: Option<bool>,
    pub incidental_copy: Option<bool>,
    pub inputs: Vec<InjectParameter>,
    pub outputs: Vec<InjectParameter>,
    /// `<body>` text exactly as written (CDATA unwrapped).
    pub body: Option<String>,
    pub line: u32,
}

/// `<callfixup name>`: replaces calls to the named targets with a p-code snippet.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallFixup {
    pub name: String,
    pub targets: Vec<String>,
    pub pcode: PcodeSnippet,
    pub line: u32,
}

/// `<callotherfixup targetop>`: replaces a user-defined p-code op.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CallOtherFixup {
    pub target_op: String,
    pub pcode: PcodeSnippet,
    pub line: u32,
}

// ---------------------------------------------------------------------------------------
// Prototype models
// ---------------------------------------------------------------------------------------

/// Ghidra `StorageClass` (`storage`/`metatype` attributes).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum StorageClass {
    General,
    Float,
    Ptr,
    HiddenRet,
    Vector,
    Class1,
    Class2,
    Class3,
    Class4,
}

impl StorageClass {
    pub fn parse(text: &str) -> Option<StorageClass> {
        Some(match text {
            "general" => StorageClass::General,
            "float" => StorageClass::Float,
            "ptr" => StorageClass::Ptr,
            "hiddenret" => StorageClass::HiddenRet,
            "vector" => StorageClass::Vector,
            "class1" => StorageClass::Class1,
            "class2" => StorageClass::Class2,
            "class3" => StorageClass::Class3,
            "class4" => StorageClass::Class4,
            _ => return None,
        })
    }

    /// Ghidra's numeric class value, used for entry ordering checks.
    pub fn rank(self) -> u32 {
        match self {
            StorageClass::General => 0,
            StorageClass::Float => 1,
            StorageClass::Ptr => 2,
            StorageClass::HiddenRet => 3,
            StorageClass::Vector => 4,
            StorageClass::Class1 => 100,
            StorageClass::Class2 => 101,
            StorageClass::Class3 => 102,
            StorageClass::Class4 => 103,
        }
    }
}

/// `<pentry extension>`: how values smaller than the entry are extended.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Extension {
    None,
    Sign,
    Zero,
    IntType,
    Float,
}

/// One `<pentry>`: a parameter or return-value storage slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamEntry {
    pub min_size: u32,
    pub max_size: u32,
    /// `align` as declared (or the legacy `size` attribute, which Ghidra reads as align).
    pub align: Option<u32>,
    /// `storage` (or deprecated `metatype`); `general` when absent.
    pub storage_class: StorageClass,
    pub extension: Extension,
    pub storage: Storage,
    /// Index of the enclosing `<group>` in this list, in declaration order.
    pub group: Option<usize>,
    pub line: u32,
}

impl ParamEntry {
    /// Ghidra's slot alignment: the declared alignment, or 0 when absent or equal to
    /// `max_size` (a single slot).
    pub fn alignment(&self) -> u32 {
        match self.align {
            Some(a) if a != self.max_size => a,
            _ => 0,
        }
    }

    /// Number of slots: `max_size / alignment`, or 1 when unaligned.
    pub fn slots(&self) -> u32 {
        match self.alignment() {
            0 => 1,
            a => self.max_size / a,
        }
    }

    pub fn is_grouped(&self) -> bool {
        self.group.is_some()
    }
}

/// `<datatype name=..>` filter class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DatatypeClass {
    /// `any`: any data-type within the size bounds.
    Any,
    /// `homogeneous-float-aggregate`.
    HomogeneousFloatAggregate,
    /// A decompiler meta-type name.
    Meta(MetaType),
}

/// Decompiler meta-types accepted by `MetaDataType.get`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MetaType {
    Void,
    Spacebase,
    Unknown,
    Int,
    Uint,
    Bool,
    Code,
    Float,
    Ptr,
    PtrRel,
    Array,
    Struct,
    Union,
    PartEnum,
    PartUnion,
    EnumInt,
    EnumUint,
}

impl MetaType {
    pub fn parse(text: &str) -> Option<MetaType> {
        Some(match text {
            "void" => MetaType::Void,
            "spacebase" => MetaType::Spacebase,
            "unknown" => MetaType::Unknown,
            "int" => MetaType::Int,
            "uint" => MetaType::Uint,
            "bool" => MetaType::Bool,
            "code" => MetaType::Code,
            "float" => MetaType::Float,
            "ptr" => MetaType::Ptr,
            "ptrrel" => MetaType::PtrRel,
            "array" => MetaType::Array,
            "struct" => MetaType::Struct,
            "union" => MetaType::Union,
            "partenum" => MetaType::PartEnum,
            "partunion" => MetaType::PartUnion,
            "enum_int" => MetaType::EnumInt,
            "enum_uint" => MetaType::EnumUint,
            _ => return None,
        })
    }
}

/// `<datatype>` filter as declared.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DatatypeFilter {
    pub class: DatatypeClass,
    pub min_size: Option<u32>,
    pub max_size: Option<u32>,
    /// `sizes="3,5,6,7"` in written order. Exclusive with min/max size.
    pub sizes: Vec<u32>,
    /// Homogeneous aggregates only.
    pub max_primitives: Option<u32>,
    /// Arrays only.
    pub min_elements: Option<u32>,
    pub max_elements: Option<u32>,
}

/// Qualifiers that further restrict when a rule applies.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleQualifier {
    /// `<varargs [first] [last]/>`.
    Varargs {
        first: Option<i32>,
        last: Option<i32>,
    },
    /// `<position index/>`.
    Position { index: i32 },
    /// `<datatype_at index><datatype ../></datatype_at>`.
    DatatypeAt {
        index: i32,
        datatype: DatatypeFilter,
    },
}

/// `<hidden_return strategy>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum HiddenReturnStrategy {
    /// `special` (the default): pointer passed in a dedicated register.
    Special,
    /// `normalparam`: pointer passed as an ordinary first parameter.
    NormalParam,
}

/// The single assignment action of a rule. Attribute values are as declared; defaults
/// are left to the resolver, which must follow Ghidra's action classes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    /// `<consume storage/>`.
    Consume { storage: StorageClass },
    /// `<convert_to_ptr/>`.
    ConvertToPointer,
    /// `<goto_stack/>`.
    GotoStack,
    /// `<join ...>` (`MultiSlotAssign`).
    Join {
        storage: Option<StorageClass>,
        reverse_justify: Option<bool>,
        reverse_significance: Option<bool>,
        align: Option<bool>,
        stack_spill: Option<bool>,
        backfill: Option<bool>,
    },
    /// `<hidden_return ...>`.
    HiddenReturn {
        strategy: Option<HiddenReturnStrategy>,
        void_lock: Option<bool>,
    },
    /// `<join_per_primitive [storage]/>`.
    JoinPerPrimitive { storage: Option<StorageClass> },
    /// `<join_dual_class ...>` (`MultiSlotDualAssign`). `storage` and `a` are synonyms.
    JoinDualClass {
        storage_a: Option<StorageClass>,
        storage_b: Option<StorageClass>,
        reverse_justify: Option<bool>,
        reverse_significance: Option<bool>,
        stack_spill: Option<bool>,
        fill_alternate: Option<bool>,
    },
}

/// Preconditions and side effects of a rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleSideEffect {
    /// `<consume_extra storage [matchsize]/>`.
    ConsumeExtra {
        storage: StorageClass,
        match_size: Option<bool>,
    },
    /// `<extra_stack [afterbytes] [afterstorage]/>`.
    ExtraStack {
        after_bytes: Option<i32>,
        after_storage: Option<StorageClass>,
    },
    /// `<consume_remaining storage/>`.
    ConsumeRemaining { storage: StorageClass },
}

/// One `<rule>` (`ModelRule`), in declaration order. Rules are data only here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelRule {
    pub datatype: DatatypeFilter,
    pub qualifiers: Vec<RuleQualifier>,
    /// `<consume_extra>` written before the action.
    pub preconditions: Vec<RuleSideEffect>,
    pub action: RuleAction,
    pub side_effects: Vec<RuleSideEffect>,
    pub line: u32,
}

/// `<input>` or `<output>` of a prototype.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamList {
    /// In document order. Order is significant: it is Ghidra's allocation order.
    pub entries: Vec<ParamEntry>,
    /// Number of `<group>` elements; [`ParamEntry::group`] indexes them.
    pub group_count: usize,
    /// In document order.
    pub rules: Vec<ModelRule>,
    /// `pointermax`. Ghidra appends an implicit rule converting larger data-types to
    /// pointers after the declared rules; that rule is not synthesized here.
    pub pointer_max: Option<u32>,
    pub this_before_return_pointer: bool,
    pub killed_by_call: bool,
    /// `separatefloat`; true when absent.
    pub separate_float: bool,
    pub line: u32,
}

impl ParamList {
    fn empty(line: u32) -> ParamList {
        ParamList {
            entries: Vec::new(),
            group_count: 0,
            rules: Vec::new(),
            pointer_max: None,
            this_before_return_pointer: false,
            killed_by_call: false,
            separate_float: true,
            line,
        }
    }

    /// Entries of one `<group>`, in declaration order.
    pub fn group(&self, index: usize) -> impl Iterator<Item = &ParamEntry> {
        self.entries.iter().filter(move |e| e.group == Some(index))
    }

    /// Register names of entries stored in a single named register, in order.
    pub fn register_names(&self) -> Vec<&str> {
        self.entries
            .iter()
            .filter_map(|e| e.storage.register_name())
            .collect()
    }

    /// The first entry in the stack space (Ghidra's stack parameter entry).
    pub fn stack_entry(&self) -> Option<&ParamEntry> {
        self.entries.iter().find(|e| e.storage.is_stack())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Extrapop {
    /// Stack-pointer change across the call, in bytes.
    Known(i32),
    /// `extrapop="unknown"`: determined per function by analysis.
    Unknown,
}

/// `strategy` attribute.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AssignStrategy {
    Standard,
    /// Output uses `ParamListRegisterOut` (first matching storage location).
    Register,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum InjectionPoint {
    UponEntry,
    UponReturn,
}

/// A prototype-level `<pcode inject=..>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrototypeInjection {
    pub point: InjectionPoint,
    pub pcode: PcodeSnippet,
}

/// `<sharestack first align/>`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShareStack {
    /// `first="input"`.
    pub input_first: bool,
    pub align: Option<i32>,
}

/// Whether a prototype's declarations were captured without errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ModelStatus {
    /// Every declaration was captured and passed the checks this crate can make without
    /// the language. It is still unresolved data, not an executable ABI.
    Complete,
    /// Errors were found; see the spec diagnostics in this prototype's line range.
    /// Ghidra would reject the file. Do not use this model for allocation.
    Incomplete { errors: usize },
}

/// A `<prototype>`: one calling convention.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrototypeModel {
    pub name: String,
    pub extrapop: Extrapop,
    pub stackshift: i32,
    pub strategy: AssignStrategy,
    /// `hasthis`, or `name == "__thiscall"` when absent (Ghidra's rule).
    pub has_this: bool,
    pub constructor: bool,
    pub input: ParamList,
    pub output: ParamList,
    pub unaffected: Vec<Storage>,
    pub killed_by_call: Vec<Storage>,
    /// Model-specific `<returnaddress>`. When `None` Ghidra uses the spec-level one; see
    /// [`CompilerSpec::return_address_for`].
    pub return_address: Option<Vec<Storage>>,
    pub likely_trash: Vec<Storage>,
    pub internal_storage: Vec<Storage>,
    pub local_range: Option<Vec<MemoryTag>>,
    pub param_range: Option<Vec<MemoryTag>>,
    pub injections: Vec<PrototypeInjection>,
    pub share_stack: Option<ShareStack>,
    pub status: ModelStatus,
    pub line: u32,
}

impl PrototypeModel {
    pub fn is_complete(&self) -> bool {
        self.status == ModelStatus::Complete
    }
}

/// `<modelalias name parent/>` or Ghidra's implicit `__thiscall` alias.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelAlias {
    pub name: String,
    pub parent: String,
    /// True for the `__thiscall` alias Ghidra creates when no model has that name.
    pub implicit: bool,
    /// `None` for the implicit alias.
    pub line: Option<u32>,
}

/// `<resolveprototype name>`: a merged model Ghidra selects from by scoring. Selection
/// is not implemented here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MergedModel {
    pub name: String,
    /// Names of the candidate models, in order.
    pub models: Vec<String>,
    pub line: u32,
}

/// A model found by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ModelRef<'a> {
    Prototype(&'a PrototypeModel),
    /// An alias and the prototype it copies.
    Alias {
        alias: &'a ModelAlias,
        target: &'a PrototypeModel,
    },
    Merged(&'a MergedModel),
}

impl<'a> ModelRef<'a> {
    pub fn name(&self) -> &'a str {
        match self {
            ModelRef::Prototype(p) => &p.name,
            ModelRef::Alias { alias, .. } => &alias.name,
            ModelRef::Merged(m) => &m.name,
        }
    }

    /// The prototype whose declarations apply, if this is not a merged model.
    pub fn prototype(&self) -> Option<&'a PrototypeModel> {
        match self {
            ModelRef::Prototype(p) => Some(p),
            ModelRef::Alias { target, .. } => Some(target),
            ModelRef::Merged(_) => None,
        }
    }

    /// Ghidra's `hasThis`: an alias has it when its parent does or it is `__thiscall`.
    pub fn has_this(&self) -> Option<bool> {
        match self {
            ModelRef::Prototype(p) => Some(p.has_this),
            ModelRef::Alias { alias, target } => Some(target.has_this || alias.name == THISCALL),
            ModelRef::Merged(_) => None,
        }
    }
}

/// Why an element is listed in [`CompilerSpec::unmodeled`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum UnmodeledReason {
    /// Ghidra uses it, but this crate does not build a typed model for it.
    NotModeled,
    /// Allowed by the schema but discarded by Ghidra's loader as well.
    IgnoredByGhidra,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unmodeled {
    pub element: String,
    pub line: u32,
    pub reason: UnmodeledReason,
}

/// Counts that separate "parsed" from "fully modeled".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SpecCoverage {
    pub prototypes: usize,
    pub complete_prototypes: usize,
    /// Elements Ghidra uses that were not modeled.
    pub not_modeled: usize,
    /// Elements Ghidra itself ignores.
    pub ignored_by_ghidra: usize,
    pub errors: usize,
    pub warnings: usize,
    pub infos: usize,
}

/// A parsed `.cspec`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerSpec {
    pub path: Option<PathBuf>,
    /// In document order; repeated keys are kept (the last wins, see [`Self::property`]).
    pub properties: Vec<Property>,
    pub data_organization: Option<DataOrganization>,
    pub stack_pointer: Option<StackPointer>,
    /// Spec-level `<returnaddress>`: the default for prototypes without their own.
    pub return_address: Option<Storage>,
    /// `<funcptr align>`.
    pub function_pointer_align: Option<u32>,
    /// `<global>` tags, accumulated in document order.
    pub global: Vec<MemoryTag>,
    pub no_high_ptr: Option<Vec<MemoryTag>>,
    pub read_only: Option<Vec<MemoryTag>>,
    pub space_bases: Vec<SpaceBase>,
    pub dead_code_delays: Vec<DeadCodeDelay>,
    pub infer_pointer_bounds: Vec<AddressRange>,
    /// `<aggressivetrim signext>`.
    pub aggressive_trim: Option<bool>,
    /// `<prefersplit style="inhalf">` storage, in order.
    pub prefer_split: Vec<Storage>,
    pub context_sets: Vec<ContextSet>,
    pub tracked_sets: Vec<TrackedSet>,
    pub call_fixups: Vec<CallFixup>,
    pub callother_fixups: Vec<CallOtherFixup>,
    /// Every `<prototype>` (including the one inside `<default_proto>`), document order.
    pub prototypes: Vec<PrototypeModel>,
    /// Name of the default model (the `<default_proto>` one).
    pub default_model: Option<String>,
    pub aliases: Vec<ModelAlias>,
    pub merged_models: Vec<MergedModel>,
    pub eval_current_prototype: Option<String>,
    pub eval_called_prototype: Option<String>,
    pub unmodeled: Vec<Unmodeled>,
    pub diagnostics: Vec<Diagnostic>,
}

impl CompilerSpec {
    pub fn from_path(path: &Path) -> Result<CompilerSpec, Error> {
        Self::from_path_with(path, &Limits::default())
    }

    pub fn from_path_with(path: &Path, limits: &Limits) -> Result<CompilerSpec, Error> {
        let doc = xml::parse_file(path, limits)?;
        Self::from_element(&doc, Some(path))
    }

    /// Parse spec text. `path` is only used for diagnostics.
    pub fn parse_str(
        text: &str,
        path: Option<&Path>,
        limits: &Limits,
    ) -> Result<CompilerSpec, Error> {
        let label = path.map(Path::to_path_buf).unwrap_or_default();
        let doc = xml::parse_text(text, &label, limits)?;
        Self::from_element(&doc, path)
    }

    fn from_element(doc: &Element, path: Option<&Path>) -> Result<CompilerSpec, Error> {
        if doc.name != "compiler_spec" {
            return Err(Error::Schema {
                path: path.map(Path::to_path_buf).unwrap_or_default(),
                line: doc.line,
                message: format!("root element is <{}>, expected <compiler_spec>", doc.name),
            });
        }
        let mut reader = Reader {
            path: path.map(Path::to_path_buf),
            diagnostics: Vec::new(),
            errors: 0,
            stack_growth: StackGrowth::Negative,
        };
        let mut spec = CompilerSpec {
            path: path.map(Path::to_path_buf),
            properties: Vec::new(),
            data_organization: None,
            stack_pointer: None,
            return_address: None,
            function_pointer_align: None,
            global: Vec::new(),
            no_high_ptr: None,
            read_only: None,
            space_bases: Vec::new(),
            dead_code_delays: Vec::new(),
            infer_pointer_bounds: Vec::new(),
            aggressive_trim: None,
            prefer_split: Vec::new(),
            context_sets: Vec::new(),
            tracked_sets: Vec::new(),
            call_fixups: Vec::new(),
            callother_fixups: Vec::new(),
            prototypes: Vec::new(),
            default_model: None,
            aliases: Vec::new(),
            merged_models: Vec::new(),
            eval_current_prototype: None,
            eval_called_prototype: None,
            unmodeled: Vec::new(),
            diagnostics: Vec::new(),
        };
        reader.unknown_attrs(doc, &[]);
        let mut seen_default = false;
        // Ghidra makes the first plain <prototype> the default when no <default_proto>
        // has been seen yet.
        let mut fallback_default: Option<String> = None;
        for child in &doc.children {
            match child.name.as_str() {
                "properties" => reader.read_properties(child, &mut spec.properties),
                "data_organization" => {
                    if spec.data_organization.is_some() {
                        reader.warn(
                            DiagnosticKind::DuplicateEntry,
                            child.line,
                            "<data_organization> repeated; values accumulate like Ghidra".into(),
                        );
                    }
                    let mut org = spec.data_organization.take().unwrap_or_default();
                    reader.read_data_organization(child, &mut org);
                    spec.data_organization = Some(org);
                }
                "callfixup" => {
                    if let Some(fixup) = reader.read_callfixup(child) {
                        if spec.call_fixups.iter().any(|f| f.name == fixup.name) {
                            reader.warn(
                                DiagnosticKind::DuplicateEntry,
                                child.line,
                                format!("callfixup `{}` repeated", fixup.name),
                            );
                        }
                        spec.call_fixups.push(fixup);
                    }
                }
                "callotherfixup" => {
                    if let Some(fixup) = reader.read_callotherfixup(child) {
                        if spec
                            .callother_fixups
                            .iter()
                            .any(|f| f.target_op == fixup.target_op)
                        {
                            reader.warn(
                                DiagnosticKind::DuplicateEntry,
                                child.line,
                                format!("callotherfixup `{}` repeated", fixup.target_op),
                            );
                        }
                        spec.callother_fixups.push(fixup);
                    }
                }
                "context_data" => {
                    let data = pspec::read_context_data_element(child, path);
                    for d in data.diagnostics {
                        reader.push(d);
                    }
                    spec.context_sets.extend(data.context_sets);
                    spec.tracked_sets.extend(data.tracked_sets);
                }
                "stackpointer" => {
                    if let Some(sp) = reader.read_stack_pointer(child) {
                        if let Some(old) = &spec.stack_pointer {
                            reader.warn(
                                DiagnosticKind::DuplicateEntry,
                                child.line,
                                format!(
                                    "<stackpointer> repeated; `{}` replaces `{}`",
                                    sp.register, old.register
                                ),
                            );
                        }
                        reader.stack_growth = sp.growth;
                        spec.stack_pointer = Some(sp);
                    }
                }
                "spacebase" => {
                    if let Some(sb) = reader.read_space_base(child) {
                        if spec.space_bases.iter().any(|s| s.name == sb.name) {
                            reader.error(
                                DiagnosticKind::DuplicateEntry,
                                child.line,
                                format!("duplicate spacebase `{}`; ignored", sb.name),
                            );
                        } else {
                            spec.space_bases.push(sb);
                        }
                    }
                }
                "global" => {
                    let tags = reader.read_memory_tags(child);
                    spec.global.extend(tags);
                }
                "nohighptr" | "readonly" => {
                    let tags = reader.read_memory_tags(child);
                    let slot = if child.name == "nohighptr" {
                        &mut spec.no_high_ptr
                    } else {
                        &mut spec.read_only
                    };
                    if slot.is_some() {
                        reader.warn(
                            DiagnosticKind::DuplicateEntry,
                            child.line,
                            format!("<{}> repeated; the last one wins", child.name),
                        );
                    }
                    *slot = Some(tags);
                }
                "default_proto" => {
                    reader.unknown_attrs(child, &[]);
                    let mut inner = child.children.iter();
                    let (Some(proto), None) = (inner.next(), inner.next()) else {
                        reader.error(
                            DiagnosticKind::MissingElement,
                            child.line,
                            "<default_proto> must contain exactly one <prototype>".into(),
                        );
                        continue;
                    };
                    let name = match proto.name.as_str() {
                        "prototype" => reader
                            .read_prototype(proto)
                            .and_then(|p| spec.add_prototype(&mut reader, p)),
                        "resolveprototype" => reader
                            .read_merged(proto, &spec)
                            .and_then(|m| spec.add_merged(&mut reader, m)),
                        other => {
                            reader.error(
                                DiagnosticKind::UnknownElement,
                                proto.line,
                                format!("<{other}> in <default_proto>; expected <prototype>"),
                            );
                            None
                        }
                    };
                    if seen_default {
                        reader.warn(
                            DiagnosticKind::DuplicateEntry,
                            child.line,
                            "<default_proto> repeated; the first stays the default".into(),
                        );
                    } else if let Some(name) = name {
                        spec.default_model = Some(name);
                        seen_default = true;
                    }
                }
                "prototype" => {
                    if let Some(name) = reader
                        .read_prototype(child)
                        .and_then(|p| spec.add_prototype(&mut reader, p))
                        && fallback_default.is_none()
                        && !seen_default
                    {
                        fallback_default = Some(name);
                    }
                }
                "modelalias" => {
                    if let Some(alias) = reader.read_alias(child, &spec) {
                        spec.add_alias(&mut reader, alias);
                    }
                }
                "resolveprototype" => {
                    if let Some(merged) = reader.read_merged(child, &spec) {
                        spec.add_merged(&mut reader, merged);
                    }
                }
                "eval_current_prototype" | "eval_called_prototype" => {
                    reader.unknown_attrs(child, &["name"]);
                    reader.no_children(child);
                    if let Some(name) = reader.require(child, "name") {
                        let slot = if child.name == "eval_current_prototype" {
                            &mut spec.eval_current_prototype
                        } else {
                            &mut spec.eval_called_prototype
                        };
                        if slot.is_some() {
                            reader.warn(
                                DiagnosticKind::DuplicateEntry,
                                child.line,
                                format!("<{}> repeated; the last one wins", child.name),
                            );
                        }
                        *slot = Some(name.to_owned());
                    }
                }
                "segmentop" => {
                    reader.diag(
                        Severity::Warning,
                        DiagnosticKind::UnmodeledElement,
                        child.line,
                        "<segmentop> (segmented address p-code) is recorded but not modeled".into(),
                    );
                    spec.unmodeled.push(Unmodeled {
                        element: child.name.clone(),
                        line: child.line,
                        reason: UnmodeledReason::NotModeled,
                    });
                }
                "enum" => {
                    reader.diag(
                        Severity::Info,
                        DiagnosticKind::UnmodeledElement,
                        child.line,
                        "<enum> is discarded by Ghidra's compiler-spec loader; not modeled".into(),
                    );
                    spec.unmodeled.push(Unmodeled {
                        element: child.name.clone(),
                        line: child.line,
                        reason: UnmodeledReason::IgnoredByGhidra,
                    });
                }
                "aggressivetrim" => {
                    reader.unknown_attrs(child, &["signext"]);
                    reader.no_children(child);
                    // decodeBoolean(null) is false in Ghidra.
                    spec.aggressive_trim =
                        Some(reader.bool_attr(child, "signext").unwrap_or(false));
                }
                "prefersplit" => {
                    reader.unknown_attrs(child, &["style"]);
                    match child.attr("style") {
                        Some("inhalf") => {
                            spec.prefer_split = reader.read_storage_list(child, false);
                        }
                        other => reader.error(
                            DiagnosticKind::InvalidAttribute,
                            child.line,
                            format!(
                                "<prefersplit> style {:?} is not `inhalf` (the only strategy); ignored",
                                other.unwrap_or("")
                            ),
                        ),
                    }
                }
                "returnaddress" => {
                    reader.unknown_attrs(child, &[]);
                    let list = reader.read_storage_list(child, false);
                    if child.children.len() != 1 || list.len() != 1 {
                        reader.error(
                            DiagnosticKind::InconsistentSpec,
                            child.line,
                            "spec-level <returnaddress> must hold exactly one storage element"
                                .into(),
                        );
                    }
                    if let Some(storage) = list.into_iter().next() {
                        spec.return_address = Some(storage);
                    }
                }
                "funcptr" => {
                    reader.unknown_attrs(child, &["align"]);
                    reader.no_children(child);
                    if reader.require(child, "align").is_some()
                        && let Ok(Some(align)) = reader.u32_attr(child, "align")
                    {
                        spec.function_pointer_align = Some(align);
                    }
                }
                "deadcodedelay" => {
                    reader.unknown_attrs(child, &["space", "delay"]);
                    reader.no_children(child);
                    if let (Some(space), Some(_)) = (
                        reader.require(child, "space"),
                        reader.require(child, "delay"),
                    ) && let Ok(Some(delay)) = reader.i32_attr(child, "delay")
                    {
                        spec.dead_code_delays.push(DeadCodeDelay {
                            space: space.to_owned(),
                            delay,
                        });
                    }
                }
                "inferptrbounds" => {
                    reader.unknown_attrs(child, &[]);
                    for tag in reader.read_memory_tags(child) {
                        match tag {
                            MemoryTag::Range(range) => spec.infer_pointer_bounds.push(range),
                            MemoryTag::Register { name } => reader.error(
                                DiagnosticKind::UnsupportedForm,
                                child.line,
                                format!(
                                    "<register name=\"{name}\"> in <inferptrbounds> needs the language; ignored"
                                ),
                            ),
                        }
                    }
                }
                other => reader.warn(
                    DiagnosticKind::UnknownElement,
                    child.line,
                    format!("ignored element <{other}> in <compiler_spec> (Ghidra discards it)"),
                ),
            }
        }

        if spec.default_model.is_none() {
            match fallback_default {
                Some(name) => {
                    reader.warn(
                        DiagnosticKind::MissingElement,
                        doc.line,
                        format!("no <default_proto>; Ghidra uses the first <prototype> `{name}`"),
                    );
                    spec.default_model = Some(name);
                }
                None => reader.error(
                    DiagnosticKind::MissingElement,
                    doc.line,
                    "no <default_proto> and no <prototype>; the spec has no default model".into(),
                ),
            }
        }
        if let Some(default) = spec.default_model.clone()
            && spec.model(THISCALL).is_none()
        {
            if spec.prototype(&default).is_some() {
                spec.aliases.push(ModelAlias {
                    name: THISCALL.into(),
                    parent: default,
                    implicit: true,
                    line: None,
                });
            } else {
                reader.error(
                    DiagnosticKind::InconsistentSpec,
                    doc.line,
                    format!(
                        "default model `{default}` is not a plain prototype, so Ghidra cannot alias `{THISCALL}` to it"
                    ),
                );
            }
        }
        for (slot, label) in [
            (&spec.eval_current_prototype, "eval_current_prototype"),
            (&spec.eval_called_prototype, "eval_called_prototype"),
        ] {
            if let Some(name) = slot
                && spec.model(name).is_none()
            {
                reader.warn(
                    DiagnosticKind::UnresolvedReference,
                    doc.line,
                    format!("<{label}> names unknown model `{name}`; Ghidra uses the default"),
                );
            }
        }
        spec.diagnostics = reader.diagnostics;
        Ok(spec)
    }

    fn name_taken(&self, name: &str) -> bool {
        self.model(name).is_some()
    }

    fn add_prototype(&mut self, reader: &mut Reader, proto: PrototypeModel) -> Option<String> {
        if self.name_taken(&proto.name) {
            reader.error(
                DiagnosticKind::DuplicateEntry,
                proto.line,
                format!(
                    "multiple prototype models named `{}`; keeping the first",
                    proto.name
                ),
            );
            return None;
        }
        let name = proto.name.clone();
        self.prototypes.push(proto);
        Some(name)
    }

    fn add_alias(&mut self, reader: &mut Reader, alias: ModelAlias) {
        if self.name_taken(&alias.name) {
            reader.error(
                DiagnosticKind::DuplicateEntry,
                alias.line.unwrap_or(0),
                format!(
                    "multiple prototype models named `{}`; alias ignored",
                    alias.name
                ),
            );
            return;
        }
        self.aliases.push(alias);
    }

    fn add_merged(&mut self, reader: &mut Reader, merged: MergedModel) -> Option<String> {
        if self.name_taken(&merged.name) {
            reader.error(
                DiagnosticKind::DuplicateEntry,
                merged.line,
                format!("multiple prototype models named `{}`; ignored", merged.name),
            );
            return None;
        }
        let name = merged.name.clone();
        self.merged_models.push(merged);
        Some(name)
    }

    /// Value of property `key`; when repeated, the last one (Ghidra map semantics).
    pub fn property(&self, key: &str) -> Option<&str> {
        self.properties
            .iter()
            .rev()
            .find(|p| p.key == key)
            .map(|p| p.value.as_str())
    }

    /// A plain `<prototype>` by name (aliases and merged models are not searched).
    pub fn prototype(&self, name: &str) -> Option<&PrototypeModel> {
        self.prototypes.iter().find(|p| p.name == name)
    }

    /// Any model by name: prototype, alias (with its target) or merged model.
    pub fn model(&self, name: &str) -> Option<ModelRef<'_>> {
        if let Some(p) = self.prototype(name) {
            return Some(ModelRef::Prototype(p));
        }
        if let Some(alias) = self.aliases.iter().find(|a| a.name == name) {
            return self
                .prototype(&alias.parent)
                .map(|target| ModelRef::Alias { alias, target });
        }
        self.merged_models
            .iter()
            .find(|m| m.name == name)
            .map(ModelRef::Merged)
    }

    /// The default model.
    pub fn default_model(&self) -> Option<ModelRef<'_>> {
        self.default_model.as_deref().and_then(|n| self.model(n))
    }

    /// Model names in Ghidra's declaration order (prototypes, then aliases, then merged
    /// models, each in document order).
    pub fn model_names(&self) -> Vec<&str> {
        self.prototypes
            .iter()
            .map(|p| p.name.as_str())
            .chain(self.aliases.iter().map(|a| a.name.as_str()))
            .chain(self.merged_models.iter().map(|m| m.name.as_str()))
            .collect()
    }

    /// Return-address storage for `proto`: its own `<returnaddress>` or else the
    /// spec-level one (`BasicCompilerSpec.setDefaultReturnAddressIfNeeded`).
    pub fn return_address_for<'a>(&'a self, proto: &'a PrototypeModel) -> &'a [Storage] {
        match &proto.return_address {
            Some(list) => list,
            None => self.return_address.as_slice(),
        }
    }

    /// Data organization with Ghidra defaults (see [`DataOrganization::resolve`]).
    pub fn resolved_data_organization(
        &self,
        language_pointer_size: u32,
    ) -> ResolvedDataOrganization {
        self.data_organization
            .clone()
            .unwrap_or_default()
            .resolve(language_pointer_size)
    }

    pub fn coverage(&self) -> SpecCoverage {
        let count = |s: Severity| self.diagnostics.iter().filter(|d| d.severity == s).count();
        SpecCoverage {
            prototypes: self.prototypes.len(),
            complete_prototypes: self.prototypes.iter().filter(|p| p.is_complete()).count(),
            not_modeled: self
                .unmodeled
                .iter()
                .filter(|u| u.reason == UnmodeledReason::NotModeled)
                .count(),
            ignored_by_ghidra: self
                .unmodeled
                .iter()
                .filter(|u| u.reason == UnmodeledReason::IgnoredByGhidra)
                .count(),
            errors: count(Severity::Error),
            warnings: count(Severity::Warning),
            infos: count(Severity::Info),
        }
    }

    /// True when a default model exists, every prototype is [`ModelStatus::Complete`],
    /// nothing Ghidra uses was left unmodeled and no error was reported. This is a data
    /// capture statement: registers are still unresolved and no allocation is performed.
    pub fn is_fully_modeled(&self) -> bool {
        let c = self.coverage();
        self.default_model().is_some()
            && c.errors == 0
            && c.not_modeled == 0
            && c.complete_prototypes == c.prototypes
    }
}

// ---------------------------------------------------------------------------------------
// Reader
// ---------------------------------------------------------------------------------------

struct Reader {
    path: Option<PathBuf>,
    diagnostics: Vec<Diagnostic>,
    /// Error diagnostics so far; prototypes compare before/after.
    errors: usize,
    /// Growth from the last `<stackpointer>` seen. Ghidra reads sequentially, so entries
    /// before the stack pointer use the default (negative).
    stack_growth: StackGrowth,
}

const PENTRY_ATTRS: &[&str] = &[
    "minsize",
    "maxsize",
    "align",
    "size",
    "storage",
    "metatype",
    "extension",
];

const DATA_ORG_VALUES: &[&str] = &[
    "absolute_max_alignment",
    "machine_alignment",
    "default_alignment",
    "default_pointer_alignment",
    "pointer_size",
    "pointer_shift",
    "char_size",
    "wchar_size",
    "short_size",
    "integer_size",
    "long_size",
    "long_long_size",
    "float_size",
    "double_size",
    "long_double_size",
];

/// `SpecExtension.isValidFormalName`.
fn is_valid_formal_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '_' | '.' | '-' | '/'))
}

impl Reader {
    fn push(&mut self, d: Diagnostic) {
        if d.severity == Severity::Error {
            self.errors += 1;
        }
        self.diagnostics.push(d);
    }

    fn diag(&mut self, severity: Severity, kind: DiagnosticKind, line: u32, message: String) {
        self.push(Diagnostic {
            severity,
            kind,
            path: self.path.clone(),
            line: Some(line),
            language_id: None,
            message,
        });
    }

    fn error(&mut self, kind: DiagnosticKind, line: u32, message: String) {
        self.diag(Severity::Error, kind, line, message);
    }

    fn warn(&mut self, kind: DiagnosticKind, line: u32, message: String) {
        self.diag(Severity::Warning, kind, line, message);
    }

    fn unknown_attrs(&mut self, el: &Element, known: &[&str]) {
        for (key, _) in &el.attrs {
            if !known.contains(&key.as_str()) {
                let msg = format!("ignored attribute `{key}` on <{}>", el.name);
                self.warn(DiagnosticKind::UnknownAttribute, el.line, msg);
            }
        }
    }

    fn no_children(&mut self, el: &Element) {
        for child in &el.children {
            let msg = format!("ignored element <{}> in <{}>", child.name, el.name);
            self.warn(DiagnosticKind::UnknownElement, child.line, msg);
        }
    }

    fn require<'e>(&mut self, el: &'e Element, attr: &str) -> Option<&'e str> {
        let value = el.attr(attr);
        if value.is_none() {
            let msg = format!("<{}> is missing required attribute `{attr}`", el.name);
            self.error(DiagnosticKind::MissingAttribute, el.line, msg);
        }
        value
    }

    fn invalid(&mut self, el: &Element, attr: &str, text: &str, what: &str) {
        let msg = format!("<{}> `{attr}=\"{text}\"` is not {what}", el.name);
        self.error(DiagnosticKind::InvalidAttribute, el.line, msg);
    }

    /// `Ok(None)` when absent; `Err` (already reported) when malformed or out of range.
    fn u32_attr(&mut self, el: &Element, attr: &str) -> Result<Option<u32>, ()> {
        let Some(text) = el.attr(attr) else {
            return Ok(None);
        };
        match xml::decode_java_int(text).and_then(|v| u32::try_from(v).ok()) {
            Some(v) => Ok(Some(v)),
            None => {
                self.invalid(el, attr, text, "a non-negative 32-bit integer");
                Err(())
            }
        }
    }

    fn i32_attr(&mut self, el: &Element, attr: &str) -> Result<Option<i32>, ()> {
        let Some(text) = el.attr(attr) else {
            return Ok(None);
        };
        match xml::decode_java_int(text).and_then(|v| i32::try_from(v).ok()) {
            Some(v) => Ok(Some(v)),
            None => {
                self.invalid(el, attr, text, "a 32-bit integer");
                Err(())
            }
        }
    }

    /// An address offset: unsigned 64-bit, or a negative value stored as its 64-bit
    /// two's-complement pattern (Java `long` semantics).
    fn offset_value(text: &str) -> Option<u64> {
        xml::decode_java_unsigned(text).or_else(|| {
            xml::decode_java_int(text)
                .filter(|v| *v < 0)
                .map(|v| v as u64)
        })
    }

    fn offset_attr(&mut self, el: &Element, attr: &str) -> Result<Option<u64>, ()> {
        let Some(text) = el.attr(attr) else {
            return Ok(None);
        };
        match Self::offset_value(text) {
            Some(v) => Ok(Some(v)),
            None => {
                self.invalid(el, attr, text, "a 64-bit address offset");
                Err(())
            }
        }
    }

    /// `SpecXmlUtils.decodeBoolean`; an unrecognised value warns and reads as false.
    fn bool_attr(&mut self, el: &Element, attr: &str) -> Option<bool> {
        let text = el.attr(attr)?;
        Some(xml::decode_java_bool(text).unwrap_or_else(|| {
            let msg = format!(
                "<{}> `{attr}=\"{text}\"` is not a boolean; Ghidra reads it as false",
                el.name
            );
            self.warn(DiagnosticKind::InvalidAttribute, el.line, msg);
            false
        }))
    }

    fn storage_class_attr(&mut self, el: &Element, attr: &str) -> Result<Option<StorageClass>, ()> {
        let Some(text) = el.attr(attr) else {
            return Ok(None);
        };
        match StorageClass::parse(text) {
            Some(c) => Ok(Some(c)),
            None => {
                self.invalid(el, attr, text, "a storage class");
                Err(())
            }
        }
    }

    fn read_properties(&mut self, el: &Element, out: &mut Vec<Property>) {
        self.unknown_attrs(el, &[]);
        for prop in &el.children {
            if prop.name != "property" {
                let msg = format!("ignored element <{}> in <properties>", prop.name);
                self.warn(DiagnosticKind::UnknownElement, prop.line, msg);
                continue;
            }
            self.unknown_attrs(prop, &["key", "value"]);
            let (Some(key), Some(value)) = (prop.attr("key"), prop.attr("value")) else {
                let msg = "<property> needs `key` and `value`; ignored".into();
                self.error(DiagnosticKind::MissingAttribute, prop.line, msg);
                continue;
            };
            if out.iter().any(|p| p.key == key) {
                let msg = format!("property `{key}` repeated; the last value wins");
                self.warn(DiagnosticKind::DuplicateEntry, prop.line, msg);
            }
            out.push(Property {
                key: key.to_owned(),
                value: value.to_owned(),
            });
        }
    }

    fn read_data_organization(&mut self, el: &Element, org: &mut DataOrganization) {
        self.unknown_attrs(el, &[]);
        let mut seen: Vec<&str> = Vec::new();
        for child in &el.children {
            let name = child.name.as_str();
            if seen.contains(&name) {
                let msg = format!("<{name}> repeated in <data_organization>; the last wins");
                self.warn(DiagnosticKind::DuplicateEntry, child.line, msg);
            }
            seen.push(name);
            match name {
                "char_type" => {
                    self.unknown_attrs(child, &["signed"]);
                    self.no_children(child);
                    if self.require(child, "signed").is_some() {
                        org.char_signed = self.bool_attr(child, "signed");
                    }
                }
                "size_alignment_map" => {
                    self.unknown_attrs(child, &[]);
                    for entry in &child.children {
                        if entry.name != "entry" {
                            let msg = format!(
                                "unsupported <{}> in <size_alignment_map>; ignored",
                                entry.name
                            );
                            self.error(DiagnosticKind::UnknownElement, entry.line, msg);
                            continue;
                        }
                        self.unknown_attrs(entry, &["size", "alignment"]);
                        self.no_children(entry);
                        let (Some(_), Some(_)) = (
                            self.require(entry, "size"),
                            self.require(entry, "alignment"),
                        ) else {
                            continue;
                        };
                        let (Ok(Some(size)), Ok(Some(alignment))) = (
                            self.u32_attr(entry, "size"),
                            self.u32_attr(entry, "alignment"),
                        ) else {
                            continue;
                        };
                        if org.size_alignment_map.iter().any(|e| e.size == size) {
                            let msg =
                                format!("size {size} mapped more than once; the last mapping wins");
                            self.warn(DiagnosticKind::DuplicateEntry, entry.line, msg);
                        }
                        org.size_alignment_map
                            .push(SizeAlignment { size, alignment });
                    }
                }
                "bitfield_packing" => {
                    self.unknown_attrs(child, &[]);
                    let packing = org.bitfield_packing.get_or_insert_with(Default::default);
                    for item in &child.children {
                        self.unknown_attrs(item, &["value"]);
                        self.no_children(item);
                        match item.name.as_str() {
                            "use_MS_convention" | "type_alignment_enabled" => {
                                if self.require(item, "value").is_none() {
                                    continue;
                                }
                                let v = self.bool_attr(item, "value");
                                if item.name == "use_MS_convention" {
                                    packing.use_ms_convention = v;
                                } else {
                                    packing.type_alignment_enabled = v;
                                }
                            }
                            "zero_length_boundary" => {
                                if self.require(item, "value").is_some()
                                    && let Ok(v) = self.u32_attr(item, "value")
                                {
                                    packing.zero_length_boundary = v;
                                }
                            }
                            other => {
                                let msg = format!(
                                    "ignored element <{other}> in <bitfield_packing> (Ghidra ignores it too)"
                                );
                                self.warn(DiagnosticKind::UnknownElement, item.line, msg);
                            }
                        }
                    }
                }
                value_name if DATA_ORG_VALUES.contains(&value_name) => {
                    self.unknown_attrs(child, &["value"]);
                    self.no_children(child);
                    if self.require(child, "value").is_none() {
                        continue;
                    }
                    let Ok(Some(v)) = self.u32_attr(child, "value") else {
                        continue;
                    };
                    let slot = match value_name {
                        "absolute_max_alignment" => &mut org.absolute_max_alignment,
                        "machine_alignment" => &mut org.machine_alignment,
                        "default_alignment" => &mut org.default_alignment,
                        "default_pointer_alignment" => &mut org.default_pointer_alignment,
                        "pointer_size" => &mut org.pointer_size,
                        "pointer_shift" => &mut org.pointer_shift,
                        "char_size" => &mut org.char_size,
                        "wchar_size" => &mut org.wchar_size,
                        "short_size" => &mut org.short_size,
                        "integer_size" => &mut org.integer_size,
                        "long_size" => &mut org.long_size,
                        "long_long_size" => &mut org.long_long_size,
                        "float_size" => &mut org.float_size,
                        "double_size" => &mut org.double_size,
                        _ => &mut org.long_double_size,
                    };
                    *slot = Some(v);
                }
                other => {
                    let msg = format!(
                        "ignored element <{other}> in <data_organization> (Ghidra ignores it too)"
                    );
                    self.warn(DiagnosticKind::UnknownElement, child.line, msg);
                }
            }
        }
    }

    fn read_stack_pointer(&mut self, el: &Element) -> Option<StackPointer> {
        self.unknown_attrs(el, &["register", "space", "growth", "reversejustify"]);
        self.no_children(el);
        let (Some(register), Some(space)) =
            (self.require(el, "register"), self.require(el, "space"))
        else {
            return None;
        };
        let growth = match el.attr("growth") {
            None | Some("negative") => StackGrowth::Negative,
            Some("positive") => StackGrowth::Positive,
            Some(other) => {
                self.invalid(
                    el,
                    "growth",
                    other,
                    "`negative` or `positive`; stack pointer ignored",
                );
                return None;
            }
        };
        // BasicCompilerSpec.getBooleanValue: only "1" or "true" (any case).
        let reverse_justify = match el.attr("reversejustify") {
            None => false,
            Some(text) => {
                let value = text == "1" || text.eq_ignore_ascii_case("true");
                if xml::decode_java_bool(text) != Some(value) {
                    let msg = format!(
                        "<stackpointer> `reversejustify=\"{text}\"` reads as {value}: Ghidra's stack pointer reader accepts only `1` or `true`"
                    );
                    self.warn(DiagnosticKind::InvalidAttribute, el.line, msg);
                }
                value
            }
        };
        Some(StackPointer {
            register: register.to_owned(),
            space: space.to_owned(),
            growth,
            reverse_justify,
            line: el.line,
        })
    }

    fn read_space_base(&mut self, el: &Element) -> Option<SpaceBase> {
        self.unknown_attrs(el, &["name", "register", "space"]);
        self.no_children(el);
        let (Some(name), Some(register), Some(space)) = (
            self.require(el, "name"),
            self.require(el, "register"),
            self.require(el, "space"),
        ) else {
            return None;
        };
        Some(SpaceBase {
            name: name.to_owned(),
            register: register.to_owned(),
            space: space.to_owned(),
            line: el.line,
        })
    }

    fn read_memory_tags(&mut self, el: &Element) -> Vec<MemoryTag> {
        self.unknown_attrs(el, &[]);
        let mut out = Vec::new();
        for child in &el.children {
            match child.name.as_str() {
                "register" => {
                    self.unknown_attrs(child, &["name"]);
                    self.no_children(child);
                    if let Some(name) = self.require(child, "name") {
                        out.push(MemoryTag::Register {
                            name: name.to_owned(),
                        });
                    }
                }
                "range" => {
                    if let Some(range) = self.read_range(child) {
                        out.push(MemoryTag::Range(range));
                    }
                }
                other => {
                    let msg = format!("unexpected <{other}> in <{}>; ignored", el.name);
                    self.error(DiagnosticKind::UnknownElement, child.line, msg);
                }
            }
        }
        out
    }

    fn read_range(&mut self, el: &Element) -> Option<AddressRange> {
        self.unknown_attrs(el, &["space", "first", "last"]);
        self.no_children(el);
        let space = self.require(el, "space")?;
        let first = self.offset_attr(el, "first").ok()?;
        let last = self.offset_attr(el, "last").ok()?;
        if first.is_some() != last.is_some() {
            let msg = "<range> gives only one of `first`/`last`; the other bound is open".into();
            self.warn(DiagnosticKind::UnsupportedForm, el.line, msg);
        }
        Some(AddressRange {
            space: space.to_owned(),
            first,
            last,
        })
    }

    /// One `<register>`, `<varnode>` or `<addr>` element.
    fn read_storage(&mut self, el: &Element) -> Option<Storage> {
        self.no_children(el);
        match el.name.as_str() {
            "register" => {
                self.unknown_attrs(el, &["name"]);
                let name = self.require(el, "name")?;
                Some(Storage::Register {
                    name: name.to_owned(),
                })
            }
            "varnode" | "addr" => {
                let space = self.require(el, "space")?;
                if space == JOIN_SPACE {
                    return self.read_join(el);
                }
                self.unknown_attrs(el, &["space", "offset", "size"]);
                let offset = match self.offset_attr(el, "offset") {
                    Ok(Some(v)) => v,
                    // Optional on <addr>; SpecXmlUtils.decodeLong(null) is 0.
                    Ok(None) if el.name == "addr" => 0,
                    Ok(None) => {
                        self.require(el, "offset");
                        return None;
                    }
                    Err(()) => return None,
                };
                let size = self.u32_attr(el, "size").ok()?;
                if el.name == "varnode" {
                    let Some(size) = size else {
                        self.require(el, "size");
                        return None;
                    };
                    Some(Storage::Varnode {
                        space: space.to_owned(),
                        offset,
                        size,
                    })
                } else {
                    Some(Storage::Address {
                        space: space.to_owned(),
                        offset,
                        size,
                    })
                }
            }
            other => {
                let msg = format!("<{other}> is not a storage element (register, varnode, addr)");
                self.error(DiagnosticKind::UnsupportedForm, el.line, msg);
                None
            }
        }
    }

    fn read_join(&mut self, el: &Element) -> Option<Storage> {
        let mut numbered: Vec<(u32, &str)> = Vec::new();
        for (key, value) in &el.attrs {
            if key == "space" || key == "size" {
                continue;
            }
            let index = key
                .strip_prefix("piece")
                .filter(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|d| d.parse::<u32>().ok())
                .filter(|n| *n >= 1);
            match index {
                Some(n) => numbered.push((n, value)),
                None => {
                    let msg = format!("ignored attribute `{key}` on join <{}>", el.name);
                    self.warn(DiagnosticKind::UnknownAttribute, el.line, msg);
                }
            }
        }
        numbered.sort_by_key(|(n, _)| *n);
        if numbered.is_empty() {
            let msg = format!("join <{}> has no pieceN attributes", el.name);
            self.error(DiagnosticKind::MissingAttribute, el.line, msg);
            return None;
        }
        for (expected, (n, _)) in (1u32..).zip(&numbered) {
            if *n != expected {
                let msg = format!(
                    "join pieces must be numbered piece1..pieceN without gaps; found piece{n} where piece{expected} was expected (Ghidra would stop at the gap)"
                );
                self.error(DiagnosticKind::InvalidAttribute, el.line, msg);
                return None;
            }
        }
        let mut pieces = Vec::with_capacity(numbered.len());
        for (n, text) in numbered {
            let piece = match text.split_once(':') {
                None if !text.is_empty() => JoinPiece::Register {
                    name: text.to_owned(),
                },
                None => {
                    self.invalid(
                        el,
                        &format!("piece{n}"),
                        text,
                        "a register or space:offset:size",
                    );
                    return None;
                }
                Some((space, rest)) => {
                    let parsed = rest.split_once(':').and_then(|(off, size)| {
                        let offset = Self::offset_value(off)?;
                        let size =
                            xml::decode_java_int(size).and_then(|v| u32::try_from(v).ok())?;
                        Some((offset, size))
                    });
                    match parsed {
                        Some((offset, size)) if !space.is_empty() => JoinPiece::Varnode {
                            space: space.to_owned(),
                            offset,
                            size,
                        },
                        _ => {
                            self.invalid(el, &format!("piece{n}"), text, "space:offset:size");
                            return None;
                        }
                    }
                }
            };
            pieces.push(piece);
        }
        let logical_size = self.u32_attr(el, "size").ok()?;
        Some(Storage::Join {
            pieces,
            logical_size,
        })
    }

    /// Children of a varnode list (`<unaffected>`, `<killedbycall>`, ...). Joins are not
    /// allowed here.
    fn read_storage_list(&mut self, el: &Element, check_attrs: bool) -> Vec<Storage> {
        if check_attrs {
            self.unknown_attrs(el, &[]);
        }
        let mut out = Vec::new();
        for child in &el.children {
            if child.name == "addr" {
                let msg = format!(
                    "<addr> in <{}>; the schema expects <register> or <varnode> (read like Ghidra)",
                    el.name
                );
                self.warn(DiagnosticKind::UnsupportedForm, child.line, msg);
            }
            let Some(storage) = self.read_storage(child) else {
                continue;
            };
            if matches!(storage, Storage::Join { .. }) {
                let msg = format!("join storage is not allowed in <{}>; ignored", el.name);
                self.error(DiagnosticKind::InconsistentSpec, child.line, msg);
                continue;
            }
            out.push(storage);
        }
        out
    }

    fn read_pcode(&mut self, el: &Element, extra_attrs: &[&str]) -> Option<PcodeSnippet> {
        let mut known = vec!["paramshift", "dynamic", "incidentalcopy"];
        known.extend_from_slice(extra_attrs);
        self.unknown_attrs(el, &known);
        let param_shift = self.i32_attr(el, "paramshift").ok()?;
        let dynamic = self.bool_attr(el, "dynamic");
        let incidental_copy = self.bool_attr(el, "incidentalcopy");
        let mut inputs = Vec::new();
        let mut outputs = Vec::new();
        let mut body: Option<String> = None;
        for child in &el.children {
            match child.name.as_str() {
                "input" | "output" => {
                    self.unknown_attrs(child, &["name", "size"]);
                    self.no_children(child);
                    let Some(name) = self.require(child, "name") else {
                        continue;
                    };
                    let Ok(size) = self.u32_attr(child, "size") else {
                        continue;
                    };
                    let param = InjectParameter {
                        name: name.to_owned(),
                        size,
                    };
                    if child.name == "input" {
                        inputs.push(param);
                    } else {
                        outputs.push(param);
                    }
                }
                "body" => {
                    self.unknown_attrs(child, &[]);
                    self.no_children(child);
                    if body.is_some() {
                        let msg = "<pcode> has more than one <body>; using the last".into();
                        self.warn(DiagnosticKind::DuplicateEntry, child.line, msg);
                    }
                    body = Some(child.text.clone());
                }
                other => {
                    let msg = format!("unexpected <{other}> in <pcode>; ignored");
                    self.error(DiagnosticKind::UnknownElement, child.line, msg);
                }
            }
        }
        if body.is_none() && dynamic != Some(true) {
            let msg = "<pcode> has no <body> and is not dynamic".into();
            self.warn(DiagnosticKind::MissingElement, el.line, msg);
        }
        Some(PcodeSnippet {
            param_shift,
            dynamic,
            incidental_copy,
            inputs,
            outputs,
            body,
            line: el.line,
        })
    }

    fn single_pcode(&mut self, el: &Element, children: &[&Element]) -> Option<PcodeSnippet> {
        match children {
            [pcode] => self.read_pcode(pcode, &[]),
            [] => {
                let msg = format!("<{}> has no <pcode>", el.name);
                self.error(DiagnosticKind::MissingElement, el.line, msg);
                None
            }
            [_, extra, ..] => {
                let msg = format!("<{}> has more than one <pcode>", el.name);
                self.error(DiagnosticKind::InconsistentSpec, extra.line, msg);
                None
            }
        }
    }

    fn read_callfixup(&mut self, el: &Element) -> Option<CallFixup> {
        self.unknown_attrs(el, &["name"]);
        let name = self.require(el, "name")?;
        let mut targets = Vec::new();
        let mut pcodes = Vec::new();
        for child in &el.children {
            match child.name.as_str() {
                "target" => {
                    self.unknown_attrs(child, &["name"]);
                    self.no_children(child);
                    if let Some(t) = self.require(child, "name") {
                        targets.push(t.to_owned());
                    }
                }
                "pcode" => pcodes.push(child),
                other => {
                    let msg = format!("unexpected <{other}> in <callfixup>; ignored");
                    self.error(DiagnosticKind::UnknownElement, child.line, msg);
                }
            }
        }
        let pcode = self.single_pcode(el, &pcodes)?;
        Some(CallFixup {
            name: name.to_owned(),
            targets,
            pcode,
            line: el.line,
        })
    }

    fn read_callotherfixup(&mut self, el: &Element) -> Option<CallOtherFixup> {
        self.unknown_attrs(el, &["targetop"]);
        let target_op = self.require(el, "targetop")?;
        let mut pcodes = Vec::new();
        for child in &el.children {
            if child.name == "pcode" {
                pcodes.push(child);
            } else {
                let msg = format!("unexpected <{}> in <callotherfixup>; ignored", child.name);
                self.error(DiagnosticKind::UnknownElement, child.line, msg);
            }
        }
        let pcode = self.single_pcode(el, &pcodes)?;
        Some(CallOtherFixup {
            target_op: target_op.to_owned(),
            pcode,
            line: el.line,
        })
    }

    fn read_alias(&mut self, el: &Element, spec: &CompilerSpec) -> Option<ModelAlias> {
        self.unknown_attrs(el, &["name", "parent"]);
        self.no_children(el);
        let (Some(name), Some(parent)) = (self.require(el, "name"), self.require(el, "parent"))
        else {
            return None;
        };
        let problem = if spec.prototype(parent).is_some() {
            None
        } else if spec.merged_models.iter().any(|m| m.name == parent) {
            Some("Ghidra cannot alias a merged model")
        } else if spec.aliases.iter().any(|a| a.name == parent) {
            Some("Ghidra cannot alias an alias")
        } else {
            Some("no earlier model has that name")
        };
        if let Some(problem) = problem {
            let msg =
                format!("<modelalias name=\"{name}\" parent=\"{parent}\">: {problem}; ignored");
            self.error(DiagnosticKind::UnresolvedReference, el.line, msg);
            return None;
        }
        Some(ModelAlias {
            name: name.to_owned(),
            parent: parent.to_owned(),
            implicit: false,
            line: Some(el.line),
        })
    }

    fn read_merged(&mut self, el: &Element, spec: &CompilerSpec) -> Option<MergedModel> {
        self.unknown_attrs(el, &["name"]);
        let name = self.require(el, "name")?;
        let mut models = Vec::new();
        let mut ok = true;
        let mut listed = 0usize;
        for child in &el.children {
            if child.name != "model" {
                let msg = format!("unexpected <{}> in <resolveprototype>; ignored", child.name);
                self.error(DiagnosticKind::UnknownElement, child.line, msg);
                continue;
            }
            listed += 1;
            self.unknown_attrs(child, &["name"]);
            self.no_children(child);
            let Some(model) = self.require(child, "name") else {
                ok = false;
                continue;
            };
            if spec.model(model).is_none() {
                let msg =
                    format!("<resolveprototype name=\"{name}\"> names missing model `{model}`");
                self.error(DiagnosticKind::UnresolvedReference, child.line, msg);
                ok = false;
                continue;
            }
            models.push(model.to_owned());
        }
        if listed == 0 {
            let msg = format!("<resolveprototype name=\"{name}\"> lists no models");
            self.error(DiagnosticKind::MissingElement, el.line, msg);
            return None;
        }
        if !ok || models.is_empty() {
            return None;
        }
        Some(MergedModel {
            name: name.to_owned(),
            models,
            line: el.line,
        })
    }

    fn read_prototype(&mut self, el: &Element) -> Option<PrototypeModel> {
        let errors_before = self.errors;
        self.unknown_attrs(
            el,
            &[
                "name",
                "extrapop",
                "stackshift",
                "strategy",
                "hasthis",
                "constructor",
            ],
        );
        let name = self.require(el, "name");
        let extrapop_text = self.require(el, "extrapop");
        let stackshift_text = self.require(el, "stackshift");
        let (Some(name), Some(extrapop_text), Some(_)) = (name, extrapop_text, stackshift_text)
        else {
            return None;
        };
        if !is_valid_formal_name(name) {
            let msg = format!("prototype name `{name}` uses illegal characters; prototype ignored");
            self.error(DiagnosticKind::InvalidAttribute, el.line, msg);
            return None;
        }
        let extrapop = if extrapop_text == "unknown" {
            Extrapop::Unknown
        } else {
            match self.i32_attr(el, "extrapop") {
                Ok(Some(v)) => Extrapop::Known(v),
                _ => return None,
            }
        };
        let Ok(Some(stackshift)) = self.i32_attr(el, "stackshift") else {
            return None;
        };
        let strategy = match el.attr("strategy") {
            None | Some("standard") => AssignStrategy::Standard,
            Some("register") => AssignStrategy::Register,
            Some(other) => {
                self.invalid(
                    el,
                    "strategy",
                    other,
                    "`standard` or `register`; prototype ignored",
                );
                return None;
            }
        };
        let has_this = self.bool_attr(el, "hasthis").unwrap_or(name == THISCALL);
        let constructor = self.bool_attr(el, "constructor").unwrap_or(false);

        let mut input: Option<ParamList> = None;
        let mut output: Option<ParamList> = None;
        let mut proto = PrototypeModel {
            name: name.to_owned(),
            extrapop,
            stackshift,
            strategy,
            has_this,
            constructor,
            input: ParamList::empty(el.line),
            output: ParamList::empty(el.line),
            unaffected: Vec::new(),
            killed_by_call: Vec::new(),
            return_address: None,
            likely_trash: Vec::new(),
            internal_storage: Vec::new(),
            local_range: None,
            param_range: None,
            injections: Vec::new(),
            share_stack: None,
            status: ModelStatus::Complete,
            line: el.line,
        };
        let mut seen: Vec<&str> = Vec::new();
        for child in &el.children {
            let tag = child.name.as_str();
            let single = matches!(
                tag,
                "input"
                    | "output"
                    | "unaffected"
                    | "killedbycall"
                    | "returnaddress"
                    | "likelytrash"
                    | "internal_storage"
                    | "localrange"
                    | "paramrange"
                    | "sharestack"
            );
            if single && seen.contains(&tag) {
                let msg = format!("<{tag}> repeated in prototype `{name}`; the last one wins");
                self.warn(DiagnosticKind::DuplicateEntry, child.line, msg);
            }
            seen.push(tag);
            match tag {
                "input" => input = Some(self.read_param_list(child)),
                "output" => output = Some(self.read_param_list(child)),
                "unaffected" => proto.unaffected = self.read_storage_list(child, true),
                "killedbycall" => proto.killed_by_call = self.read_storage_list(child, true),
                "returnaddress" => proto.return_address = Some(self.read_storage_list(child, true)),
                "likelytrash" => proto.likely_trash = self.read_storage_list(child, true),
                "internal_storage" => proto.internal_storage = self.read_storage_list(child, true),
                "localrange" => proto.local_range = Some(self.read_memory_tags(child)),
                "paramrange" => proto.param_range = Some(self.read_memory_tags(child)),
                "pcode" => {
                    let point = match child.attr("inject") {
                        Some("uponentry") => InjectionPoint::UponEntry,
                        Some("uponreturn") => InjectionPoint::UponReturn,
                        other => {
                            let msg = format!(
                                "<pcode inject={:?}> must be `uponentry` or `uponreturn`; ignored",
                                other.unwrap_or("")
                            );
                            self.error(DiagnosticKind::InvalidAttribute, child.line, msg);
                            continue;
                        }
                    };
                    if let Some(pcode) = self.read_pcode(child, &["inject"]) {
                        proto.injections.push(PrototypeInjection { point, pcode });
                    }
                }
                "sharestack" => {
                    self.unknown_attrs(child, &["first", "align"]);
                    self.no_children(child);
                    if let Ok(align) = self.i32_attr(child, "align") {
                        proto.share_stack = Some(ShareStack {
                            input_first: child.attr("first") == Some("input"),
                            align,
                        });
                    }
                }
                other => {
                    let msg = format!(
                        "ignored element <{other}> in prototype `{name}` (Ghidra discards it)"
                    );
                    self.warn(DiagnosticKind::UnknownElement, child.line, msg);
                }
            }
        }
        for (list, label) in [(&input, "input"), (&output, "output")] {
            if list.is_none() {
                let msg = format!("prototype `{name}` has no <{label}>; Ghidra uses an empty list");
                self.warn(DiagnosticKind::MissingElement, el.line, msg);
            }
        }
        if let Some(list) = input {
            proto.input = list;
        }
        if let Some(list) = output {
            proto.output = list;
        }
        let errors = self.errors - errors_before;
        if errors > 0 {
            proto.status = ModelStatus::Incomplete { errors };
        }
        Some(proto)
    }

    fn read_param_list(&mut self, el: &Element) -> ParamList {
        self.unknown_attrs(
            el,
            &[
                "pointermax",
                "thisbeforeretpointer",
                "killedbycall",
                "separatefloat",
            ],
        );
        let mut list = ParamList::empty(el.line);
        list.pointer_max = self
            .u32_attr(el, "pointermax")
            .ok()
            .flatten()
            .filter(|v| *v > 0);
        list.this_before_return_pointer =
            self.bool_attr(el, "thisbeforeretpointer").unwrap_or(false);
        list.killed_by_call = self.bool_attr(el, "killedbycall").unwrap_or(false);
        list.separate_float = self.bool_attr(el, "separatefloat").unwrap_or(true);

        // Storage-class ordering check state (ParamListStandard.parsePentry).
        let mut last_class = StorageClass::Class4;
        let mut in_rules = false;
        for child in &el.children {
            match child.name.as_str() {
                "pentry" | "group" if in_rules => {
                    let msg = format!(
                        "<{}> after a <rule>; <pentry> and <group> must come before any rule. Ignored",
                        child.name
                    );
                    self.error(DiagnosticKind::InconsistentSpec, child.line, msg);
                }
                "pentry" => {
                    if let Some(entry) = self.read_pentry(child, None) {
                        self.check_class_order(&list, &entry, &mut last_class);
                        list.entries.push(entry);
                    }
                }
                "group" => {
                    self.unknown_attrs(child, &[]);
                    let group = list.group_count;
                    list.group_count += 1;
                    let start = list.entries.len();
                    for item in &child.children {
                        if item.name != "pentry" {
                            let msg = format!("unexpected <{}> in <group>; ignored", item.name);
                            self.error(DiagnosticKind::UnknownElement, item.line, msg);
                            continue;
                        }
                        if let Some(entry) = self.read_pentry(item, Some(group)) {
                            if matches!(entry.storage, Storage::Join { .. }) {
                                let msg =
                                    "<pentry> in the join space is not allowed in <group>".into();
                                self.error(DiagnosticKind::InconsistentSpec, item.line, msg);
                            }
                            self.check_class_order(&list, &entry, &mut last_class);
                            list.entries.push(entry);
                        }
                    }
                    if list.entries.len() == start {
                        let msg = "<group> contains no <pentry>".into();
                        self.warn(DiagnosticKind::MissingElement, child.line, msg);
                    }
                    self.check_group_distinct(&list.entries[start..]);
                }
                "rule" => {
                    in_rules = true;
                    if let Some(rule) = self.read_rule(child) {
                        list.rules.push(rule);
                    }
                }
                other => {
                    let msg = format!("unexpected <{other}> in <{}>; ignored", el.name);
                    self.error(DiagnosticKind::UnknownElement, child.line, msg);
                }
            }
        }
        list
    }

    /// With `separatefloat`, entries must not move to a higher storage class.
    fn check_class_order(
        &mut self,
        list: &ParamList,
        entry: &ParamEntry,
        last_class: &mut StorageClass,
    ) {
        if !list.separate_float {
            return;
        }
        let current = if entry.is_grouped() {
            StorageClass::General
        } else {
            entry.storage_class
        };
        if *last_class != current && last_class.rank() < current.rank() {
            let msg = format!(
                "parameter list entries must be ordered by storage class ({current:?} after {last_class:?})"
            );
            self.error(DiagnosticKind::InconsistentSpec, entry.line, msg);
        }
        *last_class = current;
    }

    /// `ParamEntry.orderWithinGroup` over every pair in a group.
    fn check_group_distinct(&mut self, group: &[ParamEntry]) {
        for (i, first) in group.iter().enumerate() {
            for second in &group[i + 1..] {
                if second.min_size > first.max_size || first.min_size > second.max_size {
                    continue;
                }
                let msg = if first.storage_class != second.storage_class {
                    if first.storage_class != StorageClass::General {
                        continue;
                    }
                    "<pentry> tags with a specific type must come before the general type"
                } else {
                    "<pentry> tags within a group must be distinguished by size or type"
                };
                self.error(DiagnosticKind::InconsistentSpec, second.line, msg.into());
            }
        }
    }

    fn read_pentry(&mut self, el: &Element, group: Option<usize>) -> Option<ParamEntry> {
        // ParamEntry.restoreXml rejects unknown attributes.
        for (key, _) in &el.attrs {
            if !PENTRY_ATTRS.contains(&key.as_str()) {
                let msg = format!("unknown <pentry> attribute `{key}` (Ghidra rejects it)");
                self.error(DiagnosticKind::UnknownAttribute, el.line, msg);
            }
        }
        let min = self.require(el, "minsize");
        let max = self.require(el, "maxsize");
        if min.is_none() || max.is_none() {
            return None;
        }
        let (Ok(Some(min_size)), Ok(Some(max_size))) =
            (self.u32_attr(el, "minsize"), self.u32_attr(el, "maxsize"))
        else {
            return None;
        };
        if min_size < 1 || max_size < min_size {
            let msg = format!(
                "<pentry> size not specified properly: minsize={min_size} maxsize={max_size}"
            );
            self.error(DiagnosticKind::InvalidAttribute, el.line, msg);
            return None;
        }
        if el.attr("align").is_some() && el.attr("size").is_some() {
            let msg = "<pentry> has both `align` and legacy `size`; using `align`".into();
            self.warn(DiagnosticKind::DuplicateEntry, el.line, msg);
        }
        let align = match el.attr("align") {
            Some(_) => self.u32_attr(el, "align").ok()?,
            None => self.u32_attr(el, "size").ok()?,
        };
        if el.attr("storage").is_some() && el.attr("metatype").is_some() {
            let msg =
                "<pentry> has both `storage` and deprecated `metatype`; using `storage`".into();
            self.warn(DiagnosticKind::DuplicateEntry, el.line, msg);
        }
        let class_attr = if el.attr("storage").is_some() {
            "storage"
        } else {
            "metatype"
        };
        let storage_class = self
            .storage_class_attr(el, class_attr)
            .ok()?
            .unwrap_or(StorageClass::General);
        let extension = match el.attr("extension") {
            None | Some("none") => Extension::None,
            Some("sign") => Extension::Sign,
            Some("zero") => Extension::Zero,
            Some("inttype") => Extension::IntType,
            Some("float") => Extension::Float,
            Some(other) => {
                self.invalid(el, "extension", other, "none, sign, zero, inttype or float");
                return None;
            }
        };
        let storage = match el.children.as_slice() {
            [one] => {
                if one.name == "varnode" {
                    let msg = "<varnode> in <pentry>; the schema expects <register> or <addr> (read like Ghidra)".into();
                    self.warn(DiagnosticKind::UnsupportedForm, one.line, msg);
                }
                self.read_storage(one)?
            }
            [] => {
                self.error(
                    DiagnosticKind::MissingElement,
                    el.line,
                    "<pentry> has no storage element".into(),
                );
                return None;
            }
            [_, extra, ..] => {
                self.error(
                    DiagnosticKind::InconsistentSpec,
                    extra.line,
                    "<pentry> has more than one storage element".into(),
                );
                return None;
            }
        };
        let entry = ParamEntry {
            min_size,
            max_size,
            align,
            storage_class,
            extension,
            storage,
            group,
            line: el.line,
        };
        if let Some(size) = entry.storage.known_size()
            && max_size > size
        {
            let msg =
                format!("<pentry> maxsize {max_size} is bigger than its storage ({size} bytes)");
            self.error(DiagnosticKind::InconsistentSpec, el.line, msg);
        }
        let alignment = entry.alignment();
        if self.stack_growth == StackGrowth::Positive && alignment != 0 && max_size % alignment != 0
        {
            let msg = "for positive stack growth, <pentry> size must match alignment".into();
            self.error(DiagnosticKind::InconsistentSpec, el.line, msg);
        }
        Some(entry)
    }

    fn read_datatype(&mut self, el: &Element) -> Option<DatatypeFilter> {
        self.unknown_attrs(
            el,
            &[
                "name",
                "minsize",
                "maxsize",
                "sizes",
                "maxprimitives",
                "minelements",
                "maxelements",
            ],
        );
        self.no_children(el);
        let name = self.require(el, "name")?;
        let class = match name {
            "any" => DatatypeClass::Any,
            "homogeneous-float-aggregate" => DatatypeClass::HomogeneousFloatAggregate,
            other => match MetaType::parse(other) {
                Some(meta) => DatatypeClass::Meta(meta),
                None => {
                    self.invalid(el, "name", other, "a known data-type filter or meta-type");
                    return None;
                }
            },
        };
        let min_size = self.u32_attr(el, "minsize").ok()?;
        let max_size = self.u32_attr(el, "maxsize").ok()?;
        let mut sizes = Vec::new();
        if let Some(text) = el.attr("sizes") {
            if min_size.is_some() || max_size.is_some() {
                let msg = "<datatype> mixes `sizes` with `minsize`/`maxsize`".into();
                self.error(DiagnosticKind::InconsistentSpec, el.line, msg);
                return None;
            }
            for piece in text.split(',') {
                match xml::decode_java_int(piece.trim()).and_then(|v| u32::try_from(v).ok()) {
                    Some(v) => sizes.push(v),
                    None => {
                        self.invalid(el, "sizes", text, "a comma-separated size list");
                        return None;
                    }
                }
            }
        }
        let max_primitives = self.u32_attr(el, "maxprimitives").ok()?;
        let min_elements = self.u32_attr(el, "minelements").ok()?;
        let max_elements = self.u32_attr(el, "maxelements").ok()?;
        if max_primitives.is_some() && class != DatatypeClass::HomogeneousFloatAggregate {
            let msg =
                "`maxprimitives` only applies to homogeneous aggregates; Ghidra ignores it here"
                    .into();
            self.warn(DiagnosticKind::UnknownAttribute, el.line, msg);
        }
        if (min_elements.is_some() || max_elements.is_some())
            && class != DatatypeClass::Meta(MetaType::Array)
        {
            let msg =
                "`minelements`/`maxelements` only apply to arrays; Ghidra ignores them here".into();
            self.warn(DiagnosticKind::UnknownAttribute, el.line, msg);
        }
        Some(DatatypeFilter {
            class,
            min_size,
            max_size,
            sizes,
            max_primitives,
            min_elements,
            max_elements,
        })
    }

    fn read_side_effect(&mut self, el: &Element) -> Option<RuleSideEffect> {
        self.no_children(el);
        match el.name.as_str() {
            "consume_extra" => {
                self.unknown_attrs(el, &["storage", "matchsize"]);
                self.require(el, "storage")?;
                let storage = self.storage_class_attr(el, "storage").ok()??;
                Some(RuleSideEffect::ConsumeExtra {
                    storage,
                    match_size: self.bool_attr(el, "matchsize"),
                })
            }
            "extra_stack" => {
                self.unknown_attrs(el, &["afterbytes", "afterstorage"]);
                Some(RuleSideEffect::ExtraStack {
                    after_bytes: self.i32_attr(el, "afterbytes").ok()?,
                    after_storage: self.storage_class_attr(el, "afterstorage").ok()?,
                })
            }
            "consume_remaining" => {
                self.unknown_attrs(el, &["storage"]);
                self.require(el, "storage")?;
                let storage = self.storage_class_attr(el, "storage").ok()??;
                Some(RuleSideEffect::ConsumeRemaining { storage })
            }
            other => {
                let msg = format!("unknown model rule side effect <{other}>");
                self.error(DiagnosticKind::UnknownElement, el.line, msg);
                None
            }
        }
    }

    fn read_action(&mut self, el: &Element) -> Option<RuleAction> {
        self.no_children(el);
        let action = match el.name.as_str() {
            "consume" => {
                self.unknown_attrs(el, &["storage"]);
                self.require(el, "storage")?;
                RuleAction::Consume {
                    storage: self.storage_class_attr(el, "storage").ok()??,
                }
            }
            "convert_to_ptr" => {
                self.unknown_attrs(el, &[]);
                RuleAction::ConvertToPointer
            }
            "goto_stack" => {
                self.unknown_attrs(el, &[]);
                RuleAction::GotoStack
            }
            "join" => {
                self.unknown_attrs(
                    el,
                    &[
                        "reversejustify",
                        "reversesignif",
                        "storage",
                        "align",
                        "stackspill",
                        "backfill",
                    ],
                );
                RuleAction::Join {
                    storage: self.storage_class_attr(el, "storage").ok()?,
                    reverse_justify: self.bool_attr(el, "reversejustify"),
                    reverse_significance: self.bool_attr(el, "reversesignif"),
                    align: self.bool_attr(el, "align"),
                    stack_spill: self.bool_attr(el, "stackspill"),
                    backfill: self.bool_attr(el, "backfill"),
                }
            }
            "hidden_return" => {
                self.unknown_attrs(el, &["strategy", "voidlock"]);
                let strategy = match el.attr("strategy") {
                    None => None,
                    Some("special") => Some(HiddenReturnStrategy::Special),
                    Some("normalparam") => Some(HiddenReturnStrategy::NormalParam),
                    Some(other) => {
                        self.invalid(el, "strategy", other, "`special` or `normalparam`");
                        return None;
                    }
                };
                RuleAction::HiddenReturn {
                    strategy,
                    void_lock: self.bool_attr(el, "voidlock"),
                }
            }
            "join_per_primitive" => {
                self.unknown_attrs(el, &["storage"]);
                RuleAction::JoinPerPrimitive {
                    storage: self.storage_class_attr(el, "storage").ok()?,
                }
            }
            "join_dual_class" => {
                self.unknown_attrs(
                    el,
                    &[
                        "reversejustify",
                        "reversesignif",
                        "stackspill",
                        "fillalternate",
                        "storage",
                        "a",
                        "b",
                    ],
                );
                if el.attr("storage").is_some() && el.attr("a").is_some() {
                    let msg = "<join_dual_class> has both `storage` and `a` (synonyms)".into();
                    self.warn(DiagnosticKind::DuplicateEntry, el.line, msg);
                }
                let a_attr = if el.attr("storage").is_some() {
                    "storage"
                } else {
                    "a"
                };
                RuleAction::JoinDualClass {
                    storage_a: self.storage_class_attr(el, a_attr).ok()?,
                    storage_b: self.storage_class_attr(el, "b").ok()?,
                    reverse_justify: self.bool_attr(el, "reversejustify"),
                    reverse_significance: self.bool_attr(el, "reversesignif"),
                    stack_spill: self.bool_attr(el, "stackspill"),
                    fill_alternate: self.bool_attr(el, "fillalternate"),
                }
            }
            other => {
                let msg = format!("unknown model rule action <{other}>");
                self.error(DiagnosticKind::UnknownElement, el.line, msg);
                return None;
            }
        };
        Some(action)
    }

    /// `ModelRule.restoreXml`: datatype, qualifiers, preconditions, one action, side
    /// effects, in that order.
    fn read_rule(&mut self, el: &Element) -> Option<ModelRule> {
        self.unknown_attrs(el, &[]);
        let mut children = el.children.iter().peekable();
        let Some(first) = children.next().filter(|c| c.name == "datatype") else {
            self.error(
                DiagnosticKind::MissingElement,
                el.line,
                "<rule> must start with <datatype>; rule ignored".into(),
            );
            return None;
        };
        let datatype = self.read_datatype(first);
        let mut ok = datatype.is_some();
        let mut qualifiers = Vec::new();
        while let Some(child) =
            children.next_if(|c| matches!(c.name.as_str(), "varargs" | "position" | "datatype_at"))
        {
            let qualifier = match child.name.as_str() {
                "varargs" => {
                    self.unknown_attrs(child, &["first", "last"]);
                    self.no_children(child);
                    match (self.i32_attr(child, "first"), self.i32_attr(child, "last")) {
                        (Ok(first), Ok(last)) => Some(RuleQualifier::Varargs { first, last }),
                        _ => None,
                    }
                }
                "position" => {
                    self.unknown_attrs(child, &["index"]);
                    self.no_children(child);
                    self.require(child, "index");
                    match self.i32_attr(child, "index") {
                        Ok(Some(index)) => Some(RuleQualifier::Position { index }),
                        _ => None,
                    }
                }
                _ => {
                    self.unknown_attrs(child, &["index"]);
                    self.require(child, "index");
                    let index = self.i32_attr(child, "index");
                    let inner = match child.children.as_slice() {
                        [dt] if dt.name == "datatype" => self.read_datatype(dt),
                        _ => {
                            self.error(
                                DiagnosticKind::MissingElement,
                                child.line,
                                "<datatype_at> must contain exactly one <datatype>".into(),
                            );
                            None
                        }
                    };
                    match (index, inner) {
                        (Ok(Some(index)), Some(datatype)) => {
                            Some(RuleQualifier::DatatypeAt { index, datatype })
                        }
                        _ => None,
                    }
                }
            };
            match qualifier {
                Some(q) => qualifiers.push(q),
                None => ok = false,
            }
        }
        let mut preconditions = Vec::new();
        while let Some(child) = children.next_if(|c| c.name == "consume_extra") {
            match self.read_side_effect(child) {
                Some(s) => preconditions.push(s),
                None => ok = false,
            }
        }
        let Some(action_el) = children.next() else {
            self.error(
                DiagnosticKind::MissingElement,
                el.line,
                "<rule> has no action; rule ignored".into(),
            );
            return None;
        };
        let action = self.read_action(action_el);
        ok &= action.is_some();
        let mut side_effects = Vec::new();
        for child in children {
            match self.read_side_effect(child) {
                Some(s) => side_effects.push(s),
                None => ok = false,
            }
        }
        if !ok {
            let msg = "<rule> ignored because part of it could not be read".into();
            self.diag(
                Severity::Info,
                DiagnosticKind::UnsupportedForm,
                el.line,
                msg,
            );
            return None;
        }
        Some(ModelRule {
            datatype: datatype?,
            qualifiers,
            preconditions,
            action: action?,
            side_effects,
            line: el.line,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formal_names_match_spec_extension() {
        assert!(is_valid_formal_name("__stdcall"));
        assert!(is_valid_formal_name("a.b-c/d_1"));
        assert!(!is_valid_formal_name(""));
        assert!(!is_valid_formal_name("bad name"));
        assert!(!is_valid_formal_name("x<y"));
    }

    #[test]
    fn offsets_keep_java_long_bits() {
        assert_eq!(Reader::offset_value("-2"), Some(0xffff_ffff_ffff_fffe));
        assert_eq!(
            Reader::offset_value("0xfffffffffff0bdc1"),
            Some(0xffff_ffff_fff0_bdc1)
        );
        assert_eq!(Reader::offset_value("40"), Some(40));
        assert_eq!(Reader::offset_value("x"), None);
        assert_eq!(Reader::offset_value(""), None);
    }

    #[test]
    fn storage_class_ranks() {
        assert!(StorageClass::Float.rank() > StorageClass::General.rank());
        assert_eq!(
            StorageClass::parse("hiddenret"),
            Some(StorageClass::HiddenRet)
        );
        assert_eq!(StorageClass::parse("Float"), None);
    }
}
