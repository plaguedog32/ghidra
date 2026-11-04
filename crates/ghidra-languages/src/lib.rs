//! Java-free Ghidra language catalog.
//!
//! Reads `.ldefs` language definitions, `.pspec` processor context defaults and `.cspec`
//! compiler specifications with a bounded pure-Rust XML reader. No Java or C++ process is
//! involved.
//!
//! Scope and limits:
//! - A language whose `.slaspec` exists is *listed*; that says nothing about whether
//!   the SLEIGH source compiles or its semantics are supported. Connecting a
//!   [`LanguageDefinition`] to a SLEIGH compiler is the caller's job.
//! - Compiler specs (`.cspec`) are parsed into typed data ([`CompilerSpec`]): data
//!   organization, stack pointer, return address, prototype models with ordered parameter
//!   entries, groups, join pieces and model rules. Register names are not resolved and no
//!   parameter allocation is performed; see the [`cspec`] module docs for the boundary.
//! - Missing or odd assets produce [`Diagnostic`]s; the language stays in the catalog.
//! - Asset paths are resolved inside the catalog root. Absolute paths and paths that
//!   escape the root are rejected. Symlinks and junctions are not followed.
//! - DTDs are rejected, so no custom entity is ever expanded.
//! - Reads are bounded by [`Limits`]: file size, element count, nesting depth and text
//!   length for XML, plus semantic work and diagnostic count/byte budgets for `.cspec`
//!   files. A `.cspec` budget that runs out is an [`Error::Limit`], never a partial spec.

pub mod cspec;
mod error;
mod ldefs;
mod paths;
mod pspec;
mod xml;

pub use cspec::{
    AddressRange, AssignStrategy, BitfieldPacking, CallFixup, CallOtherFixup, CompilerSpec,
    DataOrganization, DatatypeClass, DatatypeFilter, DeadCodeDelay, Extension, Extrapop,
    HiddenReturnStrategy, InjectParameter, InjectionPoint, JoinPiece, MemoryTag, MergedModel,
    MetaType, ModelAlias, ModelRef, ModelRule, ModelStatus, ParamEntry, ParamList, PcodeSnippet,
    PrototypeInjection, PrototypeModel, ResolvedDataOrganization, RuleAction, RuleQualifier,
    RuleSideEffect, ShareStack, SizeAlignment, SpaceBase, SpecCoverage, StackGrowth, StackPointer,
    Storage, StorageClass, Unmodeled, UnmodeledReason,
};
pub use error::{AssetKind, Diagnostic, DiagnosticKind, Error, Severity};
pub use ghidra_pcode::Endianness;
pub use ldefs::{
    AssetRef, AssetStatus, Catalog, CompilerDefinition, ExternalName, LanguageDefinition,
    LanguageVersion, TruncatedSpace,
};
pub use paths::DiscoveryOptions;
pub use pspec::{
    ContextSet, ProcessorSpec, Property, ResolvedValue, SetBlock, SetValue, TrackedSet, ValueOrigin,
};
pub use xml::Limits;
