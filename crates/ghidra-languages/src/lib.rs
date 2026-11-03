//! Java-free Ghidra language catalog.
//!
//! Reads `.ldefs` language definitions and `.pspec` processor context defaults with
//! a bounded pure-Rust XML reader. No Java or C++ process is involved.
//!
//! Scope and limits:
//! - A language whose `.slaspec` exists is *listed*; that says nothing about whether
//!   the SLEIGH source compiles or its semantics are supported. Connecting a
//!   [`LanguageDefinition`] to a SLEIGH compiler is the caller's job.
//! - Compiler specs (`.cspec`) are referenced as assets only; ABI semantics are not read.
//! - Missing or odd assets produce [`Diagnostic`]s; the language stays in the catalog.
//! - Asset paths are resolved inside the catalog root. Absolute paths and paths that
//!   escape the root are rejected. Symlinks and junctions are not followed.
//! - DTDs are rejected, so no custom entity is ever expanded.

mod error;
mod ldefs;
mod paths;
mod pspec;
mod xml;

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
