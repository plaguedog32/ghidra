#![doc = include_str!("../README.md")]

mod bitfield;
mod error;
mod layout;
mod model;

pub use error::{Error, Limits, Resource, Result};
pub use ghidra_languages::{Endianness, ResolvedDataOrganization};
pub use layout::{LayoutStats, TypeLayouts};
pub use model::{
    BitfieldLayout, Builtin, Composite, Field, FieldLayout, Geometry, MAX_BITFIELD_BITS,
    MinimumAlignment, Packing, TypeDefinition, TypeId, TypeKind, TypeLayout,
};
