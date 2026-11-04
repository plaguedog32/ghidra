#![doc = include_str!("../README.md")]

mod error;
mod layout;
mod model;

pub use error::{Error, Limits, Resource, Result};
pub use ghidra_languages::ResolvedDataOrganization;
pub use layout::{LayoutStats, TypeLayouts};
pub use model::{
    Builtin, Composite, Field, FieldLayout, Geometry, MinimumAlignment, Packing, TypeDefinition,
    TypeId, TypeKind, TypeLayout,
};
