//! Compiler storage resolution against an immutable language register file.
//!
//! Resolving locations does not allocate arguments, execute prototype rules or
//! establish an ABI implementation. See the crate README for those boundaries.
#![doc = include_str!("../README.md")]

mod compiler;
mod error;
mod registry;
mod resources;
mod storage;

pub use compiler::{
    BindingSite, CompilerStorage, ParameterConstraints, ResolvedBinding, ResolvedDeadCodeDelay,
    ResolvedMemoryRange, ResolvedSpaceBase,
};
pub use error::{AbiError, AbiLimits, AbiResult};
pub use registry::{RegisterDefinition, RegisterFile, RegisterId};
pub use resources::{
    CompilerResources, EntryResources, ListResources, ModelResources, ParameterDirection,
    ResourceError, ResourceId, ResourceLimits,
};
pub use storage::{
    AbiAddress, AbiSpace, JoinKind, ResolvedPiece, ResolvedStorage, StackProperties, StorageRange,
    resolve_storage,
};
