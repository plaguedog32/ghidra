//! Compiler storage resolution against an immutable language register file.
//!
//! Storage resolution, per-pool placement and bare declaration-ordered fallback
//! allocation are distinct APIs. Prototype rules and complete signature
//! allocation remain unimplemented. See the crate README for those boundaries.
#![doc = include_str!("../README.md")]

mod compiler;
mod error;
mod fallback;
mod placement;
mod registry;
mod resources;
mod storage;

pub use compiler::{
    BindingSite, CompilerStorage, ParameterConstraints, ResolvedBinding, ResolvedDeadCodeDelay,
    ResolvedMemoryRange, ResolvedSpaceBase,
};
pub use error::{AbiError, AbiLimits, AbiResult};
pub use fallback::{
    AllocationState, ClassMatch, DeclaredRules, FallbackAssignment, FallbackBatch, FallbackError,
    FallbackLimits, FallbackOutcome, FallbackPolicy, FallbackRequest, FallbackUsage, GroupState,
    OccupiedExtent, SlotRange, UnexecutedDeclarations,
};
pub use placement::{
    Justification, NoFit, PieceRole, PlacedPiece, PlacedStorage, PlacedValue, Placement,
    PlacementError, PlacementLimits, PlacementOutcome, PlacementRequest, place_parameter,
};
pub use registry::{RegisterDefinition, RegisterFile, RegisterId};
pub use resources::{
    CompilerResources, EntryResources, ListResources, ModelResources, ParameterDirection,
    ResourceError, ResourceId, ResourceLimits,
};
pub use storage::{
    AbiAddress, AbiSpace, JoinKind, ResolvedPiece, ResolvedStorage, StackProperties, StorageRange,
    resolve_storage,
};
