//! Compiler storage resolution against an immutable language register file.
//!
//! Storage resolution, per-pool placement and bare declaration-ordered fallback
//! allocation are distinct APIs. Datatype predicates and rule qualifiers can be
//! evaluated separately. Selected-pool assignments and ordered resource effects
//! support rule execution; the full rule dispatcher and signature allocator
//! remain unimplemented. See the crate README for those boundaries.
#![doc = include_str!("../README.md")]

mod compiler;
mod error;
mod fallback;
mod placement;
mod predicates;
mod primitives;
mod registry;
mod resources;
mod storage;

pub use compiler::{
    BindingSite, CompilerStorage, ParameterConstraints, ResolvedBinding, ResolvedDeadCodeDelay,
    ResolvedMemoryRange, ResolvedSpaceBase,
};
pub use error::{AbiError, AbiLimits, AbiResult};
pub use fallback::{
    AllocationState, ClassMatch, DeclaredRules, EffectBatch, EffectContext, EffectError,
    EffectLimits, EffectOutcome, EffectUsage, FallbackAssignment, FallbackBatch, FallbackError,
    FallbackLimits, FallbackOutcome, FallbackPolicy, FallbackRequest, FallbackUsage, GroupState,
    OccupiedExtent, PoolAssignment, PoolRequest, SlotRange, StackThresholdIndexing,
    UnexecutedDeclarations,
};
pub use placement::{
    Justification, NoFit, PieceRole, PlacedPiece, PlacedStorage, PlacedValue, Placement,
    PlacementError, PlacementLimits, PlacementOutcome, PlacementRequest, place_parameter,
};
pub use predicates::{
    DatatypeFact, DatatypePredicates, HomogeneousFloat, PredicateError, PredicateLimits,
    PredicateMatch, PredicateRejection, PredicateStats, PredicateUsage, PrototypeTypes,
};
pub use primitives::{
    ExtractionError, ExtractionLimits, ExtractionOptions, ExtractionStats, Primitive,
    PrimitiveExtraction, PrimitiveSource,
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
