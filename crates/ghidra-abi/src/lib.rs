//! Compiler storage resolution against an immutable language register file.
//!
//! Storage resolution, per-pool placement and bare declaration-ordered fallback
//! allocation are distinct APIs. Datatype predicates and rule qualifiers can be
//! evaluated separately, over either the Java datatype view or the converted
//! native decompiler view (`NativeTypeGraph`). Selected-pool assignments,
//! ordered resource effects, the native `<join>` action and the
//! graph-driven `<join_dual_class>` action support rule execution; the full
//! rule dispatcher and signature allocator remain unimplemented. See the
//! crate README for those boundaries.
#![doc = include_str!("../README.md")]

mod compiler;
mod error;
mod fallback;
mod native_alignments;
mod native_extract;
mod native_predicates;
mod native_types;
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
    AllocationState, ClassMatch, DeclaredRules, DualClass, DualJoinAllocation, DualJoinAssignment,
    DualJoinAttributes, DualJoinConfig, DualJoinError, DualJoinLimits, DualJoinNoFit,
    DualJoinOutcome, DualJoinStep, DualJoinStepKind, DualJoinUsage, DualTileRejection, EffectBatch,
    EffectContext, EffectError, EffectLimits, EffectOutcome, EffectUsage, FallbackAssignment,
    FallbackBatch, FallbackError, FallbackLimits, FallbackOutcome, FallbackPolicy, FallbackRequest,
    FallbackUsage, GroupState, JoinAllocation, JoinAssignment, JoinAttributes, JoinConfig,
    JoinError, JoinLimits, JoinNoFit, JoinOutcome, JoinPiece, JoinRequest, JoinStep, JoinStepKind,
    JoinStorage, JoinUsage, OccupiedExtent, PoolAssignment, PoolRequest, SlotRange,
    StackThresholdIndexing, UnexecutedDeclarations,
};
pub use native_alignments::{
    NativeAlignmentError, NativeAlignmentLimits, NativeAlignmentMap, NativeAlignmentOrigin,
    NativeAlignmentUsage, NativePrimitiveGeometry,
};
pub use native_extract::{
    NativeExtractionError, NativeExtractionLimits, NativeExtractionOptions,
    NativeExtractionOutcome, NativeExtractionStats, NativeInvalidExtraction, NativePrimitive,
    NativePrimitiveExtraction,
};
pub use native_predicates::{
    NativeHfa, NativeHfaRejection, NativePredicateError, NativePredicateLimits,
    NativePredicateMatch, NativePredicateUsage, NativePrototypeTypes,
};
pub use native_types::{
    NATIVE_INT_MAX, NativeArray, NativeBitfield, NativeConversionError, NativeDroppedField,
    NativeField, NativeFieldKind, NativeOrigin, NativeRange, NativeShape, NativeType,
    NativeTypeError, NativeTypeGraph, NativeTypeId, NativeTypeLimits, NativeTypeOptions,
    NativeTypeStats,
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
