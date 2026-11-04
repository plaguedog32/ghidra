#![doc = include_str!("../README.md")]

mod construct;
mod def_use;
mod error;
mod lower;
mod model;
mod parallel_copy;
mod verify;

pub use construct::Ssa;
pub use def_use::{DefUseError, DefUseIndex, DefUseLimits, DefUseResource, DefUseResult};
pub use error::{Error, Limits, Resource, Result, Violation};
pub use ghidra_graph::{ImmediateDominator, NodeId};
pub use lower::{
    LoweredNode, PhiCopyBlock, PhiLowering, PhiLoweringError, PhiLoweringLimits,
    PhiLoweringResource, PhiLoweringStats,
};
pub use model::{
    Block, DefinitionSite, EntryState, OperandSite, Phi, PhiId, PhiOperandSite, PhiPlacement,
    Predecessor, RawProgram, RawStatement, RenamedBlock, RenamedStatement, StatementId, UseSite,
    Value, ValueId, ValueOrigin, VariableId,
};
pub use parallel_copy::{
    CopyError, CopyLimits, CopyLocation, CopyMove, CopyResource, CopySlot, ParallelCopy,
    ParallelCopySchedule,
};
