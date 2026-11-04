#![doc = include_str!("../README.md")]

mod construct;
mod error;
mod model;
mod verify;

pub use construct::Ssa;
pub use error::{Error, Limits, Resource, Result, Violation};
pub use ghidra_graph::{ImmediateDominator, NodeId};
pub use model::{
    Block, DefinitionSite, EntryState, OperandSite, Phi, PhiId, PhiOperandSite, PhiPlacement,
    Predecessor, RawProgram, RawStatement, RenamedBlock, RenamedStatement, StatementId, UseSite,
    Value, ValueId, ValueOrigin, VariableId,
};
