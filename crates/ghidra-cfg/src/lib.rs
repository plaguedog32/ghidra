#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]

mod build;
mod cfg;
mod error;

pub use cfg::{
    Arrival, CallSite, CallTarget, Cfg, CfgInput, Edge, EdgeId, EdgeRole, Exit, ExitKind, Gap,
    Limits, NodeKind, ProgramPoint, Statement, TargetLocation, UseropSite,
};
pub use error::{CfgError, OperandError, OperandSlot, Resource};
pub use ghidra_graph::NodeId;
