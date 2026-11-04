//! Native dataflow foundations. Storage partitioning preserves register aliases,
//! explicit temporary lifetimes and conservative whole-space RAM dependencies.
//! P-code SSA preserves those dependencies and explicit unknown effects. Typed
//! expression terms preserve aliases, memory versions and opaque definitions.
//! Sparse conditional constant propagation computes owned whole-value facts
//! and executable nodes/edges over those terms without rewriting them.
//! This crate does not yet infer types or emit decompiled code.
#![doc = include_str!("../README.md")]

mod storage;
pub use storage::*;
mod adapter;
pub use adapter::*;
mod expressions;
pub use expressions::*;
mod constants;
pub use constants::*;
