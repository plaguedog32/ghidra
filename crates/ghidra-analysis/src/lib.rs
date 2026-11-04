//! Native dataflow foundations. Storage partitioning preserves register aliases,
//! explicit temporary lifetimes and conservative whole-space RAM dependencies.
//! P-code SSA preserves those dependencies and explicit unknown effects. This
//! crate does not yet infer types or emit decompiled code.
#![doc = include_str!("../README.md")]

mod storage;
pub use storage::*;
mod adapter;
pub use adapter::*;
