//! Native dataflow foundations. Storage partitioning preserves register aliases,
//! explicit temporary lifetimes and conservative whole-space RAM dependencies.
//! This crate does not yet construct SSA, infer types or emit decompiled code.
#![doc = include_str!("../README.md")]

mod storage;
pub use storage::*;
