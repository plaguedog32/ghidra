#![doc = include_str!("../README.md")]

mod dominance;
mod graph;

pub use dominance::{Dominators, ImmediateDominator, NaturalLoop, PostDominator, PostDominators};
pub use graph::{Error, Graph, Limits, NodeId, Resource, Result, StrongComponents, Traversal};
