use std::fmt;

use ghidra_pcode::{Opcode, SpaceId, SpaceKind};
use thiserror::Error;

use crate::ProgramPoint;

/// A bounded resource. Every limit failure is reported before the output it
/// protects is allocated; there is never a truncated successful result.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum Resource {
    Spaces,
    Instructions,
    /// Total P-code operations across all supplied instructions.
    Operations,
    /// Total input plus output varnode references across all operations.
    OperandRefs,
    Blocks,
    /// Semantic CFG edges, including edges into terminal exit nodes.
    Edges,
    /// Terminal outcome nodes.
    Exits,
    /// Deterministic abstract work units for one build.
    Work,
}

/// Which operand of an operation is invalid.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum OperandSlot {
    Output,
    Input(usize),
}

impl fmt::Display for OperandSlot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Output => formatter.write_str("output"),
            Self::Input(index) => write!(formatter, "input{index}"),
        }
    }
}

/// Why an operand violates its role in raw P-code.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Error)]
pub enum OperandError {
    #[error("address space {0:?} is not declared")]
    UnknownSpace(SpaceId),
    #[error("outputs cannot be written to a constant space")]
    ConstantOutput,
    #[error("varnode byte range does not fit nonwrapping in its address space")]
    OutOfSpace,
    #[error("operand must be a constant")]
    RequiresConstant,
    #[error("LOAD/STORE selector {offset} does not name a declared nonconstant space")]
    SelectorSpace { offset: u64 },
    #[error("pointer width is {actual} bytes; the addressed space requires {expected}")]
    PointerWidth { expected: u32, actual: u32 },
    #[error("direct control-flow label is in space {space:?}, not the code space")]
    CrossSpaceLabel { space: SpaceId },
    #[error("direct control-flow label 0x{offset:X} is outside the code space")]
    LabelOutOfSpace { offset: u64 },
    #[error("CALL targets must be code addresses, not relative constants")]
    RelativeCallLabel,
}

#[derive(Debug, Error)]
pub enum CfgError {
    #[error("{resource:?} limit exceeded")]
    LimitExceeded { resource: Resource },
    #[error("at least one address space is required")]
    NoSpaces,
    #[error("invalid address space {id:?}: {source}")]
    InvalidSpace {
        id: SpaceId,
        source: ghidra_pcode::Error,
    },
    #[error("duplicate address-space id {0:?}")]
    DuplicateSpaceId(SpaceId),
    #[error("duplicate address-space name {0:?}")]
    DuplicateSpaceName(String),
    #[error("code space {0:?} is not declared")]
    UnknownCodeSpace(SpaceId),
    #[error("code space {id:?} has kind {kind:?}; expected Ram or Other")]
    CodeSpaceKind { id: SpaceId, kind: SpaceKind },
    #[error(
        "code space {id:?} has word size {word_size}; only byte-addressed code is supported, \
         and addresses are never rescaled"
    )]
    WordAddressedCode { id: SpaceId, word_size: u32 },
    #[error("instruction at 0x{address:X} has {count} operations; at most 16384 are supported")]
    InstructionOperationCount { address: u64, count: usize },
    #[error("operation at {point} has {count} inputs; at most 1024 are supported")]
    OperationInputCount { point: ProgramPoint, count: usize },
    #[error(
        "instruction at 0x{address:X} with length {length} is empty or does not fit \
         nonwrapping in the code space"
    )]
    InstructionExtent { address: u64, length: u32 },
    #[error("more than one instruction starts at 0x{address:X}")]
    DuplicateInstruction { address: u64 },
    #[error("instructions at 0x{first:X} and 0x{second:X} overlap")]
    OverlappingInstructions { first: u64, second: u64 },
    #[error("entry 0x{entry:X} is not the start of a supplied instruction")]
    EntryNotInstruction { entry: u64 },
    #[error("invalid operation at {point}: {source}")]
    InvalidOperation {
        point: ProgramPoint,
        source: ghidra_pcode::Error,
    },
    #[error("{opcode} at {point} is an analysis-only SSA operation, not raw P-code")]
    UnsupportedOperation { point: ProgramPoint, opcode: Opcode },
    #[error("invalid {slot} of {opcode} at {point}: {problem}")]
    InvalidOperand {
        point: ProgramPoint,
        opcode: Opcode,
        slot: OperandSlot,
        problem: OperandError,
    },
    #[error(
        "relative branch at {point} with displacement {displacement} targets operation \
         {target}; valid targets are 0..={operation_count}"
    )]
    InvalidRelativeTarget {
        point: ProgramPoint,
        displacement: i32,
        target: i64,
        operation_count: usize,
    },
    /// Raised by [`ghidra_graph::Graph::new`] under [`crate::Limits::graph`].
    #[error("graph construction failed: {0}")]
    Graph(#[from] ghidra_graph::Error),
}

pub(crate) fn limit(resource: Resource) -> CfgError {
    CfgError::LimitExceeded { resource }
}
