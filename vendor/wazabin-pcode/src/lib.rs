//! The vocabulary types shared between a p-code *producer* and a p-code
//! *consumer*.
//!
//! A SLEIGH specification describes memory spaces, processor registers and
//! user-defined p-code operations; an IR built from that specification refers
//! to the same things. Both sides need to agree on how those are identified, so
//! the definitions live here rather than in either crate — which lets the
//! decoder and the IR depend on each other only through this vocabulary.
//!
//! These types appear directly in precompiled specification blobs, so their
//! serialized form is part of the producer/consumer compatibility contract.
//! A producer must version its blob format; serde alone does not provide a
//! cross-version or cross-platform wire-format guarantee.
//!
//! # Example
//!
//! The vocabulary is plain data. A consumer names its spaces and registers,
//! and a producer's varnodes refer to them by id.
//!
//! ```
//! use jstd::registry::Registry;
//! use pcode_types::{
//!     Register, SpaceType,
//!     space::{Space, SpaceId, SpaceStore},
//! };
//!
//! struct MySpecification {
//!     spaces: Registry<SpaceId, Space>,
//! }
//!
//! impl SpaceStore for MySpecification {
//!     fn spaces(&self) -> &Registry<SpaceId, Space> {
//!         &self.spaces
//!     }
//! }
//!
//! let mut spaces = Registry::default();
//! // A byte-addressed 64-bit RAM space, and the space registers live in.
//! let ram = spaces.push(Space::new(Some("ram"), 1, 8));
//! let register_space = spaces.push(Space::new(Some("register"), 1, 8));
//! let spec = MySpecification { spaces };
//!
//! // `from_id` resolves against any `SpaceStore`, including your own context.
//! let resolved = Space::from_id(&spec, ram);
//! assert_eq!(resolved.name.as_deref(), Some("ram"));
//! assert!(matches!(resolved.ty, SpaceType::Ram));
//!
//! // An 8-byte register at offset 0 of the register space.
//! let rax = Register {
//!     name: "RAX".into(),
//!     space: register_space,
//!     offset: 0,
//!     size: 8,
//! };
//! assert_eq!(&*rax.name, "RAX");
//! ```

pub mod error;
pub mod expression;
pub mod instruction;
pub mod register;
pub mod space;
pub mod statement;
pub mod streaming;

pub use error::{PcodeError, PcodeErrorTy, PcodeResult};
pub use expression::{
    BinaryOperator, Binop, Builtin, Expression, ExpressionTy, Ident, Load, LocalVarId,
    LocalVarInterner, Range, RangeParam, SpaceRef as PcodeSpaceRef, UnaryOperator, Unop,
    pretty_print_ident,
};
pub use instruction::{
    BitRangeInfo, BodyWidths, InstructionPcode, LabelId, LocalSizes, Opcode, PcodeLowerError,
    PcodeLoweringContext, PcodeOp, PcodePlan, PcodeSink, SymbolicWidth, Varnode, Width,
    emit_instruction, infer_local_sizes, lower_instruction, lower_instruction_into,
    plan_instruction, plan_instruction_with, resolve_body_widths,
};
pub use register::{Register, RegisterId, RegisterMutRef, RegisterRef};
pub use space::{SPACE_CONST, Space, SpaceId, SpaceRef, SpaceStore, SpaceType};
pub use statement::{Ast, AstNode, DelaySlotArg, LabelOrNode};

use jstd::Identifier;

/// A stable identifier for a user-defined p-code operation.
///
/// These are the `define pcodeop` names in a SLEIGH specification: operations
/// with no p-code semantics, which a consumer must interpret itself.
#[derive(Identifier)]
pub struct PCodeOpId(usize);

/// Identifier used by source-shaped p-code for a decoder field.
#[derive(Identifier)]
pub struct FieldId(usize);
/// Identifier used by `build` statements for a decoder table.
#[derive(Identifier)]
pub struct TableId(usize);
/// Identifier of a p-code macro definition.
#[derive(Identifier)]
pub struct PMacroId(usize);
/// Identifier of a named register bit range.
#[derive(Identifier)]
pub struct BitRangeFieldId(usize);

/// Backend-neutral, source-shaped p-code AST for one decoded instruction.
#[derive(Debug, Clone, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub struct PcodeAst {
    /// Statements in execution order.
    pub statements: Vec<Ast>,
}

impl PcodeAst {
    /// Pretty-prints the statements using a producer-specific name resolver.
    pub fn pretty_print(&self, resolver: &impl PcodeResolver) -> String {
        self.statements
            .iter()
            .map(|statement| statement.pretty_print(resolver))
            .collect::<Vec<_>>()
            .join("\n")
    }
}

/// Supplies names for formatting a p-code AST without coupling it to a
/// particular producer such as SLEIGH.
pub trait PcodeResolver {
    /// Name of an identifier.
    fn ident_name(&self, ident: &Ident) -> String;
    /// Name of a field.
    fn field_name(&self, id: FieldId) -> String;
    /// Name of an address space.
    fn space_name(&self, id: SpaceId) -> String;
    /// Name of a user-defined operation.
    fn pcode_op_name(&self, id: PCodeOpId) -> String;
    /// Name of a macro.
    fn macro_name(&self, id: PMacroId) -> String;
}
