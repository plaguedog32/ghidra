//! The p-code AST: what a decoded instruction *does*.
//!
//! [`Instruction::pcode_ast`](crate::Instruction::pcode_ast) turns one decoded
//! instruction into a [`PcodeAst`] — a flat list of [`PcodeStatement`]s in
//! execution order. This is the crate's headline output: decoding tells you
//! which instruction you are looking at, and this tells you what it means.
//!
//! # What has already been done for you
//!
//! The AST is *source-shaped* SLEIGH p-code, not Ghidra's flattened
//! `PcodeOp` array. It keeps nested expressions, so `r0 = r1 + r2 * 3` is one
//! statement with a tree on the right, rather than three operations over
//! temporaries. Everything a specification writes for its own convenience has
//! been expanded away before you see it:
//!
//! - `macro` calls are inlined, with their locals renumbered so two expansions
//!   in one instruction cannot collide;
//! - `build` of a sub-table operand is spliced in, as is a `delayslot`;
//! - a sub-constructor's `export` is substituted into its parent;
//! - operand fields are folded to the constants this encoding gave them.
//!
//! So [`PcodeStatementKind::Build`], [`PcodeStatementKind::Export`],
//! [`PcodeExprKind::MacroCall`] and [`PcodeExprKind::DeferredCall`] should
//! never reach you. One that does is a bug in this crate, not a spec you need
//! to handle.
//!
//! # The type graph
//!
//! ```text
//! PcodeAst
//!  └── statements: Vec<PcodeStatement>
//!       └── ty: PcodeStatementKind        assignment / branch / call / ...
//!            ├── lhs: PcodeIdent          register, bit-range, temporary
//!            │     or PcodeLoad           *[space]:n ptr
//!            │     or PcodeRange          x[start, size]
//!            ├── target: PcodeTarget      label / computed address
//!            └── rhs: PcodeExpr
//!                 ├── size: Option<usize> width in BYTES
//!                 └── ty: PcodeExprKind
//!                      ├── SizedInt       a literal
//!                      ├── Ident          PcodeIdent
//!                      ├── Load           PcodeLoad
//!                      ├── Range          PcodeRange
//!                      ├── SubPieceMsb    x(n)  — drop n low bytes
//!                      ├── SubPieceLsb    x:n   — keep n low bytes
//!                      ├── Unop           PcodeUnaryOp  + operand
//!                      ├── Binop          PcodeBinaryOp + two operands
//!                      ├── FunctionCall   Builtin + args
//!                      └── PcodeOp        a `define pcodeop`, + args
//! ```
//!
//! # Sizes and signedness
//!
//! Every width in this AST is in **bytes**, and lives on the expression rather
//! than on a type — p-code values are untyped bit vectors. [`PcodeExpr::size`]
//! is `Option`: `None` means the width was not written and could not be
//! inferred, and a consumer must supply one from context rather than guess.
//!
//! Signedness likewise belongs to the *operator*, not the operand. SLEIGH
//! spells the three readings of a machine operation differently — `/`, `s/`
//! and `f/` — and each is a separate [`PcodeBinaryOp`] variant. Comparisons
//! yield one byte holding 0 or 1 whatever their operands' width; everything
//! else is as wide as its operands and wraps rather than trapping. Carry and
//! overflow are not implicit: a specification computes them with
//! [`Builtin::Carry`], [`Builtin::Scarry`] and [`Builtin::Sborrow`].
//!
//! # Ownership
//!
//! [`PcodeAst`] is owned and self-contained — it borrows nothing from the
//! [`CompiledSpec`](crate::CompiledSpec) or the instruction bytes, so it
//! outlives both. Names are indices into the specification, though, so
//! rendering one needs the spec that produced it: `PcodeIdent::Register(id)`
//! is resolved through [`CompiledSpec::registers`](crate::CompiledSpec::registers),
//! a `PcodeOp` name through
//! [`CompiledSpec::pcode_ops`](crate::CompiledSpec::pcode_ops).
//!
//! # Walking one
//!
//! ```
//! use sleigh::{Compiler, Decoder, PcodeExprKind, PcodeIdent, PcodeStatementKind, SourceDb};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let spec_source = r#"
//!     define endian=little;
//!     define space ram type=ram_space size=4 default;
//!     define space register type=register_space size=4;
//!     define register offset=0 size=4 [ r0 r1 ];
//!     define token instr(8) op=(0,7);
//!     :inc is op=1 { r0 = r1 + 1; }
//! "#;
//!
//! let mut sources = SourceDb::new();
//! let root = sources.add_file("example.slaspec", spec_source);
//! let spec = Compiler::new(&mut sources).compile(root)?;
//!
//! let instruction = Decoder::new(&spec).decode_one(0x1000, &[1], &spec.new_context())?;
//! let ast = instruction.pcode_ast()?;
//!
//! // One statement: an assignment to a register.
//! assert_eq!(ast.statements.len(), 1);
//! let PcodeStatementKind::Assignment { lhs, rhs, .. } = &ast.statements[0].ty else {
//!     panic!("expected an assignment");
//! };
//! assert!(matches!(lhs, PcodeIdent::Register(_)));
//!
//! // Its right-hand side is a tree, not a flattened operation list.
//! let PcodeExprKind::Binop(add) = &rhs.ty else {
//!     panic!("expected an addition");
//! };
//! assert!(matches!(add.lhs.ty, PcodeExprKind::Ident(PcodeIdent::Register(_))));
//! assert!(matches!(add.rhs.ty, PcodeExprKind::SizedInt { value: 1, .. }));
//!
//! // Widths are in bytes, and these registers are four wide.
//! assert_eq!(rhs.size, Some(4));
//! # Ok(())
//! # }
//! ```

use std::{error::Error, fmt};

// Re-exported rather than aliased so that every type a consumer meets while
// walking a [`PcodeAst`] is nameable, documented, and links from rustdoc. The
// span parameter these carry is `()` at this boundary — it holds byte ranges
// only while the compiler is still lowering — so their defaults make the
// `Pcode*` names spelling-compatible with the aliases they replace.
pub use pcode_types::{
    Ast as PcodeStatement, AstNode as PcodeStatementKind, BinaryOperator as PcodeBinaryOp,
    Binop as PcodeBinop, Builtin, DelaySlotArg as PcodeDelaySlot, Expression as PcodeExpr,
    ExpressionTy as PcodeExprKind, Ident as PcodeIdent, LabelOrNode as PcodeTarget,
    Load as PcodeLoad, LocalVarId, PcodeSpaceRef, Range as PcodeRange, RangeParam,
    UnaryOperator as PcodeUnaryOp, Unop as PcodeUnop,
};

/// Summary of a decoded instruction passed with its p-code AST.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionInfo {
    /// Instruction address.
    pub address: u64,
    /// Encoded length in bytes.
    pub length: usize,
}

pub use pcode_types::PcodeAst;

impl pcode_types::PcodeResolver for crate::CompiledSpec {
    fn ident_name(&self, ident: &PcodeIdent) -> String {
        match ident {
            PcodeIdent::Named(id) => format!("v{}", id.0),
            PcodeIdent::Register(id) => self.spec().registers[*id].name.to_string(),
            PcodeIdent::BitRange(id) => self.spec().bitranges[*id].name.to_string(),
            PcodeIdent::Field(id) => self.spec().fields[*id].name.to_string(),
            PcodeIdent::Table(id) => format!("table{}", usize::from(*id)),
            PcodeIdent::Global(name) => format!("?{name}"),
        }
    }

    fn field_name(&self, id: pcode_types::FieldId) -> String {
        self.spec().fields[id].name.to_string()
    }

    fn space_name(&self, id: pcode_types::SpaceId) -> String {
        self.spec().spaces[id]
            .name
            .as_deref()
            .unwrap_or("<unnamed-space>")
            .to_string()
    }

    fn pcode_op_name(&self, id: pcode_types::PCodeOpId) -> String {
        self.spec().pcode_ops[id].to_string()
    }

    fn macro_name(&self, id: pcode_types::PMacroId) -> String {
        self.spec()
            .symbols
            .iter()
            .find_map(|(name, &symbol)| match symbol {
                crate::builder::SymbolId::Macro(candidate) if candidate == id => {
                    Some(name.to_string())
                }
                _ => None,
            })
            .unwrap_or_else(|| "<unknown-macro>".to_string())
    }
}

/// Error returned by semantic sinks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EmitError {
    message: String,
}

impl EmitError {
    /// Creates a semantic emission error.
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for EmitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl Error for EmitError {}

/// Receives decoded instructions and their p-code, one at a time.
///
/// The alternative to pulling [`PcodeAst`]s out of individual
/// [`Instruction`](crate::Instruction)s: implement this and hand it to
/// [`Instruction::emit_into`](crate::Instruction::emit_into), which is the
/// shape a lifter wants when it is walking a whole function.
///
/// ```
/// use sleigh::{
///     Compiler, Decoder, EmitError, InstructionInfo, PcodeAst, SemanticsSink, SourceDb,
/// };
///
/// /// Counts p-code statements per instruction.
/// #[derive(Default)]
/// struct Counter {
///     instructions: usize,
///     statements: usize,
/// }
///
/// impl SemanticsSink for Counter {
///     fn instruction(
///         &mut self,
///         _info: &InstructionInfo,
///         pcode: &PcodeAst,
///     ) -> Result<(), EmitError> {
///         self.instructions += 1;
///         self.statements += pcode.statements.len();
///         Ok(())
///     }
/// }
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let mut sources = SourceDb::new();
/// let root = sources.add_file(
///     "tiny.slaspec",
///     "define endian=little;
///      define space ram type=ram_space size=4 default;
///      define space register type=register_space size=4;
///      define register offset=0 size=4 [ r0 ];
///      define token instr(8) op=(0,7);
///      :inc is op=1 { r0 = r0 + 1; }",
/// );
/// let spec = Compiler::new(&mut sources).compile(root)?;
///
/// let mut counter = Counter::default();
/// Decoder::new(&spec)
///     .decode_one(0x1000, &[1], &spec.new_context())?
///     .emit_into(&mut counter)?;
///
/// assert_eq!(counter.instructions, 1);
/// assert_eq!(counter.statements, 1);
/// # Ok(())
/// # }
/// ```
pub trait SemanticsSink {
    /// Emits one decoded instruction and its p-code AST.
    fn instruction(
        &mut self,
        instruction: &InstructionInfo,
        pcode: &PcodeAst,
    ) -> Result<(), EmitError>;
}
