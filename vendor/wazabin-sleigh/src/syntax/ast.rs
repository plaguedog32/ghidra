//! Typed, unresolved SLEIGH AST produced by a single Pest parse.
//!
//! All cross-references are `Box<str>` names; no symbol IDs are assigned during
//! construction. Resolution (name → ID) is deferred to the Phase 3 `resolve()`
//! pass, which walks this tree in declaration order while populating
//! `SpecBuilder`.
//!
//! Each node carries `leading_trivia` so the formatter can reconstruct
//! whitespace and comments without a second tree walk.

// Without `unstable-syntax` this AST is the compiler's own front end and
// nothing outside the crate reads it, so most fields look dead. They are not:
// they are the formatter's input.
#![cfg_attr(not(feature = "unstable-syntax"), allow(dead_code, unreachable_pub))]

use crate::{
    action::{BinOp as ActionBinOp, UnOp as ActionUnOp},
    constraint::ConstraintAst,
    pmacro::PCodeMacro,
    source::Span,
};
use pcode_types::SpaceType;

/// A single whitespace or comment token between structural AST nodes.
#[derive(Debug, Clone)]
pub struct TriviaToken {
    /// Raw text (whitespace run or `# ...` comment).
    pub text: Box<str>,
    /// Mapped physical-source span, if available.
    pub span: Span,
}

/// The root of a parsed SLEIGH source.
#[derive(Debug, Clone)]
pub struct SleighFile {
    /// Top-level items in source order. Order is significant: SLEIGH resolves
    /// names in declaration order, so a definition must precede its uses.
    pub items: Vec<SleighItem>,
}

/// One top-level item in a SLEIGH file.
///
/// The same set of items is legal inside a `with` block, so this enum is also
/// what [`WithBlockDef::items`] holds.
#[derive(Debug, Clone)]
pub enum SleighItem {
    /// `define endian=big;` / `define endian=little;`
    Endianness(EndiannessDef),
    /// `define alignment=4;`
    Alignment(AlignmentDef),
    /// `define space ram type=ram_space size=4 default;`
    Space(SpaceDef),
    /// `define register offset=0 size=8 [ RAX RCX ... ];`
    Register(RegisterDef),
    /// `define bitrange zf=statusreg[10,1] ...;`
    BitRange(BitRangeDef),
    /// `define pcodeop cpuid;` — declares a user-defined p-code operation.
    PcodeOp(PcodeOpDef),
    /// `define token instr(16) op=(0,5) ...;`
    Token(TokenDef),
    /// `define context contextreg phase=(0,1) ...;`
    Context(ContextDef),
    /// `macro addflags(op1, op2) { ... }`
    Macro(MacroDef),
    /// `attach variables [ rs rt ] [ r0 r1 ... ];`
    AttachVar(AttachVarDef),
    /// `attach values [ imm ] [ 8 16 32 64 ];`
    AttachVal(AttachValDef),
    /// `attach names [ cc ] [ "eq" "ne" ... ];`
    AttachStr(AttachStrDef),
    /// `with tbl : ctx=1 { ... }`
    WithBlock(WithBlockDef),
    /// A constructor: `tbl: display is pattern [ actions ] { semantics }`
    Constructor(ConstructorDef),
}

impl SleighItem {
    /// Span of the whole item, from its first token to its last.
    pub fn span(&self) -> Span {
        match self {
            SleighItem::Endianness(d) => d.span,
            SleighItem::Alignment(d) => d.span,
            SleighItem::Space(d) => d.span,
            SleighItem::Register(d) => d.span,
            SleighItem::BitRange(d) => d.span,
            SleighItem::PcodeOp(d) => d.span,
            SleighItem::Token(d) => d.span,
            SleighItem::Context(d) => d.span,
            SleighItem::Macro(d) => d.span,
            SleighItem::AttachVar(d) => d.span,
            SleighItem::AttachVal(d) => d.span,
            SleighItem::AttachStr(d) => d.span,
            SleighItem::WithBlock(d) => d.span,
            SleighItem::Constructor(d) => d.span,
        }
    }

    /// Mutable access to the item's leading trivia, whichever variant it is.
    ///
    /// The parser uses this to hand over the whitespace and comments it
    /// buffered since the previous item once it knows what that item is.
    pub fn leading_trivia_mut(&mut self) -> &mut Vec<TriviaToken> {
        match self {
            SleighItem::Endianness(d) => &mut d.leading_trivia,
            SleighItem::Alignment(d) => &mut d.leading_trivia,
            SleighItem::Space(d) => &mut d.leading_trivia,
            SleighItem::Register(d) => &mut d.leading_trivia,
            SleighItem::BitRange(d) => &mut d.leading_trivia,
            SleighItem::PcodeOp(d) => &mut d.leading_trivia,
            SleighItem::Token(d) => &mut d.leading_trivia,
            SleighItem::Context(d) => &mut d.leading_trivia,
            SleighItem::Macro(d) => &mut d.leading_trivia,
            SleighItem::AttachVar(d) => &mut d.leading_trivia,
            SleighItem::AttachVal(d) => &mut d.leading_trivia,
            SleighItem::AttachStr(d) => &mut d.leading_trivia,
            SleighItem::WithBlock(d) => &mut d.leading_trivia,
            SleighItem::Constructor(d) => &mut d.leading_trivia,
        }
    }
}

// ── Endianness ────────────────────────────────────────────────────────────────

/// `define endian=big;` — the spec's global byte order.
///
/// It fixes the order in which instruction bytes are assembled into tokens,
/// and is the default for every [`TokenDef`] that does not override it.
#[derive(Debug, Clone)]
pub struct EndiannessDef {
    /// Span of the whole `define endian=...;` statement.
    pub span: Span,
    /// `true` for `big`, `false` for `little`.
    pub big_endian: bool,
    /// Whitespace and comments between the previous item and this one, kept
    /// so the formatter can reprint them.
    pub leading_trivia: Vec<TriviaToken>,
}

// ── Alignment ─────────────────────────────────────────────────────────────────

/// `define alignment=4;` — the byte granularity instructions start on.
#[derive(Debug, Clone)]
pub struct AlignmentDef {
    /// Span of the whole `define alignment=...;` statement.
    pub span: Span,
    /// Instruction alignment in bytes. Defaults to 1 if the value is missing.
    pub alignment: usize,
    /// Whitespace and comments between the previous item and this one, kept
    /// so the formatter can reprint them.
    pub leading_trivia: Vec<TriviaToken>,
}

// ── Address space ─────────────────────────────────────────────────────────────

/// `define space ram type=ram_space size=4 default;` — an address space.
///
/// Attributes may appear in any order; those omitted take the defaults noted
/// on each field.
#[derive(Debug, Clone)]
pub struct SpaceDef {
    /// Span of the whole `define space ...;` statement.
    pub span: Span,
    /// Space name, as used by `*[ram]` and by register definitions.
    pub name: Box<str>,
    /// `type=` attribute: RAM, ROM, or register. Defaults to RAM.
    pub ty: SpaceType,
    /// `size=` attribute: width of an address into this space, in bytes.
    /// Defaults to 4.
    pub addr_size: usize,
    /// `wordsize=` attribute: bytes per addressable unit. Defaults to 1, so
    /// addresses count bytes; word-addressed spaces set it higher.
    pub word_size: usize,
    /// `default` attribute. At most one space per spec may carry it; it is the
    /// space branch targets and bare `*` dereferences refer to.
    pub is_default: bool,
    /// Whitespace and comments between the previous item and this one, kept
    /// so the formatter can reprint them.
    pub leading_trivia: Vec<TriviaToken>,
}

// ── Registers ─────────────────────────────────────────────────────────────────

/// `define register offset=0 size=8 [ RAX RCX ... ];` — a run of registers.
///
/// One statement names a whole consecutive block: the first entry sits at
/// `offset`, and each further entry follows `size` bytes later.
#[derive(Debug, Clone)]
pub struct RegisterDef {
    /// Span of the whole `define <space> offset=... size=... [...];`
    /// statement.
    pub span: Span,
    /// Name of the address space registers live in.
    pub space: Box<str>,
    /// Byte offset of the first named register within [`Self::space`].
    pub offset: usize,
    /// Width of each register in bytes.
    pub size: usize,
    /// `None` entries are `_` (gap / skipped offset) placeholders.
    ///
    /// A gap still consumes its slot: the following name is placed `size`
    /// bytes further on, exactly as a real register would be.
    pub names: Vec<Option<Box<str>>>,
    /// Whitespace and comments between the previous item and this one, kept
    /// so the formatter can reprint them.
    pub leading_trivia: Vec<TriviaToken>,
}

// ── Bitranges ─────────────────────────────────────────────────────────────────

/// One `name=register[offset,size]` entry of a `define bitrange`.
///
/// It gives a name to a sub-range of an existing register, typically a single
/// status flag such as `define bitrange zf=statusreg[10,1];`.
#[derive(Debug, Clone)]
pub struct BitRangeItem {
    /// Name given to the sub-range.
    pub name: Box<str>,
    /// Name of the register the sub-range is carved out of.
    pub register: Box<str>,
    /// First bracketed integer: the bit offset of the range within the
    /// register, counted from its least significant bit.
    pub low: usize,
    /// Second bracketed integer: the width of the range in bits, *not* an end
    /// index. `[10,1]` is the single bit 10.
    pub high: usize,
}

/// `define bitrange zf=statusreg[10,1] cf=statusreg[0,1];`
#[derive(Debug, Clone)]
pub struct BitRangeDef {
    /// Span of the whole `define bitrange ...;` statement.
    pub span: Span,
    /// The entries of this statement, in source order. One statement may
    /// define several bit ranges.
    pub items: Vec<BitRangeItem>,
    /// Whitespace and comments between the previous item and this one, kept
    /// so the formatter can reprint them.
    pub leading_trivia: Vec<TriviaToken>,
}

// ── PcodeOp ───────────────────────────────────────────────────────────────────

/// `define pcodeop cpuid;` — declares a user-defined p-code operation.
///
/// Such an operation has no semantics of its own; the semantic section calls
/// it by name and the lifter treats it as an opaque intrinsic.
#[derive(Debug, Clone)]
pub struct PcodeOpDef {
    /// Span of the whole `define pcodeop ...;` statement.
    pub span: Span,
    /// Name of the declared operation.
    pub name: Box<str>,
    /// Whitespace and comments between the previous item and this one, kept
    /// so the formatter can reprint them.
    pub leading_trivia: Vec<TriviaToken>,
}

// ── Tokens and fields ─────────────────────────────────────────────────────────

/// A single field defined inside a token or context block.
///
/// Written `name=(low,high)` followed by any attributes, as in
/// `op=(0,5) signed`. The bit indices are relative to the parent token or
/// context register.
#[derive(Debug, Clone)]
pub struct FieldDef {
    /// Span of the `name=(low,high) attrs` field definition.
    pub span: Span,
    /// Field name, which becomes a spec-wide symbol usable in patterns,
    /// display sections, and semantics.
    pub name: Box<str>,
    /// Inclusive low bit index.
    pub low: usize,
    /// Inclusive high bit index.
    pub high: usize,
    /// `signed` attribute: the extracted bits are sign-extended rather than
    /// zero-extended.
    pub signed: bool,
    /// `noflow` attribute. Only meaningful for context fields: it stops a
    /// committed value from persisting past the address it was set at.
    pub noflow: bool,
}

/// `define token instr(16) op=(0,5) rd=(6,10);` — an instruction token and
/// the fields cut out of it.
///
/// A token is a fixed-width window onto the instruction stream; its fields are
/// the bit ranges patterns and semantics address by name.
#[derive(Debug, Clone)]
pub struct TokenDef {
    /// Span of the whole `define token ...;` statement.
    pub span: Span,
    /// Token name, as used to disambiguate same-named fields.
    pub name: Box<str>,
    /// Token size in bits (always a multiple of 8).
    pub size: usize,
    /// `Some(true)` = big, `Some(false)` = little, `None` = inherit from global.
    pub endian: Option<bool>,
    /// Fields declared in this token, in source order.
    pub fields: Vec<FieldDef>,
    /// Whitespace and comments between the previous item and this one, kept
    /// so the formatter can reprint them.
    pub leading_trivia: Vec<TriviaToken>,
}

/// `define context contextreg phase=(0,1) noflow;` — fields of the context
/// register.
///
/// Context fields hold decoder state rather than instruction bits: they are
/// read by patterns, written by disassembly actions, and propagated between
/// addresses by `globalset`. A spec has at most one context register, so every
/// `define context` in a spec must name the same one.
#[derive(Debug, Clone)]
pub struct ContextDef {
    /// Span of the whole `define context ...;` statement.
    pub span: Span,
    /// Name of the register backing the context. It must already be defined
    /// by a `define register` statement.
    pub register: Box<str>,
    /// Context fields declared in this block, in source order.
    pub fields: Vec<FieldDef>,
    /// Whitespace and comments between the previous item and this one, kept
    /// so the formatter can reprint them.
    pub leading_trivia: Vec<TriviaToken>,
}

// ── Attach ────────────────────────────────────────────────────────────────────

/// `attach variables [ rs rt ] [ r0 r1 ... ];` — reinterprets fields as
/// registers.
///
/// The attached list is indexed by the field's decoded value, so it must have
/// exactly `2^width` entries for every field it is attached to.
#[derive(Debug, Clone)]
pub struct AttachVarDef {
    /// Span of the whole `attach variables ...;` statement.
    pub span: Span,
    /// Names of the fields the table is attached to. All of them share the
    /// one table.
    pub fields: Vec<Box<str>>,
    /// `None` entries are `_` placeholders.
    ///
    /// Position in this list is the field value being mapped; `_` marks an
    /// encoding with no register attached.
    pub registers: Vec<Option<Box<str>>>,
    /// Whitespace and comments between the previous item and this one, kept
    /// so the formatter can reprint them.
    pub leading_trivia: Vec<TriviaToken>,
}

/// `attach names [ cc ] [ "eq" "ne" ... ];` — gives fields display names.
///
/// Purely a display attachment: the field's numeric value is unchanged, but
/// the display section prints the corresponding name. The list is indexed by
/// field value and must have `2^width` entries.
#[derive(Debug, Clone)]
pub struct AttachStrDef {
    /// Span of the whole `attach names ...;` statement.
    pub span: Span,
    /// Names of the fields the table is attached to.
    pub fields: Vec<Box<str>>,
    /// One entry per field value; `None` is an `_` slot with no name attached.
    pub names: Vec<Option<Box<str>>>,
    /// Whitespace and comments between the previous item and this one, kept
    /// so the formatter can reprint them.
    pub leading_trivia: Vec<TriviaToken>,
}

/// `attach values [ imm ] [ 8 16 32 64 ];` — remaps field values to other
/// integers.
///
/// The list is indexed by the field's decoded value and must have `2^width`
/// entries.
#[derive(Debug, Clone)]
pub struct AttachValDef {
    /// Span of the whole `attach values ...;` statement.
    pub span: Span,
    /// Names of the fields the table is attached to.
    pub fields: Vec<Box<str>>,
    /// One entry per field value; `None` is an `_` slot with nothing attached.
    ///
    /// `attach values` admits negative literals, which are stored here as
    /// their 64-bit two's-complement bit pattern.
    pub values: Vec<Option<u64>>,
    /// Whitespace and comments between the previous item and this one, kept
    /// so the formatter can reprint them.
    pub leading_trivia: Vec<TriviaToken>,
}

// ── Constructor actions ───────────────────────────────────────────────────────

/// Unresolved disassembly action expression (field names as strings).
///
/// Disassembly actions are evaluated at decode time over integers only, so
/// this is a small integer expression language — no memory, no p-code.
#[derive(Debug, Clone)]
pub enum UnresolvedExpr {
    /// Infix operation, parsed with SLEIGH's action-expression precedence
    /// (`|` loosest, then `^`, `&`, shifts, `+`/`-`, `*`/`/`).
    Binary {
        /// The operator.
        op: ActionBinOp,
        /// Left operand.
        lhs: Box<UnresolvedExpr>,
        /// Right operand.
        rhs: Box<UnresolvedExpr>,
    },
    /// Prefix operation: `-x` or `~x`.
    Unary {
        /// The operator.
        op: ActionUnOp,
        /// Operand.
        expr: Box<UnresolvedExpr>,
    },
    /// A bare name. Resolution reads it as a token, context, or global field,
    /// or as an action-scoped local; a register name has no decode-time value
    /// and resolves to the constant zero, matching Ghidra.
    Ident(Box<str>),
    /// An integer literal. Decimal, `0x`, and `0b` forms all land here.
    Int(i64),
}

/// One statement in a constructor's disassembly-action block.
///
/// Variants are stored in source order: SLEIGH evaluates an action block
/// sequentially, and `globalset` commits the value a context variable holds at
/// that point, so reordering changes the meaning.
#[derive(Debug, Clone)]
pub enum UnresolvedAction {
    /// `field = expr;` — assigns a token, context, or global field.
    Assign {
        /// Name of the assigned field.
        field: Box<str>,
        /// Right-hand side of the assignment.
        expr: UnresolvedExpr,
    },

    /// `globalset(addr, field);` — commits `field`'s current value at `addr`.
    GlobalSet {
        /// Address the committed value takes effect at. Usually `inst_next`,
        /// but may be any action expression or a sub-table operand name.
        addr: UnresolvedExpr,
        /// Name of the context field whose value is committed.
        field: Box<str>,
    },
}

// ── Constructors ──────────────────────────────────────────────────────────────

/// A single element of a constructor's display section.
#[derive(Debug, Clone)]
pub enum UnresolvedDisplayToken {
    /// An identifier that may resolve to a field, table, or fall back to a string literal.
    Ident(Box<str>),
    /// A literal string fragment (quoted string content, whitespace, or punctuation).
    Literal(Box<str>),
}

/// An unresolved constructor definition.
///
/// A constructor is one decoding rule, written
/// `table: display is pattern [ actions ] { semantics }`. It is the unit that
/// matches bits, prints text, and emits p-code.
#[derive(Debug, Clone)]
pub struct ConstructorDef {
    /// Span of the whole constructor, from its table header through the
    /// closing brace of the semantic section.
    pub span: Span,
    /// Table name, or `None` for the root `instruction` table.
    ///
    /// `None` inside a `with` block means the block's default table applies
    /// instead; see [`WithBlockDef::table`].
    pub table: Option<Box<str>>,
    /// The bit pattern between `is` and the action or semantic section. An
    /// enclosing `with` block's constraint is conjoined with this one during
    /// resolution.
    pub constraint: ConstraintAst,
    /// Display section tokens, parsed from the Pest `display` rule.
    pub display: Vec<UnresolvedDisplayToken>,
    /// Byte offset of the `is` keyword in the prepared source. Used by the
    /// formatter to align `is` columns across consecutive constructors.
    pub is_start: usize,
    /// The bracketed disassembly-action block, in source order. Empty when the
    /// constructor has no `[ ... ]` section. Actions inherited from enclosing
    /// `with` blocks are prepended during resolution, not here.
    pub actions: Vec<UnresolvedAction>,
    /// Pre-parsed p-code body (Phase 2 result with deferred name references).
    pub(crate) pcode: PCodeMacro,
    /// Whitespace and comments between the previous item and this one, kept
    /// so the formatter can reprint them.
    pub leading_trivia: Vec<TriviaToken>,
}

impl ConstructorDef {
    /// Byte spans of the semantic body's top-level statements, in the prepared
    /// source, in source order.
    ///
    /// A formatter uses these to lay a body out without re-lexing it; the
    /// compiler uses the same spans to point diagnostics at one statement.
    pub fn statement_spans(&self) -> Vec<(usize, usize)> {
        self.pcode
            .body
            .iter()
            .map(|statement| statement.span)
            .collect()
    }
}

// ── Macros ────────────────────────────────────────────────────────────────────

/// `macro addflags(op1, op2) { ... }` — a named, inlined block of p-code.
///
/// Macros are expanded at their call sites in semantic sections; they take
/// varnode arguments and export nothing.
#[derive(Debug, Clone)]
pub struct MacroDef {
    /// Span of the whole macro, from `macro` through the closing brace.
    pub span: Span,
    /// Macro name, as called from a semantic section.
    pub name: Box<str>,
    /// Parameter names in declaration order. They are bound as locals of the
    /// body, so their order fixes the call-site argument order.
    pub args: Vec<Box<str>>,
    /// Pre-parsed p-code body (Phase 2 result with deferred name references).
    pub(crate) pcode: PCodeMacro,
    /// Whitespace and comments between the previous item and this one, kept
    /// so the formatter can reprint them.
    pub leading_trivia: Vec<TriviaToken>,
}

// ── With block ────────────────────────────────────────────────────────────────

/// A `with` block, which applies a default table, constraint, and actions to
/// all nested constructors and sub-blocks.
#[derive(Debug, Clone)]
pub struct WithBlockDef {
    /// Span of the whole `with ... { ... }` block, braces included.
    pub span: Span,
    /// Default table name, or `None` for anonymous (inherits outer or `instruction`).
    pub table: Option<Box<str>>,
    /// Pattern conjoined onto every nested constructor's own pattern. `with`
    /// blocks nest, and each enclosing constraint is conjoined in turn.
    pub constraint: ConstraintAst,
    /// Disassembly actions prepended to every nested constructor's own
    /// actions, outermost block first.
    pub actions: Vec<UnresolvedAction>,
    /// Nested items. Any top-level item is allowed here, not just
    /// constructors — ARM puts `attach variables` inside a `with` block.
    pub items: Vec<SleighItem>,
    /// Whitespace and comments between the previous item and this one, kept
    /// so the formatter can reprint them.
    pub leading_trivia: Vec<TriviaToken>,
}
