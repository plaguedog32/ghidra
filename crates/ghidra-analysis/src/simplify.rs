//! Bounded simplification of typed P-code expressions over SCCP facts.
//!
//! The result is an owned canonical *value-term projection* of one immutable
//! `PcodeConstants` snapshot. Each executable original expression node maps to
//! a hash-consed canonical term. The original operation stream is never
//! removed, reordered or re-executed: it remains the required evaluation order,
//! including every declared operand read, memory effect and fault.

use std::collections::HashMap;
use std::sync::Arc;

use ghidra_pcode::{Endianness, Opcode, SpaceId, Value, evaluate_pure};
use ghidra_ssa::{StatementId, ValueId, ValueOrigin};
use thiserror::Error;

use crate::{
    ConstantError, ConstantFact, ConstantPolicy, ExpressionAddress, ExpressionDefinition,
    ExpressionError, ExpressionId, ExpressionKind, ExpressionOperation, ExpressionType,
    PcodeConstants, PcodeExpressions, PcodeSsa,
};

/// Canonical term identity. This is a separate namespace from `ExpressionId`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct TermId(pub usize);

/// One piece of a canonical join, in ascending value significance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TermPiece {
    pub term: TermId,
    pub lsb_byte: u32,
    pub size: u32,
}

/// A memory address operand. Fixed varnodes keep byte offsets; LOAD/STORE
/// pointers keep their address width and word scaling, exactly as in the
/// source expression.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TermAddress {
    ByteOffset(u64),
    Pointer {
        term: TermId,
        word_size: u32,
        address_size: u8,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum TermKind {
    /// An exact bit vector of its declared width.
    Literal(Value),
    /// A stable SSA value identity, never expanded: phis, entry declarations,
    /// undefined resets, opaque outputs, memory states and values whose
    /// definitions are not propagated.
    Leaf(ValueId),
    /// At least two pieces covering the whole width in ascending significance.
    Join(Vec<TermPiece>),
    /// A proper slice from the least significant `lsb_byte`.
    Extract {
        term: TermId,
        lsb_byte: u32,
    },
    Apply {
        opcode: Opcode,
        inputs: Vec<TermId>,
    },
    /// Never shared with another read: `node` is the original read term.
    ReadMemory {
        node: ExpressionId,
        space: SpaceId,
        version: ValueId,
        address: TermAddress,
        endianness: Endianness,
    },
    /// Never shared with another write: `node` is the original write term.
    WriteMemory {
        node: ExpressionId,
        space: SpaceId,
        version: ValueId,
        address: TermAddress,
        value: TermId,
        endianness: Endianness,
    },
}

/// Whether evaluating a term's structure can fail. `Here` covers an
/// application that may fail itself (division, floating point, bit-range
/// operations, invalid operand shapes, refused literal folds) and memory
/// accesses. Reading an SSA leaf is not counted: its original operand read
/// stays in the operation stream, which remains the required evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum TermFault {
    None,
    Subterm,
    Here,
}

/// How a term is identified. Structural terms are hash-consed by their complete
/// type, operator, operands and literal bytes. Distinct terms (memory accesses
/// and applications that may fail) keep one identity per original node.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TermIdentity {
    Structural,
    Distinct,
    Value,
}

/// The original node or SSA value whose canonicalization created a term. A
/// shared structural term keeps the origin of its first creation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TermOrigin {
    Node(ExpressionId),
    Value(ValueId),
}

macro_rules! rules {
    ($( $(#[$doc:meta])* $variant:ident => $name:literal ),+ $(,)?) => {
        /// The rewrite rules. Each count is the number of times the rule fired.
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
        pub enum Rule {
            $( $(#[$doc])* $variant ),+
        }

        impl Rule {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            pub const fn name(self) -> &'static str {
                match self { $(Self::$variant => $name),+ }
            }
        }
    };
}

rules! {
    /// An SSA value with a constant fact becomes its literal.
    ConstantFact => "constant_fact",
    /// An application of literals evaluated by `evaluate_pure`.
    LiteralFold => "literal_fold",
    /// Same-width COPY or CAST becomes its input.
    CopyCast => "copy_cast",
    /// `x+0`, `x|0`, `x^0`, `x&~0`, `x*1` and shifts by 0 at equal widths.
    Identity => "identity",
    /// `BOOL_OR/XOR x,0` and `BOOL_AND x,0xff`; `BOOL_AND x,1`, `x!=0`
    /// and `x==1` only for operands proven to be 0 or 1.
    BooleanIdentity => "boolean_identity",
    /// `x&x` and `x|x` (integer and boolean).
    Idempotent => "idempotent",
    /// `~~x`, `-(-x)` and `!!x`.
    Involution => "involution",
    /// `!(a==b)` becomes `a!=b`, `!(a<b)` becomes `b<=a`, and so on.
    NegatedComparison => "negated_comparison",
    /// `x - c` becomes `x + (-c)`.
    SubtractConstant => "subtract_constant",
    /// `(x op c1) op c2` becomes `x op (c1 op c2)` for integer add, multiply,
    /// and, or, xor.
    Reassociate => "reassociate",
    /// Commutative integer operands are ordered: terms by ID, literal last.
    Commute => "commute",
    /// `PIECE hi,lo` becomes a join.
    PieceJoin => "piece_join",
    /// In-range `SUBPIECE x,k` becomes an extract.
    SubpieceExtract => "subpiece_extract",
    /// `zext(zext(x))` becomes one zero extension.
    ZextCollapse => "zext_collapse",
    /// A join piece that is itself a join is spliced in.
    JoinFlatten => "join_flatten",
    /// Adjacent literal pieces, or adjacent slices of one term, merge.
    JoinMerge => "join_merge",
    /// A join whose most significant piece is literal zero becomes `zext`.
    JoinZext => "join_zext",
    /// Full-width extracts, extracts of extracts and of literals.
    ExtractCollapse => "extract_collapse",
    /// An extract of a join selects or re-joins the covered pieces.
    ExtractJoin => "extract_join",
    /// An extract of the low part of `zext`/`sext` (the input, or a narrower
    /// extension), or of a zero extension's zero bytes.
    ExtractExtension => "extract_extension",
    /// A use of an SSA value receives its definition's canonical term.
    Propagate => "propagate",
}

const RULES: usize = 21;

#[derive(Clone, Debug)]
pub struct Term {
    pub ty: ExpressionType,
    pub kind: TermKind,
    pub fault: TermFault,
    /// This term or a subterm reads memory.
    pub reads_memory: bool,
    /// The value is proven to be one byte holding 0 or 1.
    pub boolean: bool,
    pub origin: TermOrigin,
    /// The rule that produced this term; `None` for a direct translation.
    pub rule: Option<Rule>,
}

impl Term {
    pub fn may_fault(&self) -> bool {
        self.fault != TermFault::None
    }

    pub fn identity(&self) -> TermIdentity {
        match self.kind {
            TermKind::Leaf(_) => TermIdentity::Value,
            TermKind::ReadMemory { .. } | TermKind::WriteMemory { .. } => TermIdentity::Distinct,
            TermKind::Apply { .. } if self.fault == TermFault::Here => TermIdentity::Distinct,
            _ => TermIdentity::Structural,
        }
    }
}

/// A literal-only application that `evaluate_pure` rejected. The term stays
/// an explicit application. This records a refused compile-time evaluation;
/// it is not a claim that the program faults at run time. Faults found by
/// constant propagation are reported separately through `faults()`.
#[derive(Clone, Debug)]
pub struct RefusedFold {
    pub term: TermId,
    pub node: ExpressionId,
    pub statement: StatementId,
    pub opcode: Opcode,
    pub error: Arc<ghidra_pcode::Error>,
}

/// One final constant-propagation fault, with the canonical term of its
/// node. The index matches `constants().faults()`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SimplifiedFault {
    pub statement: StatementId,
    pub node: ExpressionId,
    pub term: TermId,
    pub opcode: Opcode,
}

/// Every count is checked before the matching allocation or growth. Work is
/// a fresh deterministic budget; the supplied expression and constant
/// snapshots were built under their own budgets.
#[derive(Clone, Copy, Debug)]
pub struct SimplifyLimits {
    pub max_values: usize,
    pub max_expression_nodes: usize,
    /// Renamed statements in SSA-reachable nodes.
    pub max_statements: usize,
    pub max_terms: usize,
    /// Child references stored in terms: join pieces, extract sources,
    /// application inputs, memory addresses and stored values.
    pub max_term_inputs: usize,
    /// Owned literal payload bytes, counted once per distinct literal term.
    pub max_literal_bytes: usize,
    /// Pending entries in the iterative traversal stack.
    pub max_live: usize,
    pub max_work: u64,
}

impl Default for SimplifyLimits {
    fn default() -> Self {
        Self {
            max_values: 2_000_000,
            max_expression_nodes: 4_000_000,
            max_statements: 1_000_000,
            max_terms: 4_000_000,
            max_term_inputs: 16_000_000,
            max_literal_bytes: 64 * 1024 * 1024,
            max_live: 8_000_000,
            max_work: 200_000_000,
        }
    }
}

#[derive(Debug, Error)]
pub enum SimplifyError {
    #[error("simplification limit exceeded: {0}")]
    Limit(&'static str),
    #[error("unknown canonical term {0:?}")]
    UnknownTerm(TermId),
    #[error("unknown expression {0:?}")]
    UnknownExpression(ExpressionId),
    #[error("unknown SSA value {0:?}")]
    UnknownValue(ValueId),
    #[error("inconsistent simplification input: {0}")]
    Inconsistent(&'static str),
    #[error(transparent)]
    Constant(#[from] ConstantError),
    #[error(transparent)]
    Expression(#[from] ExpressionError),
    #[error(transparent)]
    Pcode(#[from] ghidra_pcode::Error),
}

type Result<T> = std::result::Result<T, SimplifyError>;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SimplifyStats {
    pub work: u64,
    pub executed_statements: usize,
    pub executed_operations: usize,
    /// Operations in statements that constant propagation never executed.
    pub skipped_operations: usize,
    /// Original nodes canonicalized in executable statements.
    pub canonical_nodes: usize,
    /// Original nodes without a term: nodes of unexecuted statements.
    pub unmapped_nodes: usize,
    pub terms: usize,
    pub literal_terms: usize,
    pub leaf_terms: usize,
    pub distinct_terms: usize,
    pub term_inputs: usize,
    pub literal_bytes: usize,
    pub live_peak: usize,
    /// Structural lookups that found an existing non-literal term.
    pub shared_terms: usize,
    /// Non-literal original nodes in executable statements that became
    /// literals.
    pub literal_nodes: usize,
    /// Those whose constant-propagation fact was not a constant.
    pub literals_beyond_constants: usize,
    pub literal_values: usize,
    pub propagated_values: usize,
    pub leaf_values: usize,
    /// Executed operations whose canonical output is a literal.
    pub literal_outputs: usize,
    /// Executed operations whose canonical output is an SSA leaf or the
    /// canonical term of one of their own operands.
    pub forwarded_outputs: usize,
    /// Block-ending CBRANCH conditions that became literals although their
    /// constant-propagation fact was not constant. Control flow keeps the
    /// original feasibility.
    pub new_literal_conditions: usize,
    pub evaluations: usize,
    pub refused_folds: usize,
    pub rules: [usize; RULES],
}

impl SimplifyStats {
    pub fn rule(&self, rule: Rule) -> usize {
        self.rules[rule as usize]
    }
}

/// The fixed policies of this stage and the constant-propagation policy of
/// the snapshot it reads. None is configurable yet.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub struct SimplifyPolicy {
    /// The original propagation and feasibility policy.
    pub constants: ConstantPolicy,
    /// Always `true`: only statements constant propagation executed are
    /// simplified; unreached ones keep no canonical terms.
    pub executable_statements_only: bool,
    /// Always `false`: newly literal conditions do not prune control flow.
    pub prunes_control: bool,
    /// Always `false`: the original operations, reads and effects remain the
    /// required evaluation stream; terms are a value projection.
    pub rewrites_operations: bool,
    pub eliminates_dead_code: bool,
    /// Always `false`: no store-to-load forwarding.
    pub forwards_memory: bool,
    /// Always `false`: two memory accesses are never one term.
    pub shares_memory_terms: bool,
    /// Always `false`: applications that may fault keep one term per node.
    pub shares_faulting_terms: bool,
    /// Always `false`: uses of a value whose definition may fault or reads
    /// memory refer to its SSA leaf.
    pub propagates_faulting_definitions: bool,
    /// Always `false`: a rewrite never discards a subterm that may fault.
    pub discards_faulting_subterms: bool,
    /// Always `false`: `x*0`, `x&0`, `x^x`, `x-x` and similar identities that
    /// drop a nonconstant evaluation are not applied.
    pub annihilators: bool,
    /// Always `false`: no algebraic identities on floating-point operations.
    pub float_identities: bool,
    /// Always `true`: `BOOL_AND x,1`, `x!=0` and `x==1` require an operand
    /// proven to be 0 or 1.
    pub normalized_boolean_rewrites: bool,
    /// Always `false`: pointer arithmetic, memory operations and metadata
    /// operands are never reordered or reassociated.
    pub reorders_pointer_or_metadata: bool,
    pub resolves_indirect_targets: bool,
    pub type_recovery: bool,
    pub abi_return_values: bool,
    pub decompiled_output: bool,
}

/// An original operation with its canonical operand and output terms.
#[derive(Clone, Copy, Debug)]
pub struct SimplifiedOperation<'a> {
    pub source: &'a ExpressionOperation,
    /// Constant propagation executed the statement. Otherwise no terms are
    /// reported for it.
    pub executable: bool,
    owner: &'a PcodeSimplification,
}

impl SimplifiedOperation<'_> {
    /// The canonical term of operand slot `index`, or `None` for control
    /// labels, selectors and other non-value roles, and for operations that
    /// were not executable.
    pub fn operand(&self, index: usize) -> Option<TermId> {
        if !self.executable {
            return None;
        }
        let node = self.source.operands.get(index)?.expression()?;
        self.owner.mapped(node)
    }

    /// The canonical term of the complete bit result, if any.
    pub fn output(&self) -> Option<TermId> {
        if !self.executable {
            return None;
        }
        self.owner.mapped(self.source.output?)
    }
}

/// Owned canonical terms for one constant-propagation snapshot. Terms describe
/// the values original operations produce when they complete; they are not an
/// executable replacement for the operation stream, which remains the source
/// of evaluation order, operand reads, memory effects and faults.
#[derive(Clone, Debug)]
pub struct PcodeSimplification {
    constants: Arc<PcodeConstants>,
    limits: SimplifyLimits,
    terms: Vec<Term>,
    node_terms: Vec<usize>,
    value_terms: Vec<usize>,
    refused: Vec<RefusedFold>,
    faults: Vec<SimplifiedFault>,
    stats: SimplifyStats,
}

impl PcodeSimplification {
    pub fn new(constants: Arc<PcodeConstants>, limits: SimplifyLimits) -> Result<Self> {
        let output = Builder::run(&constants, limits)?;
        Ok(Self {
            constants,
            limits,
            terms: output.terms,
            node_terms: output.node_terms,
            value_terms: output.value_terms,
            refused: output.refused,
            faults: output.faults,
            stats: output.stats,
        })
    }

    pub fn constants(&self) -> &Arc<PcodeConstants> {
        &self.constants
    }
    pub fn expressions(&self) -> &Arc<PcodeExpressions> {
        self.constants.expressions()
    }
    pub fn analysis(&self) -> &Arc<PcodeSsa> {
        self.constants.analysis()
    }
    pub fn limits(&self) -> SimplifyLimits {
        self.limits
    }
    pub fn stats(&self) -> SimplifyStats {
        self.stats
    }

    pub fn policy(&self) -> SimplifyPolicy {
        SimplifyPolicy {
            constants: self.constants.policy(),
            executable_statements_only: true,
            prunes_control: false,
            rewrites_operations: false,
            eliminates_dead_code: false,
            forwards_memory: false,
            shares_memory_terms: false,
            shares_faulting_terms: false,
            propagates_faulting_definitions: false,
            discards_faulting_subterms: false,
            annihilators: false,
            float_identities: false,
            normalized_boolean_rewrites: true,
            reorders_pointer_or_metadata: false,
            resolves_indirect_targets: false,
            type_recovery: false,
            abi_return_values: false,
            decompiled_output: false,
        }
    }

    /// Terms in ID order. Every child reference names an earlier term.
    pub fn terms(&self) -> &[Term] {
        &self.terms
    }

    pub fn term(&self, id: TermId) -> Result<&Term> {
        self.terms.get(id.0).ok_or(SimplifyError::UnknownTerm(id))
    }

    /// The canonical term of an original expression node. `None` for nodes
    /// of statements that constant propagation never executed. An SSA leaf
    /// node always maps to its value's term.
    pub fn node_term(&self, node: ExpressionId) -> Result<Option<TermId>> {
        let slot = *self
            .node_terms
            .get(node.0)
            .ok_or(SimplifyError::UnknownExpression(node))?;
        Ok((slot != NONE).then_some(TermId(slot)))
    }

    /// The term every use of `value` refers to: its literal, its propagated
    /// definition term, or its own SSA leaf.
    pub fn value_term(&self, value: ValueId) -> Result<TermId> {
        self.value_terms
            .get(value.0)
            .map(|&slot| TermId(slot))
            .ok_or(SimplifyError::UnknownValue(value))
    }

    /// Whether uses of `value` receive its definition's canonical term.
    pub fn is_propagated(&self, value: ValueId) -> Result<bool> {
        let term = self.value_term(value)?;
        let definition = self.expressions().definition(value)?;
        Ok(matches!(definition, ExpressionDefinition::Expression(_))
            && !matches!(self.terms[term.0].kind, TermKind::Leaf(v) if v == value)
            && !matches!(self.constants.value(value)?, ConstantFact::Constant(_)))
    }

    /// The simplified view of one statement's operation. `Ok(None)` for
    /// resets, no-ops and SSA-unreachable statements.
    pub fn operation(&self, statement: StatementId) -> Result<Option<SimplifiedOperation<'_>>> {
        let executable = self.constants.is_statement_executable(statement)?;
        Ok(self
            .expressions()
            .operation(statement)
            .map(|source| SimplifiedOperation {
                source,
                executable,
                owner: self,
            }))
    }

    /// Every original operation in node/statement order.
    pub fn operations(&self) -> impl Iterator<Item = Result<SimplifiedOperation<'_>>> + '_ {
        self.expressions().operations().map(move |source| {
            Ok(SimplifiedOperation {
                source,
                executable: self.constants.is_statement_executable(source.statement)?,
                owner: self,
            })
        })
    }

    pub fn refused_folds(&self) -> &[RefusedFold] {
        &self.refused
    }

    /// Final constant-propagation faults with their canonical terms.
    pub fn faults(&self) -> &[SimplifiedFault] {
        &self.faults
    }

    fn mapped(&self, node: ExpressionId) -> Option<TermId> {
        self.node_terms
            .get(node.0)
            .filter(|&&slot| slot != NONE)
            .map(|&slot| TermId(slot))
    }
}

const NONE: usize = usize::MAX;
const BUSY: usize = usize::MAX - 1;
/// Local rewrites that build further terms nest at most this deep. The
/// traversal of the input graph itself is iterative.
const MAX_DEPTH: u32 = 8;

fn words(bytes: u32) -> usize {
    (bytes as usize).div_ceil(8)
}

/// The constant-propagation cost formula for one `evaluate_pure` call,
/// charged before evaluation.
fn evaluation_cost(opcode: Opcode, inputs: &[u32], output: u32) -> usize {
    use Opcode::*;
    const FLOAT: usize = 256;
    let linear: usize = inputs.iter().map(|&size| words(size)).sum::<usize>() + words(output);
    let width = |index: usize| inputs.get(index).map_or(1, |&size| words(size) + 1);
    4 + 2 * linear
        + match opcode {
            IntMult => width(0) * width(1),
            Ptradd => width(0) + width(1) * width(2),
            IntDiv | IntRem | IntSdiv | IntSrem => 2 * width(0) * width(1),
            FloatInt2Float => FLOAT + 8 * width(0) * width(0),
            FloatEqual | FloatNotequal | FloatLess | FloatLessequal | FloatNan | FloatAdd
            | FloatDiv | FloatMult | FloatSub | FloatNeg | FloatAbs | FloatSqrt
            | FloatFloat2Float | FloatTrunc | FloatCeil | FloatFloor | FloatRound => FLOAT,
            _ => 0,
        }
}

/// Whether `evaluate_pure` accepts this opcode and shape for every input
/// value. Mirrors its width checks; division, floating point and bit-range
/// operations can fail for some values and are excluded.
fn total_shape(opcode: Opcode, inputs: &[u32], output: u32) -> bool {
    use Opcode::*;
    let same = |n: usize| inputs.len() == n && inputs.iter().all(|&w| w == output);
    match opcode {
        Copy | Cast | Int2Comp | IntNegate => same(1),
        IntZext | IntSext => inputs.len() == 1 && output > inputs[0],
        BoolNegate => same(1) && output == 1,
        Popcount | Lzcount => inputs.len() == 1,
        IntEqual | IntNotequal | IntSless | IntSlessequal | IntLess | IntLessequal | IntCarry
        | IntScarry | IntSborrow => inputs.len() == 2 && output == 1 && inputs[0] == inputs[1],
        IntAdd | IntSub | IntXor | IntAnd | IntOr | IntMult => same(2),
        IntLeft | IntRight | IntSright | Ptrsub => inputs.len() == 2 && inputs[0] == output,
        BoolXor | BoolAnd | BoolOr => same(2) && output == 1,
        Piece => inputs.len() == 2 && inputs[0].checked_add(inputs[1]) == Some(output),
        Subpiece => inputs.len() == 2 && output <= inputs[0],
        Ptradd => inputs.len() == 3 && inputs[0] == output,
        _ => false,
    }
}

fn commutative(opcode: Opcode) -> bool {
    use Opcode::*;
    matches!(
        opcode,
        IntAdd
            | IntMult
            | IntAnd
            | IntOr
            | IntXor
            | IntEqual
            | IntNotequal
            | IntCarry
            | IntScarry
            | BoolAnd
            | BoolOr
            | BoolXor
    )
}

fn comparison(opcode: Opcode) -> bool {
    use Opcode::*;
    matches!(
        opcode,
        IntEqual
            | IntNotequal
            | IntSless
            | IntSlessequal
            | IntLess
            | IntLessequal
            | IntCarry
            | IntScarry
            | IntSborrow
    )
}

/// The comparison equal to `BOOL_NEGATE` of `opcode`, and whether its
/// operands swap.
fn negated(opcode: Opcode) -> Option<(Opcode, bool)> {
    use Opcode::*;
    Some(match opcode {
        IntEqual => (IntNotequal, false),
        IntNotequal => (IntEqual, false),
        IntLess => (IntLessequal, true),
        IntLessequal => (IntLess, true),
        IntSless => (IntSlessequal, true),
        IntSlessequal => (IntSless, true),
        _ => return None,
    })
}

fn is_zero(value: &Value) -> bool {
    value.bits().bits() == 0
}
fn is_one(value: &Value) -> bool {
    value.to_u64() == Some(1)
}
fn is_ones(value: &Value) -> bool {
    value.bits().count_ones() == u64::from(value.size()) * 8
}

/// Deterministic FNV-1a, independent of the process's hash seed.
struct Fnv(u64);
impl Fnv {
    fn new() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }
    fn word(&mut self, word: u64) {
        for byte in word.to_le_bytes() {
            self.0 ^= u64::from(byte);
            self.0 = self.0.wrapping_mul(0x0000_0100_0000_01b3);
        }
    }
}

/// A structural term key borrowed from the caller.
enum Key<'k> {
    Literal(&'k Value),
    Join(&'k [TermPiece]),
    Extract(TermId, u32),
    Apply(Opcode, &'k [TermId]),
}

impl Key<'_> {
    /// Hash and the number of 64-bit words hashed.
    fn hash(&self, ty: ExpressionType) -> (u64, usize) {
        let mut hash = Fnv::new();
        match ty {
            ExpressionType::Bits(size) => hash.word(u64::from(size)),
            ExpressionType::Memory(space) => hash.word((1 << 32) | u64::from(space.0)),
        }
        let words = match self {
            Self::Literal(value) => {
                hash.word(1);
                hash.word(u64::from(value.size()));
                let mut count = 0;
                for digit in value.bits().iter_u64_digits() {
                    hash.word(digit);
                    count += 1;
                }
                count + 3
            }
            Self::Join(pieces) => {
                hash.word(2);
                hash.word(pieces.len() as u64);
                for piece in *pieces {
                    hash.word(piece.term.0 as u64);
                    hash.word((u64::from(piece.lsb_byte) << 32) | u64::from(piece.size));
                }
                2 * pieces.len() + 3
            }
            Self::Extract(term, lsb) => {
                hash.word(3);
                hash.word(term.0 as u64);
                hash.word(u64::from(*lsb));
                4
            }
            Self::Apply(opcode, inputs) => {
                hash.word(4);
                hash.word(*opcode as u64);
                hash.word(inputs.len() as u64);
                for input in *inputs {
                    hash.word(input.0 as u64);
                }
                inputs.len() + 4
            }
        };
        (hash.0, words)
    }

    fn compare_cost(&self) -> usize {
        match self {
            Self::Literal(value) => words(value.size()) + 1,
            Self::Join(pieces) => 3 * pieces.len() + 1,
            Self::Extract(..) => 2,
            Self::Apply(_, inputs) => inputs.len() + 1,
        }
    }

    fn matches(&self, kind: &TermKind) -> bool {
        match (self, kind) {
            (Self::Literal(a), TermKind::Literal(b)) => *a == b,
            (Self::Join(a), TermKind::Join(b)) => *a == b.as_slice(),
            (Self::Extract(term, lsb), TermKind::Extract { term: t, lsb_byte }) => {
                term == t && lsb == lsb_byte
            }
            (Self::Apply(op, a), TermKind::Apply { opcode, inputs }) => {
                op == opcode && *a == inputs.as_slice()
            }
            _ => false,
        }
    }

    fn inputs(&self) -> usize {
        match self {
            Self::Literal(_) => 0,
            Self::Join(pieces) => pieces.len(),
            Self::Extract(..) => 1,
            Self::Apply(_, inputs) => inputs.len(),
        }
    }

    fn owned(&self) -> TermKind {
        match self {
            Self::Literal(value) => TermKind::Literal((*value).clone()),
            Self::Join(pieces) => TermKind::Join(pieces.to_vec()),
            Self::Extract(term, lsb) => TermKind::Extract {
                term: *term,
                lsb_byte: *lsb,
            },
            Self::Apply(opcode, inputs) => TermKind::Apply {
                opcode: *opcode,
                inputs: inputs.to_vec(),
            },
        }
    }
}

#[derive(Clone, Copy)]
enum Task {
    Node {
        node: ExpressionId,
        statement: StatementId,
    },
    Value(ValueId),
}

#[derive(Clone, Copy)]
struct Frame {
    task: Task,
    expanded: bool,
}

#[derive(Clone, Copy)]
struct Ctx {
    origin: TermOrigin,
    statement: Option<StatementId>,
}

struct Output {
    terms: Vec<Term>,
    node_terms: Vec<usize>,
    value_terms: Vec<usize>,
    refused: Vec<RefusedFold>,
    faults: Vec<SimplifiedFault>,
    stats: SimplifyStats,
}

struct Builder<'a> {
    constants: &'a PcodeConstants,
    program: &'a PcodeExpressions,
    analysis: &'a PcodeSsa,
    limits: SimplifyLimits,
    work: u64,
    terms: Vec<Term>,
    /// Next term in the same hash bucket, or `NONE`.
    chain: Vec<usize>,
    /// Bucket heads. Only looked up, never iterated, so IDs do not depend on
    /// the map's hash seed.
    table: HashMap<u64, usize>,
    node_terms: Vec<usize>,
    value_terms: Vec<usize>,
    stack: Vec<Frame>,
    refused: Vec<RefusedFold>,
    stats: SimplifyStats,
}

impl<'a> Builder<'a> {
    fn run(constants: &'a PcodeConstants, limits: SimplifyLimits) -> Result<Output> {
        let program: &PcodeExpressions = constants.expressions();
        let analysis: &PcodeSsa = program.analysis();
        let ssa = analysis.ssa();
        let value_count = ssa.values().len();
        let node_count = program.nodes().len();
        if value_count > limits.max_values {
            return Err(SimplifyError::Limit("values"));
        }
        if node_count > limits.max_expression_nodes {
            return Err(SimplifyError::Limit("expression nodes"));
        }
        let mut builder = Builder {
            constants,
            program,
            analysis,
            limits,
            work: 0,
            terms: Vec::new(),
            chain: Vec::new(),
            table: HashMap::new(),
            node_terms: Vec::new(),
            value_terms: Vec::new(),
            stack: Vec::new(),
            refused: Vec::new(),
            stats: SimplifyStats::default(),
        };
        let mut statements = 0usize;
        for block in ssa.blocks() {
            builder.charge(1)?;
            if let Some(block) = block.renamed() {
                statements = statements
                    .checked_add(block.statements().len())
                    .filter(|&n| n <= limits.max_statements)
                    .ok_or(SimplifyError::Limit("statements"))?;
            }
        }
        let slots = node_count
            .checked_add(value_count)
            .ok_or(SimplifyError::Limit("work"))?;
        builder.charge(slots)?;
        builder.node_terms = vec![NONE; node_count];
        builder.value_terms = vec![NONE; value_count];
        builder.statements()?;
        for value in 0..value_count {
            builder.charge(1)?;
            if builder.value_terms[value] == NONE {
                builder.traverse(Task::Value(ValueId(value)))?;
            }
        }
        // SSA leaves are value references, so each maps to its value's term
        // even when only unexecuted statements use it.
        for (index, node) in program.nodes().iter().enumerate() {
            builder.charge(1)?;
            if let ExpressionKind::SsaValue(value) = node.kind
                && builder.node_terms[index] == NONE
            {
                builder.node_terms[index] = *builder
                    .value_terms
                    .get(value.0)
                    .ok_or(SimplifyError::UnknownValue(value))?;
            }
        }
        builder.finish()
    }

    fn charge(&mut self, amount: usize) -> Result<()> {
        self.work = u64::try_from(amount)
            .ok()
            .and_then(|amount| self.work.checked_add(amount))
            .filter(|&work| work <= self.limits.max_work)
            .ok_or(SimplifyError::Limit("work"))?;
        Ok(())
    }

    fn count(&mut self, rule: Rule) {
        self.stats.rules[rule as usize] += 1;
    }

    /// Canonicalize every term of every executed statement, in node and
    /// statement order: operands, the complete result, then definitions.
    fn statements(&mut self) -> Result<()> {
        let constants = self.constants;
        let program = self.program;
        let ssa = self.analysis.ssa();
        for node in 0..ssa.graph().node_count() {
            self.charge(1)?;
            if !constants.is_node_executable(node)? {
                continue;
            }
            let block = ssa
                .block(node)
                .map_err(|_| SimplifyError::Inconsistent("SSA block"))?
                .renamed()
                .ok_or(SimplifyError::Inconsistent(
                    "executable node is SSA-unreachable",
                ))?;
            for index in 0..block.statements().len() {
                self.charge(1)?;
                self.stats.executed_statements += 1;
                let statement = StatementId { node, index };
                let Some(operation) = program.operation(statement) else {
                    continue;
                };
                for operand in &operation.operands {
                    self.charge(1)?;
                    if let Some(node) = operand.expression() {
                        self.traverse(Task::Node { node, statement })?;
                    }
                }
                if let Some(node) = operation.output {
                    self.traverse(Task::Node { node, statement })?;
                }
                for &value in block.statements()[index].defs() {
                    self.charge(1)?;
                    if let ExpressionDefinition::Expression(root) = program.definition(value)? {
                        self.traverse(Task::Node {
                            node: *root,
                            statement,
                        })?;
                    }
                }
            }
        }
        Ok(())
    }

    fn node_slot(&self, node: ExpressionId) -> Result<usize> {
        self.node_terms
            .get(node.0)
            .copied()
            .ok_or(SimplifyError::UnknownExpression(node))
    }

    fn value_slot(&self, value: ValueId) -> Result<usize> {
        self.value_terms
            .get(value.0)
            .copied()
            .ok_or(SimplifyError::UnknownValue(value))
    }

    fn done(slot: usize) -> bool {
        slot != NONE && slot != BUSY
    }

    fn push(&mut self, task: Task, expanded: bool) -> Result<()> {
        if self.stack.len() >= self.limits.max_live {
            return Err(SimplifyError::Limit("live"));
        }
        self.charge(1)?;
        self.stack.push(Frame { task, expanded });
        self.stats.live_peak = self.stats.live_peak.max(self.stack.len());
        Ok(())
    }

    /// Iterative post-order traversal. A node finishes after its children; a
    /// value finishes after its definition root, which may belong to any
    /// executed statement, including one later in node order. Phi, entry,
    /// reset and opaque values are leaves, so a dependency cycle means
    /// malformed input.
    fn traverse(&mut self, task: Task) -> Result<()> {
        let slot = match task {
            Task::Node { node, .. } => self.node_slot(node)?,
            Task::Value(value) => self.value_slot(value)?,
        };
        if Self::done(slot) {
            return Ok(());
        }
        self.push(task, false)?;
        while let Some(frame) = self.stack.pop() {
            self.charge(1)?;
            match frame.task {
                Task::Node { node, statement } => self.node(node, statement, frame.expanded)?,
                Task::Value(value) => self.value(value, frame.expanded)?,
            }
        }
        Ok(())
    }

    fn node(&mut self, id: ExpressionId, statement: StatementId, expanded: bool) -> Result<()> {
        let slot = self.node_slot(id)?;
        if Self::done(slot) {
            return Ok(());
        }
        let program = self.program;
        let node = program.node(id)?;
        let ctx = Ctx {
            origin: TermOrigin::Node(id),
            statement: Some(statement),
        };
        if !expanded {
            if slot == BUSY {
                return Err(SimplifyError::Inconsistent("expression dependency cycle"));
            }
            match &node.kind {
                ExpressionKind::Constant(value) => {
                    let term = self.literal(value, ctx, None)?;
                    return self.set_node(id, term);
                }
                ExpressionKind::SsaValue(value) => {
                    let value_slot = self.value_slot(*value)?;
                    if Self::done(value_slot) {
                        return self.set_node(id, TermId(value_slot));
                    }
                    self.node_terms[id.0] = BUSY;
                    self.push(
                        Task::Node {
                            node: id,
                            statement,
                        },
                        true,
                    )?;
                    return self.push(Task::Value(*value), false);
                }
                _ => {}
            }
            self.node_terms[id.0] = BUSY;
            self.push(
                Task::Node {
                    node: id,
                    statement,
                },
                true,
            )?;
            let mut children = [ExpressionId(0); 2];
            let list: &[ExpressionId] = match &node.kind {
                ExpressionKind::Pure { inputs, .. } => inputs,
                ExpressionKind::Extract { value, .. } => {
                    children[0] = *value;
                    &children[..1]
                }
                ExpressionKind::ReadMemory { address, .. } => match address {
                    ExpressionAddress::Pointer { value, .. } => {
                        children[0] = *value;
                        &children[..1]
                    }
                    ExpressionAddress::ByteOffset(_) => &[],
                },
                ExpressionKind::WriteMemory { address, value, .. } => {
                    children[0] = *value;
                    match address {
                        ExpressionAddress::Pointer { value, .. } => {
                            children[1] = *value;
                            &children[..2]
                        }
                        ExpressionAddress::ByteOffset(_) => &children[..1],
                    }
                }
                ExpressionKind::Join(pieces) => {
                    // Pieces are pushed below in reverse, like other inputs.
                    for piece in pieces.iter().rev() {
                        self.child(id, piece.value, statement)?;
                    }
                    return Ok(());
                }
                ExpressionKind::Constant(_) | ExpressionKind::SsaValue(_) => &[],
            };
            for &child in list.iter().rev() {
                self.child(id, child, statement)?;
            }
            return Ok(());
        }
        let term = self.translate(id, node.ty, &node.kind, ctx)?;
        self.set_node(id, term)
    }

    fn child(
        &mut self,
        parent: ExpressionId,
        child: ExpressionId,
        statement: StatementId,
    ) -> Result<()> {
        self.charge(1)?;
        if child.0 >= parent.0 {
            return Err(SimplifyError::Inconsistent("expression edge order"));
        }
        match self.node_slot(child)? {
            BUSY => Err(SimplifyError::Inconsistent("expression dependency cycle")),
            NONE => self.push(
                Task::Node {
                    node: child,
                    statement,
                },
                false,
            ),
            _ => Ok(()),
        }
    }

    fn value(&mut self, value: ValueId, expanded: bool) -> Result<()> {
        let slot = self.value_slot(value)?;
        if Self::done(slot) {
            return Ok(());
        }
        let program = self.program;
        let root = match program.definition(value)? {
            ExpressionDefinition::Expression(root) => Some(*root),
            _ => None,
        };
        if expanded {
            let root = root.ok_or(SimplifyError::Inconsistent("expanded value definition"))?;
            return self.finish_value(value, root);
        }
        if slot == BUSY {
            return Err(SimplifyError::Inconsistent("SSA definition cycle"));
        }
        let ctx = Ctx {
            origin: TermOrigin::Value(value),
            statement: None,
        };
        match self.constants.value(value)? {
            ConstantFact::Constant(constant) => {
                let term = self.literal(constant, ctx, Some(Rule::ConstantFact))?;
                self.count(Rule::ConstantFact);
                self.stats.literal_values += 1;
                self.value_terms[value.0] = term.0;
                return Ok(());
            }
            // An unreached value is never turned into a literal or result.
            ConstantFact::Unreached => return self.leaf(value),
            ConstantFact::Unknown => {}
        }
        let Some(root) = root else {
            return self.leaf(value);
        };
        if !matches!(program.value_type(value)?, ExpressionType::Bits(_)) {
            return self.leaf(value);
        }
        let ValueOrigin::Definition(site) = self
            .analysis
            .ssa()
            .value(value)
            .map_err(|_| SimplifyError::UnknownValue(value))?
            .origin
        else {
            return Err(SimplifyError::Inconsistent("expression value origin"));
        };
        if !self.constants.is_statement_executable(site.statement)? {
            return Err(SimplifyError::Inconsistent(
                "unknown value defined by an unexecuted statement",
            ));
        }
        if Self::done(self.node_slot(root)?) {
            return self.finish_value(value, root);
        }
        self.value_terms[value.0] = BUSY;
        self.push(Task::Value(value), true)?;
        self.push(
            Task::Node {
                node: root,
                statement: site.statement,
            },
            false,
        )
    }

    /// Uses receive the definition's term unless it may fault or reads
    /// memory; then they keep the value's own SSA leaf.
    fn finish_value(&mut self, value: ValueId, root: ExpressionId) -> Result<()> {
        let slot = self.node_slot(root)?;
        if !Self::done(slot) {
            return Err(SimplifyError::Inconsistent("unfinished definition root"));
        }
        let term = &self.terms[slot];
        if matches!(term.ty, ExpressionType::Bits(_)) && !term.may_fault() && !term.reads_memory {
            self.count(Rule::Propagate);
            self.stats.propagated_values += 1;
            self.value_terms[value.0] = slot;
            Ok(())
        } else {
            self.value_terms[value.0] = NONE;
            self.leaf(value)
        }
    }

    fn set_node(&mut self, node: ExpressionId, term: TermId) -> Result<()> {
        self.node_terms[node.0] = term.0;
        self.stats.canonical_nodes += 1;
        let kind = &self.program.node(node)?.kind;
        let literal = matches!(self.terms[term.0].kind, TermKind::Literal(_));
        // Constant facts are an oracle: a constant term must canonicalize to
        // exactly that literal.
        match self.constants.expression(node)? {
            ConstantFact::Constant(expected) => {
                self.charge(words(expected.size()) + 1)?;
                match &self.terms[term.0].kind {
                    TermKind::Literal(actual) if actual == expected => {}
                    _ => {
                        return Err(SimplifyError::Inconsistent(
                            "canonical term disagrees with a constant fact",
                        ));
                    }
                }
                if !matches!(kind, ExpressionKind::Constant(_)) {
                    self.stats.literal_nodes += 1;
                }
            }
            _ if literal && !matches!(kind, ExpressionKind::Constant(_)) => {
                self.stats.literal_nodes += 1;
                self.stats.literals_beyond_constants += 1;
            }
            _ => {}
        }
        Ok(())
    }

    fn term_of(&self, node: ExpressionId) -> Result<TermId> {
        let slot = self.node_slot(node)?;
        if !Self::done(slot) {
            return Err(SimplifyError::Inconsistent("unfinished child term"));
        }
        Ok(TermId(slot))
    }

    fn width(&self, term: TermId) -> Result<u32> {
        match self.terms[term.0].ty {
            ExpressionType::Bits(size) => Ok(size),
            ExpressionType::Memory(_) => Err(SimplifyError::Inconsistent("memory-typed operand")),
        }
    }

    fn literal_of(&self, term: TermId) -> Option<&Value> {
        match &self.terms[term.0].kind {
            TermKind::Literal(value) => Some(value),
            _ => None,
        }
    }

    fn address(&self, address: &ExpressionAddress) -> Result<TermAddress> {
        Ok(match *address {
            ExpressionAddress::ByteOffset(offset) => TermAddress::ByteOffset(offset),
            ExpressionAddress::Pointer {
                value,
                word_size,
                address_size,
            } => TermAddress::Pointer {
                term: self.term_of(value)?,
                word_size,
                address_size,
            },
        })
    }

    /// The canonical term of one original node whose children are done.
    fn translate(
        &mut self,
        id: ExpressionId,
        ty: ExpressionType,
        kind: &ExpressionKind,
        ctx: Ctx,
    ) -> Result<TermId> {
        match kind {
            ExpressionKind::SsaValue(value) => {
                let slot = self.value_slot(*value)?;
                if !Self::done(slot) {
                    return Err(SimplifyError::Inconsistent("unfinished SSA leaf"));
                }
                Ok(TermId(slot))
            }
            ExpressionKind::Constant(value) => self.literal(value, ctx, None),
            ExpressionKind::Join(pieces) => {
                let ExpressionType::Bits(total) = ty else {
                    return Err(SimplifyError::Inconsistent("memory-typed join"));
                };
                self.charge(pieces.len())?;
                let mut out = Vec::with_capacity(pieces.len());
                for piece in pieces {
                    out.push(TermPiece {
                        term: self.term_of(piece.value)?,
                        lsb_byte: piece.lsb_byte,
                        size: piece.size,
                    });
                }
                self.join(out, total, ctx, None, 0)
            }
            ExpressionKind::Extract { value, lsb_byte } => {
                let ExpressionType::Bits(size) = ty else {
                    return Err(SimplifyError::Inconsistent("memory-typed extract"));
                };
                let source = self.term_of(*value)?;
                self.extract(source, *lsb_byte, size, ctx, None, 0)
            }
            ExpressionKind::Pure { opcode, inputs } => {
                let ExpressionType::Bits(size) = ty else {
                    return Err(SimplifyError::Inconsistent("memory-typed application"));
                };
                self.charge(inputs.len())?;
                let mut terms = Vec::with_capacity(inputs.len());
                for &input in inputs {
                    terms.push(self.term_of(input)?);
                }
                self.apply(*opcode, terms, size, ctx, None, 0)
            }
            ExpressionKind::ReadMemory {
                space,
                version,
                address,
                endianness,
            } => {
                let address = self.address(address)?;
                self.distinct(
                    ty,
                    TermKind::ReadMemory {
                        node: id,
                        space: *space,
                        version: *version,
                        address,
                        endianness: *endianness,
                    },
                    ctx,
                    None,
                )
            }
            ExpressionKind::WriteMemory {
                space,
                version,
                address,
                value,
                endianness,
            } => {
                let address = self.address(address)?;
                let value = self.term_of(*value)?;
                self.distinct(
                    ty,
                    TermKind::WriteMemory {
                        node: id,
                        space: *space,
                        version: *version,
                        address,
                        value,
                        endianness: *endianness,
                    },
                    ctx,
                    None,
                )
            }
        }
    }

    // ------------------------------------------------------------------
    // Term construction

    fn reserve(&mut self, inputs: usize, bytes: usize) -> Result<()> {
        if self.terms.len() >= self.limits.max_terms {
            return Err(SimplifyError::Limit("terms"));
        }
        let inputs_total = self
            .stats
            .term_inputs
            .checked_add(inputs)
            .filter(|&n| n <= self.limits.max_term_inputs)
            .ok_or(SimplifyError::Limit("term inputs"))?;
        let bytes_total = self
            .stats
            .literal_bytes
            .checked_add(bytes)
            .filter(|&n| n <= self.limits.max_literal_bytes)
            .ok_or(SimplifyError::Limit("literal bytes"))?;
        self.charge(
            1usize
                .checked_add(inputs)
                .and_then(|n| n.checked_add(bytes))
                .ok_or(SimplifyError::Limit("work"))?,
        )?;
        self.stats.term_inputs = inputs_total;
        self.stats.literal_bytes = bytes_total;
        Ok(())
    }

    fn store(&mut self, term: Term, next: usize) -> TermId {
        match term.kind {
            TermKind::Literal(_) => self.stats.literal_terms += 1,
            TermKind::Leaf(_) => self.stats.leaf_terms += 1,
            _ => {}
        }
        if term.identity() == TermIdentity::Distinct {
            self.stats.distinct_terms += 1;
        }
        self.terms.push(term);
        self.chain.push(next);
        TermId(self.terms.len() - 1)
    }

    fn leaf(&mut self, value: ValueId) -> Result<()> {
        let ty = self.program.value_type(value)?;
        self.reserve(0, 0)?;
        let term = self.store(
            Term {
                ty,
                kind: TermKind::Leaf(value),
                fault: TermFault::None,
                reads_memory: false,
                boolean: false,
                origin: TermOrigin::Value(value),
                rule: None,
            },
            NONE,
        );
        self.stats.leaf_values += 1;
        self.value_terms[value.0] = term.0;
        Ok(())
    }

    fn child_flags(&self, children: impl Iterator<Item = TermId>) -> (TermFault, bool) {
        let mut fault = TermFault::None;
        let mut reads = false;
        for child in children {
            let term = &self.terms[child.0];
            if term.may_fault() {
                fault = TermFault::Subterm;
            }
            reads |= term.reads_memory;
        }
        (fault, reads)
    }

    /// A term never shared with another: memory accesses and applications
    /// that may fault.
    fn distinct(
        &mut self,
        ty: ExpressionType,
        kind: TermKind,
        ctx: Ctx,
        rule: Option<Rule>,
    ) -> Result<TermId> {
        let (inputs, reads) = match &kind {
            TermKind::Apply { inputs, .. } => (inputs.len(), false),
            TermKind::ReadMemory { address, .. } => (
                usize::from(matches!(address, TermAddress::Pointer { .. })),
                true,
            ),
            TermKind::WriteMemory { address, .. } => (
                1 + usize::from(matches!(address, TermAddress::Pointer { .. })),
                false,
            ),
            _ => return Err(SimplifyError::Inconsistent("distinct term kind")),
        };
        self.reserve(inputs, 0)?;
        let (_, child_reads) = match &kind {
            TermKind::Apply { inputs, .. } => self.child_flags(inputs.iter().copied()),
            TermKind::ReadMemory { address, .. } => self.child_flags(pointer(address).into_iter()),
            TermKind::WriteMemory { address, value, .. } => {
                self.child_flags(pointer(address).into_iter().chain([*value]))
            }
            _ => (TermFault::None, false),
        };
        Ok(self.store(
            Term {
                ty,
                kind,
                fault: TermFault::Here,
                reads_memory: reads || child_reads,
                boolean: false,
                origin: ctx.origin,
                rule,
            },
            NONE,
        ))
    }

    /// Find or create a structural term.
    fn cons(
        &mut self,
        ty: ExpressionType,
        key: Key<'_>,
        ctx: Ctx,
        rule: Option<Rule>,
    ) -> Result<TermId> {
        let (hash, hashed) = key.hash(ty);
        self.charge(hashed + 2)?;
        let mut cursor = self.table.get(&hash).copied().unwrap_or(NONE);
        while cursor != NONE {
            self.charge(key.compare_cost())?;
            let candidate = &self.terms[cursor];
            if candidate.ty == ty && key.matches(&candidate.kind) {
                if !matches!(key, Key::Literal(_)) {
                    self.stats.shared_terms += 1;
                }
                return Ok(TermId(cursor));
            }
            cursor = self.chain[cursor];
        }
        let bytes = match key {
            Key::Literal(value) => value.size() as usize,
            _ => 0,
        };
        self.reserve(key.inputs(), bytes)?;
        let (fault, reads, boolean) = match &key {
            Key::Literal(value) => (
                TermFault::None,
                false,
                value.size() == 1 && value.to_u64().is_some_and(|v| v <= 1),
            ),
            Key::Join(pieces) => {
                let (fault, reads) = self.child_flags(pieces.iter().map(|p| p.term));
                (fault, reads, false)
            }
            Key::Extract(term, _) => {
                let (fault, reads) = self.child_flags([*term].into_iter());
                (fault, reads, false)
            }
            Key::Apply(opcode, inputs) => {
                let (fault, reads) = self.child_flags(inputs.iter().copied());
                let all_boolean = inputs.iter().all(|t| self.terms[t.0].boolean);
                let boolean = comparison(*opcode)
                    || (matches!(
                        opcode,
                        Opcode::BoolNegate | Opcode::BoolAnd | Opcode::BoolOr | Opcode::BoolXor
                    ) && all_boolean);
                (fault, reads, boolean)
            }
        };
        let head = self.table.get(&hash).copied().unwrap_or(NONE);
        let id = self.store(
            Term {
                ty,
                kind: key.owned(),
                fault,
                reads_memory: reads,
                boolean,
                origin: ctx.origin,
                rule,
            },
            head,
        );
        self.table.insert(hash, id.0);
        Ok(id)
    }

    fn literal(&mut self, value: &Value, ctx: Ctx, rule: Option<Rule>) -> Result<TermId> {
        self.cons(
            ExpressionType::Bits(value.size()),
            Key::Literal(value),
            ctx,
            rule,
        )
    }

    fn refuse(
        &mut self,
        term: TermId,
        ctx: Ctx,
        opcode: Opcode,
        error: ghidra_pcode::Error,
    ) -> Result<()> {
        let (TermOrigin::Node(node), Some(statement)) = (ctx.origin, ctx.statement) else {
            return Err(SimplifyError::Inconsistent(
                "refused fold without a source node",
            ));
        };
        self.charge(1)?;
        self.stats.refused_folds += 1;
        self.refused.push(RefusedFold {
            term,
            node,
            statement,
            opcode,
            error: Arc::new(error),
        });
        Ok(())
    }

    /// Evaluate an application of literals, charged before evaluation. The
    /// argument copies are transient and bounded by 512 bytes each.
    fn evaluate(
        &mut self,
        opcode: Opcode,
        inputs: &[TermId],
        widths: &[u32],
        width: u32,
    ) -> Result<std::result::Result<Value, ghidra_pcode::Error>> {
        self.charge(evaluation_cost(opcode, widths, width))?;
        let mut arguments = Vec::with_capacity(inputs.len());
        for &input in inputs {
            arguments.push(
                self.literal_of(input)
                    .ok_or(SimplifyError::Inconsistent("literal argument"))?
                    .clone(),
            );
        }
        self.stats.evaluations += 1;
        Ok(evaluate_pure(opcode, &arguments, width))
    }

    /// A literal computed by an operation that cannot fail at this shape.
    fn total_literal(
        &mut self,
        opcode: Opcode,
        inputs: &[TermId],
        width: u32,
        ctx: Ctx,
        rule: Rule,
    ) -> Result<TermId> {
        let mut widths = Vec::with_capacity(inputs.len());
        for &input in inputs {
            widths.push(self.width(input)?);
        }
        let value = self.evaluate(opcode, inputs, &widths, width)??;
        if value.size() != width {
            return Err(SimplifyError::Inconsistent("evaluated width"));
        }
        self.literal(&value, ctx, Some(rule))
    }

    fn apply(
        &mut self,
        opcode: Opcode,
        mut inputs: Vec<TermId>,
        width: u32,
        ctx: Ctx,
        mut rule: Option<Rule>,
        depth: u32,
    ) -> Result<TermId> {
        self.charge(1 + inputs.len())?;
        let mut widths = Vec::with_capacity(inputs.len());
        for &input in &inputs {
            widths.push(self.width(input)?);
        }
        if !inputs.is_empty() && inputs.iter().all(|&t| self.literal_of(t).is_some()) {
            return match self.evaluate(opcode, &inputs, &widths, width)? {
                Ok(value) if value.size() == width => {
                    self.count(Rule::LiteralFold);
                    self.literal(&value, ctx, Some(rule.unwrap_or(Rule::LiteralFold)))
                }
                Ok(_) => Err(SimplifyError::Inconsistent("evaluated width")),
                Err(error) => {
                    let term = self.distinct(
                        ExpressionType::Bits(width),
                        TermKind::Apply { opcode, inputs },
                        ctx,
                        rule,
                    )?;
                    self.refuse(term, ctx, opcode, error)?;
                    Ok(term)
                }
            };
        }
        if !total_shape(opcode, &widths, width) {
            return self.distinct(
                ExpressionType::Bits(width),
                TermKind::Apply { opcode, inputs },
                ctx,
                rule,
            );
        }
        if depth < MAX_DEPTH
            && let Some(term) =
                self.rewrite(opcode, &mut inputs, &widths, width, ctx, &mut rule, depth)?
        {
            return Ok(term);
        }
        self.cons(
            ExpressionType::Bits(width),
            Key::Apply(opcode, &inputs),
            ctx,
            rule,
        )
    }

    /// Exact rewrites of a total, shape-checked application. `Some` is the
    /// rewritten term; `None` keeps the application (possibly commuted).
    #[allow(clippy::too_many_arguments)]
    fn rewrite(
        &mut self,
        opcode: Opcode,
        inputs: &mut [TermId],
        widths: &[u32],
        width: u32,
        ctx: Ctx,
        rule: &mut Option<Rule>,
        depth: u32,
    ) -> Result<Option<TermId>> {
        use Opcode::*;
        let next = depth + 1;
        let inner = |builder: &Self, term: TermId| match &builder.terms[term.0] {
            Term {
                kind: TermKind::Apply { opcode, inputs },
                fault,
                ..
            } if *fault != TermFault::Here => Some((*opcode, inputs.clone())),
            _ => None,
        };
        match opcode {
            Copy | Cast => {
                self.count(Rule::CopyCast);
                return Ok(Some(inputs[0]));
            }
            Subpiece => {
                if let Some(offset) = self.literal_of(inputs[1]).and_then(Value::to_u64)
                    && offset
                        .checked_add(u64::from(width))
                        .is_some_and(|end| end <= u64::from(widths[0]))
                {
                    self.count(Rule::SubpieceExtract);
                    return self
                        .extract(
                            inputs[0],
                            offset as u32,
                            width,
                            ctx,
                            Some(Rule::SubpieceExtract),
                            next,
                        )
                        .map(Some);
                }
            }
            Piece => {
                self.count(Rule::PieceJoin);
                let pieces = vec![
                    TermPiece {
                        term: inputs[1],
                        lsb_byte: 0,
                        size: widths[1],
                    },
                    TermPiece {
                        term: inputs[0],
                        lsb_byte: widths[1],
                        size: widths[0],
                    },
                ];
                return self
                    .join(pieces, width, ctx, Some(Rule::PieceJoin), next)
                    .map(Some);
            }
            IntZext => {
                if let Some((IntZext, inner_inputs)) = inner(self, inputs[0]) {
                    self.count(Rule::ZextCollapse);
                    return self
                        .apply(
                            IntZext,
                            inner_inputs,
                            width,
                            ctx,
                            Some(Rule::ZextCollapse),
                            next,
                        )
                        .map(Some);
                }
            }
            IntSub => {
                if self.literal_of(inputs[1]).is_some() {
                    let negative = self.total_literal(
                        Int2Comp,
                        &inputs[1..2],
                        width,
                        ctx,
                        Rule::SubtractConstant,
                    )?;
                    self.count(Rule::SubtractConstant);
                    return self
                        .apply(
                            IntAdd,
                            vec![inputs[0], negative],
                            width,
                            ctx,
                            Some(Rule::SubtractConstant),
                            next,
                        )
                        .map(Some);
                }
            }
            IntNegate | Int2Comp | BoolNegate => {
                if let Some((inner_opcode, inner_inputs)) = inner(self, inputs[0]) {
                    if inner_opcode == opcode {
                        self.count(Rule::Involution);
                        return Ok(Some(inner_inputs[0]));
                    }
                    if opcode == BoolNegate
                        && let Some((negation, swap)) = negated(inner_opcode)
                    {
                        let (a, b) = (inner_inputs[0], inner_inputs[1]);
                        self.count(Rule::NegatedComparison);
                        return self
                            .apply(
                                negation,
                                if swap { vec![b, a] } else { vec![a, b] },
                                1,
                                ctx,
                                Some(Rule::NegatedComparison),
                                next,
                            )
                            .map(Some);
                    }
                }
            }
            _ => {}
        }
        if commutative(opcode) && inputs.len() == 2 {
            let key = |builder: &Self, t: TermId| (builder.literal_of(t).is_some(), t);
            if key(self, inputs[0]) > key(self, inputs[1]) {
                inputs.swap(0, 1);
                self.count(Rule::Commute);
                rule.get_or_insert(Rule::Commute);
            }
        }
        if inputs.len() != 2 {
            return Ok(None);
        }
        let (x, y) = (inputs[0], inputs[1]);
        if let Some(c) = self.literal_of(y) {
            let identity = match opcode {
                IntAdd | IntOr | IntXor | IntLeft | IntRight | IntSright => is_zero(c),
                IntAnd => is_ones(c),
                IntMult => is_one(c),
                _ => false,
            };
            if identity {
                self.count(Rule::Identity);
                return Ok(Some(x));
            }
            let normalized = self.terms[x.0].boolean;
            let boolean = match opcode {
                BoolOr | BoolXor => is_zero(c),
                BoolAnd => is_ones(c) || (is_one(c) && normalized),
                IntNotequal => is_zero(c) && normalized,
                IntEqual => is_one(c) && normalized,
                _ => false,
            };
            if boolean {
                self.count(Rule::BooleanIdentity);
                return Ok(Some(x));
            }
            if matches!(opcode, IntAdd | IntMult | IntAnd | IntOr | IntXor)
                && let Some((inner_opcode, inner_inputs)) = inner(self, x)
                && inner_opcode == opcode
                && inner_inputs.len() == 2
                && self.literal_of(inner_inputs[1]).is_some()
            {
                let combined = self.total_literal(
                    opcode,
                    &[inner_inputs[1], y],
                    width,
                    ctx,
                    Rule::Reassociate,
                )?;
                self.count(Rule::Reassociate);
                return self
                    .apply(
                        opcode,
                        vec![inner_inputs[0], combined],
                        width,
                        ctx,
                        Some(Rule::Reassociate),
                        next,
                    )
                    .map(Some);
            }
        }
        if x == y && matches!(opcode, IntAnd | IntOr | BoolAnd | BoolOr) {
            self.count(Rule::Idempotent);
            return Ok(Some(x));
        }
        Ok(None)
    }

    fn extract(
        &mut self,
        source: TermId,
        lsb: u32,
        size: u32,
        ctx: Ctx,
        rule: Option<Rule>,
        depth: u32,
    ) -> Result<TermId> {
        let total = self.width(source)?;
        let end = lsb
            .checked_add(size)
            .filter(|&end| size > 0 && end <= total)
            .ok_or(SimplifyError::Inconsistent("extract range"))?;
        self.charge(1)?;
        if lsb == 0 && size == total {
            self.count(Rule::ExtractCollapse);
            return Ok(source);
        }
        if depth < MAX_DEPTH {
            let next = depth + 1;
            match &self.terms[source.0].kind {
                TermKind::Literal(value) => {
                    let bytes = value.to_le_bytes();
                    self.charge(total as usize + size as usize)?;
                    let slice = Value::from_le_bytes(&bytes[lsb as usize..end as usize])?;
                    self.count(Rule::ExtractCollapse);
                    return self.literal(&slice, ctx, Some(Rule::ExtractCollapse));
                }
                TermKind::Extract { term, lsb_byte } => {
                    let (term, base) = (*term, *lsb_byte);
                    self.count(Rule::ExtractCollapse);
                    let offset = base
                        .checked_add(lsb)
                        .ok_or(SimplifyError::Inconsistent("extract offset"))?;
                    return self.extract(
                        term,
                        offset,
                        size,
                        ctx,
                        Some(Rule::ExtractCollapse),
                        next,
                    );
                }
                TermKind::Join(pieces) => {
                    let pieces = pieces.clone();
                    self.charge(pieces.len())?;
                    if let Some(term) = self.extract_join(&pieces, lsb, size, ctx, next)? {
                        return Ok(term);
                    }
                }
                TermKind::Apply { opcode, inputs }
                    if matches!(opcode, Opcode::IntZext | Opcode::IntSext)
                        && inputs.len() == 1
                        && self.terms[source.0].fault != TermFault::Here =>
                {
                    let (opcode, inner) = (*opcode, inputs[0]);
                    let inner_size = self.width(inner)?;
                    if end <= inner_size {
                        self.count(Rule::ExtractExtension);
                        return self.extract(
                            inner,
                            lsb,
                            size,
                            ctx,
                            Some(Rule::ExtractExtension),
                            next,
                        );
                    }
                    // The low bytes of an extension, still wider than its
                    // input, are the same extension at that width.
                    if lsb == 0 {
                        self.count(Rule::ExtractExtension);
                        return self.apply(
                            opcode,
                            vec![inner],
                            size,
                            ctx,
                            Some(Rule::ExtractExtension),
                            next,
                        );
                    }
                    if opcode == Opcode::IntZext
                        && lsb >= inner_size
                        && !self.terms[inner.0].may_fault()
                    {
                        self.count(Rule::ExtractExtension);
                        return self.literal(
                            &Value::from_u64(size, 0)?,
                            ctx,
                            Some(Rule::ExtractExtension),
                        );
                    }
                }
                _ => {}
            }
        }
        self.cons(
            ExpressionType::Bits(size),
            Key::Extract(source, lsb),
            ctx,
            rule,
        )
    }

    /// The covered pieces of a join, unless that would discard a piece that
    /// may fault.
    fn extract_join(
        &mut self,
        pieces: &[TermPiece],
        lsb: u32,
        size: u32,
        ctx: Ctx,
        depth: u32,
    ) -> Result<Option<TermId>> {
        let end = lsb + size;
        let first = pieces
            .iter()
            .position(|p| p.lsb_byte + p.size > lsb)
            .ok_or(SimplifyError::Inconsistent("join coverage"))?;
        let last = pieces
            .iter()
            .rposition(|p| p.lsb_byte < end)
            .ok_or(SimplifyError::Inconsistent("join coverage"))?;
        let discards_fault = pieces
            .iter()
            .enumerate()
            .any(|(i, p)| (i < first || i > last) && self.terms[p.term.0].may_fault());
        if discards_fault {
            return Ok(None);
        }
        self.count(Rule::ExtractJoin);
        if first == last {
            let piece = pieces[first];
            return self
                .extract(
                    piece.term,
                    lsb - piece.lsb_byte,
                    size,
                    ctx,
                    Some(Rule::ExtractJoin),
                    depth,
                )
                .map(Some);
        }
        let mut sub = Vec::with_capacity(last - first + 1);
        for piece in &pieces[first..=last] {
            let start = lsb.max(piece.lsb_byte);
            let stop = end.min(piece.lsb_byte + piece.size);
            let term = self.extract(
                piece.term,
                start - piece.lsb_byte,
                stop - start,
                ctx,
                Some(Rule::ExtractJoin),
                depth,
            )?;
            sub.push(TermPiece {
                term,
                lsb_byte: start - lsb,
                size: stop - start,
            });
        }
        self.join(sub, size, ctx, Some(Rule::ExtractJoin), depth)
            .map(Some)
    }

    fn join(
        &mut self,
        pieces: Vec<TermPiece>,
        total: u32,
        ctx: Ctx,
        rule: Option<Rule>,
        depth: u32,
    ) -> Result<TermId> {
        self.charge(1 + pieces.len())?;
        let mut covered = 0u32;
        for piece in &pieces {
            if piece.lsb_byte != covered || piece.size == 0 || self.width(piece.term)? != piece.size
            {
                return Err(SimplifyError::Inconsistent("join pieces"));
            }
            covered = covered
                .checked_add(piece.size)
                .ok_or(SimplifyError::Inconsistent("join pieces"))?;
        }
        if covered != total || pieces.is_empty() {
            return Err(SimplifyError::Inconsistent("join coverage"));
        }
        if depth >= MAX_DEPTH {
            return self.cons_join(&pieces, total, ctx, rule);
        }
        let next = depth + 1;
        let mut flat = Vec::with_capacity(pieces.len());
        for piece in pieces {
            if let TermKind::Join(inner) = &self.terms[piece.term.0].kind {
                let inner = inner.clone();
                self.charge(inner.len())?;
                self.count(Rule::JoinFlatten);
                for part in inner {
                    flat.push(TermPiece {
                        term: part.term,
                        lsb_byte: piece.lsb_byte + part.lsb_byte,
                        size: part.size,
                    });
                }
            } else {
                flat.push(piece);
            }
        }
        let mut merged: Vec<TermPiece> = Vec::with_capacity(flat.len());
        for piece in flat {
            self.charge(1)?;
            if let Some(&last) = merged.last() {
                let size = last.size + piece.size;
                if let (Some(low), Some(high)) =
                    (self.literal_of(last.term), self.literal_of(piece.term))
                {
                    let mut bytes = low.to_le_bytes();
                    bytes.extend(high.to_le_bytes());
                    self.charge(size as usize)?;
                    let value = Value::from_le_bytes(&bytes)?;
                    let term = self.literal(&value, ctx, Some(Rule::JoinMerge))?;
                    self.count(Rule::JoinMerge);
                    *merged.last_mut().expect("nonempty") = TermPiece { term, ..last };
                    merged.last_mut().expect("nonempty").size = size;
                    continue;
                }
                if let (
                    TermKind::Extract {
                        term: a,
                        lsb_byte: ka,
                    },
                    TermKind::Extract {
                        term: b,
                        lsb_byte: kb,
                    },
                ) = (
                    &self.terms[last.term.0].kind,
                    &self.terms[piece.term.0].kind,
                ) && a == b
                    && ka.checked_add(last.size) == Some(*kb)
                {
                    let (base, offset) = (*a, *ka);
                    let term =
                        self.extract(base, offset, size, ctx, Some(Rule::JoinMerge), next)?;
                    self.count(Rule::JoinMerge);
                    *merged.last_mut().expect("nonempty") = TermPiece {
                        term,
                        lsb_byte: last.lsb_byte,
                        size,
                    };
                    continue;
                }
            }
            merged.push(piece);
        }
        if let [single] = merged.as_slice() {
            return Ok(single.term);
        }
        if let Some(top) = merged.last()
            && self.literal_of(top.term).is_some_and(is_zero)
        {
            let low_size = top.lsb_byte;
            let low = if merged.len() == 2 {
                merged[0].term
            } else {
                self.cons_join(
                    &merged[..merged.len() - 1],
                    low_size,
                    ctx,
                    Some(Rule::JoinZext),
                )?
            };
            self.count(Rule::JoinZext);
            return self.apply(
                Opcode::IntZext,
                vec![low],
                total,
                ctx,
                Some(Rule::JoinZext),
                next,
            );
        }
        self.cons_join(&merged, total, ctx, rule)
    }

    fn cons_join(
        &mut self,
        pieces: &[TermPiece],
        total: u32,
        ctx: Ctx,
        rule: Option<Rule>,
    ) -> Result<TermId> {
        self.cons(ExpressionType::Bits(total), Key::Join(pieces), ctx, rule)
    }

    fn finish(mut self) -> Result<Output> {
        let constants = self.constants;
        let program = self.program;
        let mut faults = Vec::with_capacity(constants.faults().len());
        for fault in constants.faults() {
            self.charge(1)?;
            let slot = self.node_slot(fault.expression)?;
            if slot == NONE || self.terms[slot].fault != TermFault::Here {
                return Err(SimplifyError::Inconsistent(
                    "constant fault without a faulting canonical term",
                ));
            }
            faults.push(SimplifiedFault {
                statement: fault.statement,
                node: fault.expression,
                term: TermId(slot),
                opcode: fault.opcode,
            });
        }
        for operation in program.operations() {
            self.charge(1)?;
            if !constants.is_statement_executable(operation.statement)? {
                self.stats.skipped_operations += 1;
                continue;
            }
            self.stats.executed_operations += 1;
            let Some(output) = operation.output else {
                continue;
            };
            let output = self.node_slot(output)?;
            match self.terms[output].kind {
                TermKind::Literal(_) => self.stats.literal_outputs += 1,
                TermKind::Leaf(_) => self.stats.forwarded_outputs += 1,
                _ => {
                    for operand in &operation.operands {
                        self.charge(1)?;
                        if let Some(node) = operand.expression()
                            && self.node_slot(node)? == output
                        {
                            self.stats.forwarded_outputs += 1;
                            break;
                        }
                    }
                }
            }
        }
        for operation in program.operations() {
            self.charge(1)?;
            if operation.opcode != Opcode::Cbranch
                || !constants.is_statement_executable(operation.statement)?
            {
                continue;
            }
            if let Some(condition) = operation.operands.get(1).and_then(|o| o.expression())
                && matches!(
                    self.terms[self.node_slot(condition)?].kind,
                    TermKind::Literal(_)
                )
                && !matches!(constants.expression(condition)?, ConstantFact::Constant(_))
            {
                self.stats.new_literal_conditions += 1;
            }
        }
        self.charge(self.node_terms.len())?;
        self.stats.unmapped_nodes = self.node_terms.iter().filter(|&&s| s == NONE).count();
        if self.node_terms.contains(&BUSY) || self.value_terms.iter().any(|&s| !Self::done(s)) {
            return Err(SimplifyError::Inconsistent("unfinished traversal"));
        }
        self.stats.terms = self.terms.len();
        self.stats.work = self.work;
        Ok(Output {
            terms: self.terms,
            node_terms: self.node_terms,
            value_terms: self.value_terms,
            refused: self.refused,
            faults,
            stats: self.stats,
        })
    }
}

fn pointer(address: &TermAddress) -> Option<TermId> {
    match *address {
        TermAddress::Pointer { term, .. } => Some(term),
        TermAddress::ByteOffset(_) => None,
    }
}
