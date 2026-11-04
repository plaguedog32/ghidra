//! Pattern-matching decoder: byte stream → [`ConstructorInstance`].
//!
//! [`Walker`] is the hot path for instruction decoding.  Public callers go
//! through [`crate::runtime::Decoder::decode_one`], which calls
//! [`Walker::try_get`] internally.  [`crate::tree::Tree::get_constructor`]
//! drives the recursive constructor search, delegating back to
//! [`Walker::try_build_constructor`] for each candidate.
//!

pub(crate) use crate::instance::{ConstructorInstance, OperandValue};

use std::{borrow::Cow, cmp, error::Error, fmt};

/// Errors returned by the SLEIGH decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// No constructor pattern matched the byte stream.
    NoMatch,
    /// The supplied context buffer does not match the compiled specification.
    InvalidContext,
    /// A disassembly action failed to evaluate (e.g. division by zero or type mismatch).
    InvalidAction,
    /// A display element could not be resolved to a value: an unattached table
    /// entry, or a field the matched constructor exposes no operand for.
    UnresolvedDisplay,
    /// A `globalset` names a sub-table operand whose exported address is not a
    /// constant this decode can evaluate.
    UnresolvedGlobalSetAddress,
    /// More than one constructor matched and the runtime could not choose one.
    AmbiguousMatch,
    /// The matcher gave up after too many constructor attempts: this encoding
    /// sent the backtracking search degenerate.
    ///
    /// A backstop, not a working limit. The matcher memoizes nothing, so a
    /// candidate whose sub-tables fail is abandoned and the next one re-decodes
    /// everything; a specification can in principle make that super-linear. No
    /// conforming specification should get anywhere near `SEARCH_BUDGET_LIMIT`
    /// — the worst measured encoding in the vendored corpus needs 201 attempts
    /// against a limit of 2^20. Reaching it means either a pathological
    /// specification or a bug in this crate.
    SearchExhausted,

    /// The sub-table recursion ran deeper than any real specification nests:
    /// almost certainly a cycle in the specification's tables.
    ///
    /// Distinct from [`Self::SearchExhausted`] because the causes are
    /// different. This one means "these tables recurse without consuming
    /// bytes" — ARM's `buildvst3DdList` does exactly that for a handful of
    /// invalid NEON encodings. Also a backstop: legitimate ARM decodes reach
    /// depth 34 against a limit of `SEARCH_DEPTH_LIMIT`.
    SearchCycle,
    /// A `delayslot` directive could not be filled.
    DelaySlot(DelaySlotError),
    /// A constructor reads `inst_next2`, but the instruction after this one
    /// could not be decoded to measure it.
    UnresolvedInstNext2,
    /// A compiler/runtime invariant was violated.
    InternalInvariant,
}

/// Why a `delayslot` directive could not be filled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DelaySlotError {
    /// The byte stream ended before the delay slot was filled.
    Truncated,
    /// No constructor matched inside the delay slot.
    NoMatch,
    /// The instruction in the delay slot has a delay slot of its own, which
    /// SLEIGH does not allow.
    Nested,
    /// The matched tree carries more than one `delayslot` directive, so there
    /// is no single length to fill.
    Ambiguous,
    /// The directive's argument did not evaluate to a usable byte count.
    InvalidLength,
}

impl fmt::Display for DelaySlotError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated => write!(f, "the byte stream ended inside a delay slot"),
            Self::NoMatch => write!(f, "no constructor matched inside a delay slot"),
            Self::Nested => write!(f, "an instruction in a delay slot has a delay slot"),
            Self::Ambiguous => write!(f, "more than one `delayslot` directive matched"),
            Self::InvalidLength => write!(f, "a `delayslot` length did not evaluate"),
        }
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoMatch => write!(f, "no constructor matched the byte stream"),
            Self::InvalidContext => write!(f, "invalid decode context"),
            Self::InvalidAction => write!(f, "failed to evaluate a disassembly action"),
            Self::UnresolvedDisplay => {
                write!(f, "could not resolve a value for a display element")
            }
            Self::UnresolvedGlobalSetAddress => write!(
                f,
                "could not evaluate the address a `globalset` commits its value at"
            ),
            Self::AmbiguousMatch => write!(f, "multiple constructors matched the byte stream"),
            Self::SearchExhausted => {
                write!(f, "gave up matching: too many constructor attempts")
            }
            Self::SearchCycle => {
                write!(f, "gave up matching: sub-table recursion ran too deep")
            }
            Self::DelaySlot(error) => write!(f, "{error}"),
            Self::UnresolvedInstNext2 => {
                write!(f, "could not decode the instruction `inst_next2` measures")
            }
            Self::InternalInvariant => write!(f, "internal decoder invariant failed"),
        }
    }
}

impl Error for DecodeError {}

use crate::bitrange::BitRange;
use crate::builder::Endian;
use crate::token::{TokenContext, token_stream_bit};
use crate::{
    action::{Action, Atom, Expr as ActionExpr},
    constructor::{Constructor, ConstructorId},
    instance::OperandValue as OperandValueAlias,
    objects::{
        field::{FIELD_INST_NEXT, FIELD_INST_START, FieldId, FieldParent, FieldTableId, FieldType},
        table::TableId,
    },
    pattern::{CombinedRange, OperandType, PatternOutcome},
    pmacro::statement::DelaySlotArg,
    runtime::{effects::collect_context_effects, shape::ShapeRecorder},
    spec::Spec,
    tree::{INSTRUCTION_TREE_ID, TreeId},
};
use jstd::debug_print;

/// How many constructor match attempts one decode may make.
///
/// The matcher backtracks: a constructor that matches its own bits but whose
/// sub-table operands do not is abandoned, and every candidate re-decodes its
/// operands from scratch with no memoization. On a large table that search can
/// blow up combinatorially — ARM7's NEON tables have encodings that reach
/// hundreds of thousands of attempts, and at least one that does not terminate
/// before memory runs out.
///
/// Healthy decodes are nowhere near this. Measured over 200k random encodings
/// per specification: x86-64 peaks at 24 attempts, and ARM7 — whose NEON
/// register-list tables are the deepest recursion in the corpus — has a 99th
/// percentile of 57 and a worst case of 201. The limit is five orders of
/// magnitude above that, so tripping it reports
/// [`DecodeError::SearchExhausted`] rather than taking the process down.
const SEARCH_BUDGET_LIMIT: u32 = 1 << 20;

/// How deep the sub-table recursion may go in one decode.
///
/// Breadth and depth blow up independently: [`SEARCH_BUDGET_LIMIT`] bounds the
/// number of attempts, but a million of them nested ever deeper overflows the
/// stack long before the budget runs out — and a specification whose tables
/// recurse without consuming bytes never spends the budget at all.
///
/// Legitimate decodes reach **depth 34** (ARM7's 32-entry VFP register lists,
/// the deepest construct measured in the vendored corpus). This is set to
/// roughly four times that: comfortably clear of a full-length register list
/// while still cutting a cycle off in microseconds.
const SEARCH_DEPTH_LIMIT: u32 = 128;

thread_local! {
    /// Attempts left in the current top-level decode. Thread-local rather than
    /// a `Walker` field because child walkers are built at several depths and
    /// all of them must spend from one purse.
    static SEARCH_BUDGET: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };

    /// Current sub-table nesting depth.
    static SEARCH_DEPTH: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };

    /// Set when the depth limit was hit, so the abandoned branch reaches
    /// `try_get_inner` as a cycle rather than an ordinary non-match. Its own
    /// flag: zeroing the budget to smuggle the signal out made the two
    /// pathologies indistinguishable in the error.
    static SEARCH_CYCLE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Reads `range` out of `data` as a little-endian integer.
///
/// A range wider than 64 bits cannot be represented in the result, so it is
/// truncated to its low 64 bits rather than asserted against: this sits on the
/// decode hot path, where the width comes from a compiled specification and a
/// panic would take the caller down. Compilation rejects such fields where it
/// can (see the constraint width check).
pub(crate) fn extract_bytes(data: &[u8], range: &BitRange) -> u64 {
    let width = range.size().min(u64::BITS as usize);

    let byte_offset = range.start() / 8;
    let bit_offset = range.start() % 8;

    let mut buf = [0u8; 8];
    let available = data.len().saturating_sub(byte_offset);
    let to_copy = available.min(8);
    if to_copy > 0 {
        buf[..to_copy].copy_from_slice(&data[byte_offset..byte_offset + to_copy]);
    }

    let value = u64::from_le_bytes(buf);

    if width == 64 {
        value >> bit_offset
    } else {
        let mask = (1u64 << width) - 1;
        (value >> bit_offset) & mask
    }
}

/// Reads a field of a big-endian token out of the instruction bytes.
///
/// Goes through [`token_stream_bit`], the same mapping pattern construction
/// uses, so a pattern that matched cannot then extract a different value.
fn gather_be_token_field(
    data: &[u8],
    range: &BitRange,
    token_bits: usize,
    bit_offset: usize,
) -> u64 {
    let width = range.size().min(u64::BITS as usize);
    let mut value = 0;

    for i in 0..width {
        let pos = token_stream_bit(token_bits, Endian::Big, range.start() + i) + bit_offset;
        if data
            .get(pos / 8)
            .is_some_and(|byte| byte & (1 << (pos % 8)) != 0)
        {
            value |= 1u64 << i;
        }
    }

    value
}

/// Returns the signed version of a field that fits in "range".
///
/// A range at least 64 bits wide already fills the result, so there is nothing
/// to sign-extend; shifting by the full width would be undefined.
pub(crate) fn signed(value: u64, range: &BitRange) -> i64 {
    let width = range.size();
    if width >= u64::BITS as usize {
        return value as i64;
    }
    let shift = u64::BITS as usize - width;
    ((value << shift) as i64) >> shift
}

/// Updates the context by setting the bits of `field` to `value`.
/// Context is big endian.
pub(crate) fn update_context(context: &mut [u8], range: &BitRange, mut value: u64) {
    for i in range.iter().rev() {
        let byte = i / 8;
        let mask = 1 << (i % 8);

        if value & 1 == 1 {
            context[byte] |= mask;
        } else {
            context[byte] &= !mask;
        }

        value >>= 1;
    }
}

/// Evaluates a disassembly-action expression against one decode.
///
/// Token fields come from the constructor's already-decoded operands, context
/// fields from `context` — which during effect collection is the running
/// scratch copy, not the caller's input — and global fields (`inst_start`,
/// `inst_next`, `reloc`, ...) from `globals`.
pub(crate) fn eval_action_expr(
    spec: &Spec,
    expr: &ActionExpr,
    constructor: &Constructor,
    globals: &[u64],
    operand_values: &[OperandValue],
    context: &[u8],
) -> Option<i64> {
    expr.eval_fallible(&|field_id| {
        let field = &spec.fields[field_id];

        match field.parent {
            FieldParent::Token(_) => {
                let operand_id = *constructor.field_map.get(&field_id)?;

                if let &OperandValue::Int(value) = operand_values.get(operand_id as usize)? {
                    Some(value)
                } else {
                    None
                }
            }

            FieldParent::Context => Some(read_context(context, &field.range) as i64),

            FieldParent::Global => {
                Some(*globals.get(constructor.try_global_index(field_id)?)? as i64)
            }
        }
    })
}

pub(crate) fn read_context(context: &[u8], range: &BitRange) -> u64 {
    let mut value = 0;
    for i in range.iter() {
        value <<= 1;

        let byte = i / 8;
        let mask = 1 << (i % 8);

        if context[byte] & mask != 0 {
            value |= 1;
        }
    }
    value
}

/// Finds the one `delayslot` directive in a matched tree, with the instance
/// that owns it — the directive's argument may name a field, which only that
/// constructor's operands and globals can resolve.
///
/// Compilation already rejects two directives in one constructor body; two in
/// *different* constructors of one tree can only be discovered here.
fn find_delay_slot<'i>(
    spec: &Spec,
    instance: &'i ConstructorInstance,
) -> Result<Option<(&'i ConstructorInstance, DelaySlotArg)>, DecodeError> {
    let mut found: Option<(&ConstructorInstance, DelaySlotArg)> = None;

    fn walk<'i>(
        spec: &Spec,
        instance: &'i ConstructorInstance,
        found: &mut Option<(&'i ConstructorInstance, DelaySlotArg)>,
    ) -> Result<(), DecodeError> {
        if let Some(arg) = &instance.constructor(spec).delay_slot {
            if found.is_some() {
                return Err(DecodeError::DelaySlot(DelaySlotError::Ambiguous));
            }
            *found = Some((instance, arg.clone()));
        }

        for operand in &instance.operand_values {
            if let OperandValueAlias::Constructor(child) = operand {
                walk(spec, child, found)?;
            }
        }
        Ok(())
    }

    walk(spec, instance, &mut found)?;
    Ok(found)
}

/// Does any constructor in a matched tree read `inst_next2`?
fn uses_inst_next2(spec: &Spec, instance: &ConstructorInstance) -> bool {
    instance.constructor(spec).uses_inst_next2
        || instance.operand_values.iter().any(|operand| match operand {
            OperandValueAlias::Constructor(child) => uses_inst_next2(spec, child),
            _ => false,
        })
}

/// The primary runtime SLEIGH decoder.
///
/// A `Walker` holds all the state required to match a single instruction from
/// raw bytes against a compiled [`Spec`].  New public callers should use
/// [`crate::Decoder::decode_one`], which returns typed decode errors and does
/// not expose this internal runtime representation.
pub(crate) struct Walker<'spec, 'bytes, 'ctx> {
    pub(crate) context: &'ctx [u8],
    pub(crate) bytes: &'bytes [u8],
    pub(crate) spec: &'spec Spec,
    pub(crate) inst_start: u64,
    /// Where the walker records which bits it decides by, when the caller
    /// asked for the instruction's shape.
    recorder: Option<&'ctx ShapeRecorder>,
    /// The byte offset of `bytes` within the instruction being decoded, so
    /// a sub-table's walker records bits at their instruction position.
    base_offset: usize,
}

/// How much look-ahead decoding a call to [`Walker::try_get`] may still do.
///
/// A delay-slot instruction may not itself have a delay slot (SLEIGH manual
/// §7.11), and neither delayed nor looked-ahead instructions need look-ahead of
/// their own — so the recursion is one level deep by construction rather than
/// by a depth counter.
#[derive(Clone, Copy, PartialEq, Eq)]
enum LookAhead {
    /// A top-level decode: fill delay slots and measure `inst_next2`.
    Allowed,
    /// A decode that is itself look-ahead. A `delayslot` directive here is an
    /// error rather than a nested slot, and `inst_next2` is not measured.
    Forbidden,
}

impl<'spec, 'bytes, 'ctx> Walker<'spec, 'bytes, 'ctx> {
    /// Decodes one instruction, returning a typed [`DecodeError`] on failure.
    pub(crate) fn try_get(
        inst_start: u64,
        bytes: &'bytes [u8],
        spec: &'spec Spec,
        context_len: usize,
        context: &'ctx [u8],
    ) -> Result<ConstructorInstance, DecodeError> {
        Self::try_get_inner(
            inst_start,
            bytes,
            spec,
            context_len,
            context,
            LookAhead::Allowed,
            None,
        )
    }

    /// [`try_get`](Self::try_get), recording into `recorder` which bits the
    /// decode decided by; see [`crate::runtime::Shape`].
    pub(crate) fn try_get_shaped(
        inst_start: u64,
        bytes: &'bytes [u8],
        spec: &'spec Spec,
        context_len: usize,
        context: &'ctx [u8],
        recorder: &'ctx ShapeRecorder,
    ) -> Result<ConstructorInstance, DecodeError> {
        Self::try_get_inner(
            inst_start,
            bytes,
            spec,
            context_len,
            context,
            LookAhead::Allowed,
            Some(recorder),
        )
    }

    fn try_get_inner(
        inst_start: u64,
        bytes: &'bytes [u8],
        spec: &'spec Spec,
        context_len: usize,
        context: &'ctx [u8],
        look_ahead: LookAhead,
        recorder: Option<&'ctx ShapeRecorder>,
    ) -> Result<ConstructorInstance, DecodeError> {
        if context.len() != context_len {
            return Err(DecodeError::InvalidContext);
        }

        let walker = Self {
            context,
            bytes,
            spec,
            inst_start,
            recorder,
            base_offset: 0,
        };

        // The outermost decode funds the search; a delay-slot or look-ahead
        // decode spends from the same budget so one instruction cannot buy
        // itself more by nesting.
        if look_ahead == LookAhead::Allowed {
            SEARCH_BUDGET.with(|budget| budget.set(SEARCH_BUDGET_LIMIT));
            SEARCH_DEPTH.with(|depth| depth.set(0));
            SEARCH_CYCLE.with(|cycle| cycle.set(false));
        }

        let matched = spec.trees[INSTRUCTION_TREE_ID].get_constructor(INSTRUCTION_TREE_ID, &walker);

        if SEARCH_CYCLE.with(|cycle| cycle.get()) {
            return Err(DecodeError::SearchCycle);
        }

        if SEARCH_BUDGET.with(|budget| budget.get()) == 0 {
            return Err(DecodeError::SearchExhausted);
        }

        let mut constructor = matched.ok_or(DecodeError::NoMatch)?;

        constructor.inst_start = inst_start;
        constructor.inst_next = constructor.inst_start + constructor.size as u64;

        walker.resolve_globals(&mut constructor)?;

        // Everything above — sizing, globals, effects, display — uses the
        // *unextended* `inst_next`. That is the disassembly-action convention,
        // and it is what `globalset(inst_next, ...)` on a delay-slot branch has
        // to commit at. Only the semantic section sees the extended value.
        constructor.context_effects = collect_context_effects(spec, &constructor, walker.context)?;

        if spec.needs_lookahead {
            walker.resolve_look_ahead(&mut constructor, context_len, look_ahead)?;
        }

        Ok(constructor)
    }

    /// Fills the delay slot and `inst_next2`, both of which need instructions
    /// after this one to have been decoded.
    fn resolve_look_ahead(
        &self,
        instance: &mut ConstructorInstance,
        context_len: usize,
        look_ahead: LookAhead,
    ) -> Result<(), DecodeError> {
        let directive = find_delay_slot(self.spec, instance)?;
        let wants_inst_next2 = uses_inst_next2(self.spec, instance);

        if directive.is_none() && !wants_inst_next2 {
            return Ok(());
        }

        // Whatever follows this instruction now decides its decode.
        if let Some(recorder) = self.recorder {
            recorder.note_overrun();
        }

        if look_ahead == LookAhead::Forbidden {
            // A delay slot inside a delay slot has no defined meaning; a
            // look-ahead instruction reading `inst_next2` would need look-ahead
            // of its own, which this decode deliberately does not do.
            return Err(if directive.is_some() {
                DecodeError::DelaySlot(DelaySlotError::Nested)
            } else {
                DecodeError::UnresolvedInstNext2
            });
        }

        if let Some((owner, arg)) = directive {
            let wanted = self.delay_slot_length(owner, &arg)?;
            let mut consumed = 0usize;

            while consumed < wanted {
                let offset = instance.size + consumed;
                let delayed = self.decode_after(offset, context_len).map_err(|error| {
                    DecodeError::DelaySlot(match error {
                        DecodeError::NoMatch => DelaySlotError::NoMatch,
                        DecodeError::InternalInvariant => DelaySlotError::Truncated,
                        other => return other,
                    })
                })?;

                // A zero-length instruction would spin here forever, and no
                // number of them can fill a slot.
                if delayed.size == 0 {
                    return Err(DecodeError::DelaySlot(DelaySlotError::Truncated));
                }

                consumed += delayed.size;
                instance.delay_slots.push(delayed);
            }

            instance.delay_slot_len = consumed;
        }

        if wants_inst_next2 {
            // "The address after the next instruction", where the next
            // instruction's length excludes any delay slot of its own — which
            // `LookAhead::Forbidden` guarantees by refusing to fill one.
            let next = self
                .decode_after(instance.size + instance.delay_slot_len, context_len)
                .map_err(|_| DecodeError::UnresolvedInstNext2)?;
            instance.inst_next2 = Some(instance.semantic_inst_next() + next.size as u64);
        }

        Ok(())
    }

    /// Decodes the instruction `offset` bytes past this one, with the same
    /// input context.
    ///
    /// Reusing the context is a deliberate simplification: a `globalset` this
    /// instruction performs targets an address, and the delay slot is not
    /// generally that address. Threading committed context into the slot is a
    /// [`crate::ContextDatabase`]-shaped decision, and the decoder is pure.
    fn decode_after(
        &self,
        offset: usize,
        context_len: usize,
    ) -> Result<ConstructorInstance, DecodeError> {
        let rest = self
            .bytes
            .get(offset..)
            .filter(|rest| !rest.is_empty())
            .ok_or(DecodeError::InternalInvariant)?;

        Walker::try_get_inner(
            self.inst_start + offset as u64,
            rest,
            self.spec,
            context_len,
            self.context,
            LookAhead::Forbidden,
            None,
        )
    }

    /// Evaluates a `delayslot` argument to a byte count.
    fn delay_slot_length(
        &self,
        owner: &ConstructorInstance,
        arg: &DelaySlotArg,
    ) -> Result<usize, DecodeError> {
        let bytes = match arg {
            DelaySlotArg::Bytes(n) => *n as i64,

            // pi32v2's `rep` computes its slot length in a disassembly action,
            // so the field already holds a value by the time we get here.
            DelaySlotArg::Field(field_id) => self
                .do_action(
                    &ActionExpr::Atom(Atom::Ident(*field_id)),
                    owner.constructor(self.spec),
                    &owner.global_values,
                    &owner.operand_values,
                    self.context,
                )
                .ok_or(DecodeError::DelaySlot(DelaySlotError::InvalidLength))?,

            DelaySlotArg::Deferred(_) => {
                return Err(DecodeError::DelaySlot(DelaySlotError::InvalidLength));
            }
        };

        usize::try_from(bytes).map_err(|_| DecodeError::DelaySlot(DelaySlotError::InvalidLength))
    }

    /// Reads field `id` at `bit_offset` into this walker's bytes. `decisive`
    /// says the value chooses something about the decode besides its
    /// operand — the shape then keeps its bits in the mask.
    fn get_field_value(&self, id: FieldId, bit_offset: usize, decisive: bool) -> Option<i64> {
        let field = &self.spec.fields[id];

        let range = field.range.shifted(bit_offset);

        if let Some(recorder) = self.recorder
            && let FieldParent::Token(tok) = field.parent
        {
            let at = range.shifted(self.base_offset * 8);
            // A big-endian token permutes the field's bits across the
            // stream, so they are not one run a parameter names.
            if decisive || self.spec.token_endian(tok) == Endian::Big {
                self.note_field_bits(tok, &range);
            } else if let FieldType::Registers(table) = field.field_type()
                && let Some(holes) = self.register_holes(table, field.range.size())
            {
                recorder.note_register(&at, table, holes.into_iter());
            } else if field.is_attached() {
                self.note_field_bits(tok, &range);
            } else {
                recorder.note_param(&at, field.signed);
            }
        }

        let value = match field.parent {
            // A big-endian token's bits are permuted across its bytes, so the
            // field is not a contiguous run in the byte stream and has to be
            // gathered bit by bit. Little-endian tokens keep the fast path.
            FieldParent::Token(tok) if self.spec.token_endian(tok) == Endian::Big => {
                gather_be_token_field(
                    self.bytes,
                    &field.range,
                    self.spec.token_size(tok),
                    bit_offset,
                )
            }
            FieldParent::Token(_) => self.value_over_insn(&range),
            FieldParent::Context => read_context(self.context, &range),
            FieldParent::Global => return None,
        };

        Some(if field.signed {
            signed(value, &field.range)
        } else {
            value as i64
        })
    }

    /// Whether a field of `width` bits indexing register table `table`
    /// makes a [`RegisterField`](super::RegisterField): the registers are
    /// distinct and of one size, so a lift over one is a lift over any.
    /// Returns the values the table has no register for.
    fn register_holes(&self, table: FieldTableId, width: usize) -> Option<Vec<u64>> {
        if !(1..=8).contains(&width) {
            return None;
        }
        let registers = self.spec.field_tables.register_table(table);
        let mut size = None;
        for (i, &register) in registers.iter().enumerate() {
            let Some(register) = register else {
                continue;
            };
            if registers[..i].contains(&Some(register)) {
                return None;
            }
            let this = self.spec.registers[register].size;
            if *size.get_or_insert(this) != this {
                return None;
            }
        }
        Some(
            (0..1u64 << width)
                .filter(|&v| registers.get(v as usize).copied().flatten().is_none())
                .collect(),
        )
    }

    fn matches_constructor_pattern(&self, constructor: &Constructor) -> bool {
        let Some(recorder) = self.recorder else {
            return constructor
                .runtime_patterns
                .iter()
                .any(|pattern| pattern.matches(self.bytes, self.context));
        };
        // A matching alternative decides by every bit it tests. One that
        // fails on its instruction half excludes: the shape keeps its
        // pattern, since an encoding matching it decodes differently — but
        // only when the whole constructor fails, and only when the failure
        // is not already fixed by the mask. One whose context half fails
        // can never match under this context, which the caller keys on.
        let mut failed: Vec<(Option<usize>, &[u8], &[u8])> = Vec::new();
        for pattern in &constructor.runtime_patterns {
            match pattern.test(self.bytes, self.context) {
                PatternOutcome::Matched => {
                    if let Some(mask) = pattern.instruction_mask() {
                        recorder.note_mask(self.base_offset, mask);
                    }
                    return true;
                }
                PatternOutcome::FailedContext => {}
                PatternOutcome::FailedByte(byte) => {
                    let (mask, value) =
                        pattern.instruction_test().expect("a masked pattern failed");
                    failed.push((Some(byte), mask, value));
                }
                PatternOutcome::FailedShort => {
                    let (mask, value) =
                        pattern.instruction_test().expect("a masked pattern failed");
                    failed.push((None, mask, value));
                }
            }
        }
        for (byte, mask, value) in failed {
            recorder.note_exclusion(self.base_offset, byte, mask, value);
        }
        false
    }

    /// Records, for a candidate skipped because the bytes ran out before
    /// its minimum size, that no encoding of the shape matches it: with
    /// more bytes it would have been tested.
    fn note_untested(&self, constructor: &Constructor) {
        let Some(recorder) = self.recorder else {
            return;
        };
        for pattern in &constructor.runtime_patterns {
            if pattern.context_matches(self.context)
                && let Some((mask, value)) = pattern.instruction_test()
            {
                recorder.note_exclusion(self.base_offset, None, mask, value);
            }
        }
    }

    /// Records the bits of a decisive field of token `tok` at `range`
    /// within this walker's bytes.
    fn note_field_bits(&self, tok: crate::token::TokenId, range: &BitRange) {
        let Some(recorder) = self.recorder else {
            return;
        };
        if self.spec.token_endian(tok) == Endian::Big {
            let token_bits = self.spec.token_size(tok);
            for i in 0..range.size() {
                let pos = token_stream_bit(token_bits, Endian::Big, range.start() + i)
                    + self.base_offset * 8;
                recorder.note_bits(&BitRange::singleton(pos));
            }
        } else {
            recorder.note_bits(&range.shifted(self.base_offset * 8));
        }
    }

    /// Records that the decision tree dispatched on `range`.
    pub(crate) fn note_decision(&self, range: &CombinedRange) {
        if let (Some(recorder), CombinedRange::Instruction(range)) = (self.recorder, range) {
            recorder.note_bits(&range.shifted(self.base_offset * 8));
        }
    }

    /// Whether a value of one of `constructor`'s fields can change the
    /// decode beyond its own operand: an action assigns context from it,
    /// or a delay slot is sized by it.
    fn fields_are_decisive(&self, constructor: &Constructor) -> bool {
        constructor.delay_slot.is_some()
            || constructor.actions.iter().any(|action| match action {
                Action::Assign { field_id, .. } => {
                    self.spec.fields[*field_id].parent == FieldParent::Context
                }
                Action::GlobalSet { .. } => false,
            })
    }

    pub(crate) fn do_action(
        &self,
        expr: &ActionExpr,
        constructor: &Constructor,
        globals: &[u64],
        operand_values: &[OperandValue],
        context: &[u8],
    ) -> Option<i64> {
        eval_action_expr(
            self.spec,
            expr,
            constructor,
            globals,
            operand_values,
            context,
        )
    }

    pub(crate) fn do_actions1<'a>(
        &'a self,
        constructor: &Constructor,
        globals: &[u64],
        operand_values: &[OperandValue],
    ) -> Option<Cow<'a, [u8]>> {
        let mut context = Cow::Borrowed(self.context);

        for action in &constructor.actions {
            // `globalset` addresses may name `inst_next` or a sub-table that is
            // not decoded yet, so commits are collected after the match rather
            // than here. They never affect sub-table matching.
            let Action::Assign { field_id, expr } = action else {
                continue;
            };

            let field = &self.spec.fields[*field_id];

            match field.parent {
                FieldParent::Context => {
                    let value =
                        self.do_action(expr, constructor, globals, operand_values, &context)?;

                    update_context(context.to_mut(), &field.range, value as u64);

                    debug_print!(
                        "Updating context field {} ({}) to {} ({:b}) (it's now {})",
                        field.name,
                        field.width(),
                        value,
                        value as u64,
                        read_context(&context, &field.range)
                    );
                }

                FieldParent::Global => {}

                FieldParent::Token(_) => return None,
            }
        }

        Some(context)
    }

    pub(crate) fn resolve_globals(
        &self,
        instance: &mut ConstructorInstance,
    ) -> Result<(), DecodeError> {
        let constructor = &self.spec.trees[instance.tree].constructors[instance.id];

        if let Some(idx) = constructor.try_global_index(FIELD_INST_START) {
            instance.global_values[idx] = instance.inst_start;
        }

        if let Some(idx) = constructor.try_global_index(FIELD_INST_NEXT) {
            instance.global_values[idx] = instance.inst_next;
        }

        for child in &mut instance.operand_values {
            if let OperandValue::Constructor(child) = child {
                child.inst_start = instance.inst_start;
                child.inst_next = instance.inst_next;
                self.resolve_globals(child)?;

                for (field_id, child_idx) in child.constructor(self.spec).global_pairs() {
                    let value = child.global_values[child_idx];
                    if let Some(idx) = constructor.try_global_index(field_id) {
                        instance.global_values[idx] = value;
                    }
                }
            }
        }

        for action in &constructor.actions {
            let Action::Assign { field_id, expr } = action else {
                continue;
            };

            let field = &self.spec.fields[*field_id];

            match field.parent {
                FieldParent::Context => {}

                FieldParent::Global => {
                    let value = self
                        .do_action(
                            expr,
                            constructor,
                            &instance.global_values,
                            &instance.operand_values,
                            self.context,
                        )
                        .ok_or(DecodeError::InvalidAction)?;
                    let idx = constructor.global_index(*field_id);
                    instance.global_values[idx] = value as u64;
                }

                FieldParent::Token(_) => return Err(DecodeError::InvalidAction),
            }
        }

        Ok(())
    }

    fn resolve_operands_1(
        &self,
        constructor: &Constructor,
        operand_values: &mut [OperandValue],
    ) -> Option<()> {
        let decisive = self.recorder.is_some() && self.fields_are_decisive(constructor);
        for (idx, operand) in constructor.token_pattern.operands.iter().enumerate() {
            if operand.relative().is_some() {
                continue;
            }

            match operand.ty {
                OperandType::Field(field_id) => {
                    operand_values[idx] = OperandValue::Int(self.get_field_value(
                        field_id,
                        operand.offset(),
                        decisive,
                    )?);
                }

                OperandType::Register(_) | OperandType::Table(_) => continue,
            }
        }

        Some(())
    }

    fn resolve_relative_table(
        &self,
        context: &[u8],
        offset: usize,
        id: TableId,
    ) -> Option<(usize, OperandValue)> {
        let bytes = if offset == self.bytes.len() {
            &[]
        } else if offset < self.bytes.len() {
            &self.bytes[offset..]
        } else {
            debug_print!(
                "Not enough bytes to build operand required {offset}, available {}",
                self.bytes.len()
            );
            return None;
        };

        let tree = &self.spec.trees[id.into()];

        debug_print!(
            "Attempting to build operand: {} from {:?}",
            tree.name,
            &bytes
        );

        let child_walker = Walker {
            context,
            spec: self.spec,
            bytes,
            inst_start: self.inst_start,
            recorder: self.recorder,
            base_offset: self.base_offset + offset,
        };

        // Descending too far raises its own flag, so `try_get_inner` can tell
        // a cycle from a degenerate search instead of letting the abandoned
        // branch look like an ordinary non-match.
        let too_deep = SEARCH_DEPTH.with(|depth| {
            let next = depth.get() + 1;
            depth.set(next);
            next > SEARCH_DEPTH_LIMIT
        });
        if too_deep {
            SEARCH_DEPTH.with(|depth| depth.set(depth.get() - 1));
            SEARCH_CYCLE.with(|cycle| cycle.set(true));
            return None;
        }

        let child = tree.get_constructor(id.into(), &child_walker);
        SEARCH_DEPTH.with(|depth| depth.set(depth.get() - 1));
        let child = child?;

        let end = offset + child.size;

        Some((end, OperandValue::Constructor(child)))
    }

    fn resolve_relative_field(
        &self,
        id: FieldId,
        offset: usize,
        decisive: bool,
    ) -> Option<(usize, OperandValue)> {
        let field = &self.spec.fields[id];
        Some((
            field.parent_size() / 8 + offset,
            OperandValue::Int(self.get_field_value(id, offset * 8, decisive)?),
        ))
    }

    fn resolve_operands_2(
        &self,
        constructor: &Constructor,
        operand_values: &mut [OperandValue],
        context: &[u8],
    ) -> Option<usize> {
        let mut size = 0;
        let decisive = self.recorder.is_some() && self.fields_are_decisive(constructor);

        // Only concatenated (`;`) patterns need the end position of earlier
        // operands. Most constructors do not have one, and this function runs
        // for every candidate considered during backtracking, so avoid making
        // a throw-away allocation for the common case.
        let mut ends = constructor
            .token_pattern
            .operands
            .iter()
            .any(|operand| operand.relative().is_some())
            .then(|| vec![0usize; operand_values.len()]);

        for (idx, operand) in constructor.token_pattern.operands.iter().enumerate() {
            if !matches!(operand_values[idx], OperandValue::None) {
                if let OperandType::Field(id) = operand.ty {
                    let end = self.spec.fields[id].parent_size() / 8 + operand.offset() / 8;
                    if let Some(ends) = &mut ends {
                        ends[idx] = end;
                    }
                    size = cmp::max(size, end);
                }
                continue;
            }

            let mut offset = operand.offset() / 8;

            if let Some((rel, min_size)) = operand.relative() {
                // A `relative` operand comes from a `;` (concatenation) in the bit
                // pattern: it starts where the *whole* left-hand pattern ended.
                // `TokenPattern::cat` can only record a single base operand and it
                // picks the *last* one of the left-hand side, which need not be the
                // one that consumed the most bytes. `IMUL Reg64,rm64,simm32_32` is
                // written `... byte=0x69; (rm64 & Reg64 ...); simm32_32`: `Reg64`
                // comes last but is decoded out of the ModRM reg field and has zero
                // extent, while `rm64` is what eats the SIB and displacement bytes.
                // Operands are stored left-to-right, so the true end of the
                // left-hand pattern is the maximum end over `..=rel`.
                // `ends` exists whenever an operand is relative (see its
                // construction above).
                //
                // Fields start there too, not at the running end of the
                // constructor: that already counts the operands placed before
                // this one on the *right* of the `;`. PCLMULQDQ's
                // `... & m128; imm8 & imm8_4 & imm8_0` names one byte three
                // times, and must not lay the three end to end.
                let base = cmp::max(
                    ends.as_ref()?[..=rel].iter().copied().max().unwrap_or(0),
                    min_size / 8,
                );
                offset += base;
            }

            let (end, value) = match operand.ty {
                OperandType::Field(id) => self.resolve_relative_field(id, offset, decisive)?,

                OperandType::Table(id) => self.resolve_relative_table(context, offset, id)?,

                OperandType::Register(_) => {
                    // FIXME: a bare register in a bit-pattern (constraint.rs) is currently
                    // silently ignored — it returns a zero-size None operand instead of
                    // producing an implicit fixed operand as the SLEIGH spec likely intends.
                    // See constraint.rs where OperandType::Register is constructed.
                    (0, OperandValue::None)
                }
            };

            if let Some(ends) = &mut ends {
                ends[idx] = end;
            }
            operand_values[idx] = value;
            size = cmp::max(size, end);
        }

        Some(size)
    }

    fn create_globals(&self, constructor: &Constructor) -> Vec<u64> {
        let mut globals = vec![0; constructor.global_map.len()];

        if let Some(idx) = constructor.try_global_index(FIELD_INST_START) {
            globals[idx] = self.inst_start;
        }

        globals
    }

    pub(crate) fn try_build_constructor(
        &self,
        tree_id: TreeId,
        id: ConstructorId,
    ) -> Option<ConstructorInstance> {
        // Charged before any work, so an exhausted search unwinds immediately
        // instead of continuing to allocate on the way out.
        if SEARCH_BUDGET.with(|budget| {
            let left = budget.get();
            budget.set(left.saturating_sub(1));
            left == 0
        }) {
            return None;
        }

        let constructor = &self.spec.trees[tree_id].constructors[id];

        debug_print!(
            "Attempting to build ({} bytes) \n{}\n{}\n\n",
            constructor.min_size(),
            format!("bytes {:?}", constructor.src),
            constructor.token_pattern.to_string(self.spec)
        );

        if constructor.min_size() > self.bytes.len() {
            debug_print!("Not enough bytes available");
            self.note_untested(constructor);
            return None;
        }

        if !self.matches_constructor_pattern(constructor) {
            debug_print!("Token does not match");
            return None;
        }

        let mut operand_values = vec![OperandValue::None; constructor.token_pattern.operands.len()];

        self.resolve_operands_1(constructor, &mut operand_values)?;

        let global_values = self.create_globals(constructor);

        let context = self.do_actions1(constructor, &global_values, &operand_values)?;

        let operand_size = self.resolve_operands_2(constructor, &mut operand_values, &context)?;

        debug_print!("Built constructor");

        let size = cmp::max(operand_size, constructor.min_size());

        debug_print!(
            "Constructor {} took {size} bytes",
            &self.spec.trees[tree_id].name
        );

        Some(ConstructorInstance {
            tree: tree_id,
            id,
            size,
            operand_values,
            global_values,
            inst_start: self.inst_start,
            inst_next: 0,
            context_effects: Vec::new(),
            delay_slots: Vec::new(),
            delay_slot_len: 0,
            inst_next2: None,
        })
    }

    pub(crate) fn value_over(&self, range: &CombinedRange) -> u64 {
        match range {
            CombinedRange::Context(range) => self.value_over_ctx(range),
            CombinedRange::Instruction(range) => self.value_over_insn(range),
        }
    }

    pub(crate) fn value_over_insn(&self, range: &BitRange) -> u64 {
        extract_bytes(self.bytes, range)
    }

    pub(crate) fn value_over_ctx(&self, range: &BitRange) -> u64 {
        extract_bytes(self.context, range)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_signed() {
        assert_eq!(signed(255, &BitRange::new(0, 7)), -1);
        assert_eq!(signed(254, &BitRange::new(0, 7)), -2);
        assert_eq!(signed(7, &BitRange::new(0, 7)), 7);
        assert_eq!(signed(0, &BitRange::new(0, 7)), 0);
    }

    #[test]
    fn test_extract_bytes() {
        assert_eq!(extract_bytes(&[0xff, 0x05], &BitRange::new(0, 7)), 0xff);

        assert_eq!(extract_bytes(&[0xff, 0x05], &BitRange::new(8, 15)), 5);

        assert_eq!(extract_bytes(&[0xff, 0x05], &BitRange::new(8, 10)), 5);

        assert_eq!(extract_bytes(&[0xff, 0x05], &BitRange::new(6, 10)), 23);
    }

    #[test]
    fn test_update_ctx() {
        {
            let mut context = vec![0xff, 0x00, 0x0f];
            update_context(&mut context, &BitRange::new(16, 23), 11);
            assert_eq!(context, vec![0xff, 0x00, 0b11010000]);
        }

        {
            let mut context = vec![0xff, 0x00, 0x0f];
            update_context(&mut context, &BitRange::new(12, 19), 0xf5);
            assert_eq!(context, vec![0xff, 0xf0, 0b00001010]);
        }
    }
}
