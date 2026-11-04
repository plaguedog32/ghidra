//! Runtime decoding facade for compiled SLEIGH specifications.

use std::{borrow::Cow, fmt};

mod context;
mod context_db;
mod effects;
mod pcode;
mod refs;
pub(crate) mod shape;
pub(crate) mod walker;

use self::pcode::{pcode_ast_for_instance, stream_instance};
use crate::{
    builder::SymbolId,
    instance::ConstructorInstance,
    objects::{
        field::{FieldId, FieldParent, FieldTableId},
        table::TableId,
    },
    register_map::RegisterSlice,
    semantics::{EmitError, InstructionInfo, PcodeAst, SemanticsSink},
    spec::Spec,
    token::{BitRangeFieldId, TokenContext},
};
pub use context::{Context, ContextBytes, ContextError};
pub use context_db::ContextDatabase;
pub use effects::{ContextEffect, ContextScope};
use pcode_types::{
    BitRangeInfo, InstructionPcode, PcodeLoweringContext, PcodeOp, PcodePlan, PcodeSink,
    RegisterId, SpaceId, Varnode, lower_instruction, lower_instruction_into,
};
pub use refs::{FieldRef, RegisterRef, SpaceRef, SymbolKind, SymbolRef, TableRef, TokenRef};
use serde::{Deserialize, Serialize};
pub use shape::{Exclusion, ParamField, RegisterField, Shape};
use walker::Walker;

pub use walker::{DecodeError, DelaySlotError};

/// Supplies compiled-SLEIGH storage metadata to the generic flat p-code
/// lowerer. Kept private so SLEIGH remains only a producer of that metadata.
pub(crate) struct InstructionPcodeContext<'a> {
    spec: &'a Spec,
}

impl<'a> InstructionPcodeContext<'a> {
    pub(crate) fn new(spec: &'a Spec) -> Self {
        Self { spec }
    }
}

impl PcodeLoweringContext for InstructionPcodeContext<'_> {
    fn default_space(&self) -> SpaceId {
        self.spec.default_space
    }

    fn unique_space(&self) -> SpaceId {
        self.spec.unique_space
    }

    fn register_varnode(&self, id: RegisterId) -> Option<Varnode> {
        (usize::from(id) < self.spec.registers.len()).then(|| {
            let register = &self.spec.registers[id];
            Varnode::new(register.space, register.offset as u64, register.size)
        })
    }

    fn bitrange_info(&self, id: BitRangeFieldId) -> Option<BitRangeInfo> {
        if usize::from(id) >= self.spec.bitranges.len() {
            return None;
        }
        let bitrange = &self.spec.bitranges[id];
        if usize::from(bitrange.register) >= self.spec.registers.len() {
            return None;
        }
        let register = &self.spec.registers[bitrange.register];
        Some(BitRangeInfo {
            storage: Varnode::new(register.space, register.offset as u64, register.size),
            start: bitrange.offset(),
            size: bitrange.size(),
        })
    }

    fn address_size(&self, space: SpaceId) -> Option<usize> {
        (usize::from(space) < self.spec.spaces.len()).then(|| self.spec.spaces[space].addr_size)
    }
}

/// The identity of a compiled specification's content.
///
/// A fingerprint is a digest of everything a compilation depends on: the
/// specification's source text as the preprocessor delivered it to the parser
/// — every included file, every `$(NAME)` expansion and every conditional
/// already resolved, so the defines are in — and the version of this crate,
/// whose compiler turned that text into the specification. Compiling the
/// same text with the same compiler yields the same fingerprint, in any
/// process and at any time; any change to the text or the compiler yields a
/// different one. It is computed once, when the specification is compiled,
/// and travels with the serialized specification, so a precompiled
/// specification carries the fingerprint of the build that made it.
///
/// It is what a consumer stamps on state derived from a specification — a
/// lifter's register map, a module built for an architecture — to establish
/// later that another specification is *the same one*, rather than one that
/// merely looks alike. It says nothing about decode configuration: the
/// default processor context ([`CompiledSpec::set_context_bytes`]) is not
/// part of it, since it changes what an instruction decodes to, not what the
/// specification is.
///
/// The digest is 128-bit FNV-1a. It is not a cryptographic commitment; it
/// distinguishes specifications that differ, which is all provenance needs.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SpecFingerprint(u128);

impl SpecFingerprint {
    const FNV_OFFSET: u128 = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d;
    const FNV_PRIME: u128 = 0x0000_0000_0100_0000_0000_0000_0000_013b;

    /// Digests the preprocessed source text a compilation consumed, under the
    /// compiler version doing it.
    pub(crate) fn of_compilation(preprocessed: &str) -> Self {
        let mut hash = Self::FNV_OFFSET;
        let mut absorb = |bytes: &[u8]| {
            for &byte in bytes {
                hash ^= u128::from(byte);
                hash = hash.wrapping_mul(Self::FNV_PRIME);
            }
        };
        let version = env!("CARGO_PKG_VERSION");
        absorb(&(version.len() as u64).to_le_bytes());
        absorb(version.as_bytes());
        absorb(&(preprocessed.len() as u64).to_le_bytes());
        absorb(preprocessed.as_bytes());
        Self(hash)
    }

    /// The digest as a number, for a consumer that stores it in state of
    /// its own.
    pub const fn as_u128(self) -> u128 {
        self.0
    }

    /// A fingerprint a consumer stored with [`as_u128`](Self::as_u128).
    pub const fn from_u128(digest: u128) -> Self {
        Self(digest)
    }
}

impl fmt::Debug for SpecFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SpecFingerprint({self})")
    }
}

impl fmt::Display for SpecFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:032x}", self.0)
    }
}

/// A compiled SLEIGH specification.
#[derive(Serialize, Deserialize)]
pub struct CompiledSpec {
    spec: Spec,
    context_len: crate::Size,
    context_bytes: ContextBytes,
    fingerprint: SpecFingerprint,
}

impl CompiledSpec {
    /// Constructors whose p-code has a local variable with no width, and that
    /// nothing a decode can supply one for.
    ///
    /// A SLEIGH local takes its width from its uses. When none of them gives
    /// one — the name was never declared, or every use is a width-less literal
    /// — the body cannot be lowered, and no encoding of that constructor can
    /// change it. Widths are resolved when the specification is compiled, so
    /// this is a property of the specification rather than of a decode, and a
    /// tool that compiles a specification should report it there.
    ///
    /// Each item is the constructor's source file, its byte range in that
    /// file, and how many of its locals are unsizable.
    pub fn unsized_locals(&self) -> impl Iterator<Item = (crate::FileId, usize, usize, usize)> {
        self.spec.trees.iter().flat_map(|tree| {
            tree.constructors
                .iter()
                .filter(|constructor| !constructor.pmacro.unsized_locals.is_empty())
                .map(|constructor| {
                    let src = constructor.src;
                    (
                        crate::FileId::from_index(src.file as usize),
                        src.start as usize,
                        src.end as usize,
                        constructor.pmacro.unsized_locals.len(),
                    )
                })
                .collect::<Vec<_>>()
        })
    }

    pub(crate) fn from_spec(spec: Spec, fingerprint: SpecFingerprint) -> Self {
        let context_len = spec.context_len() as crate::Size;
        Self {
            spec,
            context_len,
            context_bytes: ContextBytes {
                bytes: vec![0; context_len as usize],
            },
            fingerprint,
        }
    }

    /// The identity of this specification's content; see [`SpecFingerprint`].
    pub fn fingerprint(&self) -> SpecFingerprint {
        self.fingerprint
    }

    fn context_len(&self) -> usize {
        self.context_len as usize
    }

    /// The internal compiled specification, for in-crate consumers such as
    /// [`crate::introspect`] and [`crate::annotate`].
    pub(crate) fn inner(&self) -> &Spec {
        &self.spec
    }

    /// Creates a zero-initialized processor context for this specification.
    pub fn new_context(&self) -> ContextBytes {
        self.context_bytes.clone()
    }

    /// Replaces the default processor context this specification decodes with.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidLength`] if `context_bytes` is not the
    /// length this specification's context registers require — a buffer built
    /// with [`ContextBytes::from_raw`] carries no such guarantee.
    pub fn set_context_bytes(&mut self, context_bytes: ContextBytes) -> Result<(), ContextError> {
        self.validate_context(&context_bytes)?;
        self.context_bytes = context_bytes;
        Ok(())
    }

    /// Sets a named context field in an owned context buffer.
    pub fn set_context_field(
        &self,
        context: &mut ContextBytes,
        field: FieldId,
        value: u64,
    ) -> Result<(), ContextError> {
        self.validate_context(context)?;

        if usize::from(field) >= self.spec.fields.len() {
            return Err(ContextError::UnknownField { field });
        }
        let field_ref = self.spec.fields.get(field);

        if field_ref.parent != FieldParent::Context {
            return Err(ContextError::NotContextField { field });
        }

        let width = field_ref.width();
        if width < u64::BITS as usize && value >= (1u64 << width) {
            return Err(ContextError::ValueOutOfRange {
                field,
                width,
                value,
            });
        }

        self.spec
            .set_context_field(context.as_mut_bytes(), field, value);
        Ok(())
    }

    fn validate_context(&self, context: &ContextBytes) -> Result<(), ContextError> {
        let expected = self.context_len();
        let actual = context.len();
        if actual == expected {
            Ok(())
        } else {
            Err(ContextError::InvalidLength { expected, actual })
        }
    }

    /// Looks up a register by name.
    pub fn register(&self, name: &str) -> Option<RegisterRef<'_>> {
        self.spec
            .get_register_by_name(name)
            .map(|register| RegisterRef::new(register.id, register.inner))
    }

    /// Iterates over registers in stable registry order.
    pub fn registers(&self) -> impl Iterator<Item = RegisterRef<'_>> {
        self.spec
            .registers
            .iter()
            .map(|register| RegisterRef::new(register.id, register.inner))
    }

    /// The registers an `attach variables` table binds to a field's values,
    /// by value — the table a [`RegisterField`] indexes. `None` where the
    /// table binds no register (`_`); a value past the end has none either.
    pub fn attached_registers(&self, table: FieldTableId) -> &[Option<RegisterId>] {
        self.spec.field_tables.register_table(table)
    }

    /// The varnode register `id` is declared at: its space, offset and
    /// size. The inverse of [`register_at`](Self::register_at).
    pub fn register_varnode(&self, id: RegisterId) -> Option<Varnode> {
        (usize::from(id) < self.spec.registers.len()).then(|| {
            let register = &self.spec.registers[id];
            Varnode::new(register.space, register.offset as u64, register.size)
        })
    }

    /// The register declared at exactly `varnode`: same space, offset and
    /// size.
    pub fn register_at(&self, varnode: Varnode) -> Option<RegisterId> {
        self.spec.register_map.at(varnode)
    }

    /// `varnode` as a slice of the widest register that wholly contains it:
    /// `AH` is byte 1 of `RAX`, `XMM0` is the low 16 bytes of `ZMM0`.
    /// `None` when no register contains it, which includes every varnode
    /// outside a register space and any spanning two registers. See
    /// [`RegisterSlice`] for what the slice does and does not say.
    pub fn enclosing_register(&self, varnode: Varnode) -> Option<RegisterSlice> {
        self.spec.register_map.enclosing(varnode)
    }

    /// Every register sharing at least one byte with `varnode`, in offset
    /// order, widest first among registers at the same offset: for `AH`,
    /// `RAX`, `EAX`, `AX` and `AH` itself.
    pub fn overlapping_registers(&self, varnode: Varnode) -> impl Iterator<Item = RegisterId> + '_ {
        self.spec.register_map.overlapping(varnode)
    }

    /// Looks up a field by name.
    pub fn field(&self, name: &str) -> Option<FieldRef<'_>> {
        self.spec
            .get_field_by_name(name)
            .map(|field| FieldRef::new(field.id, field.inner))
    }

    /// Looks up a token by name.
    pub fn token(&self, name: &str) -> Option<TokenRef<'_>> {
        self.spec
            .get_token_by_name(name)
            .map(|token| TokenRef::new(token.id, token.inner))
    }

    /// Looks up a constructor table by name.
    pub fn table(&self, name: &str) -> Option<TableRef<'_>> {
        if let Some(&SymbolId::Table(id)) = self.spec.symbols.get(name) {
            Some(TableRef::new(id, &self.spec.trees[id.into()]))
        } else {
            None
        }
    }

    /// Looks up a memory space by name.
    pub fn space(&self, name: &str) -> Option<SpaceRef<'_>> {
        if let Some(&SymbolId::Space(id)) = self.spec.symbols.get(name) {
            Some(SpaceRef::new(id, &self.spec.spaces[id]))
        } else {
            None
        }
    }

    /// Iterates over public symbols known to the compiled spec.
    pub fn symbols(&self) -> impl Iterator<Item = SymbolRef<'_>> {
        self.spec.symbols.iter().map(|(name, &kind)| SymbolRef {
            name: name.as_ref(),
            kind: SymbolKind::from(kind),
        })
    }

    /// Returns the parent kind for a named token/context field.
    pub fn field_parent(&self, name: &str) -> Option<FieldParent> {
        if let Some(&SymbolId::Field(id)) = self.spec.symbols.get(name) {
            Some(self.spec.fields[id].parent)
        } else {
            None
        }
    }

    /// Returns the bit start position for a named token/context field.
    pub fn field_start(&self, name: &str) -> Option<usize> {
        if let Some(&SymbolId::Field(id)) = self.spec.symbols.get(name) {
            Some(self.spec.fields[id].range.start())
        } else {
            None
        }
    }

    /// Returns the name of the parent token for a named token field.
    pub fn field_token_name(&self, name: &str) -> Option<&str> {
        if let Some(&SymbolId::Field(id)) = self.spec.symbols.get(name)
            && let FieldParent::Token(tok_id) = self.spec.fields[id].parent
        {
            return Some(self.spec.token_name(tok_id));
        }
        None
    }

    /// Returns (offset_bits, size_bits) for a named bitrange field.
    pub fn bitrange_bits(&self, name: &str) -> Option<(usize, usize)> {
        if let Some(&SymbolId::BitRangeField(id)) = self.spec.symbols.get(name) {
            let br = &self.spec.bitranges[id];
            Some((br.offset(), br.size()))
        } else {
            None
        }
    }

    /// The space that bare addresses in this specification refer to.
    pub fn default_space(&self) -> SpaceId {
        self.spec.default_space
    }

    /// Iterates over memory spaces in stable registry order.
    ///
    /// The iteration order matches the [`SpaceId`] numbering, so a consumer can
    /// rebuild an equivalently-keyed collection by collecting in order.
    pub fn spaces(&self) -> impl Iterator<Item = SpaceRef<'_>> {
        self.spec
            .spaces
            .iter()
            .map(|space| SpaceRef::new(space.id, space.inner))
    }

    /// Iterates over user-defined p-code op names in stable registry order.
    ///
    /// These are the `define pcodeop` names; their position is the
    /// `PCodeOpId` used by [`PcodeAst`] call statements.
    pub fn pcode_ops(&self) -> impl Iterator<Item = &str> {
        self.spec.pcode_ops.iter().map(|op| &**op.inner)
    }

    /// Returns `(parent register, byte start, byte size)` for a bit-range field.
    pub fn bitrange_info(&self, id: BitRangeFieldId) -> Option<(RegisterId, usize, usize)> {
        if usize::from(id) >= self.spec.bitranges.len() {
            return None;
        }
        let field = self.spec.bitranges.get(id);
        Some((field.register, field.offset() / 8, field.size().div_ceil(8)))
    }

    pub(crate) fn spec(&self) -> &Spec {
        &self.spec
    }
}

impl fmt::Debug for CompiledSpec {
    /// A summary, not a dump: a compiled specification holds every constructor
    /// of every table and printing it in full is unreadable and slow.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompiledSpec")
            .field("tables", &self.spec.trees.len())
            .field("registers", &self.spec.registers.len())
            .field("spaces", &self.spec.spaces.len())
            .field("context_len", &self.context_len())
            .finish_non_exhaustive()
    }
}

/// Decoder for a compiled SLEIGH specification.
pub struct Decoder<'spec> {
    spec: &'spec CompiledSpec,
}

impl<'spec> Decoder<'spec> {
    /// Creates a decoder for `spec`.
    pub fn new(spec: &'spec CompiledSpec) -> Self {
        Self { spec }
    }

    /// Decodes one instruction at `addr` from `bytes`.
    ///
    /// # Errors
    ///
    /// Returns a [`DecodeError`]: [`NoMatch`] if no constructor matches the
    /// bytes (including when they run out mid-instruction), [`InvalidContext`]
    /// if `context` is not this specification's context length,
    /// [`InvalidAction`] if a disassembly action divides by zero or shifts past
    /// the word width, and [`AmbiguousMatch`] if several constructors match and
    /// none is more specific.
    ///
    /// [`NoMatch`]: DecodeError::NoMatch
    /// [`InvalidContext`]: DecodeError::InvalidContext
    /// [`InvalidAction`]: DecodeError::InvalidAction
    /// [`AmbiguousMatch`]: DecodeError::AmbiguousMatch
    ///
    /// Decoding is pure: `context` is read, never written. An instruction that
    /// wants to change it for later instructions says so through
    /// [`Instruction::context_effects`], and [`ContextDatabase`] is the opt-in
    /// store that feeds those back.
    ///
    /// ```
    /// # use sleigh::{Compiler, Decoder, SourceDb};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mut sources = SourceDb::new();
    /// # let root = sources.add_file("tiny.slaspec", "define endian=little;
    /// #     define space ram type=ram_space size=4 default;
    /// #     define space register type=register_space size=4;
    /// #     define register offset=0 size=4 [ r0 ];
    /// #     define token instr(8) op=(0,7);
    /// #     :inc is op=1 { r0 = r0 + 1; }");
    /// # let spec = Compiler::new(&mut sources).compile(root)?;
    /// let decoder = Decoder::new(&spec);
    /// let context = spec.new_context();
    ///
    /// // `bytes` is the stream from `addr` on; only what the instruction
    /// // needs is read, and the rest is left for the next call.
    /// let instruction = decoder.decode_one(0x1000, &[1, 1, 1], &context)?;
    /// assert_eq!(instruction.display()?, "inc");
    /// assert_eq!(instruction.len(), 1);
    /// assert_eq!(instruction.next_address(), 0x1001);
    /// # Ok(())
    /// # }
    /// ```
    pub fn decode_one<'bytes>(
        &self,
        addr: u64,
        bytes: &'bytes [u8],
        context: &ContextBytes,
    ) -> Result<Instruction<'spec, 'bytes>, DecodeError> {
        self.spec
            .validate_context(context)
            .map_err(|_| DecodeError::InvalidContext)?;
        let instance = Walker::try_get(
            addr,
            bytes,
            &self.spec.spec,
            self.spec.context_len(),
            context.as_bytes(),
        )?;
        if instance.size > bytes.len() {
            return Err(DecodeError::InternalInvariant);
        }
        // Covers the delay slot as well, so `Instruction::delay_slots` can hand
        // each delayed instruction its own bytes. `Instruction::bytes` still
        // returns only this instruction's.
        let consumed = instance.size + instance.delay_slot_len;
        if consumed > bytes.len() {
            return Err(DecodeError::InternalInvariant);
        }
        let raw_bytes = Cow::Borrowed(&bytes[..consumed]);
        Ok(Instruction {
            spec: self.spec,
            instance,
            raw_bytes,
        })
    }

    /// [`decode_one`](Self::decode_one), also reporting the instruction's
    /// [`Shape`]: which bits chose its constructors and which fields are
    /// its parameters. Costs a little more than a plain decode.
    ///
    /// Two encodings of one shape — equal after masking, whatever their
    /// parameters — decode to the same constructors and operand layout
    /// under the same context, so per-encoding work can be shared across
    /// them; see [`Shape`].
    pub fn decode_one_shaped<'bytes>(
        &self,
        addr: u64,
        bytes: &'bytes [u8],
        context: &ContextBytes,
    ) -> Result<(Instruction<'spec, 'bytes>, Shape), DecodeError> {
        self.spec
            .validate_context(context)
            .map_err(|_| DecodeError::InvalidContext)?;
        let recorder = shape::ShapeRecorder::default();
        let instance = Walker::try_get_shaped(
            addr,
            bytes,
            &self.spec.spec,
            self.spec.context_len(),
            context.as_bytes(),
            &recorder,
        )?;
        let consumed = instance.size + instance.delay_slot_len;
        if consumed > bytes.len() {
            return Err(DecodeError::InternalInvariant);
        }
        let shape = recorder.finish(instance.size);
        let raw_bytes = Cow::Borrowed(&bytes[..consumed]);
        Ok((
            Instruction {
                spec: self.spec,
                instance,
                raw_bytes,
            },
            shape,
        ))
    }
}

/// A constructor selected while decoding an [`Instruction`].
///
/// SLEIGH instruction patterns recursively enter operand tables, so one encoded
/// instruction usually selects more than its top-level constructor. This value
/// identifies one entry in that complete selected-constructor path.
pub struct ConstructorMatch<'spec> {
    table: TableRef<'spec>,
    index: usize,
}

impl<'spec> ConstructorMatch<'spec> {
    fn from_instance(spec: &'spec CompiledSpec, instance: &ConstructorInstance) -> Self {
        let table_id = TableId::from(usize::from(instance.tree));
        Self {
            table: TableRef::new(table_id, &spec.spec.trees[instance.tree]),
            index: instance.id.into(),
        }
    }

    /// Table containing the selected constructor.
    pub fn table(&self) -> &TableRef<'spec> {
        &self.table
    }

    /// Zero-based index of the selected constructor within [`table`](Self::table).
    pub fn index(&self) -> usize {
        self.index
    }
}

/// Decoded instruction plus access to its compiled specification.
#[derive(Clone)]
pub struct Instruction<'spec, 'bytes> {
    spec: &'spec CompiledSpec,
    instance: ConstructorInstance,
    raw_bytes: Cow<'bytes, [u8]>,
}

impl<'spec, 'bytes> Instruction<'spec, 'bytes> {
    /// Instruction address.
    pub fn address(&self) -> u64 {
        self.instance.inst_start
    }

    /// Address immediately after this instruction *and its delay slot*.
    ///
    /// This is SLEIGH's semantic `inst_next` (manual §7.11): the delay-slot
    /// bytes belong to this instruction's p-code, so control resumes past them.
    /// A listing walker that wants the next *encoded* instruction and intends
    /// to render the delayed ones itself should use
    /// [`address`](Self::address)` + `[`len`](Self::len) instead; stepping by
    /// `next_address` skips them, which is correct for a lifter and wrong for a
    /// disassembly view.
    pub fn next_address(&self) -> u64 {
        self.instance.semantic_inst_next()
    }

    /// Length of this instruction alone, in bytes, excluding its delay slot.
    pub fn len(&self) -> usize {
        self.instance.size
    }

    /// Total length of the instructions filling this one's delay slot.
    ///
    /// Zero for everything but a delay-slot branch on MIPS, SPARC, SuperH and
    /// friends.
    pub fn delay_slot_len(&self) -> usize {
        self.instance.delay_slot_len
    }

    /// The instructions filling this one's delay slot, in address order.
    ///
    /// Their p-code is already spliced into
    /// [`pcode_ast`](Self::pcode_ast) at the point the `delayslot` directive
    /// sits, so a lifter does not need these — a disassembly listing does.
    pub fn delay_slots(&self) -> impl Iterator<Item = Instruction<'spec, '_>> + '_ {
        let mut offset = self.instance.size;
        self.instance.delay_slots.iter().map(move |delayed| {
            let start = offset;
            offset += delayed.size;
            Instruction {
                spec: self.spec,
                instance: delayed.clone(),
                raw_bytes: Cow::Borrowed(&self.raw_bytes[start..offset]),
            }
        })
    }

    /// Returns true when the instruction has zero encoded bytes.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Encoded bytes of this instruction, excluding its delay slot.
    pub fn bytes(&self) -> &[u8] {
        &self.raw_bytes[..self.len()]
    }

    /// Compiled specification that decoded this instruction.
    pub fn spec(&self) -> &'spec CompiledSpec {
        self.spec
    }

    /// Constructor table that produced this instruction.
    pub fn constructor_table(&self) -> TableRef<'spec> {
        TableRef::new(
            TableId::from(usize::from(self.instance.tree)),
            &self.spec.spec.trees[self.instance.tree],
        )
    }

    /// Index of the matched constructor within its table.
    pub fn constructor_index(&self) -> usize {
        self.instance.id.into()
    }

    /// Number of decoded operand values attached to the matched constructor.
    pub fn operand_count(&self) -> usize {
        self.instance.operand_values.len()
    }

    /// Iterates over every constructor selected while decoding this instruction.
    ///
    /// The root instruction constructor is first, followed recursively by
    /// constructors selected from operand tables. Constructors of decoded delay
    /// slots are included after the root instruction's operand path.
    pub fn constructor_matches(&self) -> impl Iterator<Item = ConstructorMatch<'spec>> + '_ {
        fn collect<'a>(
            instance: &'a ConstructorInstance,
            matches: &mut Vec<&'a ConstructorInstance>,
        ) {
            matches.push(instance);
            for operand in &instance.operand_values {
                if let crate::instance::OperandValue::Constructor(child) = operand {
                    collect(child, matches);
                }
            }
            for delay_slot in &instance.delay_slots {
                collect(delay_slot, matches);
            }
        }

        let mut matches = Vec::new();
        collect(&self.instance, &mut matches);
        matches
            .into_iter()
            .map(move |instance| ConstructorMatch::from_instance(self.spec, instance))
    }

    /// Context changes this instruction's disassembly actions request.
    ///
    /// Empty for the vast majority of instructions. Decoding is pure, so a
    /// caller that wants these to affect later decodes has to remember them —
    /// [`ContextDatabase`] does that.
    pub fn context_effects(&self) -> &[ContextEffect] {
        &self.instance.context_effects
    }

    /// Renders the SLEIGH display string for this instruction.
    ///
    /// # Errors
    ///
    /// Returns [`DecodeError::UnresolvedDisplay`] if the matched constructor's
    /// display references a sub-table or field this decode supplies no value
    /// for, or an attach-table entry that is out of range or unattached.
    pub fn display(&self) -> Result<String, DecodeError> {
        self.instance.try_to_string(&self.spec.spec)
    }

    /// Returns the backend-neutral p-code AST for this instruction.
    ///
    /// # Errors
    ///
    /// Returns an [`EmitError`] if the matched constructor's semantics cannot
    /// be expanded — an unresolvable operand, or a construct this crate does
    /// not yet lower.
    ///
    /// The AST is owned and borrows nothing from this instruction or its
    /// specification, so it outlives both. See the [`semantics`](crate::semantics)
    /// module for the type graph and what has already been expanded away.
    ///
    /// ```
    /// # use sleigh::{Compiler, Decoder, SourceDb};
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// # let mut sources = SourceDb::new();
    /// # let root = sources.add_file("tiny.slaspec", "define endian=little;
    /// #     define space ram type=ram_space size=4 default;
    /// #     define space register type=register_space size=4;
    /// #     define register offset=0 size=4 [ r0 ];
    /// #     define token instr(8) op=(0,7);
    /// #     :inc is op=1 { r0 = r0 + 1; }");
    /// # let spec = Compiler::new(&mut sources).compile(root)?;
    /// let instruction = Decoder::new(&spec)
    ///     .decode_one(0x1000, &[1], &spec.new_context())?;
    ///
    /// let ast = instruction.pcode_ast()?;
    /// assert_eq!(ast.pretty_print(&spec), "r0 = (r0 + 1);");
    /// # Ok(())
    /// # }
    /// ```
    pub fn pcode_ast(&self) -> Result<PcodeAst, EmitError> {
        pcode_ast_for_instance(&self.spec.spec, &self.instance)
    }

    /// Returns raw Ghidra-style flat p-code operations for this instruction.
    ///
    /// This lowers the fully expanded [`PcodeAst`] returned by
    /// [`pcode_ast`](Self::pcode_ast), allocating instruction-local temporaries
    /// in the compiled specification's real unique space.
    pub fn pcode_ops(&self) -> Result<InstructionPcode, EmitError> {
        let ast = self.pcode_ast()?;
        lower_instruction(&ast, &InstructionPcodeContext::new(&self.spec.spec))
            .map_err(|error| EmitError::new(error.to_string()))
    }

    /// Lowers flat p-code into `sink` without returning an owned
    /// [`InstructionPcode`].
    ///
    /// This is the production-path counterpart to [`pcode_ops`](Self::pcode_ops):
    /// consumers can synchronously lower the resolved p-code while it remains
    /// internal to this call. `pcode_ops` remains available for inspection,
    /// serialization, and differential tests.
    pub fn pcode_ops_into<R>(&self, sink: impl FnOnce(&[PcodeOp]) -> R) -> Result<R, EmitError> {
        let ast = self.pcode_ast()?;
        lower_instruction_into(&ast, &InstructionPcodeContext::new(&self.spec.spec), sink)
            .map_err(|error| EmitError::new(error.to_string()))
    }

    /// Plans this instruction's flat p-code, then streams it into a sink.
    ///
    /// `make_sink` receives the [`PcodePlan`] — the labels and the branch and
    /// call destinations of the whole instruction — so a consumer can prepare
    /// its instruction-wide state before any operation arrives, and never has
    /// to re-scan a flat p-code vector. The sink is returned so the consumer
    /// can recover its result.
    ///
    /// This is the production path: it plans and emits straight from the
    /// resolved semantics, and never builds the [`PcodeAst`] that
    /// [`pcode_ops`](Self::pcode_ops) lowers. The operations are the same.
    pub fn pcode_ops_streamed<S: PcodeSink>(
        &self,
        make_sink: impl FnOnce(&PcodePlan) -> S,
    ) -> Result<S, EmitError> {
        self.try_pcode_ops_streamed(|plan| Ok(make_sink(plan)))
    }

    /// [`pcode_ops_streamed`](Self::pcode_ops_streamed) for a consumer whose
    /// preparation can fail: resolving the plan's destinations may be refused
    /// by the module it lowers into, and then nothing is streamed.
    pub fn try_pcode_ops_streamed<S: PcodeSink, E: From<EmitError>>(
        &self,
        make_sink: impl FnOnce(&PcodePlan) -> Result<S, E>,
    ) -> Result<S, E> {
        stream_instance(&self.spec.spec, &self.instance, make_sink)
    }

    /// Alias for [`pcode_ops`](Self::pcode_ops).
    pub fn instruction_pcode(&self) -> Result<InstructionPcode, EmitError> {
        self.pcode_ops()
    }

    /// Emits backend-neutral semantics into `sink`.
    ///
    /// # Errors
    ///
    /// Returns an [`EmitError`] if the p-code AST cannot be built (see
    /// [`Instruction::pcode_ast`]) or if `sink` rejects it.
    pub fn emit_into<S: SemanticsSink>(&self, sink: &mut S) -> Result<(), EmitError> {
        let info = InstructionInfo {
            address: self.address(),
            length: self.len(),
        };
        let pcode = self.pcode_ast()?;
        sink.instruction(&info, &pcode)
    }

    /// Converts borrowed instruction bytes into owned bytes.
    pub fn into_owned_bytes(self) -> Instruction<'spec, 'static> {
        Instruction {
            spec: self.spec,
            instance: self.instance,
            raw_bytes: Cow::Owned(self.raw_bytes.into_owned()),
        }
    }
}

impl fmt::Debug for Instruction<'_, '_> {
    /// Address, encoding and rendered assembly — enough to identify the
    /// instruction in a test failure without dumping the whole decode tree.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Instruction")
            .field("address", &format_args!("{:#x}", self.address()))
            .field("bytes", &self.bytes())
            .field("display", &format_args!("{self}"))
            .finish_non_exhaustive()
    }
}

impl fmt::Display for Instruction<'_, '_> {
    /// Renders the display string, or the reason it could not be rendered —
    /// `fmt::Display` has nowhere to report an error, and a silently truncated
    /// disassembly line would be worse than a visible marker. Use
    /// [`Instruction::display`] to handle the failure.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.instance.try_to_string(&self.spec.spec) {
            Ok(text) => f.write_str(&text),
            Err(err) => write!(f, "<{err}>"),
        }
    }
}
