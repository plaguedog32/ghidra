//! Pure Rust SLEIGH source compilation and explicit p-code adaptation.
//!
//! This foundation compiles `.slaspec` and included `.sinc` source directly.
//! It neither invokes Java/C++ nor reads Ghidra's precompiled `.sla` format.
//! Processor support is measured by tests, not inferred from successful parsing.
//! Only byte-addressed spaces are admitted by this adapter. Catalog loading
//! applies `.pspec` decode defaults; raw source loading requires caller defaults.

mod catalog;

use std::{collections::BTreeMap, path::Path};

use ghidra_pcode::{
    AddressSpace, Endianness, Opcode, PcodeInstruction, PcodeOperation, SpaceId, SpaceKind, Varnode,
};
use sleigh::{CompiledSpec, ContextDatabase, Decoder, SourceDb};
use thiserror::Error;

/// Maximum byte window used to decode an instruction and any delay slots.
pub const MAX_DECODE_BYTES: usize = 4096;

#[derive(Debug, Error)]
pub enum Error {
    #[error("cannot load SLEIGH source: {0}")]
    Source(String),
    #[error("SLEIGH source compilation failed: {0}")]
    Compile(String),
    #[error("invalid processor context: {0}")]
    Context(String),
    #[error("SLEIGH decoding failed at 0x{address:X}: {message}")]
    Decode { address: u64, message: String },
    #[error("SLEIGH p-code lowering failed: {0}")]
    Lower(String),
    #[error("unsupported SLEIGH feature: {0}")]
    Unsupported(String),
    #[error("invalid adapted p-code: {0}")]
    Pcode(#[from] ghidra_pcode::Error),
    #[error("SLEIGH address arithmetic overflow")]
    AddressOverflow,
    #[error("SLEIGH compiler/runtime panicked: {0}")]
    DependencyPanic(String),
}

/// A source-compiled processor and its address-dependent decoding context.
pub struct SleighLanguage {
    spec: CompiledSpec,
    context: ContextDatabase,
    spaces: Vec<AddressSpace>,
    code_space: SpaceId,
    userops: Vec<String>,
    instruction_endianness: Endianness,
    catalog_context: Option<catalog::CatalogContext>,
}

#[derive(Debug, Clone)]
pub struct LiftedInstruction {
    pub text: String,
    /// Length of the displayed instruction, excluding delay-slot instructions.
    pub length: u32,
    /// Address after this instruction and its delay slots, not its branch target.
    pub next_address: u64,
    /// Delay-slot instructions are already expanded into this operation list.
    /// Its length covers the whole bundle so a concrete evaluator does not
    /// execute the delay slots a second time on fallthrough.
    pub instruction: PcodeInstruction,
    pub delay_slots: Vec<DelaySlot>,
}

#[derive(Debug, Clone)]
pub struct DelaySlot {
    pub address: u64,
    pub length: u32,
    pub text: String,
}

/// One declared register alias in the processor specification.
#[derive(Debug, Clone)]
pub struct NamedRegister {
    pub name: String,
    pub space: SpaceId,
    pub offset: u64,
    pub size: u32,
}

impl SleighLanguage {
    pub fn from_spec(spec_path: &Path, context: &BTreeMap<String, u64>) -> Result<Self, Error> {
        guard(|| Self::compile(spec_path, context))
    }

    fn compile(spec_path: &Path, overrides: &BTreeMap<String, u64>) -> Result<Self, Error> {
        let mut sources = SourceDb::new();
        let root = sources
            .add_file_from_path(spec_path)
            .map_err(|error| Error::Source(error.to_string()))?;
        // The public runtime omits global byte order. Read it from the same
        // preprocessed source AST the pinned compiler uses, including includes.
        let parsed =
            sleigh::parse(&mut sources, root).map_err(|error| Error::Compile(error.to_string()))?;
        let endianness = parsed
            .file
            .items
            .iter()
            .find_map(|item| match item {
                sleigh::SleighItem::Endianness(definition) => Some(if definition.big_endian {
                    Endianness::Big
                } else {
                    Endianness::Little
                }),
                _ => None,
            })
            .ok_or_else(|| Error::Unsupported("no top-level byte-order declaration".into()))?;
        let mut spec = sleigh::Compiler::new(&mut sources)
            .compile(root)
            .map_err(|error| Error::Compile(error.to_string()))?;
        let mut context_bytes = spec.new_context();
        for (name, value) in overrides {
            let field = spec
                .field(name)
                .ok_or_else(|| Error::Context(format!("unknown field {name}")))?;
            spec.set_context_field(&mut context_bytes, field.id, *value)
                .map_err(|error| Error::Context(format!("{name}: {error}")))?;
        }
        spec.set_context_bytes(context_bytes)
            .map_err(|error| Error::Context(error.to_string()))?;
        let mut spaces = Vec::new();
        for source in spec.spaces() {
            if source.word_size() != 1 {
                return Err(Error::Unsupported(format!(
                    "space {:?} has word size {}; this adapter admits only byte-addressed spaces",
                    source.name(),
                    source.word_size()
                )));
            }
            let id = space_id(source.id)?;
            let kind = if source.id == sleigh::SPACE_CONST {
                SpaceKind::Constant
            } else {
                match source.space().ty {
                    sleigh::SpaceType::Ram => SpaceKind::Ram,
                    sleigh::SpaceType::Register => SpaceKind::Register,
                    sleigh::SpaceType::Unique => SpaceKind::Unique,
                    // The execution model has no read-only ROM kind yet.
                    sleigh::SpaceType::Rom => return Err(Error::Unsupported("ROM-space access permissions are not represented by the current execution model".into())),
                }
            };
            let space = AddressSpace {
                id,
                name: source
                    .name()
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("space_{}", id.0)),
                kind,
                address_size: u8::try_from(source.address_size())
                    .map_err(|_| Error::Unsupported("address size exceeds u8".into()))?,
                word_size: 1,
                endianness,
            };
            space.validate()?;
            spaces.push(space);
        }
        let code_space = space_id(spec.default_space())?;
        if !spaces.iter().any(|space| space.id == code_space) {
            return Err(Error::Unsupported("default code space is missing".into()));
        }
        let userops = spec.pcode_ops().map(str::to_owned).collect();
        let context = ContextDatabase::new(&spec);
        Ok(Self {
            spec,
            context,
            spaces,
            code_space,
            userops,
            instruction_endianness: endianness,
            catalog_context: None,
        })
    }

    pub fn spaces(&self) -> &[AddressSpace] {
        &self.spaces
    }

    pub fn code_space(&self) -> SpaceId {
        self.code_space
    }

    /// Byte order declared by the source decoder. RAM data byte order can differ.
    pub fn instruction_endianness(&self) -> Endianness {
        self.instruction_endianness
    }

    /// CALLOTHER input zero indexes this table. Preserving a userop does not
    /// implement its processor-specific behavior in the evaluator.
    pub fn userops(&self) -> &[String] {
        &self.userops
    }

    /// Declared register storage, including overlapping aliases.
    pub fn register(&self, name: &str) -> Option<Varnode> {
        let register = self.spec.register(name)?;
        let varnode = self.spec.register_varnode(register.id)?;
        self.adapt_varnode(varnode).ok()
    }

    /// Enumerate all declared registers, preserving overlapping aliases.
    /// An unsupported register width is reported rather than silently omitted.
    pub fn registers(&self) -> Result<Vec<NamedRegister>, Error> {
        self.spec
            .registers()
            .map(|register| {
                let source = self.spec.register_varnode(register.id).ok_or_else(|| {
                    Error::Unsupported(format!("register {} has no storage", register.name()))
                })?;
                let varnode = self.adapt_varnode(source)?;
                Ok(NamedRegister {
                    name: register.name().into(),
                    space: varnode.space,
                    offset: varnode.offset,
                    size: varnode.size,
                })
            })
            .collect()
    }

    /// Reset all address-specific context commits to the caller-supplied defaults.
    pub fn reset_context(&mut self) {
        self.context.clear();
    }

    pub fn decode(&mut self, address: u64, bytes: &[u8]) -> Result<LiftedInstruction, Error> {
        self.decode_with_defaults(address, bytes, &BTreeMap::new())
    }

    /// Address-specific processor defaults sit beneath recorded `globalset`
    /// effects. They are recomputed for every request and cannot leak into the
    /// next address. Global/user overrides supplied at compilation remain the
    /// baseline for fields absent from `defaults`.
    pub fn decode_with_defaults(
        &mut self,
        address: u64,
        bytes: &[u8],
        defaults: &BTreeMap<String, u64>,
    ) -> Result<LiftedInstruction, Error> {
        guard(|| self.decode_inner(address, bytes, defaults))
    }

    fn decode_inner(
        &mut self,
        address: u64,
        bytes: &[u8],
        defaults: &BTreeMap<String, u64>,
    ) -> Result<LiftedInstruction, Error> {
        let code = self
            .spaces
            .iter()
            .find(|space| space.id == self.code_space)
            .ok_or_else(|| Error::Unsupported("missing code space".into()))?;
        if code.address_size < 8 && address >= 1u64 << (code.address_size * 8) {
            return Err(Error::AddressOverflow);
        }
        let bytes = &bytes[..bytes.len().min(MAX_DECODE_BYTES)];
        let mut effective = self
            .catalog_context
            .as_ref()
            .map(|context| context.at(address))
            .transpose()?
            .unwrap_or_default();
        effective.extend(defaults.iter().map(|(name, value)| (name.clone(), *value)));
        if let Some(context) = &self.catalog_context {
            effective.extend(context.overrides.clone());
        }
        let mut baseline = self.spec.new_context();
        for (name, value) in &effective {
            let field = self
                .spec
                .field(name)
                .ok_or_else(|| Error::Context(format!("unknown field {name}")))?;
            self.spec
                .set_context_field(&mut baseline, field.id, *value)
                .map_err(|e| Error::Context(format!("{name}: {e}")))?;
        }
        self.context
            .set_default_context(baseline)
            .map_err(|e| Error::Context(e.to_string()))?;
        let context = self.context.context_at(address);
        let decoded = Decoder::new(&self.spec)
            .decode_one(address, bytes, &context)
            .map_err(|error| Error::Decode {
                address,
                message: error.to_string(),
            })?;
        let text = decoded.display().map_err(|error| Error::Decode {
            address,
            message: error.to_string(),
        })?;
        let length = u32::try_from(decoded.len()).map_err(|_| Error::AddressOverflow)?;
        if length == 0 {
            return Err(Error::Decode {
                address,
                message: "zero-length instruction".into(),
            });
        }
        let mut total = u64::from(length);
        let mut delay_slots = Vec::new();
        for slot in decoded.delay_slots() {
            let slot_length = u32::try_from(slot.len()).map_err(|_| Error::AddressOverflow)?;
            let slot_address = address.checked_add(total).ok_or(Error::AddressOverflow)?;
            if let Some(context) = &self.catalog_context {
                let mut slot_defaults = context.at(slot_address)?;
                slot_defaults.extend(defaults.clone());
                slot_defaults.extend(context.overrides.clone());
                if slot_defaults != effective {
                    return Err(Error::Unsupported(
                        "processor defaults change inside a delay-slot bundle".into(),
                    ));
                }
            }
            delay_slots.push(DelaySlot {
                address: slot_address,
                length: slot_length,
                text: slot.display().map_err(|error| Error::Decode {
                    address: slot_address,
                    message: error.to_string(),
                })?,
            });
            total = total
                .checked_add(u64::from(slot_length))
                .ok_or(Error::AddressOverflow)?;
        }
        let next_address = address.checked_add(total).ok_or(Error::AddressOverflow)?;
        if total > bytes.len() as u64
            || next_address != decoded.next_address()
            || (code.address_size < 8 && next_address > 1u64 << (code.address_size * 8))
        {
            return Err(Error::AddressOverflow);
        }
        let raw = decoded
            .pcode_ops()
            .map_err(|error| Error::Lower(error.to_string()))?;
        if raw.ops.len() > ghidra_pcode::model::MAX_OPS_PER_INSTRUCTION {
            return Err(Error::Unsupported(
                "more than 16384 operations in one lifted instruction".into(),
            ));
        }
        let mut ops = Vec::with_capacity(raw.ops.len());
        for operation in raw.ops {
            let mut opcode = adapt_opcode(operation.opcode)?;
            if operation.inputs.len() > ghidra_pcode::model::MAX_INPUTS {
                return Err(Error::Unsupported("more than 1024 p-code inputs".into()));
            }
            let output = operation
                .output
                .map(|varnode| self.adapt_varnode(varnode))
                .transpose()?;
            let inputs = operation
                .inputs
                .into_iter()
                .map(|varnode| self.adapt_varnode(varnode))
                .collect::<Result<Vec<_>, _>>()?;
            // Some source specifications use sext/zext at a width that depends
            // on the selected processor variant. The source lowerer retains
            // these when both widths become equal (e.g. MIPS32 LUI). In that
            // case the bit-vector operation is exactly COPY; canonicalize it
            // here instead of weakening the execution model's validation.
            if matches!(opcode, Opcode::IntSext | Opcode::IntZext)
                && inputs.len() == 1
                && output.is_some_and(|output| output.size == inputs[0].size)
            {
                opcode = Opcode::Copy;
            }
            if opcode == Opcode::Callother {
                let input = inputs.first().ok_or_else(|| {
                    Error::Unsupported("CALLOTHER has no userop identifier".into())
                })?;
                if input.space != space_id(sleigh::SPACE_CONST)?
                    || input.offset >= self.userops.len() as u64
                {
                    return Err(Error::Unsupported(
                        "CALLOTHER identifier is not a declared constant userop".into(),
                    ));
                }
            }
            ops.push(PcodeOperation {
                opcode,
                output,
                inputs,
            });
        }
        let instruction = PcodeInstruction {
            address,
            length: u32::try_from(total).map_err(|_| Error::AddressOverflow)?,
            ops,
        };
        instruction.validate()?;
        // Failed lowering/validation must not advance context state.
        self.context.apply(&decoded);
        Ok(LiftedInstruction {
            text,
            length,
            next_address,
            instruction,
            delay_slots,
        })
    }

    fn adapt_varnode(&self, source: sleigh::Varnode) -> Result<Varnode, Error> {
        let space = space_id(source.space)?;
        let definition = self
            .spaces
            .iter()
            .find(|definition| definition.id == space)
            .ok_or_else(|| Error::Unsupported(format!("unknown varnode space {}", space.0)))?;
        let size = u32::try_from(source.size)
            .map_err(|_| Error::Unsupported("varnode size overflows u32".into()))?;
        let result = Varnode {
            space,
            offset: source.offset,
            size,
        };
        result.validate()?;
        if definition.kind != SpaceKind::Constant {
            let end = source
                .offset
                .checked_add(u64::from(size))
                .ok_or(Error::AddressOverflow)?;
            if definition.address_size < 8 && end > 1u64 << (definition.address_size * 8) {
                return Err(Error::AddressOverflow);
            }
        }
        Ok(result)
    }
}

fn space_id(source: sleigh::SpaceId) -> Result<SpaceId, Error> {
    u32::try_from(usize::from(source))
        .map(SpaceId)
        .map_err(|_| Error::Unsupported("space identifier overflows u32".into()))
}

fn guard<T>(operation: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)).map_err(|payload| {
        let message = payload
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| payload.downcast_ref::<&str>().map(|text| text.to_string()))
            .unwrap_or_else(|| "non-string panic".into());
        Error::DependencyPanic(message)
    })?
}

/// Deliberate variant mapping. In particular, old EXTRACT (numeric 71) is
/// not silently accepted as this upstream's ZPULL, and SPULL is not invented.
fn adapt_opcode(source: sleigh::Opcode) -> Result<Opcode, Error> {
    use sleigh::Opcode as S;
    Ok(match source {
        S::Copy => Opcode::Copy,
        S::Load => Opcode::Load,
        S::Store => Opcode::Store,
        S::Branch => Opcode::Branch,
        S::CBranch => Opcode::Cbranch,
        S::BranchInd => Opcode::Branchind,
        S::Call => Opcode::Call,
        S::CallInd => Opcode::Callind,
        S::CallOther => Opcode::Callother,
        S::Return => Opcode::Return,
        S::IntEqual => Opcode::IntEqual,
        S::IntNotEqual => Opcode::IntNotequal,
        S::IntSLess => Opcode::IntSless,
        S::IntSLessEqual => Opcode::IntSlessequal,
        S::IntLess => Opcode::IntLess,
        S::IntLessEqual => Opcode::IntLessequal,
        S::IntZext => Opcode::IntZext,
        S::IntSext => Opcode::IntSext,
        S::IntAdd => Opcode::IntAdd,
        S::IntSub => Opcode::IntSub,
        S::IntCarry => Opcode::IntCarry,
        S::IntSCarry => Opcode::IntScarry,
        S::IntSBorrow => Opcode::IntSborrow,
        S::Int2Comp => Opcode::Int2Comp,
        S::IntNegate => Opcode::IntNegate,
        S::IntXor => Opcode::IntXor,
        S::IntAnd => Opcode::IntAnd,
        S::IntOr => Opcode::IntOr,
        S::IntLeft => Opcode::IntLeft,
        S::IntRight => Opcode::IntRight,
        S::IntSRight => Opcode::IntSright,
        S::IntMult => Opcode::IntMult,
        S::IntDiv => Opcode::IntDiv,
        S::IntSDiv => Opcode::IntSdiv,
        S::IntRem => Opcode::IntRem,
        S::IntSRem => Opcode::IntSrem,
        S::BoolNegate => Opcode::BoolNegate,
        S::BoolXor => Opcode::BoolXor,
        S::BoolAnd => Opcode::BoolAnd,
        S::BoolOr => Opcode::BoolOr,
        S::FloatEqual => Opcode::FloatEqual,
        S::FloatNotEqual => Opcode::FloatNotequal,
        S::FloatLess => Opcode::FloatLess,
        S::FloatLessEqual => Opcode::FloatLessequal,
        S::FloatNan => Opcode::FloatNan,
        S::FloatAdd => Opcode::FloatAdd,
        S::FloatDiv => Opcode::FloatDiv,
        S::FloatMult => Opcode::FloatMult,
        S::FloatSub => Opcode::FloatSub,
        S::FloatNeg => Opcode::FloatNeg,
        S::FloatAbs => Opcode::FloatAbs,
        S::FloatSqrt => Opcode::FloatSqrt,
        S::FloatInt2Float => Opcode::FloatInt2Float,
        S::FloatFloat2Float => Opcode::FloatFloat2Float,
        S::FloatTrunc => Opcode::FloatTrunc,
        S::FloatCeil => Opcode::FloatCeil,
        S::FloatFloor => Opcode::FloatFloor,
        S::FloatRound => Opcode::FloatRound,
        S::Piece => Opcode::Piece,
        S::SubPiece => Opcode::Subpiece,
        S::PopCount => Opcode::Popcount,
        S::LzCount => Opcode::Lzcount,
        S::MultiEqual
        | S::Indirect
        | S::Cast
        | S::PtrAdd
        | S::PtrSub
        | S::SegmentOp
        | S::CpoolRef
        | S::New
        | S::Insert
        | S::Extract => {
            return Err(Error::Unsupported(format!(
                "analysis-only or unadapted opcode {source:?}"
            )));
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_extract_slot_is_not_silently_reinterpreted_as_new_zpull() {
        assert_eq!(sleigh::Opcode::Extract as u8, Opcode::Zpull as u8);
        assert!(matches!(
            adapt_opcode(sleigh::Opcode::Extract),
            Err(Error::Unsupported(_))
        ));
    }
}
