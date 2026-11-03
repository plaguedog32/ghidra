//! Bounded concrete execution of supplied P-code, without executing native code.
//!
//! State is byte-addressed, so overlapping register varnodes alias correctly.
//! Only LOAD/STORE scale pointers by a space's word size. Calls transfer control;
//! architecture-specific stack and return-address effects must be in the P-code.
//! Userops, SSA selection, and unimplemented operations fail explicitly.

use crate::{
    AddressSpace, Endianness, Opcode, PcodeInstruction, PcodeOperation, SpaceId, SpaceKind, Value,
    Varnode, evaluate_pure,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use thiserror::Error;

const PAGE_SIZE: usize = 4096;
const MAX_MEMORY: usize = 64 * 1024 * 1024;
const MAX_PROGRAM_OPS: usize = 1_000_000;
const MAX_STEPS: u64 = 10_000_000;
const MAX_TRACE: usize = 4096;
const MAX_SNAPSHOT_BYTES: usize = 1024 * 1024;
const MAX_SNAPSHOT_REGIONS: usize = 4096;

#[derive(Debug, Error)]
pub enum MachineError {
    #[error("invalid P-code program: {0}")]
    InvalidProgram(String),
    #[error("unknown address space {0:?}")]
    UnknownSpace(SpaceId),
    #[error("cannot write the constant address space")]
    ReadOnlySpace,
    #[error("uninitialized byte at {space:?}:0x{offset:X}")]
    Uninitialized { space: SpaceId, offset: u64 },
    #[error("address range overflows its space")]
    AddressOverflow,
    #[error("machine memory budget exceeded")]
    MemoryLimit,
    #[error("invalid relative P-code branch target {0}")]
    InvalidBranch(i64),
    #[error("cross-space control transfers are not supported")]
    CrossSpaceTransfer,
    #[error(transparent)]
    Value(#[from] crate::Error),
    #[error("P-code at 0x{address:X}, operation {operation}: {source}")]
    At {
        address: u64,
        operation: usize,
        source: Box<MachineError>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemoryInit {
    pub space: SpaceId,
    pub offset: u64,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, Serialize)]
pub struct MemorySnapshot {
    pub regions: Vec<MemoryInit>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionInput {
    pub spaces: Vec<AddressSpace>,
    pub code_space: SpaceId,
    pub entry: u64,
    pub instructions: Vec<PcodeInstruction>,
    #[serde(default)]
    pub memory: Vec<MemoryInit>,
    #[serde(default = "default_budget")]
    pub max_operations: u64,
}
fn default_budget() -> u64 {
    100_000
}

#[derive(Debug, Clone, Serialize)]
pub enum StopReason {
    FallThrough { next_address: u64 },
    ExternalTransfer { target: u64, kind: String },
    BudgetExhausted { address: u64, operation: usize },
}

#[derive(Debug, Clone, Serialize)]
pub struct TraceEvent {
    pub address: u64,
    pub operation: usize,
    pub opcode: Opcode,
}

#[derive(Debug, Clone, Serialize)]
pub struct ExecutionReport {
    pub operations: u64,
    pub stop: StopReason,
    pub trace: Vec<TraceEvent>,
    pub trace_truncated: bool,
}

struct Page {
    bytes: [u8; PAGE_SIZE],
    initialized: [u64; PAGE_SIZE / 64],
}
impl Page {
    fn empty() -> Self {
        Self {
            bytes: [0; PAGE_SIZE],
            initialized: [0; PAGE_SIZE / 64],
        }
    }
    fn known(&self, index: usize) -> bool {
        self.initialized[index / 64] & (1 << (index % 64)) != 0
    }
}

pub struct Machine {
    spaces: BTreeMap<SpaceId, AddressSpace>,
    pages: BTreeMap<(SpaceId, u64), Box<Page>>,
    max_memory_bytes: usize,
}

impl Machine {
    pub fn new(spaces: Vec<AddressSpace>, max_memory_bytes: usize) -> Result<Self, MachineError> {
        if spaces.is_empty()
            || spaces.len() > 256
            || !(PAGE_SIZE..=MAX_MEMORY).contains(&max_memory_bytes)
        {
            return Err(MachineError::InvalidProgram(
                "require 1..256 spaces and a 4 KiB..64 MiB memory budget".into(),
            ));
        }
        let mut map = BTreeMap::new();
        for space in spaces {
            space.validate()?;
            if map.insert(space.id, space).is_some() {
                return Err(MachineError::InvalidProgram(
                    "duplicate address space id".into(),
                ));
            }
        }
        Ok(Self {
            spaces: map,
            pages: BTreeMap::new(),
            max_memory_bytes,
        })
    }

    fn space(&self, id: SpaceId) -> Result<&AddressSpace, MachineError> {
        self.spaces.get(&id).ok_or(MachineError::UnknownSpace(id))
    }

    fn range(&self, space: SpaceId, offset: u64, size: usize) -> Result<(), MachineError> {
        let definition = self.space(space)?;
        let maximum = ((1_u128 << (definition.address_size as u32 * 8))
            * u128::from(definition.word_size))
        .min(u64::MAX as u128 + 1);
        if offset as u128 + size as u128 > maximum {
            return Err(MachineError::AddressOverflow);
        }
        Ok(())
    }

    pub fn map_bytes(
        &mut self,
        space: SpaceId,
        offset: u64,
        bytes: &[u8],
    ) -> Result<(), MachineError> {
        if self.space(space)?.kind == SpaceKind::Constant {
            return Err(MachineError::ReadOnlySpace);
        }
        self.range(space, offset, bytes.len())?;
        if bytes.len() > self.max_memory_bytes {
            return Err(MachineError::MemoryLimit);
        }
        if bytes.is_empty() {
            return Ok(());
        }
        let first = offset / PAGE_SIZE as u64;
        let last = (offset + (bytes.len() - 1) as u64) / PAGE_SIZE as u64;
        let missing = (first..=last)
            .filter(|&page| !self.pages.contains_key(&(space, page)))
            .count();
        if (self.pages.len() + missing) * PAGE_SIZE > self.max_memory_bytes {
            return Err(MachineError::MemoryLimit);
        }
        for page in first..=last {
            self.pages
                .entry((space, page))
                .or_insert_with(|| Box::new(Page::empty()));
        }
        let mut done = 0;
        while done < bytes.len() {
            let address = offset + done as u64;
            let page = self
                .pages
                .get_mut(&(space, address / PAGE_SIZE as u64))
                .expect("allocated page");
            let index = address as usize % PAGE_SIZE;
            let count = (PAGE_SIZE - index).min(bytes.len() - done);
            page.bytes[index..index + count].copy_from_slice(&bytes[done..done + count]);
            for byte in index..index + count {
                page.initialized[byte / 64] |= 1 << (byte % 64);
            }
            done += count;
        }
        Ok(())
    }

    pub fn read_bytes(
        &self,
        space: SpaceId,
        offset: u64,
        size: usize,
    ) -> Result<Vec<u8>, MachineError> {
        self.range(space, offset, size)?;
        if size > self.max_memory_bytes {
            return Err(MachineError::MemoryLimit);
        }
        let mut bytes = Vec::with_capacity(size);
        for index in 0..size {
            let address = offset + index as u64;
            let page = self.pages.get(&(space, address / PAGE_SIZE as u64));
            let local = address as usize % PAGE_SIZE;
            match page.filter(|p| p.known(local)) {
                Some(page) => bytes.push(page.bytes[local]),
                None => {
                    return Err(MachineError::Uninitialized {
                        space,
                        offset: address,
                    });
                }
            }
        }
        Ok(bytes)
    }

    pub fn read_varnode(&self, varnode: &Varnode) -> Result<Value, MachineError> {
        varnode.validate()?;
        let space = self.space(varnode.space)?;
        if space.kind == SpaceKind::Constant {
            return Ok(Value::from_u64(varnode.size, varnode.offset)?);
        }
        let mut bytes = self.read_bytes(varnode.space, varnode.offset, varnode.size as usize)?;
        if space.endianness == Endianness::Big {
            bytes.reverse();
        }
        Ok(Value::from_le_bytes(&bytes)?)
    }

    pub fn write_varnode(&mut self, varnode: &Varnode, value: &Value) -> Result<(), MachineError> {
        varnode.validate()?;
        if varnode.size != value.size() {
            return Err(MachineError::InvalidProgram(
                "value and output width differ".into(),
            ));
        }
        let mut bytes = value.to_le_bytes();
        if self.space(varnode.space)?.endianness == Endianness::Big {
            bytes.reverse();
        }
        self.map_bytes(varnode.space, varnode.offset, &bytes)
    }

    /// Returns initialized byte ranges only; uninitialized bytes are never invented.
    pub fn snapshot(&self) -> MemorySnapshot {
        let mut result: Vec<MemoryInit> = Vec::new();
        let mut bytes = 0;
        for (&(space, number), page) in &self.pages {
            for index in 0..PAGE_SIZE {
                if !page.known(index) {
                    continue;
                }
                let offset = number * PAGE_SIZE as u64 + index as u64;
                if bytes == MAX_SNAPSHOT_BYTES {
                    return MemorySnapshot {
                        regions: result,
                        truncated: true,
                    };
                }
                if let Some(last) = result.last_mut()
                    && last.space == space
                    && last.offset.checked_add(last.bytes.len() as u64) == Some(offset)
                {
                    last.bytes.push(page.bytes[index]);
                } else {
                    if result.len() == MAX_SNAPSHOT_REGIONS {
                        return MemorySnapshot {
                            regions: result,
                            truncated: true,
                        };
                    }
                    result.push(MemoryInit {
                        space,
                        offset,
                        bytes: vec![page.bytes[index]],
                    });
                }
                bytes += 1;
            }
        }
        MemorySnapshot {
            regions: result,
            truncated: false,
        }
    }

    pub fn run(
        &mut self,
        instructions: &[PcodeInstruction],
        code_space: SpaceId,
        entry: u64,
        max_operations: u64,
    ) -> Result<ExecutionReport, MachineError> {
        if instructions.len() > 100_000 || !(1..=MAX_STEPS).contains(&max_operations) {
            return Err(MachineError::InvalidProgram(
                "instruction or execution budget is out of bounds".into(),
            ));
        }
        if self.space(code_space)?.kind == SpaceKind::Constant {
            return Err(MachineError::InvalidProgram(
                "code space cannot be constant".into(),
            ));
        }
        let mut program = BTreeMap::new();
        let mut op_count = 0_usize;
        for instruction in instructions {
            instruction.validate()?;
            self.range(code_space, instruction.address, instruction.length as usize)?;
            op_count = op_count
                .checked_add(instruction.ops.len())
                .ok_or(MachineError::MemoryLimit)?;
            if op_count > MAX_PROGRAM_OPS {
                return Err(MachineError::InvalidProgram(
                    "too many P-code operations".into(),
                ));
            }
            if program.insert(instruction.address, instruction).is_some() {
                return Err(MachineError::InvalidProgram(
                    "duplicate instruction address".into(),
                ));
            }
            for operation in &instruction.ops {
                for node in operation.inputs.iter().chain(operation.output.iter()) {
                    self.space(node.space)?;
                }
                if let Some(output) = &operation.output
                    && self.space(output.space)?.kind == SpaceKind::Constant
                {
                    return Err(MachineError::ReadOnlySpace);
                }
            }
        }
        let mut previous_end = None;
        for instruction in program.values() {
            if previous_end.is_some_and(|end| end > instruction.address) {
                return Err(MachineError::InvalidProgram(
                    "overlapping instructions".into(),
                ));
            }
            previous_end = Some(
                instruction
                    .address
                    .checked_add(u64::from(instruction.length))
                    .ok_or(MachineError::AddressOverflow)?,
            );
        }
        if !program.contains_key(&entry) {
            return Err(MachineError::InvalidProgram(
                "entry is not an instruction".into(),
            ));
        }
        let mut address = entry;
        let mut steps = 0;
        let mut trace = Vec::new();
        loop {
            let instruction = program[&address];
            let mut index = 0;
            let mut transfer = None;
            while index < instruction.ops.len() {
                if steps == max_operations {
                    return Ok(ExecutionReport {
                        operations: steps,
                        stop: StopReason::BudgetExhausted {
                            address,
                            operation: index,
                        },
                        trace_truncated: steps as usize > trace.len(),
                        trace,
                    });
                }
                let operation = &instruction.ops[index];
                if trace.len() < MAX_TRACE {
                    trace.push(TraceEvent {
                        address,
                        operation: index,
                        opcode: operation.opcode,
                    });
                }
                steps += 1;
                let flow =
                    self.execute(operation, code_space)
                        .map_err(|source| MachineError::At {
                            address,
                            operation: index,
                            source: Box::new(source),
                        })?;
                match flow {
                    Flow::Next => index += 1,
                    Flow::Relative(delta) => {
                        let target = index as i64 + i64::from(delta);
                        if !(0..=instruction.ops.len() as i64).contains(&target) {
                            return Err(MachineError::InvalidBranch(target));
                        }
                        index = target as usize;
                    }
                    Flow::Transfer { target, kind } => {
                        transfer = Some((target, kind));
                        break;
                    }
                }
            }
            let (target, kind) = match transfer {
                Some(transfer) => transfer,
                None => (
                    address
                        .checked_add(u64::from(instruction.length))
                        .ok_or(MachineError::AddressOverflow)?,
                    "fallthrough",
                ),
            };
            if !program.contains_key(&target) {
                let stop = if kind == "fallthrough" {
                    StopReason::FallThrough {
                        next_address: target,
                    }
                } else {
                    StopReason::ExternalTransfer {
                        target,
                        kind: kind.into(),
                    }
                };
                return Ok(ExecutionReport {
                    operations: steps,
                    stop,
                    trace_truncated: steps as usize > trace.len(),
                    trace,
                });
            }
            address = target;
        }
    }

    fn execute(
        &mut self,
        operation: &PcodeOperation,
        code_space: SpaceId,
    ) -> Result<Flow, MachineError> {
        operation.validate()?;
        use Opcode::*;
        if matches!(operation.opcode, Call | Callind | Return)
            && (operation.inputs.len() != 1 || operation.output.is_some())
        {
            return Err(MachineError::Value(crate::Error::UnsupportedOpcode(
                operation.opcode,
            )));
        }
        match operation.opcode {
            Load | Store => {
                let id = &operation.inputs[0];
                if self.space(id.space)?.kind != SpaceKind::Constant {
                    return Err(MachineError::InvalidProgram(
                        "LOAD/STORE space selector must be constant".into(),
                    ));
                }
                let target =
                    SpaceId(u32::try_from(id.offset).map_err(|_| MachineError::AddressOverflow)?);
                if self.space(target)?.kind == SpaceKind::Constant {
                    return Err(MachineError::InvalidProgram(
                        "LOAD/STORE cannot dereference constant space".into(),
                    ));
                }
                if operation.inputs[1].size != u32::from(self.space(target)?.address_size) {
                    return Err(MachineError::InvalidProgram(
                        "LOAD/STORE pointer width must match its target space".into(),
                    ));
                }
                let pointer = self
                    .read_varnode(&operation.inputs[1])?
                    .to_u64()
                    .ok_or(MachineError::AddressOverflow)?;
                let offset = pointer
                    .checked_mul(u64::from(self.space(target)?.word_size))
                    .ok_or(MachineError::AddressOverflow)?;
                if operation.opcode == Load {
                    let output = operation.output.as_ref().expect("validated LOAD output");
                    let node = Varnode {
                        space: target,
                        offset,
                        size: output.size,
                    };
                    let value = self.read_varnode(&node)?;
                    self.write_varnode(output, &value)?;
                } else {
                    let value = self.read_varnode(&operation.inputs[2])?;
                    self.write_varnode(
                        &Varnode {
                            space: target,
                            offset,
                            size: value.size(),
                        },
                        &value,
                    )?;
                }
                Ok(Flow::Next)
            }
            Branch | Cbranch | Call => {
                if operation.opcode == Cbranch
                    && self.read_varnode(&operation.inputs[1])?.bits()
                        == &num_bigint::BigUint::default()
                {
                    return Ok(Flow::Next);
                }
                let target = &operation.inputs[0];
                if operation.opcode != Call && self.space(target.space)?.kind == SpaceKind::Constant
                {
                    return Ok(Flow::Relative(target.offset as u32 as i32));
                }
                if target.space != code_space {
                    return Err(MachineError::CrossSpaceTransfer);
                }
                self.range(code_space, target.offset, 1)?;
                Ok(Flow::Transfer {
                    target: target.offset,
                    kind: if operation.opcode == Call {
                        "call"
                    } else {
                        "branch"
                    },
                })
            }
            Branchind | Callind | Return => {
                if operation.inputs[0].size != u32::from(self.space(code_space)?.address_size) {
                    return Err(MachineError::InvalidProgram(
                        "indirect control pointer width must match code space".into(),
                    ));
                }
                let target = self
                    .read_varnode(&operation.inputs[0])?
                    .to_u64()
                    .ok_or(MachineError::AddressOverflow)?;
                self.range(code_space, target, 1)?;
                Ok(Flow::Transfer {
                    target,
                    kind: match operation.opcode {
                        Return => "return",
                        Callind => "indirect-call",
                        _ => "indirect-branch",
                    },
                })
            }
            _ => {
                let constant_operands: &[usize] = match operation.opcode {
                    Subpiece => &[1],
                    Ptradd => &[2],
                    Insert => &[2, 3],
                    Zpull | Spull => &[1, 2],
                    _ => &[],
                };
                for &index in constant_operands {
                    if self.space(operation.inputs[index].space)?.kind != SpaceKind::Constant {
                        return Err(MachineError::InvalidProgram(format!(
                            "{} operand {index} must be constant",
                            operation.opcode.mnemonic()
                        )));
                    }
                }
                let output = operation.output.as_ref().ok_or(MachineError::Value(
                    crate::Error::UnsupportedOpcode(operation.opcode),
                ))?;
                let inputs = operation
                    .inputs
                    .iter()
                    .map(|node| self.read_varnode(node))
                    .collect::<Result<Vec<_>, _>>()?;
                let value = evaluate_pure(operation.opcode, &inputs, output.size)?;
                self.write_varnode(output, &value)?;
                Ok(Flow::Next)
            }
        }
    }
}

enum Flow {
    Next,
    Relative(i32),
    Transfer { target: u64, kind: &'static str },
}

#[cfg(test)]
mod tests;
