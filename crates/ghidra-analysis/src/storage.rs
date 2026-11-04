use std::collections::{BTreeMap, BTreeSet};

use ghidra_pcode::{
    AddressSpace, Endianness, Opcode, PcodeInstruction, PcodeOperation, SpaceId, SpaceKind, Value,
    Varnode,
};
use serde::Serialize;
use thiserror::Error;

/// Native instruction analyses normally scope unique storage to its instruction.
/// Explicit P-code programs may instead define persistent unique-space state.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum UniqueScope {
    Program,
    Instruction,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub enum Lifetime {
    Program,
    Instruction(u64),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct ScalarBank {
    pub space: SpaceId,
    pub lifetime: Lifetime,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
pub struct StorageId(pub usize);

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum StorageLocation {
    Scalar {
        bank: ScalarBank,
        offset: u64,
        size: u32,
        endianness: Endianness,
    },
    /// One abstract memory state for a RAM/other space, not a concrete value.
    Memory { space: SpaceId },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StorageVariable {
    pub id: StorageId,
    pub location: StorageLocation,
}

#[derive(Clone, Copy, Debug)]
pub struct StorageLimits {
    pub max_instructions: usize,
    pub max_operations: usize,
    pub max_operand_refs: usize,
    pub max_events: usize,
    pub max_variables: usize,
    pub max_work: u64,
}

impl Default for StorageLimits {
    fn default() -> Self {
        Self {
            max_instructions: 100_000,
            max_operations: 250_000,
            max_operand_refs: 1_000_000,
            max_events: 2_000_000,
            max_variables: 250_000,
            max_work: 100_000_000,
        }
    }
}

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage analysis limit exceeded: {0}")]
    Limit(&'static str),
    #[error("invalid storage analysis input: {0}")]
    Invalid(String),
    #[error("unknown address space {0:?}")]
    UnknownSpace(SpaceId),
    #[error("no complete storage partition for {0:?}")]
    Missing(Varnode),
    #[error("indirect access to scalar space {0:?} needs an alias/effect model")]
    IndirectScalar(SpaceId),
    #[error("{0:?} needs an explicit effect summary before SSA def/use construction")]
    UnknownEffects(EffectClass),
    #[error("binding values have the wrong number or widths")]
    BindingShape,
    #[error(transparent)]
    Pcode(#[from] ghidra_pcode::Error),
}

type Result<T> = std::result::Result<T, StorageError>;

struct Budget {
    remaining: u64,
}
impl Budget {
    fn charge(&mut self, n: usize) -> Result<()> {
        self.remaining = self
            .remaining
            .checked_sub(u64::try_from(n).map_err(|_| StorageError::Limit("work"))?)
            .ok_or(StorageError::Limit("work"))?;
        Ok(())
    }
    fn map(&mut self, n: usize) -> Result<()> {
        self.charge((usize::BITS - n.leading_zeros()) as usize + 1)
    }
    fn sort(&mut self, n: usize) -> Result<()> {
        let levels = (usize::BITS - n.leading_zeros()) as usize + 1;
        self.charge(n.checked_mul(levels).ok_or(StorageError::Limit("work"))?)
    }
}

/// Immutable storage domain built from all operands before SSA conversion.
/// Scalar cells are disjoint. Their endpoints include every observed alias.
#[derive(Debug)]
pub struct StorageLayout {
    spaces: BTreeMap<SpaceId, AddressSpace>,
    instructions: BTreeSet<u64>,
    unique_scope: UniqueScope,
    variables: Vec<StorageVariable>,
    banks: BTreeMap<ScalarBank, Vec<StorageId>>,
    memory: BTreeMap<SpaceId, StorageId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BindingPiece {
    pub variable: StorageId,
    /// Offset in the original value, in bytes from its least significant end.
    pub value_offset: u32,
    pub size: u32,
}

/// Pieces ascend by value significance, independently of physical byte order.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ScalarBinding {
    size: u32,
    pieces: Vec<BindingPiece>,
}

impl ScalarBinding {
    pub fn size(&self) -> u32 {
        self.size
    }
    pub fn pieces(&self) -> &[BindingPiece] {
        &self.pieces
    }

    /// Split a full value into complete scalar cells. No read/modify/write or
    /// implicit zero-extension is invented for a partial register write.
    pub fn split(&self, value: &Value) -> Result<Vec<(StorageId, Value)>> {
        if value.size() != self.size {
            return Err(StorageError::BindingShape);
        }
        let bytes = value.to_le_bytes();
        self.pieces
            .iter()
            .map(|piece| {
                let first = piece.value_offset as usize;
                Ok((
                    piece.variable,
                    Value::from_le_bytes(&bytes[first..first + piece.size as usize])?,
                ))
            })
            .collect()
    }

    /// Every piece must be supplied, in `pieces()` order; missing state is not zero.
    pub fn compose(&self, values: &[Value]) -> Result<Value> {
        if values.len() != self.pieces.len()
            || values
                .iter()
                .zip(&self.pieces)
                .any(|(value, piece)| value.size() != piece.size)
        {
            return Err(StorageError::BindingShape);
        }
        let mut bytes = vec![0; self.size as usize];
        for (value, piece) in values.iter().zip(&self.pieces) {
            let first = piece.value_offset as usize;
            bytes[first..first + piece.size as usize].copy_from_slice(&value.to_le_bytes());
        }
        Ok(Value::from_le_bytes(&bytes)?)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum ValueBinding {
    Constant(Value),
    Scalar(ScalarBinding),
    /// Read/write at a fixed byte offset in an abstract memory state.
    Memory {
        variable: StorageId,
        space: SpaceId,
        offset: u64,
        size: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum InputBinding {
    Value(ValueBinding),
    RelativeTarget(i32),
    DirectTarget(Varnode),
    SpaceSelector(SpaceId),
    Userop(u64),
    OperationReference(Varnode),
    ConstantMetadata(Varnode),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum EffectClass {
    Explicit,
    Call,
    Userop,
    Runtime,
    AnalysisContext,
    Unimplemented,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum MemoryAccessKind {
    Read,
    Write,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MemoryAccess {
    pub variable: StorageId,
    pub space: SpaceId,
    pub kind: MemoryAccessKind,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct OperationBindings {
    pub inputs: Vec<InputBinding>,
    pub output: Option<ValueBinding>,
    pub memory: Option<MemoryAccess>,
    pub effects: EffectClass,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct DefUse {
    pub uses: Vec<StorageId>,
    pub definitions: Vec<StorageId>,
}

impl OperationBindings {
    /// Complete explicit effects only. Calls, runtime/SSA context and unknown
    /// instructions require summaries rather than silently omitting clobbers.
    pub fn def_use(&self) -> Result<DefUse> {
        if self.effects != EffectClass::Explicit {
            return Err(StorageError::UnknownEffects(self.effects));
        }
        self.declared_def_use()
    }

    // Only the operands written in the operation. For opaque operations the
    // adapter must add a complete summary before these can become SSA inputs.
    pub(crate) fn declared_def_use(&self) -> Result<DefUse> {
        let mut uses = Vec::new();
        let mut definitions = Vec::new();
        for input in &self.inputs {
            if let InputBinding::Value(value) = input {
                value.reads(&mut uses);
            }
        }
        if let Some(memory) = &self.memory {
            uses.push(memory.variable);
            if memory.kind == MemoryAccessKind::Write {
                definitions.push(memory.variable);
            }
        }
        if let Some(output) = &self.output {
            match output {
                ValueBinding::Scalar(binding) => {
                    definitions.extend(binding.pieces.iter().map(|piece| piece.variable))
                }
                ValueBinding::Memory { variable, .. } => {
                    uses.push(*variable);
                    definitions.push(*variable);
                }
                ValueBinding::Constant(_) => {
                    return Err(StorageError::Invalid("constant output".into()));
                }
            }
        }
        let mut seen = BTreeSet::new();
        definitions.retain(|id| seen.insert(*id));
        Ok(DefUse { uses, definitions })
    }
}

impl ValueBinding {
    fn reads(&self, uses: &mut Vec<StorageId>) {
        match self {
            Self::Scalar(binding) => uses.extend(binding.pieces.iter().map(|piece| piece.variable)),
            Self::Memory { variable, .. } => uses.push(*variable),
            Self::Constant(_) => {}
        }
    }
}

#[derive(Clone, Copy)]
enum Role {
    Value,
    RelativeOrDirect,
    Direct,
    Space,
    Userop,
    Reference,
    Constant,
}

fn role(opcode: Opcode, index: usize) -> Role {
    use Opcode::*;
    match (opcode, index) {
        (Branch | Cbranch, 0) => Role::RelativeOrDirect,
        (Call, 0) => Role::Direct,
        (Load | Store, 0) => Role::Space,
        (Callother, 0) => Role::Userop,
        (Subpiece, 1) | (Ptradd, 2) | (Insert, 2 | 3) | (Zpull | Spull, 1 | 2) => Role::Constant,
        (Indirect, 1) => Role::Reference,
        _ => Role::Value,
    }
}

fn effect_class(opcode: Opcode) -> EffectClass {
    match opcode {
        Opcode::Call | Opcode::Callind => EffectClass::Call,
        Opcode::Callother => EffectClass::Userop,
        Opcode::Cpoolref | Opcode::New => EffectClass::Runtime,
        Opcode::Multiequal | Opcode::Indirect => EffectClass::AnalysisContext,
        Opcode::Unimplemented => EffectClass::Unimplemented,
        _ => EffectClass::Explicit,
    }
}

fn space(map: &BTreeMap<SpaceId, AddressSpace>, id: SpaceId) -> Result<&AddressSpace> {
    map.get(&id).ok_or(StorageError::UnknownSpace(id))
}

fn check_range(space: &AddressSpace, node: Varnode, size: u32) -> Result<()> {
    let maximum = ((1u128 << (8 * u32::from(space.address_size))) * u128::from(space.word_size))
        .min(u128::from(u64::MAX) + 1);
    if u128::from(node.offset) + u128::from(size) > maximum {
        return Err(StorageError::Invalid(
            "varnode exceeds its address space".into(),
        ));
    }
    Ok(())
}

fn bank(space: &AddressSpace, address: u64, scope: UniqueScope) -> ScalarBank {
    ScalarBank {
        space: space.id,
        lifetime: if space.kind == SpaceKind::Unique && scope == UniqueScope::Instruction {
            Lifetime::Instruction(address)
        } else {
            Lifetime::Program
        },
    }
}

fn check_role(
    map: &BTreeMap<SpaceId, AddressSpace>,
    role: Role,
    node: Varnode,
) -> Result<Option<SpaceId>> {
    let definition = space(map, node.space)?;
    match role {
        Role::Value => {
            if definition.kind != SpaceKind::Constant {
                check_range(definition, node, node.size)?;
            }
        }
        Role::RelativeOrDirect if definition.kind == SpaceKind::Constant => {}
        Role::RelativeOrDirect | Role::Direct => {
            if !matches!(definition.kind, SpaceKind::Ram | SpaceKind::Other) {
                return Err(StorageError::Invalid(
                    "direct control target must name a memory space".into(),
                ));
            }
            check_range(definition, node, 1)?;
        }
        Role::Space => {
            if definition.kind != SpaceKind::Constant {
                return Err(StorageError::Invalid(
                    "space selector must be constant".into(),
                ));
            }
            let target = SpaceId(
                u32::try_from(node.offset)
                    .map_err(|_| StorageError::Invalid("space selector exceeds u32".into()))?,
            );
            let target_space = space(map, target)?;
            if !matches!(target_space.kind, SpaceKind::Ram | SpaceKind::Other) {
                return Err(StorageError::IndirectScalar(target));
            }
            return Ok(Some(target));
        }
        Role::Userop | Role::Constant => {
            if definition.kind != SpaceKind::Constant {
                return Err(StorageError::Invalid(
                    "metadata operand must be constant".into(),
                ));
            }
        }
        Role::Reference => {}
    }
    Ok(None)
}

impl StorageLayout {
    /// Extra register aliases let a later ABI model add read/clobber boundaries.
    /// Instruction-local unique scope is lexical: a CFG adapter still has to
    /// model fresh temporary state at native frame entry, including loop re-entry.
    pub fn build(
        spaces: &[AddressSpace],
        instructions: &[PcodeInstruction],
        extra_registers: &[Varnode],
        unique_scope: UniqueScope,
        limits: StorageLimits,
    ) -> Result<Self> {
        let mut budget = Budget {
            remaining: limits.max_work,
        };
        if spaces.is_empty() || spaces.len() > 256 {
            return Err(StorageError::Invalid(
                "expected 1..=256 address spaces".into(),
            ));
        }
        if instructions.len() > limits.max_instructions {
            return Err(StorageError::Limit("instructions"));
        }
        let mut map = BTreeMap::new();
        for definition in spaces {
            budget.map(spaces.len())?;
            definition.validate()?;
            if map.insert(definition.id, definition.clone()).is_some() {
                return Err(StorageError::Invalid("duplicate address-space ID".into()));
            }
        }
        let mut operations = 0usize;
        let mut refs = extra_registers.len();
        if refs > limits.max_operand_refs {
            return Err(StorageError::Limit("operand references"));
        }
        for instruction in instructions {
            budget.charge(1)?;
            operations = operations
                .checked_add(instruction.ops.len())
                .ok_or(StorageError::Limit("operations"))?;
            if operations > limits.max_operations {
                return Err(StorageError::Limit("operations"));
            }
            for op in &instruction.ops {
                budget.charge(1)?;
                refs = refs
                    .checked_add(op.inputs.len())
                    .and_then(|count| count.checked_add(usize::from(op.output.is_some())))
                    .ok_or(StorageError::Limit("operand references"))?;
                if refs > limits.max_operand_refs {
                    return Err(StorageError::Limit("operand references"));
                }
            }
        }
        let mut addresses = BTreeSet::new();
        let mut events: BTreeMap<ScalarBank, Vec<(u128, bool)>> = BTreeMap::new();
        let mut memory = BTreeSet::new();
        let mut event_count = 0usize;
        let mut collect =
            |address: u64, node: Varnode, budget: &mut Budget| -> Result<Option<SpaceId>> {
                budget.map(map.len())?;
                let definition = space(&map, node.space)?;
                if definition.kind == SpaceKind::Constant {
                    return Ok(None);
                }
                check_range(definition, node, node.size)?;
                match definition.kind {
                    SpaceKind::Register | SpaceKind::Unique => {
                        event_count = event_count
                            .checked_add(2)
                            .ok_or(StorageError::Limit("interval events"))?;
                        if event_count > limits.max_events {
                            return Err(StorageError::Limit("interval events"));
                        }
                        budget.map(refs)?;
                        let list = events
                            .entry(bank(definition, address, unique_scope))
                            .or_default();
                        list.push((u128::from(node.offset), true));
                        list.push((u128::from(node.offset) + u128::from(node.size), false));
                    }
                    SpaceKind::Ram | SpaceKind::Other => {
                        return Ok(Some(node.space));
                    }
                    SpaceKind::Constant => unreachable!(),
                }
                Ok(None)
            };
        for instruction in instructions {
            budget.map(instructions.len())?;
            if !addresses.insert(instruction.address) {
                return Err(StorageError::Invalid(
                    "duplicate instruction address".into(),
                ));
            }
            budget.charge(instruction.ops.len())?;
            instruction.validate()?;
            for op in &instruction.ops {
                for (index, node) in op.inputs.iter().copied().enumerate() {
                    budget.map(map.len())?;
                    let operand_role = role(op.opcode, index);
                    if let Some(target) = check_role(&map, operand_role, node)? {
                        if op.inputs[1].size != u32::from(space(&map, target)?.address_size) {
                            return Err(StorageError::Invalid(
                                "LOAD/STORE pointer width differs from target space".into(),
                            ));
                        }
                        memory.insert(target);
                    }
                    if matches!(operand_role, Role::Value)
                        && let Some(id) = collect(instruction.address, node, &mut budget)?
                    {
                        memory.insert(id);
                    }
                }
                if let Some(output) = op.output {
                    if space(&map, output.space)?.kind == SpaceKind::Constant {
                        return Err(StorageError::Invalid("constant output".into()));
                    }
                    if let Some(id) = collect(instruction.address, output, &mut budget)? {
                        memory.insert(id);
                    }
                }
            }
        }
        for &node in extra_registers {
            budget.charge(1)?;
            node.validate()?;
            if space(&map, node.space)?.kind != SpaceKind::Register {
                return Err(StorageError::Invalid(
                    "extra aliases must be registers".into(),
                ));
            }
            collect(0, node, &mut budget)?;
        }
        let mut layout = Self {
            spaces: map,
            instructions: addresses,
            unique_scope,
            variables: Vec::new(),
            banks: BTreeMap::new(),
            memory: BTreeMap::new(),
        };
        for (key, mut list) in events {
            budget.sort(list.len())?;
            list.sort_unstable();
            let mut previous = None;
            let mut active = 0usize;
            let mut index = 0;
            let mut ids = Vec::new();
            while index < list.len() {
                budget.charge(1)?;
                let position = list[index].0;
                if let Some(first) = previous
                    && active != 0
                    && position > first
                {
                    let size = u32::try_from(position - first)
                        .map_err(|_| StorageError::Invalid("scalar interval exceeds u32".into()))?;
                    let offset = u64::try_from(first).map_err(|_| {
                        StorageError::Invalid("scalar interval offset exceeds u64".into())
                    })?;
                    let endianness = space(&layout.spaces, key.space)?.endianness;
                    ids.push(layout.add_variable(
                        StorageLocation::Scalar {
                            bank: key,
                            offset,
                            size,
                            endianness,
                        },
                        limits.max_variables,
                    )?);
                }
                let mut starts = 0;
                let mut ends = 0;
                while index < list.len() && list[index].0 == position {
                    budget.charge(1)?;
                    if list[index].1 {
                        starts += 1;
                    } else {
                        ends += 1;
                    }
                    index += 1;
                }
                active = active
                    .checked_sub(ends)
                    .and_then(|count| count.checked_add(starts))
                    .ok_or(StorageError::Invalid("invalid interval sweep".into()))?;
                previous = Some(position);
            }
            layout.banks.insert(key, ids);
        }
        for id in memory {
            budget.charge(1)?;
            let variable =
                layout.add_variable(StorageLocation::Memory { space: id }, limits.max_variables)?;
            layout.memory.insert(id, variable);
        }
        Ok(layout)
    }

    fn add_variable(&mut self, location: StorageLocation, maximum: usize) -> Result<StorageId> {
        if self.variables.len() == maximum {
            return Err(StorageError::Limit("variables"));
        }
        let id = StorageId(self.variables.len());
        self.variables.push(StorageVariable { id, location });
        Ok(id)
    }

    pub fn variables(&self) -> &[StorageVariable] {
        &self.variables
    }
    pub fn unique_scope(&self) -> UniqueScope {
        self.unique_scope
    }
    pub fn memory_variable(&self, space: SpaceId) -> Option<StorageId> {
        self.memory.get(&space).copied()
    }
    pub fn spaces(&self) -> impl Iterator<Item = &AddressSpace> {
        self.spaces.values()
    }

    pub fn bind(&self, instruction: u64, node: Varnode) -> Result<ValueBinding> {
        node.validate()?;
        let definition = space(&self.spaces, node.space)?;
        if definition.kind == SpaceKind::Constant {
            return Ok(ValueBinding::Constant(Value::from_u64(
                node.size,
                node.offset,
            )?));
        }
        check_range(definition, node, node.size)?;
        if matches!(definition.kind, SpaceKind::Ram | SpaceKind::Other) {
            return Ok(ValueBinding::Memory {
                variable: self
                    .memory_variable(node.space)
                    .ok_or(StorageError::Missing(node))?,
                space: node.space,
                offset: node.offset,
                size: node.size,
            });
        }
        let key = bank(definition, instruction, self.unique_scope);
        if matches!(key.lifetime, Lifetime::Instruction(_))
            && !self.instructions.contains(&instruction)
        {
            return Err(StorageError::Missing(node));
        }
        let ids = self.banks.get(&key).ok_or(StorageError::Missing(node))?;
        let start = ids
            .binary_search_by_key(&node.offset, |id| match self.variables[id.0].location {
                StorageLocation::Scalar { offset, .. } => offset,
                _ => unreachable!(),
            })
            .map_err(|_| StorageError::Missing(node))?;
        let end = u128::from(node.offset) + u128::from(node.size);
        let mut next = u128::from(node.offset);
        let mut pieces = Vec::new();
        for &id in &ids[start..] {
            let StorageLocation::Scalar { offset, size, .. } = self.variables[id.0].location else {
                unreachable!()
            };
            if u128::from(offset) != next || next + u128::from(size) > end {
                return Err(StorageError::Missing(node));
            }
            let relative =
                u32::try_from(next - u128::from(node.offset)).expect("within validated varnode");
            let value_offset = if definition.endianness == Endianness::Little {
                relative
            } else {
                node.size - relative - size
            };
            pieces.push(BindingPiece {
                variable: id,
                value_offset,
                size,
            });
            next += u128::from(size);
            if next == end {
                break;
            }
        }
        if next != end {
            return Err(StorageError::Missing(node));
        }
        if definition.endianness == Endianness::Big {
            pieces.reverse();
        }
        Ok(ValueBinding::Scalar(ScalarBinding {
            size: node.size,
            pieces,
        }))
    }

    pub fn operation(
        &self,
        instruction: u64,
        operation: &PcodeOperation,
    ) -> Result<OperationBindings> {
        operation.validate()?;
        let mut inputs = Vec::new();
        let mut memory = None;
        for (index, node) in operation.inputs.iter().copied().enumerate() {
            let operand_role = role(operation.opcode, index);
            let target = check_role(&self.spaces, operand_role, node)?;
            let input = match operand_role {
                Role::Value => InputBinding::Value(self.bind(instruction, node)?),
                Role::RelativeOrDirect
                    if space(&self.spaces, node.space)?.kind == SpaceKind::Constant =>
                {
                    InputBinding::RelativeTarget(node.offset as u32 as i32)
                }
                Role::RelativeOrDirect | Role::Direct => InputBinding::DirectTarget(node),
                Role::Userop => InputBinding::Userop(node.offset),
                Role::Reference => InputBinding::OperationReference(node),
                Role::Constant => InputBinding::ConstantMetadata(node),
                Role::Space => {
                    let target = target.expect("validated space selector");
                    if operation.inputs[1].size
                        != u32::from(space(&self.spaces, target)?.address_size)
                    {
                        return Err(StorageError::Invalid(
                            "LOAD/STORE pointer width differs from target space".into(),
                        ));
                    }
                    memory = Some(MemoryAccess {
                        variable: self
                            .memory_variable(target)
                            .ok_or(StorageError::Missing(node))?,
                        space: target,
                        kind: if operation.opcode == Opcode::Load {
                            MemoryAccessKind::Read
                        } else {
                            MemoryAccessKind::Write
                        },
                    });
                    InputBinding::SpaceSelector(target)
                }
            };
            inputs.push(input);
        }
        let output = operation
            .output
            .map(|node| self.bind(instruction, node))
            .transpose()?;
        if matches!(output, Some(ValueBinding::Constant(_))) {
            return Err(StorageError::Invalid("constant output".into()));
        }
        Ok(OperationBindings {
            inputs,
            output,
            memory,
            effects: effect_class(operation.opcode),
        })
    }
}
