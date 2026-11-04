//! Typed expressions over an immutable P-code SSA snapshot.
//!
//! Expression-node edges point backward, while SSA leaves retain stable value
//! identities. Phi cycles are never recursively expanded. Memory states remain a
//! separate sort from bit vectors, and unknown effects remain opaque.

use std::collections::BTreeMap;
use std::sync::Arc;

use ghidra_cfg::{ProgramPoint, Statement};
use ghidra_pcode::{Endianness, Opcode, SpaceId, Value, Varnode};
use ghidra_ssa::{EntryState, PhiId, RenamedStatement, StatementId, ValueId, ValueOrigin};
use thiserror::Error;

use crate::{
    AdaptedStatement, AppliedEffects, InputBinding, MemoryAccessKind, OperationBindings, PcodeSsa,
    StorageId, StorageLocation, ValueBinding,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ExpressionId(pub usize);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpressionType {
    Bits(u32),
    Memory(SpaceId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExpressionAddress {
    /// Fixed varnode offsets are already byte offsets, even in word spaces.
    ByteOffset(u64),
    /// LOAD/STORE pointers are in addressable words. Scaling and overflow
    /// behavior must be retained by any later evaluator or code generator.
    Pointer {
        value: ExpressionId,
        word_size: u32,
        address_size: u8,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpressionPiece {
    pub value: ExpressionId,
    pub lsb_byte: u32,
    pub size: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExpressionKind {
    Constant(Value),
    /// A reference, not an expansion of this value's possibly cyclic definition.
    SsaValue(ValueId),
    /// Pieces cover the entire value in ascending significance order.
    Join(Vec<ExpressionPiece>),
    Extract {
        value: ExpressionId,
        lsb_byte: u32,
    },
    Pure {
        /// Arithmetic/logic semantics only; this does not promise the operation
        /// is nontrapping (division by zero, for example, remains explicit).
        opcode: Opcode,
        inputs: Vec<ExpressionId>,
    },
    ReadMemory {
        space: SpaceId,
        version: ValueId,
        address: ExpressionAddress,
        endianness: Endianness,
    },
    WriteMemory {
        space: SpaceId,
        version: ValueId,
        address: ExpressionAddress,
        value: ExpressionId,
        endianness: Endianness,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpressionNode {
    pub ty: ExpressionType,
    pub kind: ExpressionKind,
}

/// Every SSA value has exactly one definition in the same snapshot. Phi inputs
/// and opaque uses remain accessible through `analysis().ssa()`; they are not
/// duplicated or guessed here.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExpressionDefinition {
    Entry(EntryState),
    Phi(PhiId),
    Expression(ExpressionId),
    Undefined {
        statement: StatementId,
        instruction: u64,
    },
    Opaque {
        statement: StatementId,
        definition_slot: usize,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ExpressionOperand {
    Value(ExpressionId),
    ConstantMetadata {
        source: Varnode,
        value: ExpressionId,
    },
    RelativeTarget(i32),
    DirectTarget(Varnode),
    SpaceSelector(SpaceId),
    Userop(u64),
    OperationReference(Varnode),
}

impl ExpressionOperand {
    pub fn expression(&self) -> Option<ExpressionId> {
        match *self {
            Self::Value(value) | Self::ConstantMetadata { value, .. } => Some(value),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpressionMemoryUse {
    pub space: SpaceId,
    pub version: ValueId,
    pub kind: MemoryAccessKind,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpressionOperation {
    pub statement: StatementId,
    pub point: ProgramPoint,
    pub opcode: Opcode,
    pub operands: Vec<ExpressionOperand>,
    /// The complete bit-vector result before splitting scalar aliases or
    /// writing fixed-offset memory. STORE and control operations have none.
    /// An opaque result is described by `ExpressionDefinition::Opaque` instead.
    pub output: Option<ExpressionId>,
    pub indirect_memory: Option<ExpressionMemoryUse>,
    pub effects: AppliedEffects,
}

#[derive(Clone, Copy, Debug)]
pub struct ExpressionLimits {
    pub max_graph_nodes: usize,
    pub max_values: usize,
    pub max_statements: usize,
    pub max_expression_nodes: usize,
    /// Stored expression/SSA edges and operation operand slots. Phi operands
    /// and opaque dependency lists are shared from the SSA snapshot.
    pub max_references: usize,
    /// Sum of declared widths of owned literal nodes, including repeated ones.
    pub max_constant_bytes: usize,
    pub max_work: u64,
}

impl Default for ExpressionLimits {
    fn default() -> Self {
        Self {
            max_graph_nodes: 500_000,
            max_values: 2_000_000,
            max_statements: 500_000,
            max_expression_nodes: 4_000_000,
            max_references: 8_000_000,
            max_constant_bytes: 64 * 1024 * 1024,
            max_work: 100_000_000,
        }
    }
}

#[derive(Debug, Error)]
pub enum ExpressionError {
    #[error("expression reconstruction limit exceeded: {0}")]
    Limit(&'static str),
    #[error("unknown expression {0:?}")]
    UnknownExpression(ExpressionId),
    #[error("unknown SSA value {0:?}")]
    UnknownValue(ValueId),
    #[error("inconsistent expression input: {0}")]
    Inconsistent(&'static str),
    #[error(transparent)]
    Pcode(#[from] ghidra_pcode::Error),
}

type Result<T> = std::result::Result<T, ExpressionError>;

/// Owned expression terms and their immutable SSA/source snapshot. This is a
/// reconstruction layer, not type inference, memory disambiguation or structured
/// C output. No target program is executed and no undefined value becomes zero.
#[derive(Debug)]
pub struct PcodeExpressions {
    analysis: Arc<PcodeSsa>,
    nodes: Vec<ExpressionNode>,
    definitions: Vec<ExpressionDefinition>,
    operations: Vec<Option<ExpressionOperation>>,
    offsets: Vec<usize>,
    references: usize,
    constant_bytes: usize,
    work: u64,
}

impl PcodeExpressions {
    pub fn new(analysis: Arc<PcodeSsa>, limits: ExpressionLimits) -> Result<Self> {
        Builder::build(analysis, limits)
    }

    pub fn analysis(&self) -> &Arc<PcodeSsa> {
        &self.analysis
    }

    pub fn nodes(&self) -> &[ExpressionNode] {
        &self.nodes
    }

    pub fn node(&self, id: ExpressionId) -> Result<&ExpressionNode> {
        self.nodes
            .get(id.0)
            .ok_or(ExpressionError::UnknownExpression(id))
    }

    pub fn definition(&self, value: ValueId) -> Result<&ExpressionDefinition> {
        self.definitions
            .get(value.0)
            .ok_or(ExpressionError::UnknownValue(value))
    }

    pub fn value_type(&self, value: ValueId) -> Result<ExpressionType> {
        value_type(&self.analysis, value)
    }

    /// No operation is returned for resets, no-ops or unreachable statements.
    pub fn operation(&self, id: StatementId) -> Option<&ExpressionOperation> {
        let start = *self.offsets.get(id.node)?;
        let end = *self.offsets.get(id.node.checked_add(1)?)?;
        let index = start.checked_add(id.index)?;
        (index < end)
            .then(|| self.operations[index].as_ref())
            .flatten()
    }

    pub fn operations(&self) -> impl Iterator<Item = &ExpressionOperation> {
        self.operations.iter().filter_map(Option::as_ref)
    }

    pub fn reference_count(&self) -> usize {
        self.references
    }
    pub fn constant_bytes(&self) -> usize {
        self.constant_bytes
    }
    /// Reconstruction work only; the supplied SSA snapshot is not rebuilt.
    pub fn build_work(&self) -> u64 {
        self.work
    }
}

fn value_type(analysis: &PcodeSsa, value: ValueId) -> Result<ExpressionType> {
    let variable = analysis
        .ssa()
        .value(value)
        .map_err(|_| ExpressionError::UnknownValue(value))?
        .variable;
    match &analysis
        .layout()
        .variables()
        .get(variable.0)
        .ok_or(ExpressionError::Inconsistent("SSA storage variable"))?
        .location
    {
        StorageLocation::Scalar { size, .. } => Ok(ExpressionType::Bits(*size)),
        StorageLocation::Memory { space } => Ok(ExpressionType::Memory(*space)),
    }
}

struct Budget {
    limits: ExpressionLimits,
    work: u64,
    references: usize,
    constants: usize,
}

impl Budget {
    fn charge(&mut self, amount: usize) -> Result<()> {
        self.work = self
            .work
            .checked_add(u64::try_from(amount).map_err(|_| ExpressionError::Limit("work"))?)
            .filter(|&n| n <= self.limits.max_work)
            .ok_or(ExpressionError::Limit("work"))?;
        Ok(())
    }
    fn map(&mut self, length: usize) -> Result<()> {
        self.charge((usize::BITS - length.leading_zeros()) as usize + 1)
    }
    fn references(&mut self, amount: usize) -> Result<()> {
        add(
            &mut self.references,
            amount,
            self.limits.max_references,
            "references",
        )?;
        self.charge(amount)
    }
    fn preflight_references(&self, amount: usize) -> Result<()> {
        self.references
            .checked_add(amount)
            .filter(|&n| n <= self.limits.max_references)
            .ok_or(ExpressionError::Limit("references"))?;
        Ok(())
    }
}

fn add(count: &mut usize, amount: usize, maximum: usize, resource: &'static str) -> Result<()> {
    *count = count
        .checked_add(amount)
        .filter(|&n| n <= maximum)
        .ok_or(ExpressionError::Limit(resource))?;
    Ok(())
}

struct Uses<'a> {
    values: &'a [ValueId],
    position: usize,
}

impl Uses<'_> {
    fn take(
        &mut self,
        variable: StorageId,
        analysis: &PcodeSsa,
        budget: &mut Budget,
    ) -> Result<ValueId> {
        budget.charge(1)?;
        let value = *self
            .values
            .get(self.position)
            .ok_or(ExpressionError::Inconsistent("missing SSA use"))?;
        if analysis
            .ssa()
            .value(value)
            .map_err(|_| ExpressionError::UnknownValue(value))?
            .variable
            .0
            != variable.0
        {
            return Err(ExpressionError::Inconsistent("SSA use order"));
        }
        self.position += 1;
        Ok(value)
    }
}

struct Builder {
    analysis: Arc<PcodeSsa>,
    budget: Budget,
    nodes: Vec<ExpressionNode>,
    definitions: Vec<Option<ExpressionDefinition>>,
    value_nodes: Vec<Option<ExpressionId>>,
    operations: Vec<Option<ExpressionOperation>>,
    offsets: Vec<usize>,
    spaces: BTreeMap<SpaceId, SpaceProperties>,
}

struct SpaceProperties {
    endianness: Endianness,
    word_size: u32,
    address_size: u8,
}

impl Builder {
    fn build(analysis: Arc<PcodeSsa>, limits: ExpressionLimits) -> Result<PcodeExpressions> {
        let mut budget = Budget {
            limits,
            work: 0,
            references: 0,
            constants: 0,
        };
        let count = analysis.ssa().values().len();
        let nodes = analysis.ssa().graph().node_count();
        if count > limits.max_values {
            return Err(ExpressionError::Limit("values"));
        }
        if nodes > limits.max_graph_nodes {
            return Err(ExpressionError::Limit("graph nodes"));
        }
        let mut statements = 0;
        for node in 0..nodes {
            budget.charge(1)?;
            if let Some(block) = analysis
                .ssa()
                .block(node)
                .map_err(|_| ExpressionError::Inconsistent("SSA block"))?
                .renamed()
            {
                add(
                    &mut statements,
                    block.statements().len(),
                    limits.max_statements,
                    "statements",
                )?;
            }
        }
        let offset_count = nodes
            .checked_add(1)
            .ok_or(ExpressionError::Limit("graph nodes"))?;
        let slots = count
            .checked_mul(2)
            .and_then(|n| n.checked_add(offset_count))
            .and_then(|n| n.checked_add(statements))
            .ok_or(ExpressionError::Limit("work"))?;
        budget.charge(slots)?;
        let mut builder = Self {
            analysis: analysis.clone(),
            budget,
            nodes: Vec::new(),
            definitions: vec![None; count],
            value_nodes: vec![None; count],
            operations: Vec::with_capacity(statements),
            offsets: Vec::with_capacity(offset_count),
            spaces: BTreeMap::new(),
        };
        for space in analysis.cfg().spaces() {
            builder.budget.map(analysis.cfg().spaces().len())?;
            builder.spaces.insert(
                space.id,
                SpaceProperties {
                    endianness: space.endianness,
                    word_size: space.word_size,
                    address_size: space.address_size,
                },
            );
        }
        for (index, value) in analysis.ssa().values().iter().enumerate() {
            builder.budget.charge(1)?;
            builder.definitions[index] = match value.origin {
                ValueOrigin::Entry(state) => Some(ExpressionDefinition::Entry(state)),
                ValueOrigin::Phi(phi) => Some(ExpressionDefinition::Phi(phi)),
                ValueOrigin::Definition(_) => None,
            };
        }
        for node in 0..nodes {
            builder.budget.charge(1)?;
            builder.offsets.push(builder.operations.len());
            let block = analysis
                .ssa()
                .block(node)
                .map_err(|_| ExpressionError::Inconsistent("SSA block"))?;
            if let Some(block) = block.renamed() {
                for (index, statement) in block.statements().iter().enumerate() {
                    builder.budget.charge(1)?;
                    let id = StatementId { node, index };
                    let operation = builder.statement(id, statement)?;
                    builder.operations.push(operation);
                }
            }
        }
        builder.offsets.push(builder.operations.len());
        builder.budget.charge(count)?;
        let mut definitions = Vec::with_capacity(count);
        for definition in builder.definitions {
            definitions
                .push(definition.ok_or(ExpressionError::Inconsistent("missing SSA definition"))?);
        }
        Ok(PcodeExpressions {
            analysis,
            nodes: builder.nodes,
            definitions,
            operations: builder.operations,
            offsets: builder.offsets,
            references: builder.budget.references,
            constant_bytes: builder.budget.constants,
            work: builder.budget.work,
        })
    }

    fn push(&mut self, ty: ExpressionType, kind: ExpressionKind) -> Result<ExpressionId> {
        if self.nodes.len() >= self.budget.limits.max_expression_nodes {
            return Err(ExpressionError::Limit("expression nodes"));
        }
        self.budget.charge(1)?;
        let refs = match &kind {
            ExpressionKind::Constant(value) => {
                add(
                    &mut self.budget.constants,
                    value.size() as usize,
                    self.budget.limits.max_constant_bytes,
                    "constant bytes",
                )?;
                self.budget.charge(value.size() as usize)?;
                0
            }
            ExpressionKind::SsaValue(_) => 1,
            ExpressionKind::Join(parts) => parts.len(),
            ExpressionKind::Extract { .. } => 1,
            ExpressionKind::Pure { inputs, .. } => inputs.len(),
            ExpressionKind::ReadMemory { address, .. } => {
                1 + usize::from(matches!(address, ExpressionAddress::Pointer { .. }))
            }
            ExpressionKind::WriteMemory { address, .. } => {
                2 + usize::from(matches!(address, ExpressionAddress::Pointer { .. }))
            }
        };
        self.budget.references(refs)?;
        let id = ExpressionId(self.nodes.len());
        self.nodes.push(ExpressionNode { ty, kind });
        Ok(id)
    }

    fn literal(&mut self, value: &Value) -> Result<ExpressionId> {
        // Check the literal budget before cloning its arbitrary-width payload.
        if self.nodes.len() >= self.budget.limits.max_expression_nodes {
            return Err(ExpressionError::Limit("expression nodes"));
        }
        if self
            .budget
            .constants
            .checked_add(value.size() as usize)
            .is_none_or(|n| n > self.budget.limits.max_constant_bytes)
        {
            return Err(ExpressionError::Limit("constant bytes"));
        }
        self.push(
            ExpressionType::Bits(value.size()),
            ExpressionKind::Constant(value.clone()),
        )
    }

    fn ssa_value(&mut self, value: ValueId) -> Result<ExpressionId> {
        self.budget.charge(1)?;
        if let Some(id) = *self
            .value_nodes
            .get(value.0)
            .ok_or(ExpressionError::UnknownValue(value))?
        {
            return Ok(id);
        }
        let ty = value_type(&self.analysis, value)?;
        let id = self.push(ty, ExpressionKind::SsaValue(value))?;
        self.value_nodes[value.0] = Some(id);
        Ok(id)
    }

    fn space(&mut self, space: SpaceId) -> Result<(Endianness, u32, u8)> {
        self.budget.map(self.spaces.len())?;
        let space = self
            .spaces
            .get(&space)
            .ok_or(ExpressionError::Inconsistent("memory space"))?;
        Ok((space.endianness, space.word_size, space.address_size))
    }

    fn memory_type(&self, version: ValueId, space: SpaceId) -> Result<()> {
        if value_type(&self.analysis, version)? != ExpressionType::Memory(space) {
            return Err(ExpressionError::Inconsistent("memory version type"));
        }
        Ok(())
    }

    fn read(
        &mut self,
        space: SpaceId,
        version: ValueId,
        address: ExpressionAddress,
        size: u32,
    ) -> Result<ExpressionId> {
        self.memory_type(version, space)?;
        let (endianness, _, _) = self.space(space)?;
        self.push(
            ExpressionType::Bits(size),
            ExpressionKind::ReadMemory {
                space,
                version,
                address,
                endianness,
            },
        )
    }

    fn write(
        &mut self,
        space: SpaceId,
        version: ValueId,
        address: ExpressionAddress,
        value: ExpressionId,
    ) -> Result<ExpressionId> {
        self.memory_type(version, space)?;
        if !matches!(self.nodes[value.0].ty, ExpressionType::Bits(_)) {
            return Err(ExpressionError::Inconsistent("memory write value"));
        }
        let (endianness, _, _) = self.space(space)?;
        self.push(
            ExpressionType::Memory(space),
            ExpressionKind::WriteMemory {
                space,
                version,
                address,
                value,
                endianness,
            },
        )
    }

    fn binding(&mut self, binding: &ValueBinding, uses: &mut Uses<'_>) -> Result<ExpressionId> {
        match binding {
            ValueBinding::Constant(value) => self.literal(value),
            ValueBinding::Scalar(binding) => {
                self.budget.charge(binding.pieces().len())?;
                let analysis = self.analysis.clone();
                if let [piece] = binding.pieces()
                    && piece.value_offset == 0
                    && piece.size == binding.size()
                {
                    let value = uses.take(piece.variable, &analysis, &mut self.budget)?;
                    let value = self.ssa_value(value)?;
                    if self.nodes[value.0].ty != ExpressionType::Bits(piece.size) {
                        return Err(ExpressionError::Inconsistent("scalar piece width"));
                    }
                    return Ok(value);
                }
                self.budget.preflight_references(binding.pieces().len())?;
                let mut parts = Vec::with_capacity(binding.pieces().len());
                for piece in binding.pieces() {
                    let value = uses.take(piece.variable, &analysis, &mut self.budget)?;
                    let value = self.ssa_value(value)?;
                    if self.nodes[value.0].ty != ExpressionType::Bits(piece.size) {
                        return Err(ExpressionError::Inconsistent("scalar piece width"));
                    }
                    parts.push(ExpressionPiece {
                        value,
                        lsb_byte: piece.value_offset,
                        size: piece.size,
                    });
                }
                self.push(
                    ExpressionType::Bits(binding.size()),
                    ExpressionKind::Join(parts),
                )
            }
            ValueBinding::Memory {
                variable,
                space,
                offset,
                size,
            } => {
                let analysis = self.analysis.clone();
                let version = uses.take(*variable, &analysis, &mut self.budget)?;
                self.read(
                    *space,
                    version,
                    ExpressionAddress::ByteOffset(*offset),
                    *size,
                )
            }
        }
    }

    fn define(&mut self, value: ValueId, definition: ExpressionDefinition) -> Result<()> {
        self.budget.charge(1)?;
        if let ExpressionDefinition::Expression(root) = &definition {
            self.budget.references(1)?;
            if self.nodes[root.0].ty != value_type(&self.analysis, value)? {
                return Err(ExpressionError::Inconsistent("definition type"));
            }
        }
        let place = self
            .definitions
            .get_mut(value.0)
            .ok_or(ExpressionError::UnknownValue(value))?;
        if place.replace(definition).is_some() {
            return Err(ExpressionError::Inconsistent("duplicate SSA definition"));
        }
        Ok(())
    }

    fn pointer(&mut self, space: SpaceId, value: ExpressionId) -> Result<ExpressionAddress> {
        let (_, word_size, address_size) = self.space(space)?;
        if self.nodes[value.0].ty != ExpressionType::Bits(u32::from(address_size)) {
            return Err(ExpressionError::Inconsistent("memory pointer width"));
        }
        Ok(ExpressionAddress::Pointer {
            value,
            word_size,
            address_size,
        })
    }

    fn statement(
        &mut self,
        id: StatementId,
        statement: &RenamedStatement,
    ) -> Result<Option<ExpressionOperation>> {
        let analysis = self.analysis.clone();
        let source = analysis
            .statement(id)
            .ok_or(ExpressionError::Inconsistent("statement metadata"))?;
        match source {
            AdaptedStatement::NoOp { .. } => {
                if !statement.uses().is_empty() || !statement.defs().is_empty() {
                    return Err(ExpressionError::Inconsistent("no-op effects"));
                }
                Ok(None)
            }
            AdaptedStatement::UndefinedTemporaries { address, variables } => {
                if !statement.uses().is_empty() || statement.defs().len() != variables.len() {
                    return Err(ExpressionError::Inconsistent("temporary reset shape"));
                }
                for (&value, variable) in statement.defs().iter().zip(variables) {
                    self.budget.charge(1)?;
                    if analysis
                        .ssa()
                        .value(value)
                        .map_err(|_| ExpressionError::UnknownValue(value))?
                        .variable
                        .0
                        != variable.0
                    {
                        return Err(ExpressionError::Inconsistent("temporary reset order"));
                    }
                    self.define(
                        value,
                        ExpressionDefinition::Undefined {
                            statement: id,
                            instruction: *address,
                        },
                    )?;
                }
                Ok(None)
            }
            AdaptedStatement::Operation {
                point,
                bindings,
                effects,
            } => {
                let Statement::Operation(operation) = analysis
                    .cfg()
                    .statement(*point)
                    .ok_or(ExpressionError::Inconsistent("source operation"))?
                else {
                    return Err(ExpressionError::Inconsistent("source no-op"));
                };
                self.operation(
                    id,
                    *point,
                    operation.opcode,
                    operation.output.map(|v| v.size),
                    bindings,
                    *effects,
                    statement,
                )
                .map(Some)
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn operation(
        &mut self,
        id: StatementId,
        point: ProgramPoint,
        opcode: Opcode,
        output_size: Option<u32>,
        bindings: &OperationBindings,
        effects: AppliedEffects,
        statement: &RenamedStatement,
    ) -> Result<ExpressionOperation> {
        let analysis = self.analysis.clone();
        let mut uses = Uses {
            values: statement.uses(),
            position: 0,
        };
        // One owned operand slot per source operand, even when it is metadata.
        self.budget.references(bindings.inputs.len())?;
        let mut operands = Vec::with_capacity(bindings.inputs.len());
        for input in &bindings.inputs {
            self.budget.charge(1)?;
            operands.push(match input {
                InputBinding::Value(binding) => {
                    ExpressionOperand::Value(self.binding(binding, &mut uses)?)
                }
                InputBinding::RelativeTarget(target) => ExpressionOperand::RelativeTarget(*target),
                InputBinding::DirectTarget(target) => ExpressionOperand::DirectTarget(*target),
                InputBinding::SpaceSelector(space) => ExpressionOperand::SpaceSelector(*space),
                InputBinding::Userop(userop) => ExpressionOperand::Userop(*userop),
                InputBinding::OperationReference(source) => {
                    ExpressionOperand::OperationReference(*source)
                }
                InputBinding::ConstantMetadata(source) => {
                    let value = self.literal(&Value::from_u64(source.size, source.offset)?)?;
                    ExpressionOperand::ConstantMetadata {
                        source: *source,
                        value,
                    }
                }
            });
        }
        let indirect_memory = if let Some(memory) = &bindings.memory {
            let version = uses.take(memory.variable, &analysis, &mut self.budget)?;
            self.memory_type(version, memory.space)?;
            self.budget.references(1)?;
            Some(ExpressionMemoryUse {
                space: memory.space,
                version,
                kind: memory.kind,
            })
        } else {
            None
        };
        let output_memory = if let Some(ValueBinding::Memory {
            variable,
            space,
            offset,
            size,
        }) = bindings.output
        {
            Some((
                variable,
                space,
                offset,
                size,
                uses.take(variable, &analysis, &mut self.budget)?,
            ))
        } else {
            None
        };
        if matches!(effects, AppliedEffects::Conservative(_)) {
            // The adapter appends every observed variable after declared reads.
            // Share that complete dependency list rather than making a smaller
            // expression that would falsely make a call appear pure.
            for variable in analysis.layout().variables() {
                uses.take(variable.id, &analysis, &mut self.budget)?;
            }
            if uses.position != uses.values.len() {
                return Err(ExpressionError::Inconsistent("opaque use shape"));
            }
            for (slot, &value) in statement.defs().iter().enumerate() {
                self.define(
                    value,
                    ExpressionDefinition::Opaque {
                        statement: id,
                        definition_slot: slot,
                    },
                )?;
            }
            return Ok(ExpressionOperation {
                statement: id,
                point,
                opcode,
                operands,
                output: None,
                indirect_memory,
                effects,
            });
        }
        if uses.position != uses.values.len() {
            return Err(ExpressionError::Inconsistent("unconsumed SSA uses"));
        }
        let operand = |index: usize| {
            operands
                .get(index)
                .and_then(ExpressionOperand::expression)
                .ok_or(ExpressionError::Inconsistent("value operand"))
        };
        let mut writes = BTreeMap::new();
        let output = match opcode {
            Opcode::Load => {
                let memory = indirect_memory
                    .as_ref()
                    .ok_or(ExpressionError::Inconsistent("LOAD memory"))?;
                if memory.kind != MemoryAccessKind::Read {
                    return Err(ExpressionError::Inconsistent("LOAD effect"));
                }
                let address = self.pointer(memory.space, operand(1)?)?;
                let size = output_size.ok_or(ExpressionError::Inconsistent("LOAD output"))?;
                Some(self.read(memory.space, memory.version, address, size)?)
            }
            Opcode::Store => {
                let memory = indirect_memory
                    .as_ref()
                    .ok_or(ExpressionError::Inconsistent("STORE memory"))?;
                if memory.kind != MemoryAccessKind::Write || bindings.output.is_some() {
                    return Err(ExpressionError::Inconsistent("STORE effect"));
                }
                let address = self.pointer(memory.space, operand(1)?)?;
                let root = self.write(memory.space, memory.version, address, operand(2)?)?;
                let variable = bindings
                    .memory
                    .as_ref()
                    .ok_or(ExpressionError::Inconsistent("STORE variable"))?
                    .variable;
                self.insert_write(&mut writes, variable, root)?;
                None
            }
            _ => {
                if indirect_memory.is_some() {
                    return Err(ExpressionError::Inconsistent("unexpected indirect memory"));
                }
                if let Some(size) = output_size {
                    self.budget.preflight_references(operands.len())?;
                    self.budget.charge(operands.len())?;
                    let inputs = operands
                        .iter()
                        .map(|operand| {
                            operand
                                .expression()
                                .ok_or(ExpressionError::Inconsistent("pure operation metadata"))
                        })
                        .collect::<Result<Vec<_>>>()?;
                    Some(self.push(
                        ExpressionType::Bits(size),
                        ExpressionKind::Pure { opcode, inputs },
                    )?)
                } else {
                    None
                }
            }
        };
        if let Some(binding) = &bindings.output {
            let value = output.ok_or(ExpressionError::Inconsistent("missing explicit result"))?;
            match binding {
                ValueBinding::Constant(_) => {
                    return Err(ExpressionError::Inconsistent("constant output"));
                }
                ValueBinding::Scalar(binding) => {
                    for piece in binding.pieces() {
                        self.budget.charge(1)?;
                        let root = if piece.value_offset == 0 && piece.size == binding.size() {
                            value
                        } else {
                            if piece
                                .value_offset
                                .checked_add(piece.size)
                                .is_none_or(|end| end > binding.size())
                            {
                                return Err(ExpressionError::Inconsistent("output slice"));
                            }
                            self.push(
                                ExpressionType::Bits(piece.size),
                                ExpressionKind::Extract {
                                    value,
                                    lsb_byte: piece.value_offset,
                                },
                            )?
                        };
                        self.insert_write(&mut writes, piece.variable, root)?;
                    }
                }
                ValueBinding::Memory { .. } => {
                    let (variable, space, offset, size, version) = output_memory
                        .ok_or(ExpressionError::Inconsistent("output memory state"))?;
                    if self.nodes[value.0].ty != ExpressionType::Bits(size) {
                        return Err(ExpressionError::Inconsistent("fixed memory write width"));
                    }
                    let root =
                        self.write(space, version, ExpressionAddress::ByteOffset(offset), value)?;
                    self.insert_write(&mut writes, variable, root)?;
                }
            }
        } else if output.is_some() {
            return Err(ExpressionError::Inconsistent("unexpected result"));
        }
        for &value in statement.defs() {
            self.budget.map(writes.len())?;
            let variable = analysis
                .ssa()
                .value(value)
                .map_err(|_| ExpressionError::UnknownValue(value))?
                .variable;
            let root = writes
                .remove(&StorageId(variable.0))
                .ok_or(ExpressionError::Inconsistent("missing expression write"))?;
            self.define(value, ExpressionDefinition::Expression(root))?;
        }
        if !writes.is_empty() {
            return Err(ExpressionError::Inconsistent("unmatched expression write"));
        }
        if output.is_some() {
            self.budget.references(1)?;
        }
        Ok(ExpressionOperation {
            statement: id,
            point,
            opcode,
            operands,
            output,
            indirect_memory,
            effects,
        })
    }

    fn insert_write(
        &mut self,
        writes: &mut BTreeMap<StorageId, ExpressionId>,
        variable: StorageId,
        value: ExpressionId,
    ) -> Result<()> {
        self.budget.map(writes.len())?;
        if writes.insert(variable, value).is_some() {
            return Err(ExpressionError::Inconsistent("duplicate expression write"));
        }
        Ok(())
    }
}
