//! Construction: bounded validation, leader marking, block splitting, and
//! edge/exit materialization. Every pass is an explicit loop; nothing recurses.

use std::sync::Arc;

use ghidra_graph::Graph;
use ghidra_pcode::model::{MAX_INPUTS, MAX_OPS_PER_INSTRUCTION};
use ghidra_pcode::{
    AddressSpace, Opcode, PcodeInstruction, PcodeOperation, SpaceId, SpaceKind, Varnode,
};

use crate::error::limit;
use crate::{
    Arrival, CallSite, CallTarget, Cfg, CfgError, CfgInput, Edge, EdgeRole, Exit, ExitKind, Gap,
    Limits, OperandError, OperandSlot, ProgramPoint, Resource, TargetLocation, UseropSite,
};

struct Budget {
    limit: u64,
    used: u64,
}

impl Budget {
    fn charge(&mut self, amount: usize) -> Result<(), CfgError> {
        self.used = u64::try_from(amount)
            .ok()
            .and_then(|amount| self.used.checked_add(amount))
            .filter(|&used| used <= self.limit)
            .ok_or_else(|| limit(Resource::Work))?;
        Ok(())
    }

    fn tick(&mut self) -> Result<(), CfgError> {
        self.charge(1)
    }

    /// Precharge `n * (ceil(log2 n) + 1)` for a comparison sort.
    fn sorting(&mut self, n: usize) -> Result<(), CfgError> {
        if n > 1 {
            let levels = (usize::BITS - (n - 1).leading_zeros()) as usize + 1;
            self.charge(n.checked_mul(levels).ok_or_else(|| limit(Resource::Work))?)?;
        }
        Ok(())
    }

    fn search(&mut self, n: usize) -> Result<(), CfgError> {
        self.charge(search_cost(n))
    }
}

/// `floor(log2 n) + 2` covers the comparisons of one binary search over `n`.
fn search_cost(n: usize) -> usize {
    (usize::BITS - n.leading_zeros()) as usize + 1
}

/// Byte extent of a space: `2^(8 * address_size) * word_size`, capped at 2^64.
fn extent(space: &AddressSpace) -> u128 {
    let units = 1_u128 << (u32::from(space.address_size) * 8);
    (units * u128::from(space.word_size)).min(1_u128 << 64)
}

fn fits(space: &AddressSpace, varnode: &Varnode) -> bool {
    u128::from(varnode.offset) + u128::from(varnode.size) <= extent(space)
}

struct SpaceTable<'a> {
    by_id: Vec<(SpaceId, &'a AddressSpace)>,
}

impl<'a> SpaceTable<'a> {
    fn new(
        spaces: &'a [AddressSpace],
        limits: &Limits,
        budget: &mut Budget,
    ) -> Result<Self, CfgError> {
        if spaces.is_empty() {
            return Err(CfgError::NoSpaces);
        }
        if spaces.len() > limits.max_spaces {
            return Err(limit(Resource::Spaces));
        }
        budget.charge(spaces.len())?;
        for space in spaces {
            space.validate().map_err(|source| CfgError::InvalidSpace {
                id: space.id,
                source,
            })?;
        }
        budget.sorting(spaces.len())?;
        let mut by_id: Vec<_> = spaces.iter().map(|space| (space.id, space)).collect();
        by_id.sort_unstable_by_key(|&(id, _)| id);
        for pair in by_id.windows(2) {
            if pair[0].0 == pair[1].0 {
                return Err(CfgError::DuplicateSpaceId(pair[0].0));
            }
        }
        // Names are at most 256 bytes, so each comparison is constant-bounded.
        budget.sorting(spaces.len())?;
        let mut names: Vec<&str> = spaces.iter().map(|space| space.name.as_str()).collect();
        names.sort_unstable();
        for pair in names.windows(2) {
            if pair[0] == pair[1] {
                return Err(CfgError::DuplicateSpaceName(pair[0].to_owned()));
            }
        }
        Ok(Self { by_id })
    }

    fn get(&self, id: SpaceId) -> Option<&'a AddressSpace> {
        let index = self.by_id.binary_search_by_key(&id, |&(id, _)| id).ok()?;
        Some(self.by_id[index].1)
    }
}

/// How an operation uses each input.
#[derive(Clone, Copy)]
enum Role {
    /// Read as a value; constant-space inputs are literals.
    Value,
    Constant,
    /// LOAD/STORE input0: constant naming the accessed space.
    Selector,
    /// LOAD/STORE input1: pointer sized for the selected space.
    Pointer,
    /// BRANCHIND/CALLIND input0: runtime code address; RETURN also permits a literal sentinel.
    CodePointer,
    /// BRANCH/CBRANCH input0: relative constant or code-space address label.
    BranchLabel,
    /// CALL input0: code-space address label.
    CallLabel,
}

fn role(opcode: Opcode, index: usize) -> Role {
    use Opcode::*;
    match (opcode, index) {
        (Load | Store, 0) => Role::Selector,
        (Load | Store, 1) => Role::Pointer,
        (Branch | Cbranch, 0) => Role::BranchLabel,
        (Call, 0) => Role::CallLabel,
        (Branchind | Callind | Return, 0) => Role::CodePointer,
        (Callother, 0) | (Subpiece, 1) | (Ptradd, 2) | (Insert, 2 | 3) | (Zpull | Spull, 1 | 2) => {
            Role::Constant
        }
        _ => Role::Value,
    }
}

/// Resolved successor of a point.
#[derive(Clone, Copy)]
enum Flow {
    Point { index: usize, arrival: Arrival },
    Exit(ExitKind),
}

type Outcomes = [Option<(EdgeRole, Flow)>; 2];

struct BlockEnd {
    rank: usize,
    operation: usize,
    outcomes: Outcomes,
}

struct Builder<'a> {
    instructions: &'a [PcodeInstruction],
    table: SpaceTable<'a>,
    code: &'a AddressSpace,
    code_extent: u128,
    lookup_cost: usize,
    order: Vec<usize>,
    addresses: Vec<u64>,
    point_start: Vec<usize>,
    budget: Budget,
}

impl<'a> Builder<'a> {
    fn instruction(&self, rank: usize) -> &'a PcodeInstruction {
        &self.instructions[self.order[rank]]
    }

    fn end(&self, rank: usize) -> u128 {
        let instruction = self.instruction(rank);
        u128::from(instruction.address) + u128::from(instruction.length)
    }

    /// Flow to `address + length`, which includes any expanded delay slots.
    fn end_flow(&self, rank: usize) -> Flow {
        let end = self.end(rank);
        if end >= self.code_extent {
            return Flow::Exit(ExitKind::SpaceEndFallthrough);
        }
        let end = end as u64;
        if self.addresses.get(rank + 1) == Some(&end) {
            Flow::Point {
                index: self.point_start[rank + 1],
                arrival: Arrival::InstructionEntry,
            }
        } else {
            Flow::Exit(ExitKind::OutsideFallthrough { target: end })
        }
    }

    fn sequential(&self, rank: usize, operation: usize) -> Flow {
        if operation + 1 < self.instruction(rank).ops.len() {
            Flow::Point {
                index: self.point_start[rank] + operation + 1,
                arrival: Arrival::SameInstruction,
            }
        } else {
            self.end_flow(rank)
        }
    }

    /// Classify a code address against the sorted, nonoverlapping extents.
    fn locate(&mut self, address: u64) -> Result<(TargetLocation, usize), CfgError> {
        self.budget.search(self.addresses.len())?;
        let after = self.addresses.partition_point(|&start| start <= address);
        let Some(rank) = after.checked_sub(1) else {
            return Ok((TargetLocation::NotSupplied, 0));
        };
        Ok(if self.addresses[rank] == address {
            (TargetLocation::InstructionStart, rank)
        } else if u128::from(address) < self.end(rank) {
            (
                TargetLocation::InstructionInterior {
                    instruction: self.addresses[rank],
                },
                rank,
            )
        } else {
            (TargetLocation::NotSupplied, rank)
        })
    }

    /// BRANCH/CBRANCH label. Constant labels are signed 32-bit displacements
    /// from the current operation index; `ops.len()` means the instruction end.
    fn label(&mut self, rank: usize, operation: usize, label: &Varnode) -> Result<Flow, CfgError> {
        self.budget.charge(self.lookup_cost)?;
        let constant = self
            .table
            .get(label.space)
            .is_some_and(|space| space.kind == SpaceKind::Constant);
        if !constant {
            let target = label.offset;
            return Ok(match self.locate(target)? {
                (TargetLocation::InstructionStart, rank) => Flow::Point {
                    index: self.point_start[rank],
                    arrival: Arrival::InstructionEntry,
                },
                (TargetLocation::InstructionInterior { instruction }, _) => {
                    Flow::Exit(ExitKind::InteriorBranch {
                        target,
                        instruction,
                    })
                }
                (TargetLocation::NotSupplied, _) => Flow::Exit(ExitKind::ExternalBranch { target }),
            });
        }
        let instruction = self.instruction(rank);
        let count = instruction.ops.len();
        let displacement = label.offset as u32 as i32;
        let target = operation as i64 + i64::from(displacement);
        if !(0..=count as i64).contains(&target) {
            return Err(CfgError::InvalidRelativeTarget {
                point: ProgramPoint::new(instruction.address, operation as u32),
                displacement,
                target,
                operation_count: count,
            });
        }
        Ok(if target as usize == count {
            self.end_flow(rank)
        } else {
            Flow::Point {
                index: self.point_start[rank] + target as usize,
                arrival: Arrival::SameInstruction,
            }
        })
    }

    /// Outcomes of a block-ending operation, or `None` for ordinary operations.
    fn terminator(&mut self, rank: usize, operation: usize) -> Result<Option<Outcomes>, CfgError> {
        let op = &self.instruction(rank).ops[operation];
        Ok(Some(match op.opcode {
            Opcode::Branch => [
                Some((
                    EdgeRole::Branch,
                    self.label(rank, operation, &op.inputs[0])?,
                )),
                None,
            ],
            Opcode::Cbranch => [
                Some((EdgeRole::ConditionFalse, self.sequential(rank, operation))),
                Some((
                    EdgeRole::ConditionTrue,
                    self.label(rank, operation, &op.inputs[0])?,
                )),
            ],
            Opcode::Branchind => [
                Some((
                    EdgeRole::IndirectBranch,
                    Flow::Exit(ExitKind::UnresolvedIndirectBranch),
                )),
                None,
            ],
            Opcode::Call | Opcode::Callind => [
                Some((EdgeRole::CallReturn, self.sequential(rank, operation))),
                Some((EdgeRole::CallNoReturn, Flow::Exit(ExitKind::CallNoReturn))),
            ],
            Opcode::Return => [Some((EdgeRole::Return, Flow::Exit(ExitKind::Return))), None],
            Opcode::Unimplemented => [
                Some((EdgeRole::Unimplemented, Flow::Exit(ExitKind::Unimplemented))),
                None,
            ],
            _ => return Ok(None),
        }))
    }

    /// Last point and outcomes of `block`. `rank` only advances, so a full
    /// sweep over ascending blocks costs `O(blocks + instructions)`.
    fn block_end(
        &mut self,
        block_start: &[usize],
        block: usize,
        rank: &mut usize,
    ) -> Result<BlockEnd, CfgError> {
        self.budget.tick()?;
        let last = block_start[block + 1] - 1;
        while self.point_start[*rank + 1] <= last {
            self.budget.tick()?;
            *rank += 1;
        }
        let operation = last - self.point_start[*rank];
        let terminator = if self.instruction(*rank).ops.is_empty() {
            None
        } else {
            self.terminator(*rank, operation)?
        };
        let outcomes = terminator.unwrap_or_else(|| {
            [
                Some((EdgeRole::Fallthrough, self.sequential(*rank, operation))),
                None,
            ]
        });
        Ok(BlockEnd {
            rank: *rank,
            operation,
            outcomes,
        })
    }

    fn validate(&mut self, point: ProgramPoint, op: &PcodeOperation) -> Result<(), CfgError> {
        let references = op.inputs.len() + usize::from(op.output.is_some());
        // One lookup per reference, one extra for a LOAD/STORE selector, plus
        // linear structural checks inside `PcodeOperation::validate`.
        self.budget
            .charge((references + 2) * (self.lookup_cost + 2))?;
        op.validate()
            .map_err(|source| CfgError::InvalidOperation { point, source })?;
        if matches!(op.opcode, Opcode::Multiequal | Opcode::Indirect) {
            return Err(CfgError::UnsupportedOperation {
                point,
                opcode: op.opcode,
            });
        }
        let invalid = |slot, problem| CfgError::InvalidOperand {
            point,
            opcode: op.opcode,
            slot,
            problem,
        };
        if let Some(output) = &op.output {
            let space = self.table.get(output.space).ok_or_else(|| {
                invalid(
                    OperandSlot::Output,
                    OperandError::UnknownSpace(output.space),
                )
            })?;
            if space.kind == SpaceKind::Constant {
                return Err(invalid(OperandSlot::Output, OperandError::ConstantOutput));
            }
            if !fits(space, output) {
                return Err(invalid(OperandSlot::Output, OperandError::OutOfSpace));
            }
        }
        let mut selected = None;
        for (index, input) in op.inputs.iter().enumerate() {
            let slot = OperandSlot::Input(index);
            let space = self
                .table
                .get(input.space)
                .ok_or_else(|| invalid(slot, OperandError::UnknownSpace(input.space)))?;
            let constant = space.kind == SpaceKind::Constant;
            let value = |required_width: Option<u32>| {
                if let Some(expected) = required_width
                    && input.size != expected
                {
                    return Err(invalid(
                        slot,
                        OperandError::PointerWidth {
                            expected,
                            actual: input.size,
                        },
                    ));
                }
                if !constant && !fits(space, input) {
                    return Err(invalid(slot, OperandError::OutOfSpace));
                }
                Ok(())
            };
            // Direct labels are addresses, not value reads: only the label
            // address must lie in the code space, not `offset + size`.
            let address_label = || {
                if input.space != self.code.id {
                    Err(invalid(
                        slot,
                        OperandError::CrossSpaceLabel { space: input.space },
                    ))
                } else if u128::from(input.offset) >= self.code_extent {
                    Err(invalid(
                        slot,
                        OperandError::LabelOutOfSpace {
                            offset: input.offset,
                        },
                    ))
                } else {
                    Ok(())
                }
            };
            match role(op.opcode, index) {
                Role::Value => value(None)?,
                Role::Constant if !constant => {
                    return Err(invalid(slot, OperandError::RequiresConstant));
                }
                Role::Constant => {}
                Role::Selector => {
                    if !constant {
                        return Err(invalid(slot, OperandError::RequiresConstant));
                    }
                    selected = u32::try_from(input.offset)
                        .ok()
                        .and_then(|id| self.table.get(SpaceId(id)))
                        .filter(|target| target.kind != SpaceKind::Constant);
                    if selected.is_none() {
                        return Err(invalid(
                            slot,
                            OperandError::SelectorSpace {
                                offset: input.offset,
                            },
                        ));
                    }
                }
                Role::Pointer => {
                    let target = selected.expect("selector precedes pointer");
                    value(Some(u32::from(target.address_size)))?;
                }
                // SLEIGH also uses RETURN with a narrow constant sentinel for
                // terminating traps (x86 INT1/INT3 emit return [0:1]). It is a
                // literal exit target, not a truncated computed pointer read.
                Role::CodePointer if op.opcode == Opcode::Return && constant => value(None)?,
                Role::CodePointer => value(Some(u32::from(self.code.address_size)))?,
                Role::BranchLabel if constant => {}
                Role::BranchLabel => address_label()?,
                Role::CallLabel if constant => {
                    return Err(invalid(slot, OperandError::RelativeCallLabel));
                }
                Role::CallLabel => address_label()?,
            }
        }
        Ok(())
    }
}

pub(crate) fn build(input: CfgInput, limits: Limits) -> Result<Cfg, CfgError> {
    let CfgInput {
        spaces,
        code_space,
        entry,
        instructions,
    } = input;
    let mut budget = Budget {
        limit: limits.max_work,
        used: 0,
    };
    let table = SpaceTable::new(&spaces, &limits, &mut budget)?;
    let code = table
        .get(code_space)
        .ok_or(CfgError::UnknownCodeSpace(code_space))?;
    if !matches!(code.kind, SpaceKind::Ram | SpaceKind::Other) {
        return Err(CfgError::CodeSpaceKind {
            id: code_space,
            kind: code.kind,
        });
    }
    if code.word_size != 1 {
        return Err(CfgError::WordAddressedCode {
            id: code_space,
            word_size: code.word_size,
        });
    }

    // Count-only passes: no operand contents are inspected until every total
    // fits, so huge operand vectors cannot cost more than their length check.
    let count = instructions.len();
    if count > limits.max_instructions {
        return Err(limit(Resource::Instructions));
    }
    if count == 0 {
        return Err(CfgError::EntryNotInstruction { entry });
    }
    let mut operations = 0_usize;
    let mut empty = 0_usize;
    for instruction in instructions.iter() {
        budget.tick()?;
        let length = instruction.ops.len();
        if length > MAX_OPS_PER_INSTRUCTION {
            return Err(CfgError::InstructionOperationCount {
                address: instruction.address,
                count: length,
            });
        }
        operations = operations
            .checked_add(length)
            .filter(|&total| total <= limits.max_operations)
            .ok_or_else(|| limit(Resource::Operations))?;
        empty += usize::from(length == 0);
    }
    let mut references = 0_usize;
    for instruction in instructions.iter() {
        for (index, op) in instruction.ops.iter().enumerate() {
            budget.tick()?;
            if op.inputs.len() > MAX_INPUTS {
                return Err(CfgError::OperationInputCount {
                    point: ProgramPoint::new(instruction.address, index as u32),
                    count: op.inputs.len(),
                });
            }
            references = references
                .checked_add(op.inputs.len() + usize::from(op.output.is_some()))
                .filter(|&total| total <= limits.max_operand_refs)
                .ok_or_else(|| limit(Resource::OperandRefs))?;
        }
    }
    let point_count = operations + empty;

    // Canonical order: (address, length), so errors and output never depend
    // on the supplied order. Extents and duplicates are checked before any
    // operation content, so duplicate addresses report deterministically.
    let code_extent = extent(code);
    budget.charge(count)?;
    let mut order: Vec<usize> = (0..count).collect();
    budget.sorting(count)?;
    order.sort_by_key(|&index| (instructions[index].address, instructions[index].length));
    budget.charge(count)?;
    let addresses: Vec<u64> = order
        .iter()
        .map(|&index| instructions[index].address)
        .collect();
    let mut gaps = Vec::new();
    let mut point_start = Vec::with_capacity(count + 1);
    let mut previous_end: Option<u128> = None;
    let mut next_point = 0;
    for (rank, &index) in order.iter().enumerate() {
        budget.tick()?;
        let instruction = &instructions[index];
        let start = u128::from(instruction.address);
        let end = start + u128::from(instruction.length);
        if instruction.length == 0 || end > code_extent {
            return Err(CfgError::InstructionExtent {
                address: instruction.address,
                length: instruction.length,
            });
        }
        if let Some(previous) = previous_end {
            if addresses[rank - 1] == instruction.address {
                return Err(CfgError::DuplicateInstruction {
                    address: instruction.address,
                });
            }
            if previous > start {
                return Err(CfgError::OverlappingInstructions {
                    first: addresses[rank - 1],
                    second: instruction.address,
                });
            }
            if previous < start {
                gaps.push(Gap {
                    start: previous as u64,
                    end: instruction.address,
                });
            }
        }
        previous_end = Some(end);
        point_start.push(next_point);
        next_point += instruction.ops.len().max(1);
    }
    point_start.push(next_point);
    debug_assert_eq!(next_point, point_count);
    budget.search(count)?;
    let entry_rank = addresses
        .binary_search(&entry)
        .map_err(|_| CfgError::EntryNotInstruction { entry })?;

    budget.charge(point_count)?;
    let mut points = Vec::with_capacity(point_count);
    for &index in &order {
        let instruction = &instructions[index];
        if instruction.ops.is_empty() {
            points.push(ProgramPoint::new(instruction.address, 0));
        }
        for operation in 0..instruction.ops.len() {
            points.push(ProgramPoint::new(instruction.address, operation as u32));
        }
    }

    let mut builder = Builder {
        instructions: &instructions,
        lookup_cost: search_cost(spaces.len()),
        table,
        code,
        code_extent,
        order,
        addresses,
        point_start,
        budget,
    };

    // Validation and leader marking, in canonical order.
    builder.budget.charge(point_count)?;
    let mut leader = vec![false; point_count];
    leader[0] = true;
    leader[builder.point_start[entry_rank]] = true;
    let mut userop_points = Vec::new();
    for rank in 0..count {
        builder.budget.tick()?;
        let instruction = builder.instruction(rank);
        let start = builder.point_start[rank];
        if rank > 0 && builder.end(rank - 1) != u128::from(instruction.address) {
            leader[start] = true;
        }
        for (operation, op) in instruction.ops.iter().enumerate() {
            builder.validate(ProgramPoint::new(instruction.address, operation as u32), op)?;
            if op.opcode == Opcode::Callother {
                userop_points.push((start + operation, op.inputs[0].offset));
            }
            if let Some(outcomes) = builder.terminator(rank, operation)? {
                if let Some(next) = leader.get_mut(start + operation + 1) {
                    *next = true;
                }
                for (_, flow) in outcomes.into_iter().flatten() {
                    if let Flow::Point { index, .. } = flow {
                        leader[index] = true;
                    }
                }
            }
        }
    }

    builder.budget.charge(2 * point_count)?;
    let block_count = leader.iter().filter(|&&is_leader| is_leader).count();
    if block_count > limits.max_blocks {
        return Err(limit(Resource::Blocks));
    }
    let mut block_start = Vec::with_capacity(block_count + 1);
    block_start.extend(
        leader
            .iter()
            .enumerate()
            .filter_map(|(index, &is_leader)| is_leader.then_some(index)),
    );
    block_start.push(point_count);
    drop(leader);

    // Count outcomes before allocating edges or exits. Outcomes are
    // recomputed in the fill pass instead of being stored per block.
    let mut edge_count = 0_usize;
    let mut exit_count = 0_usize;
    let mut rank = 0;
    for block in 0..block_count {
        let end = builder.block_end(&block_start, block, &mut rank)?;
        for (_, flow) in end.outcomes.iter().flatten() {
            edge_count += 1;
            exit_count += usize::from(matches!(flow, Flow::Exit(_)));
        }
    }
    if edge_count > limits.max_edges {
        return Err(limit(Resource::Edges));
    }
    if exit_count > limits.max_exits {
        return Err(limit(Resource::Exits));
    }
    let node_count = block_count + exit_count;
    if node_count > limits.graph.max_nodes {
        return Err(ghidra_graph::Error::LimitExceeded {
            resource: ghidra_graph::Resource::Nodes,
        }
        .into());
    }
    if edge_count > limits.graph.max_edges {
        return Err(ghidra_graph::Error::LimitExceeded {
            resource: ghidra_graph::Resource::Edges,
        }
        .into());
    }

    builder.budget.charge(node_count + edge_count)?;
    let mut edges = Vec::with_capacity(edge_count);
    let mut exits = Vec::with_capacity(exit_count);
    let mut calls = Vec::new();
    let mut out_start = Vec::with_capacity(node_count + 1);
    let mut rank = 0;
    for block in 0..block_count {
        let end = builder.block_end(&block_start, block, &mut rank)?;
        out_start.push(edges.len());
        let source = points[block_start[block + 1] - 1];
        let mut continuation = None;
        let mut no_return = None;
        for &(role, flow) in end.outcomes.iter().flatten() {
            builder.budget.tick()?;
            let (to, arrival) = match flow {
                Flow::Point { index, arrival } => {
                    builder.budget.search(block_count)?;
                    let target = block_start
                        .binary_search(&index)
                        .expect("every flow target is a block leader");
                    (target, arrival)
                }
                Flow::Exit(kind) => {
                    let node = block_count + exits.len();
                    exits.push(Exit {
                        node,
                        from: block,
                        source,
                        role,
                        kind,
                    });
                    (node, Arrival::Exit)
                }
            };
            match role {
                EdgeRole::CallReturn => continuation = Some(to),
                EdgeRole::CallNoReturn => no_return = Some(to),
                _ => {}
            }
            edges.push(Edge {
                from: block,
                to,
                source,
                role,
                arrival,
            });
        }
        if let (Some(continuation), Some(no_return)) = (continuation, no_return) {
            let op = &builder.instruction(end.rank).ops[end.operation];
            let target = if op.opcode == Opcode::Call {
                let address = op.inputs[0].offset;
                CallTarget::Direct {
                    address,
                    location: builder.locate(address)?.0,
                }
            } else {
                CallTarget::Indirect
            };
            calls.push(CallSite {
                point: source,
                block,
                target,
                continuation,
                no_return,
            });
        }
    }
    out_start.resize(node_count + 1, edges.len());

    builder.budget.charge(userop_points.len() + block_count)?;
    let mut userops = Vec::with_capacity(userop_points.len());
    let mut block = 0;
    for (index, userop) in userop_points {
        while block_start[block + 1] <= index {
            block += 1;
        }
        userops.push(UseropSite {
            point: points[index],
            block,
            userop,
        });
    }

    // Incoming adjacency by counting sort: ascending edge IDs per target.
    builder.budget.charge(2 * (node_count + edge_count))?;
    let mut in_start = vec![0_usize; node_count + 1];
    for edge in &edges {
        in_start[edge.to + 1] += 1;
    }
    for node in 0..node_count {
        in_start[node + 1] += in_start[node];
    }
    let mut cursor = in_start.clone();
    let mut in_edges = vec![0; edge_count];
    for (id, edge) in edges.iter().enumerate() {
        in_edges[cursor[edge.to]] = id;
        cursor[edge.to] += 1;
    }

    builder.budget.search(block_count)?;
    let entry_node = block_start
        .binary_search(&builder.point_start[entry_rank])
        .expect("the entry point is a block leader");
    let graph = Graph::new(
        node_count,
        edges.iter().map(|edge| (edge.from, edge.to)),
        limits.graph,
    )?;

    let Builder {
        order,
        addresses,
        point_start,
        budget,
        ..
    } = builder;
    Ok(Cfg {
        spaces,
        code_space,
        entry_address: entry,
        instructions,
        order,
        addresses,
        point_start,
        points,
        block_start,
        edges,
        out_start,
        in_edges,
        in_start,
        exits,
        calls,
        userops,
        gaps,
        graph: Arc::new(graph),
        entry: entry_node,
        limits,
        work: budget.used,
    })
}
