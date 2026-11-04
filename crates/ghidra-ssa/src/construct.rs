use std::sync::Arc;

use ghidra_graph::{Graph, ImmediateDominator, NodeId};

use crate::error::{Budget, Error, Limits, Resource, Result, account, limit};
use crate::model::{
    Block, DefinitionSite, EntryState, OperandSite, Phi, PhiId, Predecessor, RawProgram,
    RenamedBlock, RenamedStatement, StatementId, UseSite, Value, ValueId, ValueOrigin, VariableId,
};

/// Placeholder for phi operands before renaming fills them. Every operand is
/// filled exactly once, because the walk visits every reachable predecessor.
const UNSET: ValueId = ValueId(usize::MAX);

/// Owned SSA form of one raw program over one immutable graph.
///
/// The result retains a clone of the caller's `Arc<Graph>` and owns every
/// renamed statement, phi, and value; it borrows neither the graph nor the raw
/// program. Value IDs are laid out as: entry values (`ValueId(x)` for variable
/// `x`), then phis in node and phi order, then reachable definitions in node,
/// statement, and slot order. The form is unpruned: phis are placed at the
/// iterated dominance frontier of each variable's definitions regardless of
/// liveness, so some phis can be dead.
#[derive(Clone, Debug)]
pub struct Ssa {
    pub(crate) graph: Arc<Graph>,
    pub(crate) entry: NodeId,
    pub(crate) limits: Limits,
    pub(crate) entry_states: Vec<EntryState>,
    pub(crate) idom: Vec<ImmediateDominator>,
    pub(crate) blocks: Vec<Block>,
    pub(crate) values: Vec<Value>,
    pub(crate) phi_count: usize,
    pub(crate) phi_operand_count: usize,
    pub(crate) work: u64,
}

impl Ssa {
    /// Validate `program` against `graph` and `limits`, then build SSA form.
    ///
    /// Runs `Graph::dominators(entry)` and `Dominators::frontiers()` once each;
    /// both have their own graph work budget. Fails without a partial result.
    pub fn construct(
        graph: Arc<Graph>,
        entry: NodeId,
        program: &RawProgram,
        limits: Limits,
    ) -> Result<Self> {
        let mut budget = Budget::new(limits.max_work);
        let built = build(&graph, entry, program, &limits, &mut budget)?;
        Ok(Self {
            graph,
            entry,
            limits,
            entry_states: program.variables.clone(),
            idom: built.idom,
            blocks: built.blocks,
            values: built.values,
            phi_count: built.phi_count,
            phi_operand_count: built.phi_operand_count,
            work: budget.used(),
        })
    }

    pub fn graph(&self) -> &Arc<Graph> {
        &self.graph
    }

    pub fn entry(&self) -> NodeId {
        self.entry
    }

    pub fn limits(&self) -> Limits {
        self.limits
    }

    /// SSA work units spent by construction, excluding graph-analysis budgets.
    pub fn work(&self) -> u64 {
        self.work
    }

    pub fn node_count(&self) -> usize {
        self.blocks.len()
    }

    pub fn variable_count(&self) -> usize {
        self.entry_states.len()
    }

    pub fn entry_state(&self, variable: VariableId) -> Result<EntryState> {
        self.check_variable(variable)?;
        Ok(self.entry_states[variable.0])
    }

    /// The value of `variable` on function entry. Always `ValueId(variable.0)`.
    pub fn entry_value(&self, variable: VariableId) -> Result<ValueId> {
        self.check_variable(variable)?;
        Ok(ValueId(variable.0))
    }

    pub fn immediate_dominator(&self, node: NodeId) -> Result<ImmediateDominator> {
        self.check_node(node)?;
        Ok(self.idom[node])
    }

    pub fn is_reachable(&self, node: NodeId) -> Result<bool> {
        Ok(self.block(node)?.is_reachable())
    }

    /// One block per graph node, indexed by `NodeId`.
    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    pub fn block(&self, node: NodeId) -> Result<&Block> {
        self.check_node(node)?;
        Ok(&self.blocks[node])
    }

    pub fn values(&self) -> &[Value] {
        &self.values
    }

    pub fn value(&self, value: ValueId) -> Result<Value> {
        self.values
            .get(value.0)
            .copied()
            .ok_or(Error::InvalidValue {
                value,
                value_count: self.values.len(),
            })
    }

    pub fn phi_count(&self) -> usize {
        self.phi_count
    }

    /// Total phi operands, the sum of all phi arities.
    pub fn phi_operand_count(&self) -> usize {
        self.phi_operand_count
    }

    pub fn phi(&self, phi: PhiId) -> Result<&Phi> {
        self.blocks
            .get(phi.node)
            .and_then(Block::renamed)
            .and_then(|block| block.phis.get(phi.index))
            .ok_or(Error::InvalidPhi { phi })
    }

    /// A renamed statement. Statements of unreachable nodes are not renamed.
    pub fn statement(&self, statement: StatementId) -> Result<&RenamedStatement> {
        self.blocks
            .get(statement.node)
            .and_then(Block::renamed)
            .and_then(|block| block.statements.get(statement.index))
            .ok_or(Error::InvalidStatement { statement })
    }

    pub fn definition(&self, site: DefinitionSite) -> Result<ValueId> {
        self.statement(site.statement)?
            .defs
            .get(site.slot)
            .copied()
            .ok_or(Error::InvalidStatement {
                statement: site.statement,
            })
    }

    pub fn use_value(&self, site: UseSite) -> Result<ValueId> {
        self.statement(site.statement)?
            .uses
            .get(site.slot)
            .copied()
            .ok_or(Error::InvalidStatement {
                statement: site.statement,
            })
    }

    fn check_node(&self, node: NodeId) -> Result<()> {
        if node >= self.blocks.len() {
            return Err(Error::InvalidNode {
                node,
                node_count: self.blocks.len(),
            });
        }
        Ok(())
    }

    fn check_variable(&self, variable: VariableId) -> Result<()> {
        if variable.0 >= self.entry_states.len() {
            return Err(Error::InvalidVariable {
                variable,
                variable_count: self.entry_states.len(),
            });
        }
        Ok(())
    }
}

/// Bounded validation of the whole raw program, reachable or not. All counts
/// are checked before the corresponding operands are scanned.
pub(crate) fn validate_program(
    node_count: usize,
    program: &RawProgram,
    limits: &Limits,
    budget: &mut Budget,
) -> Result<()> {
    if program.blocks.len() != node_count {
        return Err(Error::BlockCount {
            node_count,
            blocks: program.blocks.len(),
        });
    }
    let variable_count = program.variables.len();
    if variable_count > limits.max_variables {
        return Err(limit(Resource::Variables));
    }
    budget.charge(variable_count)?;
    budget.charge(node_count)?;
    // Stamped with a 1-based statement serial, so no per-statement clearing.
    let mut defined_by = vec![0usize; variable_count];
    let mut statements = 0usize;
    let mut operands = 0usize;
    for (node, block) in program.blocks.iter().enumerate() {
        budget.tick()?;
        account(
            &mut statements,
            block.len(),
            limits.max_statements,
            Resource::Statements,
        )?;
        let mut serial = statements - block.len();
        for (index, raw) in block.iter().enumerate() {
            budget.tick()?;
            serial += 1;
            let size = raw
                .uses
                .len()
                .checked_add(raw.defs.len())
                .ok_or_else(|| limit(Resource::Operands))?;
            account(&mut operands, size, limits.max_operands, Resource::Operands)?;
            budget.charge(size)?;
            let statement = StatementId { node, index };
            for (slot, &variable) in raw.uses.iter().enumerate() {
                if variable.0 >= variable_count {
                    return Err(Error::InvalidOperand {
                        site: OperandSite::Use(UseSite { statement, slot }),
                        variable,
                        variable_count,
                    });
                }
            }
            for (slot, &variable) in raw.defs.iter().enumerate() {
                if variable.0 >= variable_count {
                    return Err(Error::InvalidOperand {
                        site: OperandSite::Definition(DefinitionSite { statement, slot }),
                        variable,
                        variable_count,
                    });
                }
                if defined_by[variable.0] == serial {
                    return Err(Error::DuplicateDefinition {
                        statement,
                        variable,
                    });
                }
                defined_by[variable.0] = serial;
            }
        }
    }
    Ok(())
}

/// Dominator-tree children in compressed form: children of `node` are
/// `children[start[node]..start[node + 1]]`, ascending.
pub(crate) fn dominator_children(
    idom: &[ImmediateDominator],
    budget: &mut Budget,
) -> Result<(Vec<usize>, Vec<NodeId>)> {
    let n = idom.len();
    budget.charge(n)?;
    let mut start = vec![0usize; n + 1];
    for parent in idom {
        if let ImmediateDominator::Parent(parent) = *parent {
            start[parent + 1] += 1;
        }
    }
    budget.charge(n)?;
    for node in 0..n {
        start[node + 1] += start[node];
    }
    budget.charge(n)?;
    let mut cursor = start[..n].to_vec();
    let mut children = vec![0; start[n]];
    for (node, parent) in idom.iter().enumerate() {
        if let ImmediateDominator::Parent(parent) = *parent {
            children[cursor[parent]] = node;
            cursor[parent] += 1;
        }
    }
    Ok((start, children))
}

struct Built {
    idom: Vec<ImmediateDominator>,
    blocks: Vec<Block>,
    values: Vec<Value>,
    phi_count: usize,
    phi_operand_count: usize,
}

fn build(
    graph: &Graph,
    entry: NodeId,
    program: &RawProgram,
    limits: &Limits,
    budget: &mut Budget,
) -> Result<Built> {
    let n = graph.node_count();
    if entry >= n {
        return Err(Error::InvalidNode {
            node: entry,
            node_count: n,
        });
    }
    validate_program(n, program, limits, budget)?;
    let variable_count = program.variables.len();
    budget.charge(variable_count)?;

    // Graph analysis 1 of 2, with its own graph budget.
    let dom = graph.dominators(entry)?;
    budget.charge(n)?;
    let mut idom = Vec::with_capacity(n);
    for node in 0..n {
        idom.push(dom.immediate_dominator(node)?);
    }
    let reachable: Vec<bool> = idom
        .iter()
        .map(|parent| *parent != ImmediateDominator::Unreachable)
        .collect();
    let (child_start, children) = dominator_children(&idom, budget)?;

    // Only reachable definitions become values; fail fast on the value limit.
    budget.charge(n)?;
    let mut def_offset = vec![0usize; n];
    let mut definitions = 0usize;
    for node in 0..n {
        def_offset[node] = definitions;
        if reachable[node] {
            for raw in &program.blocks[node] {
                budget.tick()?;
                account(
                    &mut definitions,
                    raw.defs.len(),
                    limits.max_operands,
                    Resource::Operands,
                )?;
            }
        }
    }
    let mut value_count = 0usize;
    account(
        &mut value_count,
        variable_count,
        limits.max_values,
        Resource::Values,
    )?;
    account(
        &mut value_count,
        definitions,
        limits.max_values,
        Resource::Values,
    )?;

    // Graph analysis 2 of 2, with its own graph budget.
    let frontiers = dom.frontiers()?;

    // Phi arity: the virtual entry edge plus reachable predecessors.
    budget.charge(n)?;
    let mut arity = vec![0usize; n];
    for node in 0..n {
        if reachable[node] {
            let mut count = usize::from(node == entry);
            for &pred in graph.predecessors(node)? {
                budget.tick()?;
                count += usize::from(reachable[pred]);
            }
            arity[node] = count;
        }
    }

    // Distinct reachable defining blocks per variable, in compressed form.
    budget.charge(variable_count)?;
    budget.charge(variable_count)?;
    let mut def_start = vec![0usize; variable_count + 1];
    let mut last_block = vec![usize::MAX; variable_count];
    for_each_reachable_def(program, &reachable, budget, |node, variable| {
        if last_block[variable] != node {
            last_block[variable] = node;
            def_start[variable + 1] += 1;
        }
    })?;
    budget.charge(variable_count)?;
    for variable in 0..variable_count {
        def_start[variable + 1] += def_start[variable];
        last_block[variable] = usize::MAX;
    }
    budget.charge(variable_count)?;
    let mut def_cursor = def_start[..variable_count].to_vec();
    let mut def_blocks = vec![0; def_start[variable_count]];
    for_each_reachable_def(program, &reachable, budget, |node, variable| {
        if last_block[variable] != node {
            last_block[variable] = node;
            def_blocks[def_cursor[variable]] = node;
            def_cursor[variable] += 1;
        }
    })?;
    drop(def_cursor);
    drop(last_block);

    // Cytron et al. placement at the iterated dominance frontier. Node-sized
    // marks are stamped with the variable index, so they are never cleared.
    budget.charge(n)?;
    budget.charge(n)?;
    let mut has_phi = vec![usize::MAX; n];
    let mut queued = vec![usize::MAX; n];
    let mut placements: Vec<(NodeId, VariableId)> = Vec::new();
    let mut phi_count = 0usize;
    let mut phi_operand_count = 0usize;
    let mut worklist = Vec::new();
    for variable in 0..variable_count {
        budget.tick()?;
        let blocks = &def_blocks[def_start[variable]..def_start[variable + 1]];
        worklist.clear();
        for &node in blocks {
            budget.tick()?;
            queued[node] = variable;
            worklist.push(node);
        }
        while let Some(node) = worklist.pop() {
            budget.tick()?;
            for &frontier in &frontiers[node] {
                budget.tick()?;
                if has_phi[frontier] == variable {
                    continue;
                }
                has_phi[frontier] = variable;
                account(&mut phi_count, 1, limits.max_phis, Resource::Phis)?;
                account(
                    &mut phi_operand_count,
                    arity[frontier],
                    limits.max_phi_operands,
                    Resource::PhiOperands,
                )?;
                account(&mut value_count, 1, limits.max_values, Resource::Values)?;
                placements.push((frontier, VariableId(variable)));
                if queued[frontier] != variable {
                    queued[frontier] = variable;
                    worklist.push(frontier);
                }
            }
        }
    }
    drop(frontiers);
    drop(def_blocks);
    drop(dom);

    // Group placements by node. They were appended in ascending variable
    // order, so a stable counting sort leaves each node's phis ascending.
    budget.charge(n)?;
    budget.charge(phi_count)?;
    let mut phi_start = vec![0usize; n + 1];
    for &(node, _) in &placements {
        phi_start[node + 1] += 1;
    }
    for node in 0..n {
        phi_start[node + 1] += phi_start[node];
    }
    budget.charge(n)?;
    budget.charge(phi_count)?;
    let mut phi_cursor = phi_start[..n].to_vec();
    let mut phi_variables = vec![VariableId(0); phi_count];
    for &(node, variable) in &placements {
        phi_variables[phi_cursor[node]] = variable;
        phi_cursor[node] += 1;
    }
    drop(placements);
    drop(phi_cursor);

    // Values: entry values, phis, then reachable definitions.
    budget.charge(value_count)?;
    budget.charge(n)?;
    let mut values = Vec::with_capacity(value_count);
    for (variable, &state) in program.variables.iter().enumerate() {
        values.push(Value {
            variable: VariableId(variable),
            origin: ValueOrigin::Entry(state),
        });
    }
    for node in 0..n {
        for (index, &variable) in phi_variables[phi_start[node]..phi_start[node + 1]]
            .iter()
            .enumerate()
        {
            values.push(Value {
                variable,
                origin: ValueOrigin::Phi(PhiId { node, index }),
            });
        }
    }
    for (node, block) in program.blocks.iter().enumerate() {
        if !reachable[node] {
            continue;
        }
        for (index, raw) in block.iter().enumerate() {
            budget.tick()?;
            for (slot, &variable) in raw.defs.iter().enumerate() {
                values.push(Value {
                    variable,
                    origin: ValueOrigin::Definition(DefinitionSite {
                        statement: StatementId { node, index },
                        slot,
                    }),
                });
            }
        }
    }
    debug_assert_eq!(values.len(), value_count);

    // Block shells: canonical incoming lists and phis with unset operands.
    budget.charge(n)?;
    budget.charge(phi_operand_count)?;
    let mut blocks = Vec::with_capacity(n);
    for node in 0..n {
        if !reachable[node] {
            blocks.push(Block::Unreachable {
                statement_count: program.blocks[node].len(),
            });
            continue;
        }
        let mut incoming = Vec::with_capacity(arity[node]);
        if node == entry {
            incoming.push(Predecessor::Entry);
        }
        for &pred in graph.predecessors(node)? {
            budget.tick()?;
            if reachable[pred] {
                incoming.push(Predecessor::Node(pred));
            }
        }
        let first_phi = phi_start[node];
        let phis = phi_variables[first_phi..phi_start[node + 1]]
            .iter()
            .enumerate()
            .map(|(index, &variable)| Phi {
                variable,
                value: ValueId(variable_count + first_phi + index),
                operands: vec![UNSET; arity[node]],
            })
            .collect();
        blocks.push(Block::Reachable(RenamedBlock {
            incoming,
            phis,
            statements: Vec::with_capacity(program.blocks[node].len()),
        }));
    }
    drop(phi_variables);

    // The virtual entry edge carries each variable's entry value.
    if let Block::Reachable(block) = &mut blocks[entry] {
        for phi in &mut block.phis {
            budget.tick()?;
            phi.operands[0] = ValueId(phi.variable.0);
        }
    }

    budget.charge(variable_count)?;
    let mut renamer = Renamer {
        graph,
        program,
        blocks: &mut blocks,
        current: (0..variable_count).map(ValueId).collect(),
        undo: Vec::new(),
        first_definition: variable_count + phi_count,
        def_offset: &def_offset,
        budget,
    };
    renamer.rename_tree(entry, &child_start, &children)?;
    debug_assert!(blocks.iter().filter_map(Block::renamed).all(|block| {
        block
            .phis
            .iter()
            .all(|phi| phi.operands.iter().all(|&operand| operand != UNSET))
    }));
    Ok(Built {
        idom,
        blocks,
        values,
        phi_count,
        phi_operand_count,
    })
}

fn for_each_reachable_def(
    program: &RawProgram,
    reachable: &[bool],
    budget: &mut Budget,
    mut visit: impl FnMut(NodeId, usize),
) -> Result<()> {
    budget.charge(program.blocks.len())?;
    for (node, block) in program.blocks.iter().enumerate() {
        if !reachable[node] {
            continue;
        }
        for raw in block {
            budget.tick()?;
            budget.charge(raw.defs.len())?;
            for variable in &raw.defs {
                visit(node, variable.0);
            }
        }
    }
    Ok(())
}

struct Frame {
    node: NodeId,
    next_child: usize,
    undo_mark: usize,
}

/// Renaming state for an iterative dominator-tree walk. `current[x]` is the
/// reaching value of variable `x`; `undo` restores it when a subtree finishes.
struct Renamer<'a> {
    graph: &'a Graph,
    program: &'a RawProgram,
    blocks: &'a mut [Block],
    current: Vec<ValueId>,
    undo: Vec<(usize, ValueId)>,
    first_definition: usize,
    def_offset: &'a [usize],
    budget: &'a mut Budget,
}

impl Renamer<'_> {
    fn rename_tree(&mut self, root: NodeId, start: &[usize], children: &[NodeId]) -> Result<()> {
        self.rename_block(root)?;
        let mut stack = vec![Frame {
            node: root,
            next_child: start[root],
            undo_mark: 0,
        }];
        while let Some(frame) = stack.last_mut() {
            self.budget.tick()?;
            if frame.next_child < start[frame.node + 1] {
                let child = children[frame.next_child];
                frame.next_child += 1;
                let undo_mark = self.undo.len();
                self.rename_block(child)?;
                stack.push(Frame {
                    node: child,
                    next_child: start[child],
                    undo_mark,
                });
            } else {
                let undo_mark = frame.undo_mark;
                stack.pop();
                self.budget.charge(self.undo.len() - undo_mark)?;
                while self.undo.len() > undo_mark {
                    if let Some((variable, value)) = self.undo.pop() {
                        self.current[variable] = value;
                    }
                }
            }
        }
        Ok(())
    }

    fn rename_block(&mut self, node: NodeId) -> Result<()> {
        let Block::Reachable(block) = &mut self.blocks[node] else {
            return Ok(());
        };
        for phi in &block.phis {
            self.budget.tick()?;
            self.undo
                .push((phi.variable.0, self.current[phi.variable.0]));
            self.current[phi.variable.0] = phi.value;
        }
        let mut next = self.first_definition + self.def_offset[node];
        for raw in &self.program.blocks[node] {
            self.budget.tick()?;
            self.budget.charge(raw.uses.len() + raw.defs.len())?;
            // Every use reads the state before any def of the same statement.
            let uses = raw.uses.iter().map(|x| self.current[x.0]).collect();
            let mut defs = Vec::with_capacity(raw.defs.len());
            for variable in &raw.defs {
                let value = ValueId(next);
                next += 1;
                self.undo.push((variable.0, self.current[variable.0]));
                self.current[variable.0] = value;
                defs.push(value);
            }
            block.statements.push(RenamedStatement { uses, defs });
        }
        // Fill this node's operand slot in every successor's phis, using the
        // values live at the end of this node. Critical edges and self-loops
        // need no special case: each canonical edge has one slot.
        for &successor in self.graph.successors(node)? {
            self.budget.tick()?;
            let Block::Reachable(target) = &mut self.blocks[successor] else {
                continue;
            };
            if target.phis.is_empty() {
                continue;
            }
            self.budget.search(target.incoming.len())?;
            let Ok(slot) = target.incoming.binary_search(&Predecessor::Node(node)) else {
                continue;
            };
            for phi in &mut target.phis {
                self.budget.tick()?;
                phi.operands[slot] = self.current[phi.variable.0];
            }
        }
        Ok(())
    }
}
