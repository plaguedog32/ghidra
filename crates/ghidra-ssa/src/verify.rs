//! Structural verification. This deliberately does not replay renaming: it
//! recomputes dominance through the graph crate, checks local invariants
//! directly, checks reaching definitions with an offline dominator-interval
//! sweep, and checks phi placement against the dominance-frontier closure.
//! For pruned placement it recomputes raw-program liveness on its own (sorted
//! pair lists and a separate backward flood, not construction's tables).

use ghidra_graph::{Dominators, ImmediateDominator, NodeId};

use crate::construct::{Ssa, dominator_children, validate_program};
use crate::error::{Budget, Resource, Result, Violation, account, violation};
use crate::model::{
    Block, DefinitionSite, PhiId, PhiOperandSite, PhiPlacement, Predecessor, RawProgram,
    StatementId, UseSite, Value, ValueId, ValueOrigin, VariableId,
};

#[derive(Clone, Copy)]
enum Site {
    Use(UseSite),
    Phi(PhiOperandSite),
    /// A block's final definition (or phi) of a variable.
    Definition,
}

/// One reaching-definition query or one block's final definition of a variable.
#[derive(Clone, Copy)]
struct Event {
    variable: usize,
    preorder: usize,
    node: NodeId,
    /// The value observed (query) or provided at block end (definition).
    value: ValueId,
    site: Site,
}

impl Event {
    /// At equal preorder, queries sort before the same block's definition:
    /// a query is always about the state before that block's own definitions.
    fn key(&self) -> (usize, usize, bool) {
        (
            self.variable,
            self.preorder,
            matches!(self.site, Site::Definition),
        )
    }
}

impl Ssa {
    /// Check this SSA form against the raw program it claims to rename.
    ///
    /// Recomputes dominators and frontiers (one graph call each, own budgets)
    /// and spends a fresh `Limits::max_work` SSA budget. Returns
    /// `Error::Verification` for the first broken invariant found, in a
    /// deterministic order. See the crate documentation for the invariants.
    pub fn verify(&self, program: &RawProgram) -> Result<()> {
        let mut budget = Budget::new(self.limits.max_work);
        let graph = &*self.graph;
        let n = graph.node_count();
        validate_program(n, program, &self.limits, &mut budget)?;
        budget.charge(program.variables.len())?;
        if self.blocks.len() != n || self.idom.len() != n || program.variables != self.entry_states
        {
            return Err(violation(Violation::InputShape { node: None }));
        }

        // Recomputed dominance is the reference, not the stored tree.
        let dom = graph.dominators(self.entry)?;
        budget.charge(n)?;
        let mut parents = Vec::with_capacity(n);
        for node in 0..n {
            let expected = dom.immediate_dominator(node)?;
            if self.idom[node] != expected {
                return Err(violation(Violation::ImmediateDominator { node }));
            }
            let reachable = expected != ImmediateDominator::Unreachable;
            match &self.blocks[node] {
                Block::Unreachable { statement_count } => {
                    if reachable {
                        return Err(violation(Violation::Reachability { node }));
                    }
                    if *statement_count != program.blocks[node].len() {
                        return Err(violation(Violation::InputShape { node: Some(node) }));
                    }
                }
                Block::Reachable(_) if !reachable => {
                    return Err(violation(Violation::Reachability { node }));
                }
                Block::Reachable(_) => {}
            }
            parents.push(expected);
        }

        self.verify_values(&mut budget)?;
        self.verify_blocks(program, &dom, &mut budget)?;
        let events = self.verify_reaching(program, &parents, &mut budget)?;
        self.verify_placement(program, &dom, &events, &mut budget)
    }

    /// Every value names exactly one defining location, which defines it.
    fn verify_values(&self, budget: &mut Budget) -> Result<()> {
        let variable_count = self.entry_states.len();
        budget.charge(self.values.len())?;
        for (index, value) in self.values.iter().enumerate() {
            let id = ValueId(index);
            let variable = value.variable;
            let consistent = variable.0 < variable_count
                && match value.origin {
                    ValueOrigin::Entry(state) => {
                        index == variable.0 && state == self.entry_states[variable.0]
                    }
                    ValueOrigin::Phi(phi) => self
                        .phi(phi)
                        .is_ok_and(|phi| phi.value == id && phi.variable == variable),
                    // The variable is checked per slot in `verify_blocks`.
                    ValueOrigin::Definition(site) => {
                        self.definition(site).is_ok_and(|defined| defined == id)
                    }
                };
            if !consistent {
                return Err(violation(Violation::ValueOrigin { value: id }));
            }
        }
        budget.charge(variable_count)?;
        for variable in 0..variable_count {
            let entry = self.values.get(variable);
            if !entry.is_some_and(|value| {
                value.variable.0 == variable && matches!(value.origin, ValueOrigin::Entry(_))
            }) {
                return Err(violation(Violation::EntryValue {
                    variable: VariableId(variable),
                }));
            }
        }
        Ok(())
    }

    fn known(&self, value: ValueId) -> Result<Value> {
        self.values
            .get(value.0)
            .copied()
            .ok_or_else(|| violation(Violation::UnknownValue { value }))
    }

    /// Canonical incoming lists, arity, phi order, round-trip definitions,
    /// and strict-SSA dominance of every use and phi operand.
    fn verify_blocks(
        &self,
        program: &RawProgram,
        dom: &Dominators<'_>,
        budget: &mut Budget,
    ) -> Result<()> {
        let graph = &*self.graph;
        let variable_count = self.entry_states.len();
        let mut expected = Vec::new();
        for node in graph.nodes() {
            let Block::Reachable(block) = &self.blocks[node] else {
                continue;
            };
            budget.tick()?;
            expected.clear();
            if node == self.entry {
                expected.push(Predecessor::Entry);
            }
            for &pred in graph.predecessors(node)? {
                budget.tick()?;
                if self.blocks[pred].is_reachable() {
                    expected.push(Predecessor::Node(pred));
                }
            }
            if block.incoming != expected {
                return Err(violation(Violation::Incoming { node }));
            }
            let raw = &program.blocks[node];
            if block.statements.len() != raw.len() {
                return Err(violation(Violation::InputShape { node: Some(node) }));
            }
            for (index, phi) in block.phis.iter().enumerate() {
                budget.tick()?;
                let id = PhiId { node, index };
                if phi.variable.0 >= variable_count
                    || (index > 0 && block.phis[index - 1].variable >= phi.variable)
                {
                    return Err(violation(Violation::PhiOrder { phi: id }));
                }
                if self.known(phi.value)?.origin != ValueOrigin::Phi(id) {
                    return Err(violation(Violation::ValueOrigin { value: phi.value }));
                }
                if phi.operands.len() != block.incoming.len() {
                    return Err(violation(Violation::PhiArity { phi: id }));
                }
                for (operand, (&value, &pred)) in
                    phi.operands.iter().zip(&block.incoming).enumerate()
                {
                    budget.tick()?;
                    let site = PhiOperandSite { phi: id, operand };
                    let known = self.known(value)?;
                    if known.variable != phi.variable {
                        return Err(violation(Violation::PhiOperandVariable { site }));
                    }
                    match pred {
                        Predecessor::Entry if value != ValueId(phi.variable.0) => {
                            return Err(violation(Violation::EntryOperand { site }));
                        }
                        Predecessor::Entry => {}
                        Predecessor::Node(pred) => {
                            if !available_at_end(dom, known.origin, pred)? {
                                return Err(violation(Violation::PhiOperandNotDominating { site }));
                            }
                        }
                    }
                }
            }
            for (index, (raw, renamed)) in raw.iter().zip(&block.statements).enumerate() {
                budget.tick()?;
                if raw.uses.len() != renamed.uses.len() || raw.defs.len() != renamed.defs.len() {
                    return Err(violation(Violation::InputShape { node: Some(node) }));
                }
                budget.charge(raw.uses.len() + raw.defs.len())?;
                let statement = StatementId { node, index };
                for (slot, (&variable, &value)) in raw.defs.iter().zip(&renamed.defs).enumerate() {
                    let site = DefinitionSite { statement, slot };
                    let known = self.known(value)?;
                    if known.origin != ValueOrigin::Definition(site) {
                        return Err(violation(Violation::ValueOrigin { value }));
                    }
                    if known.variable != variable {
                        return Err(violation(Violation::DefinitionVariable { site }));
                    }
                }
                for (slot, (&variable, &value)) in raw.uses.iter().zip(&renamed.uses).enumerate() {
                    let site = UseSite { statement, slot };
                    let known = self.known(value)?;
                    if known.variable != variable {
                        return Err(violation(Violation::UseVariable { site }));
                    }
                    let dominated = match known.origin {
                        ValueOrigin::Entry(_) => true,
                        ValueOrigin::Phi(phi) => dom.dominates(phi.node, node)?,
                        ValueOrigin::Definition(def) if def.statement.node == node => {
                            def.statement.index < index
                        }
                        ValueOrigin::Definition(def) => dom.dominates(def.statement.node, node)?,
                    };
                    if !dominated {
                        return Err(violation(Violation::UseNotDominated { site }));
                    }
                }
            }
        }
        Ok(())
    }

    /// Exact reaching definitions. Same-block reads are checked directly.
    /// Every other read must equal the final value of its variable in the
    /// nearest dominator-tree ancestor that defines it (or has its phi), or
    /// the entry value if there is none. Ancestors are found by one sorted
    /// sweep over dominator-tree preorder intervals per variable, rather than
    /// by a renaming walk or per-query ancestor scans.
    fn verify_reaching(
        &self,
        program: &RawProgram,
        parents: &[ImmediateDominator],
        budget: &mut Budget,
    ) -> Result<Vec<Event>> {
        let graph = &*self.graph;
        let variable_count = self.entry_states.len();
        let (preorder, end) = intervals(parents, self.entry, budget)?;

        budget.charge(variable_count)?;
        let mut local = vec![ValueId(0); variable_count];
        let mut stamp = vec![usize::MAX; variable_count];
        let mut touched = Vec::new();
        let mut events = Vec::new();
        for (node, block) in self.blocks.iter().enumerate() {
            let Block::Reachable(block) = block else {
                continue;
            };
            budget.tick()?;
            touched.clear();
            for phi in &block.phis {
                budget.tick()?;
                stamp[phi.variable.0] = node;
                touched.push(phi.variable.0);
                local[phi.variable.0] = phi.value;
            }
            for (index, (raw, renamed)) in program.blocks[node]
                .iter()
                .zip(&block.statements)
                .enumerate()
            {
                budget.tick()?;
                budget.charge(raw.uses.len() + raw.defs.len())?;
                let statement = StatementId { node, index };
                for (slot, (&variable, &actual)) in raw.uses.iter().zip(&renamed.uses).enumerate() {
                    let site = UseSite { statement, slot };
                    if stamp[variable.0] == node {
                        if local[variable.0] != actual {
                            return Err(violation(Violation::StaleUse {
                                site,
                                expected: local[variable.0],
                                actual,
                            }));
                        }
                    } else {
                        events.push(Event {
                            variable: variable.0,
                            preorder: preorder[node],
                            node,
                            value: actual,
                            site: Site::Use(site),
                        });
                    }
                }
                for (&variable, &value) in raw.defs.iter().zip(&renamed.defs) {
                    if stamp[variable.0] != node {
                        stamp[variable.0] = node;
                        touched.push(variable.0);
                    }
                    local[variable.0] = value;
                }
            }
            for &successor in graph.successors(node)? {
                budget.tick()?;
                let Block::Reachable(target) = &self.blocks[successor] else {
                    return Err(violation(Violation::Reachability { node: successor }));
                };
                budget.search(target.incoming.len())?;
                let Some(slot) = target.incoming_index(Predecessor::Node(node)) else {
                    return Err(violation(Violation::Incoming { node: successor }));
                };
                for (index, phi) in target.phis.iter().enumerate() {
                    budget.tick()?;
                    let site = PhiOperandSite {
                        phi: PhiId {
                            node: successor,
                            index,
                        },
                        operand: slot,
                    };
                    let actual = phi.operands[slot];
                    let variable = phi.variable.0;
                    if stamp[variable] == node {
                        if local[variable] != actual {
                            return Err(violation(Violation::StalePhiOperand {
                                site,
                                expected: local[variable],
                                actual,
                            }));
                        }
                    } else {
                        events.push(Event {
                            variable,
                            preorder: preorder[node],
                            node,
                            value: actual,
                            site: Site::Phi(site),
                        });
                    }
                }
            }
            budget.charge(touched.len())?;
            for &variable in &touched {
                events.push(Event {
                    variable,
                    preorder: preorder[node],
                    node,
                    value: local[variable],
                    site: Site::Definition,
                });
            }
        }

        budget.sorting(events.len())?;
        events.sort_unstable_by_key(Event::key);
        // Per variable, the stack holds the defining ancestors of the current
        // preorder position (intervals are laminar), deepest on top.
        let mut stack: Vec<(usize, ValueId)> = Vec::new();
        let mut variable = usize::MAX;
        for event in &events {
            budget.tick()?;
            if event.variable != variable {
                variable = event.variable;
                stack.clear();
            }
            while stack
                .last()
                .is_some_and(|&(stop, _)| stop <= event.preorder)
            {
                budget.tick()?;
                stack.pop();
            }
            let expected = stack
                .last()
                .map_or(ValueId(event.variable), |&(_, value)| value);
            match event.site {
                Site::Definition => stack.push((end[event.node], event.value)),
                Site::Use(site) if expected != event.value => {
                    return Err(violation(Violation::StaleUse {
                        site,
                        expected,
                        actual: event.value,
                    }));
                }
                Site::Phi(site) if expected != event.value => {
                    return Err(violation(Violation::StalePhiOperand {
                        site,
                        expected,
                        actual: event.value,
                    }));
                }
                Site::Use(_) | Site::Phi(_) => {}
            }
        }
        Ok(events)
    }

    /// Phi sets must be closed under dominance frontiers: if a block defines
    /// a variable or has its phi, every frontier member has a phi for it.
    /// When pruned, only frontier members where the variable is live need
    /// one, and every phi must be live.
    fn verify_placement(
        &self,
        program: &RawProgram,
        dom: &Dominators<'_>,
        events: &[Event],
        budget: &mut Budget,
    ) -> Result<()> {
        let frontiers = dom.frontiers()?;
        if self.placement == PhiPlacement::Pruned {
            return self.verify_pruned_placement(program, &frontiers, events, budget);
        }
        for event in events {
            if !matches!(event.site, Site::Definition) {
                continue;
            }
            budget.tick()?;
            for &frontier in &frontiers[event.node] {
                let Block::Reachable(target) = &self.blocks[frontier] else {
                    return Err(violation(Violation::Reachability { node: frontier }));
                };
                budget.search(target.phis.len())?;
                let variable = VariableId(event.variable);
                if target.phi_for(variable).is_none() {
                    return Err(violation(Violation::MissingPhi {
                        node: frontier,
                        variable,
                    }));
                }
            }
        }
        Ok(())
    }

    /// Pruned placement, per variable in ascending order: every phi must be
    /// at a block where the variable is live on entry (else `DeadPhi`), and
    /// every live frontier member of a block that defines the variable or
    /// has its phi must have its phi (else `MissingPhi`).
    ///
    /// Liveness is recomputed from the raw program: exposed reads and
    /// writes of reachable blocks are collected as sorted (variable, node)
    /// pairs, and a variable is flooded backward only once it has a phi or
    /// a frontier candidate to judge.
    fn verify_pruned_placement(
        &self,
        program: &RawProgram,
        frontiers: &[Vec<NodeId>],
        events: &[Event],
        budget: &mut Budget,
    ) -> Result<()> {
        let n = self.blocks.len();
        let variable_count = self.entry_states.len();
        budget.charge(variable_count)?;
        budget.charge(variable_count)?;
        // `written[x] == node`: an earlier statement of `node` writes x.
        // `read[x] == node`: x is already recorded as exposed in `node`.
        let mut written = vec![usize::MAX; variable_count];
        let mut read = vec![usize::MAX; variable_count];
        let mut exposed: Vec<(usize, NodeId)> = Vec::new();
        let mut writes: Vec<(usize, NodeId)> = Vec::new();
        let mut phis: Vec<(usize, PhiId)> = Vec::new();
        for (node, block) in self.blocks.iter().enumerate() {
            let Block::Reachable(block) = block else {
                continue;
            };
            budget.tick()?;
            for (index, phi) in block.phis.iter().enumerate() {
                budget.tick()?;
                phis.push((phi.variable.0, PhiId { node, index }));
            }
            for raw in &program.blocks[node] {
                budget.tick()?;
                budget.charge(raw.uses.len() + raw.defs.len())?;
                for variable in &raw.uses {
                    if written[variable.0] != node && read[variable.0] != node {
                        read[variable.0] = node;
                        exposed.push((variable.0, node));
                    }
                }
                for variable in &raw.defs {
                    if written[variable.0] != node {
                        written[variable.0] = node;
                        writes.push((variable.0, node));
                    }
                }
            }
        }
        drop(written);
        drop(read);
        for list in [&mut exposed, &mut writes] {
            budget.sorting(list.len())?;
            list.sort_unstable();
        }
        budget.sorting(phis.len())?;
        phis.sort_unstable();

        budget.charge(n)?;
        budget.charge(n)?;
        let mut flood = Flood {
            live: vec![usize::MAX; n],
            writes: vec![usize::MAX; n],
            stack: Vec::new(),
            live_ins: 0,
        };
        let (mut event, mut phi, mut seed, mut write) = (0, 0, 0, 0);
        loop {
            while events
                .get(event)
                .is_some_and(|next| !matches!(next.site, Site::Definition))
            {
                budget.tick()?;
                event += 1;
            }
            let next_event = events.get(event).map(|next| next.variable);
            let next_phi = phis.get(phi).map(|&(variable, _)| variable);
            let Some(variable) = next_event.into_iter().chain(next_phi).min() else {
                break;
            };
            let seeds = take_variable(&exposed, &mut seed, variable, budget)?;
            let kills = take_variable(&writes, &mut write, variable, budget)?;
            let mut flooded = false;
            while let Some(&(_, id)) = phis.get(phi).filter(|&&(x, _)| x == variable) {
                budget.tick()?;
                phi += 1;
                if !flooded {
                    flooded = true;
                    flood.run(self, variable, seeds, kills, budget)?;
                }
                if !flood.is_live(id.node, variable) {
                    return Err(violation(Violation::DeadPhi { phi: id }));
                }
            }
            while let Some(current) = events.get(event).filter(|next| next.variable == variable) {
                budget.tick()?;
                event += 1;
                if !matches!(current.site, Site::Definition) {
                    continue;
                }
                for &frontier in &frontiers[current.node] {
                    budget.tick()?;
                    let Block::Reachable(target) = &self.blocks[frontier] else {
                        return Err(violation(Violation::Reachability { node: frontier }));
                    };
                    if !flooded {
                        flooded = true;
                        flood.run(self, variable, seeds, kills, budget)?;
                    }
                    if !flood.is_live(frontier, variable) {
                        continue;
                    }
                    budget.search(target.phis.len())?;
                    let variable = VariableId(variable);
                    if target.phi_for(variable).is_none() {
                        return Err(violation(Violation::MissingPhi {
                            node: frontier,
                            variable,
                        }));
                    }
                }
            }
        }
        Ok(())
    }
}

/// The run of `pairs` (sorted by variable) for `variable`, advancing `cursor`
/// past it. Runs of smaller variables are skipped; each step is charged.
fn take_variable<'a>(
    pairs: &'a [(usize, NodeId)],
    cursor: &mut usize,
    variable: usize,
    budget: &mut Budget,
) -> Result<&'a [(usize, NodeId)]> {
    while pairs.get(*cursor).is_some_and(|&(x, _)| x < variable) {
        budget.tick()?;
        *cursor += 1;
    }
    let start = *cursor;
    while pairs.get(*cursor).is_some_and(|&(x, _)| x == variable) {
        budget.tick()?;
        *cursor += 1;
    }
    Ok(&pairs[start..*cursor])
}

/// The verifier's own backward liveness flood, one variable at a time.
/// Node-sized marks are stamped with the variable index.
struct Flood {
    live: Vec<usize>,
    writes: Vec<usize>,
    stack: Vec<NodeId>,
    live_ins: usize,
}

impl Flood {
    /// `seeds` are blocks that read `variable` before writing it; `kills`
    /// are blocks that write it. Only reachable predecessors are followed.
    fn run(
        &mut self,
        ssa: &Ssa,
        variable: usize,
        seeds: &[(usize, NodeId)],
        kills: &[(usize, NodeId)],
        budget: &mut Budget,
    ) -> Result<()> {
        let limit = ssa.limits.max_live_ins;
        for &(_, node) in kills {
            budget.tick()?;
            self.writes[node] = variable;
        }
        self.stack.clear();
        for &(_, node) in seeds {
            budget.tick()?;
            account(&mut self.live_ins, 1, limit, Resource::LiveIns)?;
            self.live[node] = variable;
            self.stack.push(node);
        }
        while let Some(node) = self.stack.pop() {
            budget.tick()?;
            for &pred in ssa.graph.predecessors(node)? {
                budget.tick()?;
                if !ssa.blocks[pred].is_reachable()
                    || self.live[pred] == variable
                    || self.writes[pred] == variable
                {
                    continue;
                }
                account(&mut self.live_ins, 1, limit, Resource::LiveIns)?;
                self.live[pred] = variable;
                self.stack.push(pred);
            }
        }
        Ok(())
    }

    fn is_live(&self, node: NodeId, variable: usize) -> bool {
        self.live[node] == variable
    }
}

/// A phi or definition is available at the end of `pred` iff its block
/// dominates `pred`. Entry values are available everywhere reachable.
fn available_at_end(dom: &Dominators<'_>, origin: ValueOrigin, pred: NodeId) -> Result<bool> {
    Ok(match origin {
        ValueOrigin::Entry(_) => true,
        ValueOrigin::Phi(phi) => dom.dominates(phi.node, pred)?,
        ValueOrigin::Definition(def) => dom.dominates(def.statement.node, pred)?,
    })
}

/// Iterative dominator-tree preorder intervals: `a` is an ancestor-or-self of
/// `b` iff `preorder[a] <= preorder[b] < end[a]`.
fn intervals(
    parents: &[ImmediateDominator],
    root: NodeId,
    budget: &mut Budget,
) -> Result<(Vec<usize>, Vec<usize>)> {
    let n = parents.len();
    let (start, children) = dominator_children(parents, budget)?;
    budget.charge(n)?;
    let mut preorder = vec![0; n];
    let mut end = vec![0; n];
    let mut time = 1;
    let mut stack = vec![(root, start[root])];
    while let Some((node, next)) = stack.last_mut() {
        budget.tick()?;
        if *next < start[*node + 1] {
            let child = children[*next];
            *next += 1;
            preorder[child] = time;
            time += 1;
            stack.push((child, start[child]));
        } else {
            end[*node] = time;
            stack.pop();
        }
    }
    Ok((preorder, end))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use ghidra_graph::{Graph, Limits as GraphLimits};

    use crate::{
        Block, EntryState, Error, Limits, Phi, PhiId, PhiPlacement, RawProgram, RawStatement,
        Resource, Ssa, ValueId, ValueOrigin, VariableId, Violation,
    };

    fn v(index: usize) -> VariableId {
        VariableId(index)
    }

    fn stmt(uses: &[usize], defs: &[usize]) -> RawStatement {
        RawStatement::new(uses.iter().map(|&x| v(x)), defs.iter().map(|&x| v(x)))
    }

    fn build(nodes: usize, edges: &[(usize, usize)], program: &RawProgram) -> Ssa {
        let graph =
            Arc::new(Graph::new(nodes, edges.iter().copied(), GraphLimits::default()).unwrap());
        let ssa = Ssa::construct(graph, 0, program, Limits::default()).unwrap();
        ssa.verify(program).unwrap();
        ssa
    }

    fn violation_of(result: crate::Result<()>) -> Violation {
        match result {
            Err(Error::Verification(violation)) => violation,
            other => panic!("expected a violation, got {other:?}"),
        }
    }

    fn renamed(ssa: &mut Ssa, node: usize) -> &mut crate::RenamedBlock {
        match &mut ssa.blocks[node] {
            Block::Reachable(block) => block,
            Block::Unreachable { .. } => panic!("node {node} is unreachable"),
        }
    }

    // 0 -> 1 -> 2 -> 3, x defined in 0 and 1, used in 3.
    fn chain() -> (RawProgram, Ssa) {
        let program = RawProgram {
            variables: vec![EntryState::Input],
            blocks: vec![
                vec![stmt(&[], &[0])],
                vec![stmt(&[0], &[0])],
                vec![],
                vec![stmt(&[0], &[])],
            ],
        };
        let ssa = build(4, &[(0, 1), (1, 2), (2, 3)], &program);
        (program, ssa)
    }

    // Diamond 0 -> {1, 2} -> 3 with x defined only in 1.
    fn diamond() -> (RawProgram, Ssa) {
        let program = RawProgram {
            variables: vec![EntryState::Undefined],
            blocks: vec![vec![], vec![stmt(&[], &[0])], vec![], vec![stmt(&[0], &[])]],
        };
        let ssa = build(4, &[(0, 1), (0, 2), (1, 3), (2, 3)], &program);
        (program, ssa)
    }

    #[test]
    fn stale_dominating_use_is_rejected_even_though_it_dominates() {
        let (program, mut ssa) = chain();
        // The use in 3 should read the def in 1; the def in 0 still dominates it.
        let old = renamed(&mut ssa, 0).statements[0].defs[0];
        renamed(&mut ssa, 3).statements[0].uses[0] = old;
        assert!(matches!(
            violation_of(ssa.verify(&program)),
            Violation::StaleUse { expected, actual, .. } if actual == old && expected != old
        ));
    }

    #[test]
    fn non_dominating_and_misordered_uses_are_rejected() {
        let (program, mut ssa) = diamond();
        let def = renamed(&mut ssa, 1).statements[0].defs[0];
        // Make 1's def the value read at 3 instead of the join phi.
        renamed(&mut ssa, 3).statements[0].uses[0] = def;
        assert!(matches!(
            violation_of(ssa.verify(&program)),
            Violation::UseNotDominated { .. }
        ));
        let (program, mut ssa) = chain();
        // A use in 1 that reads 1's own later definition.
        let def = renamed(&mut ssa, 1).statements[0].defs[0];
        renamed(&mut ssa, 1).statements[0].uses[0] = def;
        assert!(matches!(
            violation_of(ssa.verify(&program)),
            Violation::UseNotDominated { .. }
        ));
    }

    #[test]
    fn wrong_phi_and_entry_operands_are_rejected() {
        let (program, mut ssa) = diamond();
        let entry = ssa.entry_value(v(0)).unwrap();
        let def = renamed(&mut ssa, 1).statements[0].defs[0];
        // Swap the operands of the join phi: incoming is [1, 2].
        renamed(&mut ssa, 3).phis[0].operands = vec![entry, def];
        assert!(matches!(
            violation_of(ssa.verify(&program)),
            Violation::PhiOperandNotDominating { .. }
        ));
        // A dominating but stale operand: entry value along the edge from 1.
        let (program, mut ssa) = diamond();
        renamed(&mut ssa, 3).phis[0].operands = vec![entry, entry];
        assert!(matches!(
            violation_of(ssa.verify(&program)),
            Violation::StalePhiOperand { .. }
        ));
        // Self-loop at the entry: the virtual Entry operand must be the entry value.
        let program = RawProgram {
            variables: vec![EntryState::Input],
            blocks: vec![vec![stmt(&[0], &[0])]],
        };
        let mut ssa = build(1, &[(0, 0)], &program);
        let def = renamed(&mut ssa, 0).statements[0].defs[0];
        renamed(&mut ssa, 0).phis[0].operands[0] = def;
        assert!(matches!(
            violation_of(ssa.verify(&program)),
            Violation::EntryOperand { .. }
        ));
    }

    #[test]
    fn missing_dead_phi_is_rejected() {
        // The join phi of x in a diamond is dead when x is not used afterwards.
        let program = RawProgram {
            variables: vec![EntryState::Input],
            blocks: vec![vec![], vec![stmt(&[], &[0])], vec![], vec![]],
        };
        let mut ssa = build(4, &[(0, 1), (0, 2), (1, 3), (2, 3)], &program);
        // Remove the phi and its value. Its value is the last phi value, and
        // only definition values follow, so shift definitions down by one.
        let removed = renamed(&mut ssa, 3).phis.remove(0).value;
        ssa.values.remove(removed.0);
        ssa.phi_count -= 1;
        for block in ssa.blocks.iter_mut().filter_map(|block| match block {
            Block::Reachable(block) => Some(block),
            Block::Unreachable { .. } => None,
        }) {
            for statement in &mut block.statements {
                for value in statement.defs.iter_mut().chain(statement.uses.iter_mut()) {
                    if value.0 > removed.0 {
                        value.0 -= 1;
                    }
                }
            }
        }
        assert_eq!(
            violation_of(ssa.verify(&program)),
            Violation::MissingPhi {
                node: 3,
                variable: v(0)
            }
        );
    }

    #[test]
    fn identity_shape_and_reachability_corruption_is_rejected() {
        let (program, ssa) = diamond();
        let mut corrupt = ssa.clone();
        let phi_value = renamed(&mut corrupt, 3).phis[0].value;
        corrupt.values[phi_value.0].variable = v(5);
        assert_eq!(
            violation_of(corrupt.verify(&program)),
            Violation::ValueOrigin { value: phi_value }
        );
        let mut corrupt = ssa.clone();
        renamed(&mut corrupt, 3).incoming.reverse();
        assert_eq!(
            violation_of(corrupt.verify(&program)),
            Violation::Incoming { node: 3 }
        );
        let mut corrupt = ssa.clone();
        renamed(&mut corrupt, 3).phis[0].operands.pop();
        assert!(matches!(
            violation_of(corrupt.verify(&program)),
            Violation::PhiArity { .. }
        ));
        let mut corrupt = ssa.clone();
        renamed(&mut corrupt, 3).statements[0].uses[0] = ValueId(usize::MAX);
        assert!(matches!(
            violation_of(corrupt.verify(&program)),
            Violation::UnknownValue { .. }
        ));
        let mut corrupt = ssa.clone();
        corrupt.blocks[2] = Block::Unreachable { statement_count: 0 };
        assert_eq!(
            violation_of(corrupt.verify(&program)),
            Violation::Reachability { node: 2 }
        );
        let mut corrupt = ssa.clone();
        renamed(&mut corrupt, 3).phis.push(Phi {
            variable: v(0),
            value: phi_value,
            operands: vec![phi_value; 2],
        });
        assert!(matches!(
            violation_of(corrupt.verify(&program)),
            Violation::PhiOrder { .. }
        ));
        // Verification against a different raw program is a shape violation.
        let mut other = program.clone();
        other.blocks[3][0].uses.push(v(0));
        assert_eq!(
            violation_of(ssa.verify(&other)),
            Violation::InputShape { node: Some(3) }
        );
        let mut other = program.clone();
        other.variables[0] = EntryState::Input;
        assert_eq!(
            violation_of(ssa.verify(&other)),
            Violation::InputShape { node: None }
        );
        // Swapping two definitions' values breaks origin round-trips.
        let (program, mut ssa) = chain();
        let a = renamed(&mut ssa, 0).statements[0].defs[0];
        let b = renamed(&mut ssa, 1).statements[0].defs[0];
        renamed(&mut ssa, 0).statements[0].defs[0] = b;
        renamed(&mut ssa, 1).statements[0].defs[0] = a;
        assert!(matches!(
            violation_of(ssa.verify(&program)),
            Violation::ValueOrigin { .. }
        ));
    }

    fn build_with(
        nodes: usize,
        edges: &[(usize, usize)],
        program: &RawProgram,
        placement: PhiPlacement,
    ) -> Ssa {
        let graph =
            Arc::new(Graph::new(nodes, edges.iter().copied(), GraphLimits::default()).unwrap());
        let ssa = Ssa::construct_with(graph, 0, program, Limits::default(), placement).unwrap();
        ssa.verify(program).unwrap();
        ssa
    }

    // Diamond 0 -> {1, 2} -> 3: x is written in 0 and 1 and read in 3 (a live
    // join); y is written in 1 and never read (a dead join).
    fn live_and_dead_join(placement: PhiPlacement) -> (RawProgram, Ssa) {
        let program = RawProgram {
            variables: vec![EntryState::Input, EntryState::Input],
            blocks: vec![
                vec![stmt(&[], &[0])],
                vec![stmt(&[], &[0, 1])],
                vec![],
                vec![stmt(&[0], &[])],
            ],
        };
        let ssa = build_with(4, &[(0, 1), (0, 2), (1, 3), (2, 3)], &program, placement);
        (program, ssa)
    }

    // Loop 0 -> 1 -> 2 -> 1, 1 -> 3: x is written in 0 and 2 and read at the
    // header; d is written in 2 and never read.
    fn pruned_loop() -> (RawProgram, Ssa) {
        let program = RawProgram {
            variables: vec![EntryState::Input, EntryState::Input],
            blocks: vec![
                vec![stmt(&[], &[0])],
                vec![stmt(&[0], &[])],
                vec![stmt(&[], &[0, 1])],
                vec![],
            ],
        };
        let ssa = build_with(
            4,
            &[(0, 1), (1, 2), (2, 1), (1, 3)],
            &program,
            PhiPlacement::Pruned,
        );
        (program, ssa)
    }

    /// Remove the only phi of `node`, as if placement had skipped it: every
    /// read of its value reads `replacement` instead, and later value IDs
    /// shift down so origins still round-trip.
    fn remove_only_phi(ssa: &mut Ssa, node: usize, replacement: ValueId) {
        let block = renamed(ssa, node);
        assert_eq!(block.phis.len(), 1);
        let removed = block.phis.remove(0);
        ssa.values.remove(removed.value.0);
        ssa.phi_count -= 1;
        ssa.phi_operand_count -= removed.operands.len();
        let fix = |value: &mut ValueId| {
            if *value == removed.value {
                *value = replacement;
            }
            if value.0 > removed.value.0 {
                value.0 -= 1;
            }
        };
        for block in ssa.blocks.iter_mut().filter_map(|block| match block {
            Block::Reachable(block) => Some(block),
            Block::Unreachable { .. } => None,
        }) {
            for phi in &mut block.phis {
                fix(&mut phi.value);
                phi.operands.iter_mut().for_each(fix);
            }
            for statement in &mut block.statements {
                statement.defs.iter_mut().for_each(fix);
                statement.uses.iter_mut().for_each(fix);
            }
        }
    }

    #[test]
    fn pruned_missing_live_phi_is_rejected_even_when_uses_read_a_dominating_def() {
        // Without the join phi, the use in 3 reads the def in 0, which is
        // its nearest dominating definition, so reaching-definition checks
        // pass; only liveness-aware completeness catches it.
        let (program, mut ssa) = live_and_dead_join(PhiPlacement::Pruned);
        let dominating = renamed(&mut ssa, 0).statements[0].defs[0];
        remove_only_phi(&mut ssa, 3, dominating);
        assert_eq!(
            violation_of(ssa.verify(&program)),
            Violation::MissingPhi {
                node: 3,
                variable: v(0)
            }
        );
        // The same for a live loop-header phi, replaced by the preheader def.
        let (program, mut ssa) = pruned_loop();
        let dominating = renamed(&mut ssa, 0).statements[0].defs[0];
        remove_only_phi(&mut ssa, 1, dominating);
        assert_eq!(
            violation_of(ssa.verify(&program)),
            Violation::MissingPhi {
                node: 1,
                variable: v(0)
            }
        );
    }

    #[test]
    fn dead_phis_and_wrong_placement_modes_are_rejected() {
        // Unpruned form has a dead phi of y at 3; claiming it is pruned fails.
        let (program, mut ssa) = live_and_dead_join(PhiPlacement::Unpruned);
        assert_eq!(renamed(&mut ssa, 3).phis.len(), 2);
        ssa.placement = PhiPlacement::Pruned;
        assert_eq!(
            violation_of(ssa.verify(&program)),
            Violation::DeadPhi {
                phi: PhiId { node: 3, index: 1 }
            }
        );
        // Pruned form lacks that phi; claiming it is unpruned fails.
        let (program, mut ssa) = live_and_dead_join(PhiPlacement::Pruned);
        assert_eq!(renamed(&mut ssa, 3).phis.len(), 1);
        ssa.placement = PhiPlacement::Unpruned;
        assert_eq!(
            violation_of(ssa.verify(&program)),
            Violation::MissingPhi {
                node: 3,
                variable: v(1)
            }
        );
    }

    #[test]
    fn pruned_stale_operands_and_corrupt_origins_are_rejected() {
        let (program, ssa) = pruned_loop();
        let preheader = ssa.blocks[0].renamed().unwrap().statements[0].defs[0];
        let header_phi = ssa.blocks[1].renamed().unwrap().phis[0].value;
        // The preheader def dominates the latch but is stale along it.
        let mut corrupt = ssa.clone();
        renamed(&mut corrupt, 1).phis[0].operands[1] = preheader;
        assert!(matches!(
            violation_of(corrupt.verify(&program)),
            Violation::StalePhiOperand { expected, actual, .. }
                if actual == preheader && expected != preheader
        ));
        // ... and dominates the header use, which must read the phi.
        let mut corrupt = ssa.clone();
        renamed(&mut corrupt, 1).statements[0].uses[0] = preheader;
        assert!(matches!(
            violation_of(corrupt.verify(&program)),
            Violation::StaleUse { expected, actual, .. }
                if actual == preheader && expected == header_phi
        ));
        let mut corrupt = ssa.clone();
        corrupt.values[header_phi.0].origin = ValueOrigin::Entry(EntryState::Input);
        assert_eq!(
            violation_of(corrupt.verify(&program)),
            Violation::ValueOrigin { value: header_phi }
        );
        let mut corrupt = ssa.clone();
        corrupt.values[header_phi.0].variable = v(1);
        assert_eq!(
            violation_of(corrupt.verify(&program)),
            Violation::ValueOrigin { value: header_phi }
        );
    }

    #[test]
    fn pruned_verification_has_its_own_live_in_and_work_bounds() {
        // x is live on entry to 3 and 2; y needs a flood but has no reads.
        let (program, mut ssa) = live_and_dead_join(PhiPlacement::Pruned);
        ssa.limits.max_live_ins = 2;
        ssa.verify(&program).unwrap();
        ssa.limits.max_live_ins = 1;
        assert_eq!(
            ssa.verify(&program).unwrap_err(),
            Error::LimitExceeded {
                resource: Resource::LiveIns
            }
        );
        ssa.limits.max_live_ins = 2;
        let mut fits = None;
        for max_work in 0..10_000 {
            ssa.limits.max_work = max_work;
            match ssa.verify(&program) {
                Ok(()) => {
                    fits = Some(max_work);
                    break;
                }
                Err(error) => assert_eq!(
                    error,
                    Error::LimitExceeded {
                        resource: Resource::Work
                    }
                ),
            }
        }
        assert!(fits.is_some());
    }
}
