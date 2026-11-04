use std::collections::BTreeSet;

use crate::graph::{Budget, account, limit};
use crate::{Graph, NodeId, Resource, Result};

const NONE: usize = usize::MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImmediateDominator {
    Unreachable,
    Root,
    Parent(NodeId),
}

/// A synthetic exit is never exposed as a public node ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PostDominator {
    /// No finite path from this node to any designated exit.
    Unreachable,
    SyntheticExit,
    Node(NodeId),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NaturalLoop {
    pub header: NodeId,
    /// All reachable tails of edges to the header that the header dominates.
    pub latches: Vec<NodeId>,
    /// Union of natural-loop bodies for all latches, including the header.
    pub body: Vec<NodeId>,
}

/// Borrows its immutable graph, preventing accidental use with a different CFG.
#[derive(Debug)]
pub struct Dominators<'g> {
    graph: &'g Graph,
    entry: NodeId,
    tree: Tree,
}

#[derive(Debug)]
pub struct PostDominators<'g> {
    graph: &'g Graph,
    exits: Vec<NodeId>,
    tree: Tree,
}

impl Graph {
    /// Entry-rooted dominance; disconnected/unreachable nodes remain explicit.
    pub fn dominators(&self, entry: NodeId) -> Result<Dominators<'_>> {
        self.validate(entry)?;
        let mut budget = Budget::new(self.limits);
        let tree = Tree::build(&self.successors, &self.predecessors, entry, &mut budget)?;
        Ok(Dominators {
            graph: self,
            entry,
            tree,
        })
    }

    /// Finite-exit-path post-dominance. Designated exits are treated as terminal:
    /// their original outgoing edges are cut, and each connects to a synthetic exit.
    /// Nodes unable to reach an exit have no post-dominance relation, even to self.
    /// Infinite paths are ignored, including from nodes that can also terminate.
    /// Empty exits are valid and make every public node `Unreachable`.
    /// Duplicate exit records consume node/work budget before being collapsed.
    pub fn post_dominators(
        &self,
        exits: impl IntoIterator<Item = NodeId>,
    ) -> Result<PostDominators<'_>> {
        let n = self.node_count();
        let internal_count = n.checked_add(1).ok_or_else(|| limit(Resource::Nodes))?;
        let mut budget = Budget::new(self.limits);
        budget.charge(internal_count)?;
        let mut is_exit = vec![false; n];
        let mut records = 0;
        for exit in exits {
            budget.tick()?;
            self.validate(exit)?;
            account(&mut records, self.limits.max_nodes, Resource::Nodes)?;
            is_exit[exit] = true;
        }
        let mut exits = Vec::new();
        let mut successors = vec![Vec::new(); internal_count];
        let mut predecessors = vec![Vec::new(); internal_count];
        // Reverse the terminalized CFG, rooted at the synthetic exit n.
        for node in 0..n {
            budget.tick()?;
            if is_exit[node] {
                exits.push(node);
                successors[n].push(node);
                predecessors[node].push(n);
            } else {
                for &to in &self.successors[node] {
                    budget.tick()?;
                    successors[to].push(node);
                    predecessors[node].push(to);
                }
            }
        }
        let tree = Tree::build(&successors, &predecessors, n, &mut budget)?;
        Ok(PostDominators {
            graph: self,
            exits,
            tree,
        })
    }
}

impl Dominators<'_> {
    pub fn entry(&self) -> NodeId {
        self.entry
    }

    pub fn immediate_dominator(&self, node: NodeId) -> Result<ImmediateDominator> {
        self.graph.validate(node)?;
        Ok(if !self.tree.reachable(node) {
            ImmediateDominator::Unreachable
        } else if node == self.entry {
            ImmediateDominator::Root
        } else {
            ImmediateDominator::Parent(self.tree.idom[node])
        })
    }

    /// Constant-time inclusive dominance; false if either node is unreachable.
    pub fn dominates(&self, dominator: NodeId, node: NodeId) -> Result<bool> {
        self.graph.validate(dominator)?;
        self.graph.validate(node)?;
        Ok(self.tree.dominates(dominator, node))
    }

    /// Ascending frontier sets indexed by public ID. Unreachable nodes have empty
    /// frontiers. The entry can occur in its own frontier when a cycle returns to it.
    pub fn frontiers(&self) -> Result<Vec<Vec<NodeId>>> {
        let n = self.graph.node_count();
        let mut budget = Budget::new(self.graph.limits);
        budget.charge(n)?;
        let mut sets: Vec<BTreeSet<NodeId>> = vec![BTreeSet::new(); n];
        let mut entries = 0;
        for &node in &self.tree.postorder {
            budget.tick()?;
            for &to in &self.graph.successors[node] {
                budget.tick()?;
                if to == node || self.tree.idom[to] != node {
                    insert_frontier(&mut sets[node], to, &mut entries, self.graph, &mut budget)?;
                }
            }
            for &child in &self.tree.children[node] {
                budget.tick()?;
                // Children have finished sets and cannot be node itself.
                let (destination, source) = two_sets(&mut sets, node, child);
                for &to in source.iter() {
                    budget.tick()?;
                    if to == node || self.tree.idom[to] != node {
                        insert_frontier(destination, to, &mut entries, self.graph, &mut budget)?;
                    }
                }
            }
        }
        budget.charge(n)?;
        budget.charge(entries)?;
        Ok(sets
            .into_iter()
            .map(|set| set.into_iter().collect())
            .collect())
    }

    /// One loop per header, ordered by header ID; bodies and latches ascend.
    /// Irreducible SCCs need not have a natural loop. Only reachable backedges
    /// whose header dominates their tail qualify. Self-latches add just the header.
    pub fn natural_loops(&self) -> Result<Vec<NaturalLoop>> {
        let n = self.graph.node_count();
        let mut budget = Budget::new(self.graph.limits);
        budget.charge(n)?;
        let mut latches = vec![Vec::new(); n];
        let mut entries = 0;
        for tail in 0..n {
            budget.tick()?;
            if !self.tree.reachable(tail) {
                continue;
            }
            for &head in &self.graph.successors[tail] {
                budget.tick()?;
                if self.tree.dominates(head, tail) {
                    account(
                        &mut entries,
                        self.graph.limits.max_loop_entries,
                        Resource::LoopEntries,
                    )?;
                    latches[head].push(tail);
                }
            }
        }
        budget.charge(n)?;
        // Process dominated headers first. A completed natural loop has no
        // reachable incoming edges except at its header, so an enclosing loop
        // can consume it as one component and scan only that header's inputs.
        // This avoids rescanning dense inner-loop edges at every nesting level.
        let mut representative: Vec<_> = (0..n).collect();
        let mut next = vec![NONE; n];
        let mut last: Vec<_> = (0..n).collect();
        let mut loops = Vec::new();
        for &header in &self.tree.postorder {
            budget.tick()?;
            let latches = std::mem::take(&mut latches[header]);
            if latches.is_empty() {
                continue;
            }
            let mut body = Vec::new();
            let mut stack = Vec::new();
            account(
                &mut entries,
                self.graph.limits.max_loop_entries,
                Resource::LoopEntries,
            )?;
            body.push(header);
            for &latch in &latches {
                budget.tick()?;
                let component = find(latch, &mut representative, &mut budget)?;
                if component != header {
                    stack.push(component);
                    representative[component] = header;
                }
            }
            while let Some(node) = stack.pop() {
                budget.tick()?;
                let mut member = node;
                while member != NONE {
                    budget.tick()?;
                    account(
                        &mut entries,
                        self.graph.limits.max_loop_entries,
                        Resource::LoopEntries,
                    )?;
                    body.push(member);
                    member = next[member];
                }
                next[last[header]] = node;
                last[header] = last[node];
                for &pred in &self.graph.predecessors[node] {
                    budget.tick()?;
                    if self.tree.reachable(pred) {
                        let component = find(pred, &mut representative, &mut budget)?;
                        if component != header {
                            stack.push(component);
                            representative[component] = header;
                        }
                    }
                }
            }
            budget.sorting(body.len())?;
            body.sort_unstable();
            loops.push(NaturalLoop {
                header,
                latches,
                body,
            });
        }
        budget.sorting(loops.len())?;
        loops.sort_unstable_by_key(|natural_loop| natural_loop.header);
        Ok(loops)
    }
}

// Union roots are forced to the enclosing loop header. Iterative compression
// bounds repeated finds without recursive parent chasing.
fn find(node: NodeId, representative: &mut [NodeId], budget: &mut Budget) -> Result<NodeId> {
    let mut root = node;
    while representative[root] != root {
        budget.tick()?;
        root = representative[root];
    }
    let mut node = node;
    while node != root {
        budget.tick()?;
        let parent = representative[node];
        representative[node] = root;
        node = parent;
    }
    Ok(root)
}

fn two_sets(
    sets: &mut [BTreeSet<NodeId>],
    a: usize,
    b: usize,
) -> (&mut BTreeSet<NodeId>, &BTreeSet<NodeId>) {
    if a < b {
        let (left, right) = sets.split_at_mut(b);
        (&mut left[a], &right[0])
    } else {
        let (left, right) = sets.split_at_mut(a);
        (&mut right[0], &left[b])
    }
}

fn insert_frontier(
    set: &mut BTreeSet<NodeId>,
    node: NodeId,
    entries: &mut usize,
    graph: &Graph,
    budget: &mut Budget,
) -> Result<()> {
    // Charge logarithmic lookup/insertion work even on duplicate candidates.
    budget.charge(2 * (usize::BITS - set.len().leading_zeros()) as usize + 1)?;
    if !set.contains(&node) {
        account(
            entries,
            graph.limits.max_frontier_entries,
            Resource::FrontierEntries,
        )?;
        set.insert(node);
    }
    Ok(())
}

impl PostDominators<'_> {
    /// Sorted, deduplicated designated terminal exits.
    pub fn exits(&self) -> &[NodeId] {
        &self.exits
    }

    pub fn immediate_post_dominator(&self, node: NodeId) -> Result<PostDominator> {
        self.graph.validate(node)?;
        Ok(if !self.tree.reachable(node) {
            PostDominator::Unreachable
        } else if self.tree.idom[node] == self.graph.node_count() {
            PostDominator::SyntheticExit
        } else {
            PostDominator::Node(self.tree.idom[node])
        })
    }

    pub fn can_reach_exit(&self, node: NodeId) -> Result<bool> {
        self.graph.validate(node)?;
        Ok(self.tree.reachable(node))
    }

    /// Constant time. Quantifies only over finite paths to designated exits.
    /// False if either argument cannot reach an exit. Synthetic exit is not a NodeId.
    pub fn post_dominates(&self, post_dominator: NodeId, node: NodeId) -> Result<bool> {
        self.graph.validate(post_dominator)?;
        self.graph.validate(node)?;
        Ok(self.tree.dominates(post_dominator, node))
    }
}

#[derive(Debug)]
struct Tree {
    idom: Vec<NodeId>,
    children: Vec<Vec<NodeId>>,
    tin: Vec<usize>,
    tout: Vec<usize>,
    postorder: Vec<NodeId>,
}

impl Tree {
    fn reachable(&self, node: NodeId) -> bool {
        self.idom[node] != NONE
    }

    fn dominates(&self, a: NodeId, b: NodeId) -> bool {
        self.reachable(a)
            && self.reachable(b)
            && self.tin[a] <= self.tin[b]
            && self.tin[b] < self.tout[a]
    }

    // Simple Lengauer-Tarjan with iterative union-find path compression. Unlike
    // repeated set intersections/CHK sweeps, this has O((V+E) log V) worst-case work.
    fn build(
        successors: &[Vec<NodeId>],
        predecessors: &[Vec<NodeId>],
        root: NodeId,
        budget: &mut Budget,
    ) -> Result<Self> {
        let n = successors.len();
        budget.charge(n)?;
        let mut semi = vec![NONE; n];
        let mut parent = vec![NONE; n];
        let mut vertex = vec![root];
        semi[root] = 0;
        let mut stack = vec![(root, 0)];
        while let Some((node, next)) = stack.last_mut() {
            budget.tick()?;
            if let Some(&child) = successors[*node].get(*next) {
                *next += 1;
                if semi[child] == NONE {
                    parent[child] = *node;
                    semi[child] = vertex.len();
                    vertex.push(child);
                    stack.push((child, 0));
                }
            } else {
                stack.pop();
            }
        }
        budget.charge(n)?;
        let mut label: Vec<_> = (0..n).collect();
        let mut ancestor = vec![NONE; n];
        let mut bucket = vec![Vec::new(); n];
        let mut idom = vec![NONE; n];
        let mut path = Vec::new();
        for &node in vertex[1..].iter().rev() {
            budget.tick()?;
            for &pred in &predecessors[node] {
                budget.tick()?;
                if semi[pred] != NONE {
                    let u = eval(pred, &mut ancestor, &mut label, &semi, &mut path, budget)?;
                    semi[node] = semi[node].min(semi[u]);
                }
            }
            bucket[vertex[semi[node]]].push(node);
            let p = parent[node];
            ancestor[node] = p;
            for v in std::mem::take(&mut bucket[p]) {
                budget.tick()?;
                let u = eval(v, &mut ancestor, &mut label, &semi, &mut path, budget)?;
                idom[v] = if semi[u] < semi[v] { u } else { p };
            }
        }
        idom[root] = root;
        for &node in &vertex[1..] {
            budget.tick()?;
            if idom[node] != vertex[semi[node]] {
                idom[node] = idom[idom[node]];
            }
        }
        budget.charge(n)?;
        let mut children = vec![Vec::new(); n];
        for node in 0..n {
            budget.tick()?;
            if node != root && idom[node] != NONE {
                children[idom[node]].push(node);
            }
        }
        let mut tin = vec![0; n];
        let mut tout = vec![0; n];
        let mut postorder = Vec::new();
        let mut time = 1;
        let mut stack = vec![(root, 0)];
        while let Some((node, next)) = stack.last_mut() {
            budget.tick()?;
            if let Some(&child) = children[*node].get(*next) {
                *next += 1;
                tin[child] = time;
                time += 1;
                stack.push((child, 0));
            } else {
                tout[*node] = time;
                postorder.push(*node);
                stack.pop();
            }
        }
        Ok(Self {
            idom,
            children,
            tin,
            tout,
            postorder,
        })
    }
}

fn eval(
    node: NodeId,
    ancestor: &mut [NodeId],
    label: &mut [NodeId],
    semi: &[usize],
    path: &mut Vec<NodeId>,
    budget: &mut Budget,
) -> Result<NodeId> {
    budget.tick()?;
    path.clear();
    let mut current = node;
    while ancestor[current] != NONE && ancestor[ancestor[current]] != NONE {
        budget.tick()?;
        path.push(current);
        current = ancestor[current];
    }
    for &v in path.iter().rev() {
        budget.tick()?;
        let a = ancestor[v];
        if semi[label[a]] < semi[label[v]] {
            label[v] = label[a];
        }
        ancestor[v] = ancestor[a];
    }
    Ok(label[node])
}
