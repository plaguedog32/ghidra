use std::fmt;

/// Stable dense public IDs are exactly `0..Graph::node_count()`.
pub type NodeId = usize;
pub type Result<T> = std::result::Result<T, Error>;

/// Limits are immutable for a graph. Work resets for each public analysis call.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Limits {
    pub max_nodes: usize,
    /// Input edge records, including duplicates, not just canonical edges.
    pub max_edges: usize,
    pub max_work: u64,
    /// Total distinct (node, frontier member) pairs in one frontier result.
    pub max_frontier_entries: usize,
    /// Sum of body and latch lengths across all loops in one result.
    pub max_loop_entries: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_nodes: 1_000_000,
            max_edges: 4_000_000,
            max_work: 100_000_000,
            max_frontier_entries: 4_000_000,
            max_loop_entries: 4_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Resource {
    Nodes,
    Edges,
    Work,
    FrontierEntries,
    LoopEntries,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    InvalidNode { node: NodeId, node_count: usize },
    LimitExceeded { resource: Resource },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidNode { node, node_count } => {
                write!(f, "node {node} is outside 0..{node_count}")
            }
            Self::LimitExceeded { resource } => write!(f, "{resource:?} limit exceeded"),
        }
    }
}

impl std::error::Error for Error {}

pub(crate) fn limit(resource: Resource) -> Error {
    Error::LimitExceeded { resource }
}

pub(crate) struct Budget {
    remaining: u64,
}

impl Budget {
    pub(crate) fn new(limits: Limits) -> Self {
        Self {
            remaining: limits.max_work,
        }
    }

    pub(crate) fn charge(&mut self, amount: usize) -> Result<()> {
        let amount = u64::try_from(amount).map_err(|_| limit(Resource::Work))?;
        self.remaining = self
            .remaining
            .checked_sub(amount)
            .ok_or_else(|| limit(Resource::Work))?;
        Ok(())
    }

    pub(crate) fn tick(&mut self) -> Result<()> {
        self.charge(1)
    }

    // Precharge a conservative n * (ceil(log2(n)) + 1) sorting allowance.
    pub(crate) fn sorting(&mut self, n: usize) -> Result<()> {
        if n > 1 {
            let levels = (usize::BITS - (n - 1).leading_zeros()) as usize + 1;
            self.charge(n.checked_mul(levels).ok_or_else(|| limit(Resource::Work))?)?;
        }
        Ok(())
    }
}

pub(crate) fn account(count: &mut usize, maximum: usize, resource: Resource) -> Result<()> {
    if *count >= maximum {
        return Err(limit(resource));
    }
    *count += 1;
    Ok(())
}

/// Immutable simple directed graph. Self-edges are retained; duplicates collapse.
#[derive(Debug)]
pub struct Graph {
    pub(crate) successors: Vec<Vec<NodeId>>,
    pub(crate) predecessors: Vec<Vec<NodeId>>,
    pub(crate) limits: Limits,
    edge_count: usize,
}

impl Graph {
    /// Validate every input endpoint and bound input consumption before deduplication.
    /// Adjacency and predecessor slices are always ascending and duplicate-free.
    pub fn new(
        node_count: usize,
        edges: impl IntoIterator<Item = (NodeId, NodeId)>,
        limits: Limits,
    ) -> Result<Self> {
        if node_count > limits.max_nodes {
            return Err(limit(Resource::Nodes));
        }
        let mut budget = Budget::new(limits);
        budget.charge(node_count)?;
        let mut graph = Self {
            successors: vec![Vec::new(); node_count],
            predecessors: vec![Vec::new(); node_count],
            limits,
            edge_count: 0,
        };
        let mut input_count = 0;
        for (from, to) in edges {
            budget.tick()?;
            graph.validate(from)?;
            graph.validate(to)?;
            account(&mut input_count, limits.max_edges, Resource::Edges)?;
            graph.successors[from].push(to);
        }
        for from in 0..node_count {
            budget.tick()?;
            let adjacent = &mut graph.successors[from];
            budget.sorting(adjacent.len())?;
            budget.charge(adjacent.len())?;
            adjacent.sort_unstable();
            adjacent.dedup();
            for &to in adjacent.iter() {
                budget.tick()?;
                graph.predecessors[to].push(from);
                graph.edge_count += 1;
            }
        }
        Ok(graph)
    }

    pub fn node_count(&self) -> usize {
        self.successors.len()
    }
    pub fn edge_count(&self) -> usize {
        self.edge_count
    }
    pub fn nodes(&self) -> std::ops::Range<NodeId> {
        0..self.node_count()
    }
    pub fn limits(&self) -> Limits {
        self.limits
    }

    pub(crate) fn validate(&self, node: NodeId) -> Result<()> {
        if node >= self.node_count() {
            return Err(Error::InvalidNode {
                node,
                node_count: self.node_count(),
            });
        }
        Ok(())
    }

    pub fn successors(&self, node: NodeId) -> Result<&[NodeId]> {
        self.validate(node)?;
        Ok(&self.successors[node])
    }

    pub fn predecessors(&self, node: NodeId) -> Result<&[NodeId]> {
        self.validate(node)?;
        Ok(&self.predecessors[node])
    }

    pub fn traversal(&self, entry: NodeId) -> Result<Traversal> {
        self.validate(entry)?;
        let mut budget = Budget::new(self.limits);
        budget.charge(self.node_count())?;
        let mut seen = vec![false; self.node_count()];
        let mut preorder = Vec::new();
        let mut postorder = Vec::new();
        dfs(
            &self.successors,
            entry,
            &mut seen,
            &mut preorder,
            &mut postorder,
            &mut budget,
        )?;
        budget.charge(postorder.len())?;
        let reverse_postorder = postorder.iter().rev().copied().collect();
        Ok(Traversal {
            preorder,
            postorder,
            reverse_postorder,
            reachable: seen,
        })
    }

    /// Iterative Kosaraju passes over all nodes, including disconnected components.
    /// Components and their IDs are ordered by smallest member; members ascend.
    pub fn strongly_connected_components(&self) -> Result<StrongComponents> {
        let n = self.node_count();
        let mut budget = Budget::new(self.limits);
        budget.charge(n)?;
        let mut seen = vec![false; n];
        let mut preorder = Vec::new();
        let mut postorder = Vec::new();
        for node in 0..n {
            budget.tick()?;
            if !seen[node] {
                dfs(
                    &self.successors,
                    node,
                    &mut seen,
                    &mut preorder,
                    &mut postorder,
                    &mut budget,
                )?;
            }
        }
        budget.charge(n)?;
        let mut raw = vec![usize::MAX; n];
        let mut stack = Vec::new();
        let mut count = 0;
        for &root in postorder.iter().rev() {
            budget.tick()?;
            if raw[root] != usize::MAX {
                continue;
            }
            raw[root] = count;
            stack.push(root);
            while let Some(node) = stack.pop() {
                budget.tick()?;
                for &pred in &self.predecessors[node] {
                    budget.tick()?;
                    if raw[pred] == usize::MAX {
                        raw[pred] = count;
                        stack.push(pred);
                    }
                }
            }
            count += 1;
        }
        budget.charge(n)?;
        let mut remap = vec![usize::MAX; count];
        let mut components: Vec<Vec<NodeId>> = Vec::new();
        let mut component_of = vec![0; n];
        for node in 0..n {
            budget.tick()?;
            let id = &mut remap[raw[node]];
            if *id == usize::MAX {
                *id = components.len();
                components.push(Vec::new());
            }
            component_of[node] = *id;
            components[*id].push(node);
        }
        Ok(StrongComponents {
            components,
            component_of,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Traversal {
    pub preorder: Vec<NodeId>,
    pub postorder: Vec<NodeId>,
    pub reverse_postorder: Vec<NodeId>,
    /// Indexed by every public node, including unreachable nodes.
    pub reachable: Vec<bool>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StrongComponents {
    pub components: Vec<Vec<NodeId>>,
    pub component_of: Vec<usize>,
}

pub(crate) fn dfs(
    successors: &[Vec<NodeId>],
    root: NodeId,
    seen: &mut [bool],
    preorder: &mut Vec<NodeId>,
    postorder: &mut Vec<NodeId>,
    budget: &mut Budget,
) -> Result<()> {
    budget.tick()?;
    seen[root] = true;
    preorder.push(root);
    let mut stack = vec![(root, 0)];
    while let Some((node, next)) = stack.last_mut() {
        budget.tick()?;
        if let Some(&child) = successors[*node].get(*next) {
            *next += 1;
            if !seen[child] {
                seen[child] = true;
                preorder.push(child);
                stack.push((child, 0));
            }
        } else {
            postorder.push(*node);
            stack.pop();
        }
    }
    Ok(())
}
