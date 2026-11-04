use std::{cmp, collections::HashMap};

use jstd::{Identifier, debug_print, registry::Registry};

use crate::{
    constructor::{Constructor, ConstructorId},
    instance::ConstructorInstance,
    objects::{
        field::{Field, FieldId},
        table::{Table, TableId},
    },
    pattern::{CombinedPattern, CombinedRange},
    runtime::walker::Walker,
};

use crate::bitrange::BitRange;
use serde::{Deserialize, Serialize};

pub(crate) const INSTRUCTION_TREE_ID: TreeId = TreeId(0);

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ConstructorPair<'a> {
    constructor: ConstructorId,
    pattern: &'a CombinedPattern,
}

/// Gets the shanon entropy for a given bitrange
fn entropy(patterns: &[ConstructorPair], range: &CombinedRange) -> Option<f64> {
    let size = 1usize << range.size();

    let mut counts = vec![0usize; size];

    let mut total = 0usize;

    for pair in patterns {
        if !pair.pattern.specifies_range(range) {
            continue;
        }

        let v = pair.pattern.get_value(range) as usize;
        counts[v] += 1;
        total += 1;
    }

    // No pattern has this mask
    if total == 0 {
        return None;
    }

    let mut entropy = 0.0f64;
    let mut nonzero = 0usize;

    for c in counts {
        if c == 0 {
            continue;
        }

        nonzero += 1;

        let p = c as f64 / total as f64;
        entropy -= p * p.log2();
    }

    if nonzero <= 1 { None } else { Some(entropy) }
}

/// Counts the number of patterns that specify a given bitrange
fn num_fixed(patterns: &[ConstructorPair], range: &CombinedRange) -> usize {
    patterns
        .iter()
        .filter(|&pair| pair.pattern.specifies_range(range))
        .count()
}

/// Chooses an optimal bitrange to split on, preferring ranges that are specified by many patterns and have high entropy.
fn choose_optimal_range(max_len: usize, patterns: &[ConstructorPair]) -> Option<CombinedRange> {
    #[derive(Debug)]
    struct State {
        fixed: usize,
        entropy: f64,
        range: Option<CombinedRange>,
    }

    let mut best = State {
        fixed: 1,
        entropy: 0.0,
        range: None,
    };

    let state_from_range = |best: &State, range: CombinedRange| -> Option<State> {
        let fixed = num_fixed(patterns, &range);

        // We do not have maximum specificity
        if fixed < best.fixed {
            return None;
        }

        let entropy = entropy(patterns, &range)?;

        Some(State {
            fixed,
            entropy,
            range: Some(range),
        })
    };

    for range in (0..max_len).map(BitRange::singleton).flat_map(|range| {
        [
            CombinedRange::Context(range.clone()),
            CombinedRange::Instruction(range),
        ]
    }) {
        let Some(state) = state_from_range(&best, range) else {
            continue;
        };

        if state.fixed > best.fixed || state.entropy > best.entropy {
            best = state;
        }
    }

    // Attempt to "grow the range" left
    let best_range = best.range.clone()?;
    let max_left = cmp::min(7, best_range.start());
    for dx in 1..=max_left {
        let mut range = best_range.clone();
        *range.bitrange_mut() = BitRange::new(best_range.start() - dx, best_range.end());

        let Some(state) = state_from_range(&best, range) else {
            break;
        };

        if state.fixed > best.fixed || state.entropy > best.entropy {
            best = state;
        }
    }

    // Attempt to "grow the range" right
    let best_range = best.range.clone()?;
    let max_right = cmp::min(max_len - best_range.end(), 8 - best_range.size());
    for dx in 1..=max_right {
        let mut range = best_range.clone();
        *range.bitrange_mut() = BitRange::new(best_range.start(), best_range.end() + dx);

        let Some(state) = state_from_range(&best, range) else {
            break;
        };

        if state.fixed > best.fixed || state.entropy > best.entropy {
            best = state;
        }
    }

    best.range
}

// Creates an identifier to use with [`TreeNode`]s
#[derive(Identifier)]
pub(crate) struct TreeNodeId(usize);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum TreeNode {
    Node {
        range: CombinedRange,
        children: Box<[Option<TreeNodeId>]>,
    },

    Leaf {
        // The id of the associated constructor
        constructors: Vec<ConstructorId>,
    },
}

impl TreeNode {
    /// Attempts to get a constructor from a list of bytes
    fn get_constructor(
        &self,
        tree_id: TreeId,
        walker: &Walker<'_, '_, '_>,
    ) -> Option<ConstructorInstance> {
        let tree = &walker.spec.trees[tree_id];
        match self {
            TreeNode::Node { range, children } => {
                walker.note_decision(range);
                let v = walker.value_over(range);
                children
                    .get(v as usize)
                    .copied()
                    .flatten()
                    .map(|id| &tree.nodes[id])
                    .and_then(|node| node.get_constructor(tree_id, walker))
            }

            TreeNode::Leaf { constructors } => {
                for &id in constructors {
                    if let Some(constructor) = walker.try_build_constructor(tree_id, id) {
                        return Some(constructor);
                    }
                }

                None
            }
        }
    }
}

struct TreeBuilder<'b> {
    tree: Tree,
    max_len: usize,
    cache: HashMap<Vec<ConstructorPair<'b>>, TreeNodeId>,
}

impl<'b> TreeBuilder<'b> {
    /// Builds a tree from a table
    pub(crate) fn from_table(fields: &Registry<FieldId, Field>, table: Table) -> Tree {
        let max_len = table.max_len();

        let pairs = table
            .constructors
            .iter()
            .flat_map(|c| {
                c.pattern
                    .unwrap_pattern()
                    .combined_patterns()
                    .map(move |pattern| ConstructorPair {
                        pattern,
                        constructor: c.id,
                    })
            })
            .collect::<Vec<_>>();

        let mut builder = Self {
            tree: Tree::default(),
            max_len,
            cache: HashMap::new(),
        };

        builder.tree.root = builder.node_from_constructor_pairs(pairs);
        let mut tree = builder.tree;

        // Builds the constructors
        tree.constructors = table
            .constructors
            .into_iter()
            .map(|builder| builder.inner)
            .map(|builder| Constructor::from_builder(fields, builder))
            .collect();

        // updates the name
        tree.name = table.name;

        tree
    }

    fn node_from_constructor_pairs(&mut self, pairs: Vec<ConstructorPair<'b>>) -> TreeNodeId {
        if let Some(&id) = self.cache.get(&pairs) {
            id
        } else {
            let id = self.build_node_from_constructor_pairs(&pairs);
            self.cache.insert(pairs, id);
            id
        }
    }

    fn build_node_from_constructor_pairs(&mut self, pairs: &[ConstructorPair<'b>]) -> TreeNodeId {
        if pairs.len() == 1 {
            return self.create_leaf(pairs);
        }

        let Some(range) = choose_optimal_range(self.max_len, pairs) else {
            return self.create_leaf(pairs);
        };

        let mut children: HashMap<u8, Vec<ConstructorPair>> = HashMap::new();

        for pair in pairs {
            for value in pair.pattern.values_over(&range) {
                debug_assert!(value < 256);
                children.entry(value as u8).or_default().push(pair.clone())
            }
        }

        self.create_node(range, children)
    }

    fn create_leaf(&mut self, pairs: &[ConstructorPair]) -> TreeNodeId {
        // Deduplicate identical patterns, keeping the first-defined constructor (Ghidra semantics).
        let mut deduped: Vec<ConstructorPair> = Vec::with_capacity(pairs.len());
        'outer: for pair in pairs {
            for seen in &deduped {
                if seen.pattern == pair.pattern && seen.constructor != pair.constructor {
                    debug_print!(
                        "sleigh: duplicate pattern detected — keeping first constructor, discarding {:?}",
                        pair.constructor
                    );
                    continue 'outer;
                }
            }
            deduped.push(pair.clone());
        }

        let mut conflicts = Vec::new();

        let mut sorted_pairs: Vec<ConstructorPair> = vec![];

        for pair in deduped {
            let insert_at = sorted_pairs
                .iter()
                .position(|existing: &ConstructorPair<'_>| {
                    existing.pattern.is_less_specific(pair.pattern)
                })
                .unwrap_or(sorted_pairs.len());

            for existing in &sorted_pairs[..insert_at] {
                if !existing.pattern.is_less_specific(pair.pattern)
                    && pair.constructor != existing.constructor
                {
                    conflicts.push((pair.pattern, existing.pattern));
                }
            }

            sorted_pairs.insert(insert_at, pair);
        }

        if !conflicts.is_empty() {
            debug_print!(
                "sleigh: {} ambiguous constructor pattern(s) in this leaf — ordering by declaration",
                conflicts.len()
            );
        }

        let constructors = sorted_pairs.iter().map(|pair| pair.constructor).collect();

        self.tree.nodes.push(TreeNode::Leaf { constructors })
    }

    fn create_node(
        &mut self,
        range: CombinedRange,
        children: HashMap<u8, Vec<ConstructorPair<'b>>>,
    ) -> TreeNodeId {
        let id = self.tree.nodes.push(TreeNode::Node {
            range,
            children: vec![None; 256].into_boxed_slice(),
        });

        for (k, pairs) in children {
            let child = self.node_from_constructor_pairs(pairs);

            let TreeNode::Node { children, .. } = &mut self.tree.nodes[id] else {
                unreachable!()
            };

            children[k as usize] = Some(child);
        }

        id
    }
}

#[derive(Identifier)]
pub(crate) struct TreeId(usize);

impl From<TableId> for TreeId {
    fn from(val: TableId) -> Self {
        TreeId(val.into())
    }
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub(crate) struct Tree {
    /// The name of this tree
    pub(crate) name: Box<str>,

    /// The nodes in this tree
    nodes: Registry<TreeNodeId, TreeNode>,

    /// The root node
    root: TreeNodeId,

    /// The constructors for this tree
    pub(crate) constructors: Registry<ConstructorId, Constructor>,
}

impl Tree {
    pub(crate) fn from_table(fields: &Registry<FieldId, Field>, table: Table) -> Self {
        TreeBuilder::from_table(fields, table)
    }

    fn root(&self) -> &TreeNode {
        &self.nodes[self.root]
    }

    /// Id of this tree's root decision node.
    #[cfg(feature = "unstable-introspect")]
    pub(crate) fn root_id(&self) -> TreeNodeId {
        self.root
    }

    /// The decision node `id` names.
    #[cfg(feature = "unstable-introspect")]
    pub(crate) fn node(&self, id: TreeNodeId) -> &TreeNode {
        &self.nodes[id]
    }

    /// Every decision node, in id order.
    #[cfg(feature = "unstable-introspect")]
    pub(crate) fn node_ids(&self) -> impl Iterator<Item = TreeNodeId> + '_ {
        (0..self.nodes.len()).map(TreeNodeId::from)
    }

    pub(crate) fn get_constructor(
        &self,
        id: TreeId,
        walker: &Walker<'_, '_, '_>,
    ) -> Option<ConstructorInstance> {
        self.root().get_constructor(id, walker)
    }
}

#[cfg(test)]
mod tests {
    // use super::*;

    // use crate::sleigh::pattern::{BitPreference, CombinedPattern};

    // #[test]
    // fn test_optimal_field() {
    //     // use
    //     use BitPreference::*;
    //     // TODO:
    // }
}
