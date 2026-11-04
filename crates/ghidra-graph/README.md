# ghidra-graph

A dependency-free, native Rust directed-graph foundation for future SSA and
decompiler work. Rust 1.88, edition 2024, Apache-2.0, version 0.3.0. No Java or C++
process or runtime is used. This crate is not a decompiler or a complete port of
Ghidra's Graph framework.

## API and identity

`Graph::new(node_count, edges, Limits)` constructs an immutable simple directed
graph. `NodeId` is a `usize` in `0..node_count`; IDs never change. Isolated nodes
are retained. Self-edges are retained, duplicate edges collapse, and both
`successors(node)` and `predecessors(node)` return ascending, duplicate-free
slices. All ID-taking public operations reject out-of-range IDs with
`Error::InvalidNode`. Public output vectors are ordinary owned data that callers
may inspect or modify without changing the graph or analysis objects.

```rust
use ghidra_graph::{Graph, ImmediateDominator, Limits, PostDominator};

# fn main() -> Result<(), ghidra_graph::Error> {
let graph = Graph::new(5, [(0, 1), (0, 2), (1, 3), (2, 3)], Limits::default())?;
let traversal = graph.traversal(0)?;
assert_eq!(traversal.reverse_postorder, [0, 2, 1, 3]);
assert!(!traversal.reachable[4]);

let dom = graph.dominators(0)?;
assert_eq!(dom.immediate_dominator(3)?, ImmediateDominator::Parent(0));
assert_eq!(dom.immediate_dominator(4)?, ImmediateDominator::Unreachable);
assert!(dom.dominates(0, 3)?);
assert_eq!(dom.frontiers()?[1], [3]);
assert!(dom.natural_loops()?.is_empty());

let post = graph.post_dominators([3])?;
assert_eq!(post.immediate_post_dominator(0)?, PostDominator::Node(3));
assert_eq!(post.immediate_post_dominator(3)?, PostDominator::SyntheticExit);
assert!(!post.can_reach_exit(4)?);
assert_eq!(graph.strongly_connected_components()?.component_of, [0, 1, 2, 3, 4]);
# Ok(())
# }
```

- `traversal(entry)` returns iterative DFS preorder, postorder, reverse
  postorder, and a reachability flag for **every** public node. Neighbors are
  visited in ascending ID order. Unreachable nodes do not appear in the orders.
- `strongly_connected_components()` uses two iterative Kosaraju passes over
  **all** nodes. Members ascend; components are numbered by ascending smallest
  member, independently of traversal discovery order. `component_of` covers
  every node. An isolated node is a singleton SCC; the empty graph has none.
- `dominators(entry)` uses iterative Lengauer-Tarjan semidominators, link/eval
  path compression, and a dominator tree. Immediate status is `Root`,
  `Parent(NodeId)`, or `Unreachable`. Inclusive `dominates(a, b)` uses tree
  intervals in constant time and is false if either node is unreachable, even
  when `a == b`. An entry is required, so an empty graph has no entry analysis.
- `Dominators::frontiers()` returns ascending frontier sets indexed by public
  ID. The definition is: `y` is in `DF(x)` iff `x` dominates a reachable
  predecessor of `y` and does not **strictly** dominate `y`. An entry or self-loop
  header can therefore belong to its own frontier. Unreachable nodes have empty
  sets; reachability is separately explicit in immediate-dominator status.
- `Dominators::natural_loops()` recognizes reachable edges `tail -> header`
  for which the header dominates the tail. It combines all latches of each
  header into one loop and unions their reverse-reachable bodies, stopping at
  the header and excluding entry-unreachable predecessors. Header, latches, and
  body include the self-loop case correctly: a self-edge alone has body
  `[header]`, without absorbing the header's predecessors. Results ascend by
  header, and each body/latch list ascends. Natural loops do not enumerate all
  cycles; an irreducible SCC can have no natural loop. Completed inner loops
  are contracted while processing dominator-tree postorder: their only reachable
  external inputs enter at the header. This also works for natural loops inside
  an otherwise irreducible graph.

`Dominators` and `PostDominators` borrow their immutable graph, so an analysis
cannot accidentally be paired with another graph. There is no mutable CFG,
incremental analysis, node payload, or multigraph API yet.

## Exact post-dominance policy

`post_dominators(exits)` takes **explicit** designated exits, not inferred sinks.
Exits are terminal: original outgoing edges from each designated exit are cut.
A single private synthetic exit is added, with an edge from each designated
exit, even when there is just one exit. Dominance of the reversed augmented graph
is post-dominance of the terminalized graph. The synthetic exit has no public
`NodeId`; an immediate parent there is `PostDominator::SyntheticExit`.

This is **finite-exit-path post-dominance**: `a` post-dominates `b` iff `b` has at
least one finite path to a designated exit and every such path contains `a`.
Infinite paths are ignored. In particular, a branch into a nonterminating SCC
does not remove post-dominators of the branch's terminating paths. This is not
a guarantee over infinite executions or a strong post-dominance definition.

A node with no finite path to any designated exit gets
`PostDominator::Unreachable`, `can_reach_exit == false`, and no post-dominance
relation, including to itself. No dominators are invented for nonterminating
components. Empty exit lists are valid: every public node is unreachable in
this analysis. Reachability here is from exits in the reversed graph, not from
an entry; entry-disconnected components can still reach an explicit exit.
Exit records are validated and deduplicated; `exits()` returns them ascending.

## Bounds and failure behavior

The graph retains a caller-supplied `Limits` value (with practical defaults).
Each constructor or analysis call starts a fresh `max_work` budget; dependent
calls such as `dom.frontiers()` have their own budgets, not a shared session
budget. Queries and accessors are constant time and do not spend work units.
To impose a budget across several calls, the caller must bound the calls too.

- `max_nodes` bounds public nodes and separately bounds the number of input exit
  records in one post-dominance call, **including duplicate exits**.
- `max_edges` bounds edge input records **before deduplication**, so an infinite
  duplicate iterator cannot evade resource checks. Canonical edge count is
  available as `edge_count()`. Post-dominance's internal graph can have one extra
  synthetic node and up to one extra edge per public node: these are a fixed
  linear allowance outside the public node/edge limits, still charged as work.
- `max_frontier_entries` bounds the total number of distinct frontier pairs in
  a result, checked **before** each new set insertion.
- `max_loop_entries` bounds the sum of body **and latch** lengths across the
  loop result, checked before materialization. Nested loop bodies are counted
  separately; a singleton self-loop consumes two entries.
- Work charges cover node-sized setup, every input record, traversal/iteration
  step, edge scan, union-find climb/compression, output copy, and each loop-body
  expansion. Sorting is precharged by `n * (ceil(log2(n)) + 1)` and frontier-set
  operations by logarithmic size. These are deterministic abstract work units,
  not CPU instructions, elapsed time, bytes, or exact allocator comparisons.
  Constant-factor initialization and standard-library allocation bookkeeping
  are included in their surrounding logical operation, not charged separately.
  Work-account arithmetic is checked for overflow.

Every resource failure returns `Error::LimitExceeded { resource }`; there is
no truncated success or partially exposed analysis. Errors do not mutate the
graph or previously returned results. Budgets apply while consuming iterators,
but cannot interrupt a caller's blocking/expensive `Iterator::next()`. The work
budget can be exhausted even when node/edge counts fit their limits. A rejected
iterator may have yielded the first over-limit record. Limits bound logical
sizes, not allocator overhead; normal Rust allocation failure is not converted
to an analysis error. Callers must choose limits appropriate to available memory.

## Complexity

Let `N` be public nodes, `M` canonical edges, `R` input edge records, `F` total
frontier entries, and `B` total loop body plus latch entries. Logarithms below
mean `log(2 + size)`. These are successful-run bounds; work exhaustion can stop
any pass earlier with an error.

| Operation | Time | Additional space, excluding immutable graph |
| --- | --- | --- |
| Construction | `O(N + R log R)` | `O(N + R)` peak; retained graph `O(N + M)` |
| Traversal / SCCs | `O(N + M)` | `O(N)` |
| Dominators | `O((N + M) log N)` | `O(N)` |
| Post-dominators | `O((N + M) log N)` plus exit input | `O(N + M)` reversed graph and tree |
| Dominance / post-dominance query | `O(1)` | `O(1)` |
| Frontiers | `O(N + (M + F) log N)` | `O(N + F)` |
| Natural loops | `O((N + M + B) log N)` | `O(N + B)` |

Simple link/eval uses iterative path compression rather than the more complex
balanced Lengauer-Tarjan variant. Frontiers propagate completed child sets up
the dominator tree once per child; they do not walk all ancestors for each edge.
Loop contraction ensures each consumed component header's predecessors are
scanned once across the entire loop analysis; member lists are expanded only
when copied into an output body. Header-rooted union-find uses path compression;
sorting bodies accounts for the `B log N` term. No production algorithm uses a
dense `N * N` matrix, recursive DFS, or repeated whole-graph convergence sweeps.
Frontiers and nested-loop bodies can inherently have quadratic output size;
their explicit entry/work limits intentionally reject oversized results.

## References and verification

Inspected retained upstream sources under
`Ghidra/Framework/Graph/src/main/java/ghidra/graph/algo/`:
`AbstractDominanceAlgorithm`, `ChkDominanceAlgorithm`,
`ChkPostDominanceAlgorithm`, and `TarjanStronglyConnectedAlgorthm` (upstream
spelling). They provide semantic context for source/sink unification, reversed
dominance, and SCCs. The Rust algorithms are native implementations using
explicit entries/exits, iterative Kosaraju and Lengauer-Tarjan rather than a
translation of Java CHK or recursive Tarjan.

Tests cover diamonds; combined, nested and self loops; irreducible and
disconnected cycles; terminalized multiple exits; empty exits and nontermination;
malformed IDs; duplicate order/limits; work and output exhaustion; a dense
nested-loop stress graph; and a 100,000-node chain through every analysis.
1,600 fixed-seed small graphs compare dominators and post-dominators against an
independent vertex-removal/reachability oracle, frontiers against their direct
definition, SCCs against mutual reachability, and natural loops against
header-avoiding path reachability. Only test oracles use dense matrices.
