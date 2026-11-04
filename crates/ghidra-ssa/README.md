# ghidra-ssa

A native Rust engine that builds and verifies generic SSA form over a
`ghidra_graph::Graph`. Rust 1.88, edition 2024, Apache-2.0, version 0.3.0. The
only dependency is `ghidra-graph`. No Java or C++ process or runtime is used.

This crate is **only** the SSA construction engine. It is not a P-code
adapter, alias analysis, memory SSA, call or ABI model, liveness analysis,
type inference, optimizer, or decompiler. It has no opcode knowledge: callers
supply abstract variables and per-statement def/use lists, and must resolve
register aliasing, partial overlap, memory, and call effects before calling it.

```rust
use std::sync::Arc;

use ghidra_graph::{Graph, Limits as GraphLimits};
use ghidra_ssa::{
    EntryState, Limits, Predecessor, RawProgram, RawStatement, Ssa, ValueOrigin, VariableId,
};

# fn main() -> Result<(), ghidra_ssa::Error> {
let x = VariableId(0);
// Diamond 0 -> {1, 2} -> 3; x is written only on the 0 -> 1 -> 3 path.
let graph = Arc::new(Graph::new(4, [(0, 1), (0, 2), (1, 3), (2, 3)], GraphLimits::default())?);
let program = RawProgram {
    variables: vec![EntryState::Undefined],
    blocks: vec![
        vec![],
        vec![RawStatement::new([], [x])],
        vec![],
        vec![RawStatement::new([x], [])],
    ],
};
let ssa = Ssa::construct(Arc::clone(&graph), 0, &program, Limits::default())?;
ssa.verify(&program)?;

let join = ssa.block(3)?.renamed().expect("reachable");
assert_eq!(join.incoming(), [Predecessor::Node(1), Predecessor::Node(2)]);
let (_, phi) = join.phi_for(x).expect("phi at the join");
let from_1 = ssa.value(phi.operands()[0])?;
let from_2 = ssa.value(phi.operands()[1])?;
assert!(matches!(from_1.origin, ValueOrigin::Definition(_)));
// The undefined entry value stays explicit on the path that skips the write.
assert_eq!(from_2.origin, ValueOrigin::Entry(EntryState::Undefined));
assert_eq!(join.statements()[0].uses(), [phi.value()]);
# Ok(())
# }
```

## Input contract

`Ssa::construct(graph: Arc<Graph>, entry: NodeId, program: &RawProgram, limits: Limits)`.

- **Variables** are a dense domain `VariableId(0..variables.len())`. Each has a
  caller-declared `EntryState`: `Input` (a parameter or live-in state) or
  `Undefined`. Neither is turned into a constant.
- **Blocks**: `program.blocks[node]` is the ordered statement list of graph node
  `node`. There must be exactly one list per graph node, including empty
  synthetic exits and entry-unreachable nodes.
- **Statements** (`RawStatement { uses, defs }`) read every `uses` operand,
  then write every `defs` operand. All reads happen before any write, so
  `uses: [a, b], defs: [b, a]` is a swap, and a read of a variable that the
  same statement writes sees the old value. Uses may repeat (each occurrence
  is its own slot). Several variables can be defined at once, but the same
  variable twice in one `defs` list is rejected.

The whole raw program, including unreachable nodes, is validated and bounded
before any graph analysis: block count, variable count, statement and operand
counts, operand IDs, and duplicate definitions.

## Output and ownership

`Ssa` owns every renamed statement, phi, incoming list, and value, and retains
a clone of the caller's `Arc<Graph>`. It borrows neither the graph nor the raw
program, so it can outlive both, be moved across threads, and be cloned.
All access is through immutable accessors:

| Accessor | Meaning |
| --- | --- |
| `graph()`, `entry()`, `node_count()`, `limits()`, `work()` | Inputs, and SSA work spent by construction |
| `variable_count()`, `entry_state(x)`, `entry_value(x)` | Declared domain; the entry value is always `ValueId(x.0)` |
| `immediate_dominator(node)`, `is_reachable(node)` | Copied dominance facts |
| `blocks()`, `block(node)` | `Block::Unreachable { statement_count }` or `Block::Reachable(RenamedBlock)` |
| `values()`, `value(id)` | `Value { variable, origin }` |
| `phi(PhiId)`, `phi_count()`, `phi_operand_count()` | Phis and their total arity |
| `statement(StatementId)`, `definition(DefinitionSite)`, `use_value(UseSite)` | Renamed operands |

`RenamedBlock` exposes `incoming()`, `incoming_index(pred)`, `phis()`,
`phi_for(variable)`, and `statements()`. `Phi` exposes `variable()`, `value()`,
and `operands()`. `RenamedStatement` exposes `uses()` and `defs()`.

**Stable identity.** `StatementId { node, index }` is the same in the raw
program and the output, so callers can map it to their own program points.
`DefinitionSite { statement, slot }` and `UseSite { statement, slot }` index
into `defs` and `uses`. `PhiId { node, index }` indexes a block's phi list, which
is sorted by strictly ascending variable (at most one phi per variable).
`ValueOrigin` is `Entry(EntryState)`, `Phi(PhiId)`, or
`Definition(DefinitionSite)`. Every SSA value has exactly one origin, and the
origin's slot holds exactly that value.

**Value layout** is deterministic: entry values first (`ValueId(x)` for
variable `x`, always present), then phis in node and phi order, then reachable
definitions in node, statement, and slot order.

**Incoming order.** A reachable block's `incoming()` is canonical:
`Predecessor::Entry` first if the block is the entry node, then every
entry-reachable graph predecessor in ascending `NodeId` order. The graph is a
simple graph, so one predecessor names exactly one edge, including critical
edges and self-loops. Phi operand `i` belongs to `incoming()[i]`.

## Algorithm

1. **Validate** the raw program (bounded; see below).
2. **Dominators**: one `Graph::dominators(entry)` call (iterative
   Lengauer-Tarjan). Immediate dominators are copied; dominator-tree children
   are built as a compressed adjacency array.
3. **Defining blocks**: a compressed per-variable list of distinct reachable
   blocks that define it, built by two counting passes. No `variables * nodes`
   matrix exists.
4. **Phi placement** (Cytron et al.): one `Dominators::frontiers()` call, then
   for each variable a worklist over its defining blocks, placing a phi at
   each frontier member and adding new phi blocks to the worklist. Two
   node-sized marker arrays are stamped with the variable index, so they are
   allocated once and never cleared. This is the iterated dominance frontier
   per variable, not a whole-graph fixed point.
5. **Layout**: phis are grouped by node with a stable counting sort (keeping
   variable order), values are numbered, and block shells are created.
6. **Renaming**: an iterative preorder walk of the dominator tree with an
   explicit stack (no recursion), a dense `current[variable]` array, and an
   undo log that restores `current` when a subtree is finished. In each block:
   phis define their values; each statement reads all uses from `current`,
   then writes its fresh definitions; finally, for each graph successor, the
   phi operand slot of this edge (found by binary search in the successor's
   sorted incoming list) receives the value live at the end of this block.

The retained upstream decompiler source
`Ghidra/Features/Decompiler/src/decompile/cpp/heritage.cc` was inspected for
semantics (`placeMultiequals`, `calcMultiequals`, `renameRecurse`). Upstream
places MULTIEQUALs with an augmented dominator tree and renames recursively;
this crate uses explicit frontiers and an iterative walk instead, and has no
INDIRECT, guard, or address-range logic.

## Policies

- **Unpruned SSA.** Phis go at the iterated dominance frontier of each
  variable's definitions regardless of liveness, so dead phis can exist. No
  liveness, copy propagation, or type reasoning is performed.
- **Entry values are explicit.** A read with no reaching definition gets the
  variable's entry value, tagged with its declared `EntryState`. Nothing is
  zero-filled. A join where one path has no definition keeps the entry value
  (including an `Undefined` one) as that operand.
- **Virtual entry edge.** The entry node always lists `Predecessor::Entry`
  first. If a backedge or self-loop returns to the entry and it gets a phi,
  that phi's `Entry` operand is the entry value, so the first iteration is
  represented separately from later iterations.
- **Unreachable code.** Nodes unreachable from the entry are
  `Block::Unreachable`: no phis, renamed statements, incoming list, or values.
  Their raw statements are still validated. Edges from unreachable nodes add no
  incoming slot or phi operand. Frontiers only consider reachable predecessors.
- **Irreducible graphs** need no special handling: placement uses dominance
  frontiers and the walk uses the dominator tree, which are defined for any
  rooted graph.
- **Determinism.** Every order (children, successors, phis, values) is derived
  from ascending IDs; equal inputs give equal outputs.

## Verification

`Ssa::verify(&program)` checks the result against the raw program using
structural invariants. It does not replay renaming. It recomputes dominators
through the graph crate, then checks, returning the first
`Error::Verification(Violation)` in a deterministic order:

1. **Shape**: same block count, entry states, statement counts and arities;
   stored immediate dominators and reachability equal the recomputed ones;
   unreachable blocks carry the raw statement count.
2. **Identity**: every value's origin round-trips to the one slot (def slot,
   phi, or entry) that holds it, and every def slot and phi holds a value whose
   origin is that slot. Entry values are `ValueId(x)` with the declared state.
3. **Canonical incoming lists**, strictly ascending phi variables, and phi
   arity equal to the incoming count.
4. **Strict SSA dominance**: a use reads a value of the same variable whose
   definition is an earlier statement of the same block, a phi of a dominating
   block (including this one), a definition in a strictly dominating block, or
   an entry value. A phi operand along `Node(p)` has the phi's variable and is
   defined in a block dominating `p` (any statement), or is an entry value. A
   phi operand along `Entry` is exactly the entry value.
5. **Exact reaching definitions**: a read within a block that already defined
   (or has a phi for) its variable must see the latest such value. Every other
   read, and every phi operand, must equal the final value in the nearest
   dominator-tree ancestor that defines the variable (or has its phi), or the
   entry value if none exists. This is checked with one sorted sweep over
   dominator-tree preorder intervals per variable, not with per-query ancestor
   walks.
6. **Phi completeness**: one `frontiers()` call; for every block that defines
   a variable or has its phi, every member of its dominance frontier has a phi
   for that variable. Extra phis are not rejected.

Together, 4 to 6 are the standard conditions under which every use observes the
most recent raw definition along every entry path. Verification spends its own
fresh `max_work` budget and two graph analysis budgets, so it can fail with a
limit error even when construction just fit.

## Limits and failure

`Limits` (with practical defaults) bounds `max_variables`, `max_statements`
(raw, all nodes), `max_operands` (raw use + def references, all nodes),
`max_values`, `max_phis`, `max_phi_operands` (sum of phi arities), and
`max_work`. Every count is checked with overflow-checked arithmetic **before**
the corresponding output grows: statement and operand totals before a block or
statement is scanned, and phis, phi operands, and values before each phi is
recorded. Any failure is `Error::LimitExceeded { resource }` with no partial
result; inputs and earlier results are never mutated.

**Aggregate work.** `max_work` is a fresh budget for each `construct` or
`verify` call, charged for validation, every pass, edge scan, binary search,
frontier entry scanned, phi operand filled, undo restore, and sort (precharged
as `n * (ceil(log2 n) + 1)`). Each `construct` or `verify` call also makes
exactly two graph calls, `Graph::dominators` and `Dominators::frontiers`, each
with a fresh `graph.limits().max_work` budget and the graph's frontier-entry
limit; their failures surface as `Error::Graph`. Total abstract work per call
is therefore at most `limits.max_work + 2 * graph.limits().max_work`. Callers
that need a session-wide cap must also bound how many calls they make. Work
units are deterministic abstract operations, not time or bytes, and limits do
not bound allocator overhead.

## Complexity

Let `N` be nodes, `E` canonical edges, `V` variables, `S` raw statements, `O`
raw operands, `P` phis, `A` phi operands, `F` frontier entries, and `W` the
Cytron placement work, the sum over variables of frontier sizes of their
defining and phi blocks. `W` can approach `V * F` and is bounded by `max_work`
and `max_phis`. Logarithms mean `log(2 + size)`.

| Phase | Time | Additional space |
| --- | --- | --- |
| Validation | `O(N + V + S + O)` | `O(V)` |
| Dominators and frontiers (graph crate) | `O((N + E + F) log N)` | `O(N + F)` |
| Placement | `O(N + V + O + W)` | `O(N + V + O + P)` |
| Layout and renaming | `O(N + V + S + O + A + E log N)` | `O(N + V + O + P + A)` |
| Verification | `O(N + V + S + O + A + W + (O + A) log(O + A) + E log N)` | `O(N + V + O + A + F)` |

There is no recursion anywhere (a 100,000-node chain is tested), no dense
matrix, and no repeated ancestor scan.

## Evidence

Tests cover a diamond; a loop; nested loops with multiple latches; an entry
self-loop and a longer entry backedge with `Entry` operands; an irreducible
cycle with a critical edge; simultaneous definitions and repeated uses;
undefined-entry joins; unreachable nodes and predecessors; empty statements and
nodes; ownership; malformed IDs, block counts, and duplicate definitions; every
limit at its exact size and one below; work exhaustion at every budget until
success; separate graph-budget failure; a 100,000-node chain, loop, and entry
loop; and a 99,001-node ladder of 33,000 phis with phi, phi-operand, value, and
work exhaustion. Every constructed result is also verified.

An independent behavioral oracle generates 3,000 random small CFGs and
programs (random entries, self-loops, irreducible cycles, unreachable nodes,
both entry states) and executes 24 random bounded entry paths each, plus every
path of up to 13 nodes in a fixed irreducible graph whose entry is a loop
header. Each path runs the raw program on variables and the SSA program on
values, assigning all phis of a block simultaneously from the operand of the
edge taken. Every use and phi must observe the same dynamic definition event.
The oracle uses no dominance or renaming logic, and a sensitivity test shows it
rejects a stale phi. Unit tests corrupt verified results (stale dominating use,
non-dominating use, stale or swapped phi operands, wrong entry operand, missing
dead phi, broken origins, incoming order, arity, reachability, duplicate phi,
mismatched program) and check that `verify` reports the matching violation.

## Limitations

- No P-code integration: register aliasing, sub-register pieces, memory,
  indirect effects, calls, and ABI behavior are the caller's responsibility.
- Unpruned only: no liveness-pruned or semi-pruned mode and no dead-phi
  removal. No def-use chains, copy folding, or out-of-SSA translation.
- One immutable graph per result; no incremental update or re-heritage.
- Values are per whole variable; there is no partial-definition model.
