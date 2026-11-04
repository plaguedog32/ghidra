# ghidra-ssa

A native Rust engine that builds and verifies generic SSA form over a
`ghidra_graph::Graph`. Rust 1.88, edition 2024, Apache-2.0, version 0.3.0. The
only dependency is `ghidra-graph`. No Java or C++ process or runtime is used.

This crate is **only** the SSA construction engine plus an owned def-use
index over its results ([Def-use index](#def-use-index)). It is not a P-code
adapter, alias analysis, memory SSA, call or ABI model, liveness API, type
inference, optimizer, or decompiler. It computes liveness internally only to
prune phis when asked. It has no opcode knowledge: callers
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

`Ssa::construct(graph: Arc<Graph>, entry: NodeId, program: &RawProgram, limits: Limits)`
builds unpruned SSA. `Ssa::construct_pruned` takes the same arguments and
builds liveness-pruned SSA, and `Ssa::construct_with(.., placement:
PhiPlacement)` selects the mode explicitly (see [Phi placement
modes](#phi-placement-modes)). All three share this contract.

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
| `placement()` | `PhiPlacement::Unpruned` or `PhiPlacement::Pruned`, as constructed |
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
   per variable, not a whole-graph fixed point. When pruned, a frontier member
   where the variable is not live on entry gets no phi and is not added to
   the worklist (liveness is described under [Phi placement
   modes](#phi-placement-modes)).
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

## Phi placement modes

`PhiPlacement::Unpruned` (the default, built by `Ssa::construct`) places a phi
at every block of each variable's iterated dominance frontier, so dead phis can
exist. `PhiPlacement::Pruned` (built by `Ssa::construct_pruned`) places a phi
only where its variable is also **live on entry**: some path from the start of
that block reaches a read of the variable before any raw statement writes it.
Both modes use the same validation, dominators, frontiers, layout, renaming,
value numbering, and verifier; only the phi set differs. Pruning is opt-in, and
`Ssa::construct` is unchanged.

```rust
use std::sync::Arc;

use ghidra_graph::{Graph, Limits as GraphLimits};
use ghidra_ssa::{EntryState, Limits, PhiPlacement, RawProgram, RawStatement, Ssa, VariableId};

# fn main() -> Result<(), ghidra_ssa::Error> {
let (i, t) = (VariableId(0), VariableId(1));
// Loop 0 -> 1 -> 1: i is carried around the loop; t is written before it is read.
let graph = Arc::new(Graph::new(2, [(0, 1), (1, 1)], GraphLimits::default())?);
let program = RawProgram {
    variables: vec![EntryState::Input, EntryState::Undefined],
    blocks: vec![
        vec![RawStatement::new([], [i])],
        vec![
            RawStatement::new([i], [i]),
            RawStatement::new([], [t]),
            RawStatement::new([t], []),
        ],
    ],
};
let unpruned = Ssa::construct(Arc::clone(&graph), 0, &program, Limits::default())?;
let pruned = Ssa::construct_pruned(graph, 0, &program, Limits::default())?;
pruned.verify(&program)?;
assert_eq!(unpruned.phi_count(), 2); // i and a dead phi of t
assert_eq!(pruned.phi_count(), 1); // only i
assert_eq!(pruned.placement(), PhiPlacement::Pruned);
# Ok(())
# }
```

**Liveness** is computed from the raw program over reachable blocks and edges
only. A block's *exposed* variables are those it reads before writing (a
statement's uses come before its own defs, so `uses: [x], defs: [x]` exposes
`x`). Two counting passes build a compressed per-variable list of exposed
blocks, as for defining blocks. A variable is live on entry to a block iff a
backward walk along reachable predecessors from one of its exposed blocks
reaches it without entering a block that writes the variable. Unreachable
predecessors and their reads never contribute, and the virtual entry edge has
no block to walk into. Each variable is walked with an explicit stack (no
recursion), and two node-sized marker arrays are stamped with the variable
index, so there is no `variables * nodes` matrix and no per-block scan of all
variables.

**Laziness.** A variable's liveness is computed only when its placement
worklist meets its first frontier candidate. Variables whose definitions have
an empty dominance frontier (including variables that are never written)
cannot need a phi and cost no liveness work, however widely they are read.

**Why skipping dead blocks is exact.** The pruned set equals the iterated
dominance frontier of the variable's defining blocks intersected with its
live-in blocks, even though dead frontier blocks are not propagated. Suppose
`G` is a live frontier member of a dead block `Y` (not live, not defining).
Take a path from the last visit of `Y` through `G` to a read with no write
after `G`. Because `Y` is dead, the path writes the variable between `Y` and
`G`; let `D` be the last block that does, which `Y` dominates. The first later
block on the path that `D` does not strictly dominate is in `D`'s frontier, is
live (no writes follow it before the read), and is either `G` or a block that
`Y` dominates, which therefore cannot strictly dominate `G`. Repeating the step
from that new phi block reaches `G` through live blocks only. This is the same
live-in restriction LLVM's IDF calculator applies.

## Policies

- **Placement.** Unpruned by default; pruned only on request (see above). No
  copy propagation, dead-code removal, or type reasoning is performed in
  either mode.
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
6. **Phi completeness** for the stored `placement()`, using one `frontiers()`
   call. *Unpruned*: for every block that defines a variable or has its phi,
   every member of its dominance frontier has a phi for that variable; extra
   phis are not rejected. *Pruned*: the verifier first recomputes liveness from
   the raw program on its own. It collects exposed reads and writes of
   reachable blocks as (variable, node) pairs, sorts them, and floods each
   variable backward with its own marker arrays; it reads no construction
   tables. Then, per variable in ascending order, every phi must be at a block
   where its variable is live on entry (`DeadPhi`), and every live frontier
   member of a defining or phi block must have a phi (`MissingPhi`). Extra
   live phis are not rejected. A flipped mode fails: unpruned output claiming
   `Pruned` has dead phis, and pruned output claiming `Unpruned` misses them.

Together, 4 to 6 are the standard conditions under which every use observes the
most recent raw definition along every entry path. In pruned mode this still
holds for every read and every phi operand: if the last definition on a path
did not dominate a read, the first block after it that it does not strictly
dominate would be a live frontier member, so the closure in 6 would put a phi
there. Verification spends its own fresh `max_work` budget, its own
`max_live_ins` count, and two graph analysis budgets. It can therefore fail
with a limit error even when construction just fit.

## Def-use index

`DefUseIndex::new(&ssa, DefUseLimits)` builds an owned index from every SSA
value to every operand that reads it. It is the use side of the def-use
relation; the definition side is `Ssa::value(id).origin`. It is groundwork for
sparse simplification and out-of-SSA translation, neither of which exists yet.

```rust
use std::sync::Arc;

use ghidra_graph::{Graph, Limits as GraphLimits};
use ghidra_ssa::{
    DefUseIndex, DefUseLimits, EntryState, Limits, Predecessor, RawProgram, RawStatement, Ssa,
    VariableId,
};

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let x = VariableId(0);
// Entry self-loop 0 -> 0 that reads x twice and then rewrites it.
let graph = Arc::new(Graph::new(1, [(0, 0)], GraphLimits::default())?);
let program = RawProgram {
    variables: vec![EntryState::Undefined],
    blocks: vec![vec![RawStatement::new([x, x], [x])]],
};
let ssa = Ssa::construct_pruned(graph, 0, &program, Limits::default())?;
let index = DefUseIndex::new(&ssa, DefUseLimits::default())?;

let entry = ssa.entry_value(x)?;
let block = ssa.block(0)?.renamed().expect("reachable");
let (_, phi) = block.phi_for(x).expect("loop phi");
// The undefined entry value is read only by the phi, along the virtual entry edge.
let [site] = index.phi_uses(entry)? else { panic!() };
assert_eq!(block.incoming()[site.operand], Predecessor::Entry);
// Both read slots of the statement are separate uses of the phi.
let slots: Vec<_> = index.statement_uses(phi.value())?.iter().map(|u| u.slot).collect();
assert_eq!(slots, [0, 1]);
assert_eq!(index.total_uses(), 4);
# Ok(())
# }
```

**Contents.** For each `ValueId`, `statement_uses(v)` lists every renamed
statement operand slot (`UseSite`) and `phi_uses(v)` every phi operand slot
(`PhiOperandSite`) that holds `v`; `use_count(v)` is their sum. Repeated
operands are separate entries: a statement reading `v` in two slots gives two
`UseSite`s, and a phi with `v` on two edges gives two `PhiOperandSite`s. Phi
operands along the virtual `Predecessor::Entry` edge are included (map
`operand` through `RenamedBlock::incoming()`). Unreachable blocks have no
renamed statements or phis, so their raw statements contribute nothing. In
unpruned SSA a dead phi may have no uses or feed only other dead phis; its
operands are still uses of their values. In constructed pruned SSA every phi reaches some statement read
through phis (tested on the generated corpus below).

**Order.** Each `statement_uses(v)` row is strictly ascending in `UseSite`'s
derived order (node, statement index, slot); each `phi_uses(v)` row strictly
ascending in `PhiOperandSite`'s derived order (node, phi index, operand). Equal
SSA results give equal indexes.

**Ownership and snapshot.** The index owns all its data and borrows nothing,
so it is `Send + Sync`, `Clone`, and outlives the `Ssa`. It describes exactly
the `Ssa` it was built from (or an equal clone) and keeps no link to it: it
cannot detect being paired with a different result, whose answers would be
meaningless but memory-safe. `value_count()`, `node_count()`, and
`placement()` record the source shape for cheap sanity checks. A lookup
outside `0..value_count()` returns `DefUseError::InvalidValue`, never panics.

**Storage.** Compressed sparse rows: two offset arrays of `V + 1` entries and
two flat site arrays with one record per operand reference (`U` statement uses
and `A` phi operands over reachable blocks). Building is two linear passes over
reachable blocks: count per value, prefix sums, then fill in reverse so each
row comes out ascending without a cursor array. There is no recursion, graph
analysis, per-value rescan, hashing, sorting, or `variables * nodes` structure.

**Limits and work.** `DefUseLimits` has its own `max_values` (checked before
the offset arrays are allocated), `max_uses` (`U + A`, accounted per statement
and phi during counting, so the site arrays are only allocated once the total
fits), and a fresh `max_work` budget per call. Every count is
overflow-checked. Any failure is `DefUseError::LimitExceeded { resource }`
with no partial index; construction limits and `Ssa::work()` are not touched.
`work()` is exactly `2 + 4V + 2N + 2P + 2S + 3U + 3A` (offset arrays, two
passes over `N` nodes, `P` phis, `S` reachable statements and their operands,
two prefix sums, and site allocation), and `total_uses()`,
`total_statement_uses()`, and `total_phi_uses()` expose the stored record
counts. Time and space are `O(V + N + P + S + U + A)`.

## Limits and failure

`Limits` (with practical defaults) bounds `max_variables`, `max_statements`
(raw, all nodes), `max_operands` (raw use + def references, all nodes),
`max_values`, `max_phis`, `max_phi_operands` (sum of phi arities),
`max_live_ins`, and `max_work`. Every count is checked with overflow-checked
arithmetic **before** the corresponding output grows: statement and operand
totals before a block or statement is scanned, phis, phi operands, and values
before each phi is recorded, and each live-in pair before it is marked or
pushed on a liveness stack. Any failure is `Error::LimitExceeded { resource }`
with no partial result; inputs and earlier results are never mutated. In
particular, running out of live-in pairs or work during pruned placement is
an error (`Resource::LiveIns` or `Resource::Work`), never a silently omitted
phi or a fallback to unpruned placement.

`max_live_ins` bounds the (reachable block, variable) live-in pairs computed
in one pruned construction or pruned verification. Only variables whose
definitions have a non-empty dominance frontier are counted (see laziness
above), so the count is at most `V * N` and usually far less. Unpruned calls
never compute liveness and ignore this limit.

**Aggregate work.** `max_work` is a fresh budget for each construction
(`construct`, `construct_pruned`, or `construct_with`) or `verify` call. It is
charged for validation, every pass, edge and predecessor scan, binary search,
frontier entry scanned, phi operand filled, undo restore, liveness seed and
pushed block, and sort (precharged as `n * (ceil(log2 n) + 1)`). Each such call
also makes exactly two nested graph calls, `Graph::dominators` and
`Dominators::frontiers`, in both modes. Each runs with its own fresh
`graph.limits().max_work` budget and the graph's frontier-entry limit, and its
failures surface as `Error::Graph`. Liveness only reads
`Graph::predecessors`, an unbudgeted slice accessor, and starts no further
graph analysis. Total abstract work per call is therefore at most
`limits.max_work + 2 * graph.limits().max_work`, whatever the mode. Callers
that need a session-wide cap must also bound how many calls they make (for
example, construct and verify are two calls). Work units are deterministic
abstract operations, not time or bytes, and limits do not bound allocator
overhead.

## Complexity

Let `N` be nodes, `E` canonical edges, `V` variables, `S` raw statements, `O`
raw operands, `P` phis, `A` phi operands, `F` frontier entries, and `W` the
Cytron placement work, the sum over variables of frontier sizes of their
defining and phi blocks. `W` can approach `V * F` and is bounded by `max_work`
and `max_phis`. For pruned placement, `L` is the live-in pairs computed and
`R` the liveness walk work, the sum over those pairs of the block's in-degree
(`R <= L + E` per flooded variable). `L` and `R` are bounded by `max_live_ins`
and `max_work`, and pruned `W` only propagates through live blocks.
Logarithms mean `log(2 + size)`.

| Phase | Time | Additional space |
| --- | --- | --- |
| Validation | `O(N + V + S + O)` | `O(V)` |
| Dominators and frontiers (graph crate) | `O((N + E + F) log N)` | `O(N + F)` |
| Placement, unpruned | `O(N + V + O + W)` | `O(N + V + O + P)` |
| Placement, pruned (adds liveness) | `O(N + V + S + O + W + L + R)` | `O(N + V + O + P)` |
| Layout and renaming | `O(N + V + S + O + A + E log N)` | `O(N + V + O + P + A)` |
| Verification, unpruned | `O(N + V + S + O + A + W + (O + A) log(O + A) + E log N)` | `O(N + V + O + A + F)` |
| Verification, pruned (adds) | `O(S + O log O + P log P + W + L + R)` | `O(N + O + P)` |

There is no recursion anywhere (a 100,000-node chain is tested), no dense
matrix, and no repeated ancestor scan. Liveness keeps only node-sized markers,
a node-sized stack, and the compressed exposed-block lists; live-in pairs are
counted, not stored.

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

**Pruned placement.** A second oracle builds both modes for 4,000 random cases
and compares every reachable block's phi set exactly against a naive
reference. The reference takes dominance by node removal, frontiers from their
definition, liveness by round-robin dataflow, and the iterated frontier by
fixed point, using neither the graph crate nor any crate code. The unpruned set
must equal the iterated frontier, and the pruned set must equal it intersected
with live-in. About 4,600 of 15,500 unpruned phis are pruned, about 2,700
pruned phis sit at entry nodes, and more than 700,000 dynamic reads on 16
random paths per case are checked against raw execution. The fixed irreducible
entry-loop graph is path-checked exhaustively in both modes.

Hand-checked tests cover live and dead joins in a diamond; an undefined entry
value kept as a live join operand; an entry self-loop and an entry backedge
(phi with its `Entry` operand only when live); an irreducible cycle whose
edges are all critical; simultaneous swaps and writes before reads;
never-read variables; unreachable predecessors and still-validated unreachable
statements; `construct` and `construct_with(Unpruned)` giving identical
results (including work); and pruned output equal to unpruned when every phi
is live. Every limit, including `max_live_ins`, is tested at its exact size and
one below, along with work exhaustion at every budget until construction plus
verification fit, and separate graph-budget failure.

A 100,000-node loop gives each node its own temporary that is written before
it is read, the shape the P-code adapter produces for instruction-local
temporaries. Unpruned construction fails there with a 100-phi cap, while pruned
construction keeps only the two live loop phis (a header counter and an
accumulator updated halfway round), with checked operands. Its work is
`75 * N` plus a constant (unpruned is `64 * N`), the test asserts that doubling
the loop at most doubles the work, and its exact 199,998 live-in pairs are
tested at and one below the limit. A 10,000-node version of the same shape
also fits the 100-phi cap.

Verifier unit tests on pruned results check that it rejects a live phi removed
while its uses read the nearest dominating definition (diamond join and loop
header, `MissingPhi`); a stale dominating phi operand or use; corrupt phi
origins and variables; dead phis (`DeadPhi`, by claiming that unpruned output
is pruned); a pruned result claiming `Unpruned`; and its own live-in and work
exhaustion. Disabling the construction's kill check, its backward walk, or its
write-before-read rule, or the verifier's kill check, dead-phi check, or
liveness test, each fails tests. The verifier alone rejects the result of the
under-live construction bug.

**Def-use index.** Every index built in the tests is compared against a
reference built only from public `Ssa` accessors (one sorted site set per
value), including its exact documented work. Hand-checked tests cover a value
on two edges of one phi and read twice in one statement, edge identities of
every phi operand, an undefined entry value read directly and through a phi,
an entry self-loop and entry backedge with `Entry` operands, an irreducible
cycle with critical edges, unreachable statements and predecessors, dead
unpruned phis versus pruned output, invalid and zero-value lookups, and
ownership after dropping the `Ssa`. Each of `max_values`, `max_uses`, and
`max_work` is tested exact and one below, every smaller work budget fails,
and the value cap fails before any work. A 100,000-node pruned loop
(200,004 values, 300,002 uses) has the exact formula work, at most twice the
50,000-node work. 1,500 generated cases in both modes (about 53,500 sites,
1,800 dead unpruned phis, 2,500 entry-node phis) are checked against the
reference and against a worklist over SSA operand lists that must agree with a
round-robin over the index on which phis are transitively used; in pruned mode
all are. Reversing the fill order of statement slots, or misnumbering phi
entry operands, fails tests.

## Limitations

- No P-code integration: register aliasing, sub-register pieces, memory,
  indirect effects, calls, and ABI behavior are the caller's responsibility.
  The native P-code adapter in `ghidra-analysis` selects pruned placement through
  `construct_with` by default; callers can explicitly select unpruned placement.
- Pruning is all-or-nothing per call: there is no semi-pruned mode, no
  dead-phi removal pass over an existing result, and no public liveness
  query. Extra live phis are accepted by verification.
- The def-use index is a read-only snapshot: no incremental update as
  values are rewritten, no copy folding, expression simplification, or
  out-of-SSA translation yet, and no check that it is paired with its own
  `Ssa`. It is not used by `ghidra-analysis` yet.
- One immutable graph per result; no incremental update or re-heritage.
- Values are per whole variable; there is no partial-definition model.
