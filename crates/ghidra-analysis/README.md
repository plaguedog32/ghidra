# ghidra-analysis

Native P-code storage and SSA foundations. This crate partitions scalar storage,
tracks explicit operand and memory-state dependencies, and connects them to the
native CFG and generic SSA engine. It does not yet infer types, resolve ABIs or
emit decompiled code.

`StorageLayout::build(spaces, instructions, extra_registers, unique_scope, limits)`
constructs an immutable domain with dense `StorageId`s. Registers and unique
spaces are partitioned at every observed alias endpoint; gaps are not allocated.
Extra register aliases can add boundaries needed by a later ABI model. IDs are
deterministic by space, lifetime and physical byte offset, followed by RAM/other
memory states in space-ID order. Input instruction/operand order does not change
the domain. Source instructions are inspected without mutation or execution.

`bind(instruction_address, varnode)` returns a constant, a scalar binding, or a
fixed-offset access through a memory-state token. A scalar binding lists whole
cells in least-significant-first order with byte offsets into the original
value. These offsets use the scalar space's byte order; RAM order is independent.
`split` and `compose` convert concrete values between that representation and
complete cell values. Missing state is never invented as zero. A query that
would split an unobserved cell is rejected; include that alias when building
the domain. Partial register writes preserve the other cells. Architectural
rules such as x86 EAX zero-extension must already be present in lifted P-code.

```rust
use ghidra_analysis::{StorageLayout, StorageLimits, UniqueScope, ValueBinding};
use ghidra_pcode::{AddressSpace, Endianness, SpaceId, SpaceKind, Value, Varnode};
# fn main() -> Result<(), ghidra_analysis::StorageError> {
let register = AddressSpace { id: SpaceId(2), name: "register".into(),
    kind: SpaceKind::Register, address_size: 8, word_size: 1,
    endianness: Endianness::Little };
let wide = Varnode { space: SpaceId(2), offset: 0, size: 8 };
let low = Varnode { size: 1, ..wide };
let layout = StorageLayout::build(&[register], &[], &[wide, low],
    UniqueScope::Program, StorageLimits::default())?;
let ValueBinding::Scalar(binding) = layout.bind(0, wide)? else { unreachable!() };
assert_eq!(binding.pieces().iter().map(|p| p.size).collect::<Vec<_>>(), [1, 7]);
let pieces = binding.split(&Value::from_u64(8, 0x1234)?)?;
let values: Vec<_> = pieces.into_iter().map(|(_, value)| value).collect();
assert_eq!(binding.compose(&values)?.to_u64(), Some(0x1234));
# Ok(())
# }
```

`UniqueScope::Program` preserves the persistent unique-space model admitted by
explicit concrete P-code programs. `UniqueScope::Instruction` assigns a separate
lexical bank per native address. The layout alone does not implement dynamic
frame entry. `PcodeSsa` adds fresh undefined temporary definitions on native entry
and re-entry, while keeping internal relative branches in the same frame.

`operation(address, operation)` binds actual value operands and separates native
control labels, relative targets, space selectors, userop IDs and operation
references from data reads. RAM/other spaces use one abstract memory state each.
LOAD reads it; STORE and direct memory outputs read and define it, preserving
dependencies on bytes outside the write. This is a conservative whole-space
dependency model, not pointer disambiguation or a concrete memory implementation.
Memory pointer widths are checked against their target spaces. Word scaling is
retained in space metadata; physical varnode offsets are byte offsets.

`OperationBindings::def_use()` preserves ordered and repeated uses and returns
simultaneous definitions only when explicit effects are complete. It refuses
calls, userops, runtime operations, SSA-context operations and UNIMPLEMENTED
without an effect model. Indirect LOAD/STORE into register or unique spaces is
rejected until an alias model covers it. No ABI clobbers, operating-system effects,
type recovery, injection execution or architecture-specific semantics are guessed.

Construction bounds instruction, operation and operand-reference counts,
interval events, resulting variables and logical work. Input-count preflight
precedes operation validation and interval allocation. Work charges cover input
scans, map operations, sorting and the interval sweep; budgets may expire before
size limits. Resource exhaustion returns an error with no partial layout.
Ordinary Rust allocation failure is not caught; callers choose appropriate limits.
Space IDs, widths, ranges, output permissions and supported operand roles are
checked. CFG target/extent validation remains the CFG layer's responsibility.

For `R` operand/extra-alias references and `V` resulting variables, construction
uses `O(R log R)` time and `O(R + V + instruction_count)` extra storage. No matrix
or allocation is proportional to an address-space span. A scalar lookup is
`O(log V + pieces)`; pieces are bounded by the 512-byte value width. An operation
query is additionally bounded by its validated 1024-input limit. Callers must
bound repeated queries and total materialized bindings in their own analysis.

The overlap approach follows the byte-range/PIECE/SUBPIECE relationships described
by retained `heritage.cc` and `varnode.cc`; this is a native interval partition,
not a translation of Ghidra's entire heritage pass. Tests compare overlapping
128-byte aliases against the concrete machine for 400 writes and 49,200 reads in
both byte orders. They also cover the full 512-byte width, mixed RAM/register
endianness, explicit temporary scope, conservative memory dependencies, opaque
effects, metadata roles, bounds, gaps, final addresses and a 10,000-bank domain.

## P-code SSA

`PcodeSsa::new(Arc<Cfg>, extra_registers, options, limits)` owns the CFG, storage
layout, raw def/use program, renamed SSA and statement metadata. Choose
`AnalysisOptions::native()` for instruction-scoped temporaries or
`AnalysisOptions::pcode_program()` for the persistent unique-space model of the
concrete machine. Neither constructor assumes unknown operations are pure.

Register cells and abstract memory states are function inputs by default;
program-scoped uniques are undefined by default. `EntryPolicy` can change those
declarations. Instruction-local uniques always start undefined. An entry value
is a symbolic declaration, not initialized concrete memory.

```rust
use std::sync::Arc;
use ghidra_analysis::{AnalysisOptions, PcodeSsa};
use ghidra_cfg::{Cfg, CfgInput};
use ghidra_pcode::machine::ExecutionInput;
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let input: ExecutionInput = serde_json::from_str(
    include_str!("../../../examples/pcode/sum-loop.json"))?;
let cfg = Arc::new(Cfg::new(CfgInput::new(input.spaces, input.code_space,
    input.entry, input.instructions), Default::default())?);
let analysis = PcodeSsa::new(cfg, &[], AnalysisOptions::pcode_program(),
    Default::default())?;
analysis.ssa().verify(analysis.raw())?;
assert!(analysis.ssa().phi_count() > 0);
# Ok(())
# }
```

Original CFG block and terminal-exit node IDs are preserved. Native-entry edges
that need resets are split by appended synthetic nodes. `edge_reset(edge_id)`
exposes that path. Internal relative branches, including branches to op 0,
keep the current frame. Address changes inside a merged block insert resets
before that instruction's first point. A reset's `UndefinedTemporaries` metadata
means undefined fresh state, never zero. SSA definitions for resets must be
interpreted using that metadata; they are not ordinary computed assignments.

`statement_id(ProgramPoint)` and `statement(StatementId)` preserve the operation
source, no-op placeholders, operand bindings, and effect policy. Unreachable raw
statements retain metadata but have no renamed SSA statements. Each ordinary
explicit operation uses `OperationBindings::def_use()` order; writes to aliased
cells are simultaneous and occur after every input read. Memory-state tokens
are abstract dependencies, not scalar values suitable for integer evaluation.

`UnknownEffectPolicy::Reject` returns an error naming the point and effect class.
`HavocAll` reads every variable in the observed domain and defines fresh opaque
versions of all of them, including extra register aliases. Explicit reads are
listed first, followed by every domain variable in ID order; definitions use ID
order. The operation retains `AppliedEffects::Conservative(class)`. Its values
cannot be evaluated as pure opcode results. This is an overapproximation within
the observed domain, not ABI recovery or a claim to capture all machine state.
Adding storage later requires rebuilding the analysis. CFG call/no-return exits,
unresolved branches, and unknown userop control behavior remain as documented by
`ghidra-cfg`; selecting havoc does not resolve them.

Adapter limits bound nodes, semantic edge records, statements, materialized
bindings, raw use/definition references and work. The binding cap uses a
conservative byte-width bound before materialization, so it can reject inputs
with fewer actual alias pieces. All variable/frame/edge expansion is bounded;
there is no recursion or address-span allocation. Storage construction, graph
construction, and SSA each have separate finite budgets. SSA runs two graph
analyses with separate graph budgets, and an explicit `ssa().verify(raw())`
starts its own budgets. Ordinary Rust allocation failure is not caught.

Both `AnalysisOptions::native()` and `pcode_program()` use liveness-pruned SSA:
joins receive a phi only for storage that is live on entry. Native-entry resets
still define undefined temporary state; pruning does not extend a temporary's
lifetime. Callers can set `phi_placement = ghidra_ssa::PhiPlacement::Unpruned`
to retain the original construction. `ssa().placement()` reports the actual
mode. Sparse live-in pairs, phis and work have separate limits; exhaustion is
an error, without falling back to another mode. This adapter does not perform
constant propagation, pointer disambiguation, call resolution, type inference,
or out-of-SSA conversion. Processor-defined `SEGMENTOP` also requires an
explicit unknown-effect policy: its selector is metadata, and its injection
semantics are not guessed from the base/offset operands.

Adapter tests cover partial-register diamonds in both byte orders, memory-token
versions, opaque clobbers, native re-entry versus internal backedges, merged
instruction/no-op boundaries, unreachable metadata, entry policies, exact work
and count limits, a 10,000-instruction loop that fits a 100-phi cap with no dead
temporary phis while retaining all native-entry resets, and semantic comparison of renamed
aliases and loop phis against concrete machine traces.

## Expressions over SSA

`PcodeExpressions::new(Arc<PcodeSsa>, ExpressionLimits)` reconstructs typed
expression terms from a verified native analysis snapshot. It retains that
snapshot, so value identities, phi operands, control edges and opaque dependency
lists stay associated with their source. It owns its output and is `Send + Sync`.

```rust
use std::sync::Arc;
use ghidra_analysis::{AnalysisOptions, ExpressionDefinition, PcodeExpressions, PcodeSsa};
use ghidra_cfg::{Cfg, CfgInput, ProgramPoint};
use ghidra_pcode::machine::ExecutionInput;

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let input: ExecutionInput = serde_json::from_str(include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"), "/../../examples/pcode/alias-branch.json")))?;
let cfg = Arc::new(Cfg::new(CfgInput::new(input.spaces, input.code_space,
    input.entry, input.instructions), Default::default())?);
let analysis = Arc::new(PcodeSsa::new(cfg, &[], AnalysisOptions::native(), Default::default())?);
analysis.ssa().verify(analysis.raw())?;
let terms = PcodeExpressions::new(analysis.clone(), Default::default())?;
let source = analysis.cfg().points()[0];
let statement = analysis.statement_id(ProgramPoint::new(source.address, source.operation_index)).unwrap();
assert!(terms.operation(statement).is_some());
for value in analysis.ssa().statement(statement)?.defs() {
    assert!(matches!(terms.definition(*value)?, ExpressionDefinition::Expression(_)));
}
# Ok(())
# }
```

Bit vectors and whole-space memory states have separate `ExpressionType`s.
Scalar reads compose the exact SSA cells in significance order; writes extract
the appropriate byte slices from the full operation result. Partial writes do
not read or overwrite unmentioned cells. Direct memory varnodes retain **byte
offsets**; LOAD/STORE pointers retain their address width and word scaling.
Each memory read/write names the exact prior SSA memory version and the byte
order of its own space, including mixed data/register byte orders.

Arithmetic/logic terms retain their P-code opcode and widths. They are not
evaluated or folded here: potentially trapping operations such as division by
zero remain explicit. Control labels, selectors, userop IDs and numeric
metadata retain distinct operand roles. A direct label is never a memory read.
An explicit operation's `output` is its complete bit result before splitting
aliases or updating memory; stores and control operations have none.

Each SSA value's `definition()` is an entry declaration, phi identity,
expression root, undefined instruction reset, or opaque statement output.
Phi inputs and full-domain havoc uses are shared from the original SSA rather
than copied or approximated. Opaque output definitions name their source
statement and definition slot; `operation().output` is `None` for these. Resets
remain undefined, never literal zero. Unreachable statements have no expression
operations, and no-op/reset statements remain available in the original snapshot.

Expression-node edges point to earlier nodes; SSA leaves can refer to cyclic
definitions without expanding them. Construction is iterative, with no
per-value scan of the program. It makes linear passes over values, graph nodes,
reachable statements and operand pieces, with logarithmic address-space,
per-operation write and source-instruction lookups. Source lookup costs
`O(S log I)` for `S` reachable operations and `I` supplied instructions; term
storage stays linear in the visited records and pieces. This does not perform pointer disambiguation,
calling-convention recovery, value propagation, type inference or C generation.

Separate limits bound graph nodes, SSA values, reachable statements, expression
nodes, stored references, literal bytes and reconstruction work. Count/overflow
checks precede protected growth. Literal bytes count each owned literal's
declared width, including repeats. References count operation operand slots,
node edges (including SSA leaves and memory versions), operation result/memory
version slots, and expression-definition roots; shared phi/opaque operands
stay charged to the upstream SSA budget. Work charges allocation slots,
visited records, references, literal bytes and logarithmic map operations.
`reference_count()`, `constant_bytes()` and `build_work()` expose the totals.
Running out returns an explicit error, with no partial result or fallback.
Ordinary Rust allocation failure is not caught.

Behavior tests compare reconstructed terms with the native concrete Machine
after every defined scalar/memory result in 400 generated programs, across both
byte orders and all four word sizes. They also cover 512-byte aliases, metadata
roles, opaque dependencies, undefined resets, phi cycles, exact limits,
deterministic IDs and 25k/50k straight-line scaling. The arithmetic evaluator
itself is shared with the already-tested P-code core; these tests establish the
reconstruction's binding and state semantics, not a fresh arithmetic proof.

## Sparse conditional constant propagation

`PcodeConstants::new(Arc<PcodeExpressions>, ConstantLimits)` runs classic
whole-value SCCP over a verified expression snapshot and its owned `PcodeSsa`.
It returns owned immutable facts: one lattice element per SSA value and per
expression term, plus executable graph nodes and feasible edges. It never
rewrites terms, removes operations, executes target code or falls back to a
weaker result. It is `Send + Sync`.

```rust
use std::sync::Arc;
use ghidra_analysis::{AnalysisOptions, ConstantFact, PcodeConstants, PcodeExpressions, PcodeSsa};
use ghidra_cfg::{Cfg, CfgInput, ProgramPoint};
use ghidra_pcode::machine::ExecutionInput;

# fn example() -> Result<(), Box<dyn std::error::Error>> {
let input: ExecutionInput = serde_json::from_str(include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"), "/../../examples/pcode/sum-loop.json")))?;
let cfg = Arc::new(Cfg::new(CfgInput::new(input.spaces, input.code_space,
    input.entry, input.instructions), Default::default())?);
let analysis = Arc::new(PcodeSsa::new(cfg, &[], AnalysisOptions::pcode_program(),
    Default::default())?);
let terms = Arc::new(PcodeExpressions::new(analysis.clone(), Default::default())?);
let facts = PcodeConstants::new(terms, Default::default())?;
// `COPY r0, 0` before the loop is constant.
let first = analysis.statement_id(ProgramPoint::new(0x1000, 0)).unwrap();
let zero = analysis.ssa().statement(first)?.defs()[0];
assert_eq!(facts.value(zero)?.constant().and_then(|v| v.to_u64()), Some(0));
// The loop phis meet constants with their updates: not single constants.
let mut phis = 0;
for node in facts.executable_nodes() {
    for phi in analysis.ssa().block(node)?.renamed().unwrap().phis() {
        assert_eq!(facts.value(phi.value())?, ConstantFact::Unknown);
        phis += 1;
    }
}
assert!(phis > 0);
// The fixed conservative policy is reported with the facts.
let policy = facts.policy();
assert!(policy.prunes_constant_branches && !policy.models_memory);
# Ok(())
# }
# example().unwrap();
```

**Lattice.** `ConstantFact` is `Unreached < Constant(value) < Unknown`; two
different constants meet to `Unknown`. `Unreached` (bottom) only means that
no executable definition was found; it is never used for unknown state. Every
entry value (`EntryState::Input` and `EntryState::Undefined`), native-entry or
merged-instruction reset definition, opaque havoc output, memory-state value,
LOAD and fixed-offset memory read is `Unknown` as soon as it executes.
Undefined state is never treated optimistically and never becomes zero, so a
phi meeting an undefined path with `5` is `Unknown`. Memory contents are not
modeled: a load after a constant store is `Unknown`. Constants keep their
exact declared width, 1 to 512 bytes.

**Transfer functions.** A literal, including SUBPIECE/INSERT/ZPULL/SPULL/
PTRADD metadata, is its constant. A join, extract or pure operation is
`Unknown` if any input is `Unknown`, `Unreached` if any remaining input is
`Unreached`, and otherwise evaluated exactly. Joins compose pieces by value
significance and extracts slice by least-significant byte offset,
independently of memory byte order. Pure operations use
`ghidra_pcode::evaluate_pure`; `COPY` and same-width `CAST` share their
input's constant. When evaluation fails (division by zero, an unsupported
opcode or float format, invalid operands), the result is `Unknown` and an
`EvaluationFault` names the statement, term, opcode and error. Only faults
whose inputs are still constant at the fixpoint are reported; one seen in an
optimistic intermediate state, such as a loop divisor that is 0 until the
backedge raises it, is not. The term is unchanged and control flow is not cut:
the CFG has no trap edges, so every outcome of the block stays feasible. No
algebraic identities with unknown operands (`x * 0`, `x ^ x`) are applied and
partially known bytes are not tracked, so a value whose pieces are only partly
constant is `Unknown` as a whole.

**Feasibility.** The entry node is executable through the virtual entry edge.
A CFG block's semantic out-edges follow their `ghidra-cfg` roles. A
block-ending CBRANCH with a constant condition enables only its taken outcome
(nonzero is true, as in the concrete machine), read from the condition's full
operand binding, joined across aliases. An `Unknown` condition enables both,
and an `Unreached` one neither until it rises (on SSA built by `PcodeSsa` an
executed use is dominated by an executed definition, so this does not occur
at the fixpoint). Every other role is enabled when its block executes:
fallthrough, BRANCH, both `CallReturn` and `CallNoReturn` outcomes of every
call, RETURN, the unresolved `IndirectBranch` exit and UNIMPLEMENTED. Constant
BRANCHIND/CALLIND targets are reported as term facts but never become new
edges, and userops keep the CFG's fallthrough. Each semantic edge maps to the
augmented SSA graph through
`PcodeSsa::edge_reset`: an edge split by a reset node enables `from -> reset`,
and the reset's single `reset -> to` edge is enabled when the reset executes.
Several semantic edges (for example CBRANCH true and false to the same point,
or a relative and a native self-branch) can share one distinct graph edge; it
is feasible if any of them is. Relative branches, including to operation 0,
have no reset node and keep their instruction's temporaries. Phis meet only
operands whose incoming edge is feasible, including the virtual entry operand
and backedges that become feasible later. Feasibility is relative to the
supplied CFG, which may omit unresolved indirect targets; it is not a claim
about complete machine control flow.

**Queries.** `value(ValueId)` and `expression(ExpressionId)` return facts. An
SSA leaf term has its value's fact; any other term is `Unreached` unless its
statement executed. An executed statement gives a fact to every operand term,
including memory addresses and stored values. `constants()` lists all constant
values. `is_node_executable`, `executable_nodes`, `is_statement_executable`,
`is_edge_executable(from, to)` (distinct augmented graph edges),
`is_cfg_edge_feasible(EdgeId)` and `feasible_cfg_edges` (semantic edges, first
hop) expose flow facts. `faults()` lists fixpoint evaluation faults, `stats()`
the counters below, `limits()` the limits used and `policy()` the fixed
conservative choices (`ConstantPolicy`) with the snapshot's `AnalysisOptions`.
The result owns its `Arc<PcodeExpressions>` and is the least fixpoint of
these monotone transfer functions, so it does not depend on worklist order and
is identical for equal inputs.

**Algorithm and complexity.** The pass builds a `ghidra_ssa::DefUseIndex`
and keeps two FIFO worklists, newly feasible graph edges and raised values.
Both deduplicate: an edge is queued once, and a value only when its lattice
level rises, at most twice. A newly executable node folds its phis over
feasible operands and executes its statements once. Each executed statement
gets a plan: its needed terms in ascending ID (topological) order with child,
parent, SSA-leaf and definition-root links. A raised value notifies only its
use sites from the index; a statement updates only the affected leaf and
propagates upward through parent links. Computations count unreached children
and are evaluated at most once, when the last one becomes constant. A newly
feasible edge folds one operand per phi at its target. There is no recursion,
no dense value-by-node structure and no rescan of a program, statement or
expression prefix per value. With `V` values, `N` graph nodes, `E` graph
edges, `C` semantic edges, `T` plan terms and links of executed statements,
`U` def-use records and `A` phi operands, work is
`O(V + N + (E + C) log E + T log T + U + A)` plus the evaluation cost below.

**Accounting.** `ConstantLimits` caps graph nodes, distinct graph edges,
semantic CFG edges, values, reachable statements and expression nodes before
allocation. Plan records (terms, child links, parent links, leaf and root
records), pending entries in the global worklists and in each statement-local
traversal or propagation stack, and owned evaluated constant bytes are checked
before each growth. Literal payloads and COPY/CAST results are shared, not
counted again. The evaluator takes a contiguous `[Value]` slice, so each
evaluation clones its constant inputs; these transient copies are charged as
work and dropped after the call, and only the result is retained and counted
as bytes. `max_work` is one deterministic budget: every record visited costs
at least one unit, binary searches cost `floor(log2 n) + 2`, sorts
`n (ceil(log2 n) + 1)`, constant comparisons one unit per 64-bit word, and
joins/extracts their byte widths. Each `evaluate_pure` call is charged before
it runs: `4 + 2 * (input + output words)`, plus the product of the operand
word counts (+1 each) for multiplication, twice that for division and
remainder, and a fixed float term with an extra quadratic term for INT2FLOAT.
The nested def-use index runs under `ConstantLimits::def_use` with its own
budget, so aggregate work is at most `max_work + def_use.max_work`. `stats()`
reports both separately with executable/feasible counts, plan records, queue
peak, phi folds, notifications, evaluations, faults and fact totals.
Exhaustion returns `ConstantError::Limit` with no partial result or
all-unknown fallback. Ordinary Rust allocation failure is not caught.
Malformed input, such as a shared non-leaf term, a CBRANCH that does not end
its block, a decreasing fact or two different constants for one value at the
same lattice level, is reported as `ConstantError::Inconsistent`.

**Limitations.** This is a library dataflow stage; no CLI or desktop view
uses it yet. Facts are whole values: no ranges, known bits or partially known
aliases, and no algebraic identities. Memory is not modeled at all, so stores
never reach loads, and calls, userops and other opaque effects have no
summaries. Indirect targets are never resolved, so feasibility is relative to
the supplied CFG. Faults never cut control, so code after a definite trap
stays feasible. The pass requires statement-local non-leaf terms, as
`PcodeExpressions` builds them. It performs no pointer disambiguation, ABI or
calling-convention modeling, simplification, rewriting or code generation.

Tests compare every value, term, node, graph edge, semantic edge and fault
with an independent dense round-robin reference fixpoint, and check facts
against the concrete `Machine` after every executed operation and at every
block entry for generated branching and looping programs in both byte orders,
both temporary scopes and both phi placements. Every reference comparison
also checks bounds derived from the SSA shape alone: each statement executes
once, notifications stay within twice the def-use statement records and phi
folds within four times the phi operands. Targeted tests cover equal and
conflicting diamonds, dead branches, undefined incoming paths, entry
self-loops and entry backedges through native reset nodes, optimistic loop
invariants, delayed backedge feasibility, joins that must refold on a late
value or a late edge, irreducible cycles, temporary resets against relative
branches, duplicate semantic and reset edges, repeated uses and repeated phi
operands, aliases, memory and opaque conservatism, calls that clobber branch
inputs, indirect control, metadata roles with hand-computed results, odd and
512-byte widths, fixpoint and transient faults, exact and one-below limits
(including the nested def-use limits) and linear chain, loop and fan-out
scaling. The pure arithmetic evaluator is shared with the P-code core and is
not re-proven here; these tests establish binding, lattice and control
semantics.
