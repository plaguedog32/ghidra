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
