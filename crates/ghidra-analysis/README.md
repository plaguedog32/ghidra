# ghidra-analysis

Native P-code storage foundations for the forthcoming CFG/SSA adapter. This
crate currently partitions scalar storage and describes explicit operand and
memory-state dependencies. It does not yet construct SSA or emit decompiled code.

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
lexical bank per native address. The latter does **not** implement dynamic frame
entry by itself: a CFG adapter must model fresh temporary state on native entry
and re-entry, while keeping internal relative P-code branches in the same frame.

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
