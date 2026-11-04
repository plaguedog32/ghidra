# Native compiler storage

This crate resolves compiler-spec storage declarations against actual language
registers and address spaces. It keeps signed stack addresses, register aliases
and join significance explicit. It is a native Rust layer and uses no Java or
Ghidra C++ process.

Whole-signature allocation, prototype-rule evaluation, injection compilation and
type recovery remain separate stages. Resource-group planning and placement in
an explicitly selected pool are described below. Successful
storage resolution does not mean that a calling convention is executable.

## API and ownership

`RegisterFile::new(spaces, default_space, registers, limits)` owns an immutable
physical register layout, including named registers in RAM-type spaces.
Overlapping aliases are permitted; exact duplicate
register names, invalid spaces and overflowing extents are errors. Register IDs
retain input order. Name lookup follows Ghidra's exact/lower/upper spelling
policy for ASCII identifiers, with later case-variation collisions winning.
Other Unicode case folding and additional processor-spec register aliases are
not synthesized. Large declarative registers are permitted; this does not
extend the concrete P-code evaluator's maximum value width.

`CompilerStorage::new(Arc<CompilerSpec>, Arc<RegisterFile>, limits)` creates an
owned resolution overlay while sharing its inputs. `BindingSite` identifies
the original model/list index, so input/output pools, return locations,
unaffected/killed registers and other declarations remain attributable to the
source. Range, space-base and dead-code-delay declarations are resolved too.
`return_addresses(model)` applies the spec-level fallback; an explicit empty
model return list suppresses it. Queries borrow existing data and do not
allocate. The types are usable across threads without a compiled SLEIGH object.

`resolve_storage` resolves an individual declaration without a compiler model:

```rust
use ghidra_abi::{RegisterFile, ResolvedStorage, resolve_storage};
use ghidra_languages::Storage;
use ghidra_pcode::{AddressSpace, Endianness, SpaceId, SpaceKind};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let ram = AddressSpace { id: SpaceId(1), name: "ram".into(),
    kind: SpaceKind::Ram, address_size: 4, word_size: 1,
    endianness: Endianness::Little };
let file = RegisterFile::new(vec![ram], SpaceId(1), vec![], Default::default())?;
let declaration = Storage::Address { space: "stack".into(),
    offset: (-4_i64) as u64, size: Some(4) };
let resolved = resolve_storage(&file, None, &declaration, None, Default::default())?;
let ResolvedStorage::Single(range) = resolved else { unreachable!() };
assert_eq!(range.address.signed_stack_offset(), Some(-4));
# Ok(())
# }
```

## Address and storage policies

- Language spaces retain their actual IDs. Compiler-only `Stack` and `Other`
  use distinct enum variants, never invented colliding numeric IDs. Numeric
  join-space locations are rejected without a join record.
- Offsets are **bytes**, including in word-addressed spaces. Stack width is
  the smaller of the pointer register width and backing-space width; its unit
  size comes from the backing space. Without a stack pointer, the default
  language space supplies those properties. Stack domains wider than 64 byte
  address bits are rejected.
- Stack offsets use signed, sign-extended Java-long bits. Narrow unsigned
  spaces normalize accepted negative Java-long offsets as Ghidra does;
  arbitrary out-of-range offsets are rejected rather than blindly masked.
  Fully sized physical extents must also fit, which is stricter than Ghidra's
  first-address-only validation in some parameter declarations. Literals in
  constant space are values, not memory extents.
- An unsized address stays unsized. A parameter pool's `max_size` is capacity,
  not a concrete allocated argument width. A declared physical storage width
  must be at least that maximum. Group indices and alignment/extension/class
  constraints are retained without assigning ABI resource group numbers.
- Join pieces remain **most significant first**. Concatenation pieces carry
  their least-significant-byte position. A single piece with a different
  logical width is a floating-format extension/conversion, not a bit slice;
  conversion is not executed. Empty joins, unsupported logical overrides,
  zero-width pieces and size overflow fail explicitly.

The retained references for these policies are `RegisterBuilder`,
`AbstractAddressSpace.makeValidOffset`, `BasicCompilerSpec`, `ParamEntry`,
`AddressXML.readJoinXML` and native `AddrSpaceManager::findAddJoin`.

## Bounds and remaining work

Every registry construction, compiler overlay construction and standalone
resolution call has a fresh `AbiLimits` budget. Counts bound spaces, registers,
models, output records, space bases, per-join/total pieces, name length, visited
name bytes and work. Defaults include 100,000 registers/output records,
1,024 pieces per join, one million total pieces, 16 MiB of name bytes and
100 million work units. Limits are checked before protected allocation/growth;
errors return no partial result. Error labels retain at most 64 UTF-8 bytes
plus an ellipsis.
Input ownership is supplied by the caller, and ordinary Rust allocation
failure is not caught. Upstream XML parsing and SLEIGH compilation have their
own behavior and are outside this crate's budgets.

Index construction uses ordered maps rather than repeated vector scans.
Output records and physical pieces determine storage use; no allocation is
proportional to an address-space span. Name comparisons and lookups are
charged, including the ASCII lookup spellings. Public queries must be bounded
by their caller if repeatedly applied to untrusted inputs.

The overlay preserves source diagnostics and incomplete-model status. It does
not establish legal nesting of parameter overlaps, derive resource groups,
allocate/justify arguments, evaluate model rules or merged-model scores,
compile injection bodies, initialize tracked registers, recover types or
apply call effects to SSA. These are required follow-on stages for the full
Rust replacement.

## Validation evidence

Expected values in the tests come from retained Ghidra sources, retained
`.sinc`/`.cspec` text or small independent models, not from replaying this
crate. `tests/basics.rs` is the original regression set. The behavioral suites
are:

- `registry.rs`: rejected layouts with their specific reasons (space count,
  width/unit/name, duplicate IDs and names, default-space kind, register space,
  zero or overflowing extents, empty and over-long names). Case-variant lookup
  is checked against a model of `RegisterBuilder`'s put order, including
  generated collisions. Alias overlap is checked against explicit byte sets in
  little- and big-endian spaces, the big-endian MIPS FPU pair layout, and
  extents ending at `u64::MAX`. Count, name-length, name-byte and work budgets
  are checked at their exact size and one below. A 4x larger register file costs
  4x the name bytes and less than 6x the work.
- `normalization.rs`: a reference model transcribed from
  `AbstractAddressSpace` (constructor and `makeValidOffset`) plus the documented
  whole-extent rule. It is compared with ram, stack and constant spaces of
  1/2/4/8-byte addresses and 1/2/4/8-byte units (more than 3,000 cases). Other
  checks cover accepted Java-long negatives, out-of-domain rejection, signed
  stack bounds, extents that would wrap, stack geometry (no-pointer fallback,
  minimum of pointer and backing width, backing units, growth/justification,
  `OTHER` backing, domains over 64 bits), default sizes, labels truncated on a
  character boundary, and standalone budgets at their exact thresholds.
- `joins.rs`: mixed-width significance, declaration order, and the nine join
  declarations taken from the retained `AARCH64_golang.cspec` text. Also float
  extensions in both directions, the native single-constant-piece exception,
  every invalid variant, a byte total of exactly `u32::MAX` versus overflow, and
  1,024 versus 1,025 pieces. The piece count is checked before any name is
  resolved.
- `compiler.rs`: every `BindingSite` kind at its source position. Also group,
  alignment, class and extension constraints; an unsized 500-byte stack pool;
  `TooSmall` exactly at the storage width, including a float extension's
  logical width; inherited, explicit and empty return addresses; open, signed
  and register ranges; space bases and dead-code delays; errors attributed to
  their site; shared `Arc` inputs; construction budgets at their exact size and
  one below; and linear overlay scaling.
- `real_catalog.rs` (ignored by default): run
  `cargo test --release -p ghidra-abi --test real_catalog -- --ignored`. It
  compiles each retained source once and resolves x86-64 `windows`, `gcc` and
  `golang`, ARMv7 `default`, MIPS32 BE `default`, AArch64 `golang` and SH-2A
  `default`. The SH-2A probe includes its 40,960-byte `resbank_base`, whose
  metadata is independent of the evaluator's value-width limit. Register
  offsets, inputs, groups, stack pools, local ranges, return-address fallback
  and Go join order are compared with the retained text. Binding, range, piece,
  space-base and delay counts are recomputed from the parsed declarations. On
  Windows, after a release build, the four probes ran in about 2 s. Observed
  output: x86-64 has 1,440 registers; its `windows`, `gcc` and `golang` specs
  produce 71/83/214 bindings, 6/4/3 ranges and 72/84/216 pieces. ARMv7 has 153
  registers, 88 bindings, 1 range and 88 pieces. MIPS32 BE has 471 registers,
  44 bindings, 4 ranges and 44 pieces. AArch64 Go has 633 registers, 157
  bindings, 1 range and 194 pieces. These are observations, not fixed
  expectations. These checked-in probes now cover seven pairs. A prior independent
  sweep at `fdb61172e6` resolved all 196 currently compiling pairs out of 296
  and matched their input/output resource plans against a source-derived Java
  oracle; the other 100 fail explicitly in compiler/address-space support.
  This does not establish complete processor or calling-convention semantics.

Known identity divergence, pinned by a `divergence_*` test:
- `RegisterBuilder` turns a register with an identical address and bit range
  into an alias of the earlier `Register`. Here each declaration keeps its own
  `RegisterId`; the two still overlap. No such pair occurs in the four compiled
  probe layouts.

Other differences from Ghidra that are known and accepted: an empty register or
space name is reported as `Limit("name length")` rather than as an invalid
layout. Range bounds are normalized. Reversed global, readonly, nohighptr and
inferptrbounds ranges are swapped as Java's `AddressRangeImpl` does; local and
parameter ranges are rejected. Ranges naming a compiler `<spacebase>` virtual
frame are not modeled and fail with an unknown-space error; resolving the base
register/backing space alone does not implement those relative ranges.
Compiler-frame names that duplicate a processor address space are rejected
against the immutable language layout, as Ghidra's `restoreSpaceBase` requires.
Names are case-sensitive. Frames named `stack`, `join` or `OTHER` are also
explicitly unsupported here: these names would shadow the overlay's synthetic
spaces, and silently interpreting frame-relative offsets as synthetic-space
addresses would be wrong. This last restriction can reject forms Java accepts.
The compiler-spec reader now diagnoses explicit stack references made before
an earlier `<stackpointer>`; Ghidra's no-pointer fallback appears only after
XML loading. Standalone `resolve_storage(..., None, ...)` still describes
post-load fallback geometry and does not replay XML load order.
Parameter size bounds are checked
after the storage resolves, so a declaration with both problems reports the
storage error first.

Not yet validated: the MSRV toolchain, pairs still blocked by source/compiler
support, complete ISA semantics in the resolved layouts, and behavior that
depends on whole-signature allocation or prototype-rule execution.

Address spaces with word sizes outside 1..=8 or byte domains larger than 2^64
are now rejected during registry construction, matching Ghidra's constructor.

## Parameter resource groups

`CompilerResources::new(Arc<CompilerStorage>, ResourceLimits)` derives separate
input/output resource namespaces for each prototype. It shares the immutable
overlay and owns the resulting groups, entry sites and slot capacities.
`list(model, ParameterDirection)` borrows one list; counts and `build_work()`
expose accounting. IDs are local to that list, not physical register IDs.

The pass follows declaration order: explicit group members share their starting
resource; a larger contiguous pool inherits resources from earlier contained
pools, skipping already-overlapping entries; a join inherits the most recent
exact earlier pool for each physical piece. At least one nonconstant piece
must match. Constant padding does not supply resources. Group lists are sorted
and retain repetitions, matching retained `ParamEntry` behavior. An aligned
pool uses one group with several slots, not one group per slot. Capacity is
logical metadata, including near an address-space boundary; it is never
converted into an allocated value extent. Actual slice placement must still
validate its address domain.

Incomplete prototypes, reused/noncontiguous declared groups, indistinguishable
members, joins inside explicit groups, non-nesting overlaps and unmatched joins
fail explicitly. Comparisons use normalized mathematical byte coordinates and
detect crossing partial overlaps, including ones the retained `intersects`
routine misses. Signed stack containment across zero is accepted; retained
unsigned comparisons can instead reject that layout. These are deliberate
mathematical-coordinate policies in both directions, not bit-for-bit emulation
of wrapping/unsigned overlap quirks. No shipped pair in the review sweep differs.

Models, entries, physical regions, resource groups, stored group references and
work have separate limits, checked before protected growth. One budget covers
all models/lists. Defaults include 100,000 entries/groups, one million regions
and references, and 16 million work units. The initial algorithm scans earlier
entries/pieces and can be quadratic; large otherwise-valid lists can exhaust
work before count limits. Group-reference output and sorting are charged too.
It has no recursion or allocation proportional to an address-space span.

Thirteen default resource tests include exact limits, a byte-set oracle over
1,000 generated lists, explicit/overlapping groups, joins/padding and a bounded
2,000-entry stress case. An opt-in test covers six real compiler/language pairs.
The CLI exposes this pass with `--compiler-storage ... --resources`; default
inspection still emits only resolved locations. This is resource sharing,
not argument allocation, justification, output-part inference, rule execution
or a complete calling-convention implementation. Independent review at
`fdb61172e6` approved the pass. Its follow-up validation also rejects upward-
growth pool sizes that are not a multiple of alignment, even when a caller
manually marks an invalid prototype complete. Review evidence and remaining
processor-loader limitations are recorded in `docs/RUST_PORT.md`.

## Placement in an explicit parameter pool

`place_parameter(&CompilerStorage, BindingSite, PlacementRequest, PlacementLimits)`
places one value in a selected input or output pool. `PlacementRequest::new(size)`
starts at slot zero with relative alignment one and default justification;
requests can override `used_slots`, `type_alignment` and `justification`.
The owned result records its site, next cursor, source piece count, work, and
either `PlacedValue` or a typed `NoFit` reason. Invalid requests, unsupported
format combinations and exhausted budgets are errors, without a partial result.
The query leaves its source and all resource state unchanged.

An exclusion pool accepts only slot zero and a width in its declared bounds;
its successful cursor remains zero, matching `ParamEntry::getAddrBySlot`.
The future allocator must separately reserve every shared exclusion resource.
Aligned pools round the value width to slots and skip alignment holes relative
to the pool origin. A failed fit retains the cursor after those holes. Positive
stack growth allocates aligned pools backwards, including aligned register
pools, as the retained implementation does. Actual selected extents must fit
their signed/unsigned byte domain without wrapping, even if the pool's metadata
capacity extends beyond it. No payload bytes are allocated or evaluated.

Default justification uses each physical space's byte order: little-endian
values start at the slot's beginning and big-endian values at its end. It uses
the pool maximum rather than a named register alias's wider physical width.
Big-endian stack `reversejustify` changes the default to left; explicit left
or right overrides are supported. Native C++ rejects little-endian reverse
stack justification, so this query reports it as unsupported rather than
silently applying Java's ignored attribute. The final resolved stack geometry
applies to every query; historical XML load-order quirks are not replayed.

Join slices follow native `JoinRecord::getEquivalentAddress` and
`renormalizeJoinAddress`: the synthetic pool uses the language default byte
order, physical byte traversal uses the first piece's byte order, and output
pieces stay most-significant-first with explicit selected-value significance.
Mixed-space pieces and partial selections retain original piece indices, byte
displacements and register provenance. Register provenance identifies the
declared container, not an exact alias name for the selected slice. Constant
join components stay marked padding with their original offset; they never
become writable storage or invented zero/known bytes.

This intentionally follows native rather than Java's partial-join construction.
For a big-endian six-byte value in a `D0:D1` join of two four-byte registers,
native/Rust selects `D0+2` (two bytes) followed by all of `D1`; retained Java
selects all of `D0` followed by two bytes of `D1`. The independent review found
this distinction in 19 of its 196 real compiler/language pairs. The per-space
byte-order policy also has a real mixed-endian effect: in
`ARM:LEBE:32:v7LEInstruction`, a one-byte value in `r0` uses offset `0x20`,
while Java's uniformly big-endian register model gives `0x23`. Stack pools
remain big-endian/right-justified. The Rust result agrees with its retained
source-order register layout, not with Java's space-order override.
Constant-first joins likewise use the adapter's declared constant-space byte
order, which can differ from native's always-little-endian constant space;
no shipped compiler spec in that review had constant join pieces.

Floating extensions keep a full physical container plus the requested logical
width under `PlacedStorage::FloatConversion`. No integer slicing or conversion
is executed. Partial/aligned floating joins and floating conversion of a
concatenated join are explicitly unsupported. Sign/zero/inttype policies remain
metadata and do not assert any value for the container's unused bytes.

Relative alignment uses an exact gcd/congruence calculation, including
nondividing alignments. This deliberately avoids the retained floor-division
quirk that can return misaligned locations. Divisible/power-of-two alignments
give the same placements. A join query takes linear work in physical piece
count plus bounded integer gcd work; a single-pool query does not scan other
entries. Source/output piece counts and work have independent per-query caps,
checked before protected growth (defaults: 1,024/1,024 pieces, 100,000 work).

Nineteen default placement tests cover these policies, exact and one-below
limits, every smaller work budget, 1,000-piece scaling and a million-byte value
without a byte buffer. An expanded byte-address oracle checks over 12,000
partial join selections across both default/physical byte orders. Eight
compiling mutations were caught in an isolated package. The five opt-in real
source probes now also check 827 concrete pool placements across x86-64 Windows,
GCC and Go, ARMv7 AAPCS, MIPS32 BE, AArch64 Go and SH-2A, including aligned-pool tail
rejections. Independent review of `679f2671d8` at `f6b57e116a` approved the pass:
1,574,316 synthetic and 3,472,470 real-catalog comparisons matched a separate
native-source oracle, across all 196 pairs that compiled at that checkpoint.
These are bounded source-derived comparisons, not execution of Ghidra's native
decompiler or proof of complete calling-convention behavior. Five additional
review-suggested tests pin negative stack minima, register isolation from stack
justification, aligned float bytes and multi-slot upward growth.

This primitive does not select a model or pool from a datatype, consume shared
resources, allocate a complete signature, execute model rules, infer ABI return
values from P-code RETURN, or integrate call effects. Those remain required
work toward a complete native calling-convention implementation.
