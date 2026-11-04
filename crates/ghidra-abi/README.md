# Native compiler storage

This crate resolves compiler-spec storage declarations against actual language
registers and address spaces. It keeps signed stack addresses, register aliases
and join significance explicit. It is a native Rust layer and uses no Java or
Ghidra C++ process.

Whole-signature allocation, prototype-rule evaluation, injection compilation and
type recovery remain separate stages. Resource-group planning, placement in
an explicitly selected pool and the retained declaration-ordered *fallback*
primitive are described below. Successful storage resolution, or a successful
fallback batch, does not mean that a calling convention is executable.

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
work toward a complete native calling-convention implementation. The fallback
layer below consumes resources for explicit requests; it is still not
signature allocation.

## Fallback allocation over declared pools

`AllocationState::new(&CompilerResources, model, ParameterDirection, FallbackLimits)`
creates the owned list-local resource state (`allocateStatus`): one
`GroupState` per list group plus the physical extents held so far.
`assign_fallback(&resources, &[FallbackRequest], FallbackPolicy, FallbackLimits)`
assigns a batch with the retained primitive (C++ `ParamListStandard::
assignAddressFallback`, Java `ParamListStandard.assignAddressFallback`) over
`place_parameter`:

```rust
use std::sync::Arc;
use ghidra_abi::*;
use ghidra_languages::{CompilerSpec, StorageClass};
use ghidra_pcode::{AddressSpace, Endianness, SpaceId, SpaceKind};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let space = |id, name: &str, kind| AddressSpace { id: SpaceId(id), name: name.into(),
    kind, address_size: 4, word_size: 1, endianness: Endianness::Little };
let registers = ["r0", "r1", "sp"].iter().enumerate().map(|(i, name)|
    RegisterDefinition { name: (*name).into(), space: SpaceId(1),
        offset: 4 * i as u64, size: 4 }).collect();
let file = Arc::new(RegisterFile::new(vec![space(0, "ram", SpaceKind::Ram),
    space(1, "register", SpaceKind::Register)], SpaceId(0), registers,
    Default::default())?);
let spec = CompilerSpec::parse_str(r#"<compiler_spec>
<stackpointer register="sp" space="ram"/><default_proto>
<prototype name="p" extrapop="0" stackshift="0"><input>
<pentry minsize="1" maxsize="4"><register name="r0"/></pentry>
<pentry minsize="1" maxsize="4"><register name="r1"/></pentry>
<pentry minsize="1" maxsize="500" align="4"><addr space="stack" offset="4"/></pentry>
</input><output/></prototype></default_proto></compiler_spec>"#,
    None, &Default::default())?;
let storage = CompilerStorage::new(Arc::new(spec), file, Default::default())?;
let resources = CompilerResources::new(Arc::new(storage), Default::default())?;
let mut state = AllocationState::new(&resources, 0, ParameterDirection::Input,
    Default::default())?;
let int = FallbackRequest::new(4, 4, StorageClass::General);
let batch = state.assign_fallback(&resources, &[int; 3], FallbackPolicy::default(),
    Default::default())?;
let FallbackOutcome::Assigned(third) = &batch.outcomes[2] else { unreachable!() };
assert_eq!(third.site, BindingSite::Input { model: 0, entry: 2 });
assert_eq!(third.slots, Some(SlotRange { first: 0, next: 1 }));
assert_eq!(state.groups(), [GroupState::Consumed, GroupState::Consumed,
    GroupState::Available { used_slots: 1 }]);
# Ok(())
# }
```

Each request visits the list's entries in declaration order. An entry is
skipped when its *first* group is consumed or its class does not match:
`ClassMatch::GeneralAcceptsAny` (retained `matchExact == false`) lets a
`General` entry take any class; `ClassMatch::Exact` requires the requested
class. Otherwise `place_parameter` runs at that group's cursor with default
justification. A candidate that does not fit writes skipped alignment holes
back to the cursor, as `getAddrBySlot` does, and the loop continues. An
exclusion success consumes every group of the entry; an aligned success
advances only the first group's cursor. The first request that fits nowhere is
`NoFit` and later ones are `NotAttempted`, as in Java `assignMap`. Results
keep the model, direction and entry site, slot ranges, and the unchanged
`PlacedValue` (register provenance, constant padding, float conversion).

A request is an explicit storage width (the datatype's aligned size), a
relative alignment and a `StorageClass`. No datatype graph, metatype mapping
or concrete value is involved.

**This is not prototype allocation.** Model rules, `pointermax`, hidden-return
conversion and pointer insertion, `this` and `thisbeforeretpointer` ordering,
the register output strategy, injections, `sharestack`, merged-model selection
and parameter conversion are never executed. With the default
`DeclaredRules::Reject` policy, a list that declares rules or `pointermax` is
refused with `RulesNotExecuted`. `DeclaredRules::BypassUnexecuted` runs the
bare primitive anyway, as upstream rule actions do, and
`FallbackBatch::unexecuted` records every skipped declaration. An output
`NoFit` is neither a void result nor a hidden-return decision. Nothing is
inferred from P-code `RETURN`.

### State ownership and refusals

The state is owned, `Clone`, `Send` and `Sync`, and tied to one overlay
(`Arc` identity) and list; another overlay is a `StateMismatch`. Input and
output lists, and different models, use separate states. Any error restores
the state exactly and returns no partial batch. A `NoFit` is not an error: the
state keeps earlier assignments and the cursor holes, matching the retained
status array. A caller that needs all-or-nothing behavior can clone a state,
run fallback on the clone and commit it, as `MultiMemberAssign` does with
`tmpStatus`.

The retained status test reads one group per entry. Valid lists can still
make it reuse resources, so these typed errors replace such results:

- `GroupInUse`: the selected entry's first group is free but another of its
  groups is consumed or has used slots. Example: `r0` (minimum 4), a
  `<group>` of float `f0` and `r1`, and a join `r1:r0` (groups `[0, 1]`). A
  2-byte float skips `r0` and consumes the shared group in `f0`; an 8-byte
  value would then take `r1:r0`.
- `Overlap`: the selected storage shares a byte with storage held by an
  earlier assignment. Exclusion entries hold their whole pool (every
  nonconstant join piece, or the pool capacity); aligned entries hold their
  used slots; constant padding holds nothing. Examples: two joins sharing a
  piece that matches no earlier pool, a join piece that only partly matches an
  earlier pool, and an aligned pool spanning several groups, whose cursor does
  not mark a contained register.
- `Unsupported`: an aligned join pool (no slot-to-piece occupancy model), or
  a selected slice outside its address domain. Retained code would wrap the
  address; trying the next entry instead would be a new policy.

Retained selection is safe when each aligned pool has one distinct group,
every join piece exactly matches an earlier single pool, and no request can
take a later group of a multi-group entry while its first group stays free.
The real probes below never hit a refusal. Among shipped specs only Dalvik
has an aligned register pool (one group), and none has an aligned join. A
survey of every compiling pair has not been done. Coordinates are
mathematical bytes with signed stack offsets; unsigned wrapping is not
emulated.

### Bounds

One `FallbackLimits` budget covers each batch: requests (default 4,096),
examined entries (4 million), group references (8 million), group updates
(1 million), assignments (4,096), output pieces (65,536), occupied extents
held by the state (65,536) and work (64 million). `max_groups` (100,000)
bounds the state created by `new`. Each nested placement receives only the
remaining work and output-piece budget plus a fixed per-candidate source-piece
cap (1,024); its work is added to the total. Counts are checked before growth
with overflow-checked arithmetic. A batch examines at most requests times
entries. Overlap checks use an ordered map with charged logarithmic cost.
There is no recursion and no buffer proportional to an address span. An undo
journal, bounded by updates and new extents, restores the state on error.

### Validation evidence

`tests/fallback.rs` has 19 default tests with hand-derived expectations:
Windows-like shared float/integer groups continuing onto the stack, exact
versus General class matching and declaration order, containing pools and
joins, alignment holes kept after `NoFit` and from failed candidates, positive
growth, signed stack containment across zero, big-endian justification,
padding and float conversion compared with direct `place_parameter`,
independent input/output states, each refusal (state restored, the same error
in a combined batch, a one-byte boundary overlap versus adjacency), the rules
policy, invalid requests/lists/states, determinism and thread safety. Every
limit is checked at its exact value and one below, every smaller work budget
fails, and a later failing batch restores the earlier state. A 4,096-request
batch costs about four times a 1,024-request batch. An independent model
transcribes Java `assignAddressFallback` and `getAddrBySlot` (power-of-two
alignments, little endian) with a byte-set oracle that does not read group
arrays. Over 2,500 generated layouts (2,129 valid) it matched 4,820
assignments, 1,037 no-fits, 80 group-in-use and 59 overlap refusals. In an
isolated copy, 20 of 21 source mutations were caught. The survivor removes the
nested work cap; the total charge still rejects it with the same
`Limit("work")` error.

`tests/fallback_real.rs` is ignored by default; run
`cargo test --release -p ghidra-abi --test fallback_real -- --ignored`. It
compiles real SLEIGH register files and checks x86-64 Windows `__fastcall`,
GCC `__stdcall` and Go `abi-internal`, ARMv7 `default`, MIPS32 BE, AArch64 Go
(input and output joins) and SH-2A. Each probe with rules pins a request
the bypassed rules would assign differently: Windows `pointermax`, GCC
`join_dual_class`, the Go float `goto_stack`, ARM `s2:s3` backfill, and MIPS
`consume_extra`. AArch64 Go input and SH-2A declare no rules, so the default
policy runs. The five probes took about 2 s after a release build.

Remaining required work: model-rule actions and `pointermax`, hidden-return
handling, `this` and hidden-parameter ordering, output strategy and
`sharestack` semantics, merged-model selection, datatype-driven requests, and
call effects in SSA. The refused layouts above, a survey of every compiling
pair and the 1.88 MSRV toolchain remain unvalidated.
