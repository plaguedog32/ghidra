# Native compiler storage

This crate resolves compiler-spec storage declarations against actual language
registers and address spaces. It keeps signed stack addresses, register aliases
and join significance explicit. It is a native Rust layer and uses no Java or
Ghidra C++ process.

Whole-signature allocation, complete prototype-rule dispatch, injection
compilation and type recovery remain separate stages. Resource-group planning, placement in
an explicitly selected pool, the retained declaration-ordered *fallback*
primitive, the one-value *native* fallback primitive and the native `<join>`
and `<join_dual_class>` rule actions are described below. Successful storage
resolution, or a successful fallback batch, does not mean that a calling
convention is executable.

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

`tests/fallback.rs` has 20 default tests with hand-derived expectations:
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

Independent review found and reproduced a later-batch cap gap: an empty or
no-fit batch could retain more occupied extents than a newly lowered limit.
The entry preflight now bounds already-held extents, with a regression for both
paths and the exact boundary. The reviewer verified that fix, all 20 default
tests and all five real probes, and reported no remaining actionable findings.

Compiler frame-name validation also has independent tests for its name-byte and
namespace-lookup work charges. Empty frame names fail explicitly as unsupported
storage rather than being mislabeled as a resource-budget failure.

`tests/fallback_real.rs` is ignored by default; run
`cargo test --release -p ghidra-abi --test fallback_real -- --ignored`. It
compiles real SLEIGH register files and checks x86-64 Windows `__fastcall`,
GCC `__stdcall` and Go `abi-internal`, ARMv7 `default`, MIPS32 BE, AArch64 Go
(input and output joins) and SH-2A. Each probe with rules pins a request
the bypassed rules would assign differently: Windows `pointermax`, GCC
`join_dual_class`, the Go float `goto_stack`, ARM `s2:s3` backfill, and MIPS
`consume_extra`. AArch64 Go input and SH-2A declare no rules, so the default
policy runs. The five probes took about 2 s after a release build.

Remaining required work: complete model-rule dispatch/actions and `pointermax`, hidden-return
handling, `this` and hidden-parameter ordering, output strategy and
`sharestack` semantics, merged-model selection, datatype-driven requests, and
call effects in SSA. The refused layouts above, a survey of every compiling
pair and the 1.88 MSRV toolchain remain unvalidated.

## Datatype predicates and rule qualifiers

`DatatypePredicates::new(Arc<TypeLayouts>, PredicateLimits)` builds immutable
canonical-type and homogeneous-float summaries for one declared datatype graph.
It shares the layout snapshot and never expands arrays into individual elements.
`matches_filter` tests a captured `DatatypeFilter`; `matches_rule` tests only a
rule's datatype and ordered qualifiers. Both return a `PredicateMatch` with the
first rejection and charged query work. Actions, resource preconditions and side
effects are not executed, and no storage allocation is performed.

```rust
use std::sync::Arc;
use ghidra_abi::{DatatypePredicates, PrototypeTypes};
use ghidra_languages::{CompilerSpec, DataOrganization};
use ghidra_types::{TypeDefinition, TypeId, TypeKind, TypeLayouts};

let spec = CompilerSpec::parse_str(r#"<compiler_spec><default_proto>
<prototype name="p" extrapop="0" stackshift="0"><input>
<rule><datatype name="float" minsize="4" maxsize="8"/>
<position index="0"/><consume storage="float"/></rule>
</input><output/></prototype></default_proto></compiler_spec>"#,
    None, &Default::default())?;
let layouts = Arc::new(TypeLayouts::new(vec![
    TypeDefinition::new("f32", TypeKind::Float { bytes: 4 }),
    TypeDefinition::new("void", TypeKind::Void),
].into(), DataOrganization::default().resolve(8), Default::default())?);
let predicates = DatatypePredicates::new(layouts, Default::default())?;
let parameters = [TypeId(0)];
let context = PrototypeTypes { result: TypeId(1), parameters: &parameters,
    first_vararg: None };
assert!(predicates.matches_rule(&spec.prototypes[0].input.rules[0], TypeId(0),
    context, 0, Default::default())?.matched);
// The consume action has not run; this result is only a predicate match.
# Ok::<(), Box<dyn std::error::Error>>(())
```

Semantics follow the retained Java `protorules` filters and `MetaDataType.get`:

- Any/meta/array size checks use public `getLength`, not aligned length. Missing
  or zero maximum means `i32::MAX`, minimum defaults to zero, and a nonempty
  size list tests membership. Empty composites/zero arrays therefore have
  filter length one. Unsized function definitions have filter length -1.
- Ordinary meta filters strip aliases. Signed/unsigned enums map to `int`/`uint`,
  not the accepted but unreachable `enum_int`/`enum_uint` filter names. `Char`
  uses compiler signedness and `WChar` maps to `int`. Retained Java maps void to
  `unknown`, with length zero, and functions to `code`, whose negative length
  fails XML-default size bounds. Fixed opaque storage explicitly uses the
  generic unrecognized-type `unknown` fallback; its width never implies float
  or integer semantics. Incomplete types produce explicit errors when queried.
- A parsed `array` filter uses the direct-array check of `ArrayFilter`; an
  alias of an array fails it. Element bounds apply only to direct arrays, with
  maximum zero meaning unlimited.
- Homogeneous-float-aggregate requires an outer array/struct after aliases,
  at least one float leaf, one shared canonical float `TypeId`, and no union or
  nonfloat leaf. Different IDs with equal widths remain different datatype
  identities. Empty nested structures/zero arrays add no leaves. The default
  primitive maximum is four, including an explicit zero setting. This source
  filter ignores inherited size bounds. Both supported packing modes enable
  automatic packing, so alignment holes and trailing padding do not disqualify
  an HFA. Manual-layout extraction is not implemented.
- Qualifiers use AND with declaration-order short-circuiting. Position compares
  literally. `datatype_at` selects the return type for any negative index and
  fails for an absent input slot. Varargs positions are relative to the first
  variable slot; absent bounds are `i32::MIN..=i32::MAX`, which can include the
  return position. No first variable slot means false. Subtraction outside the
  modeled signed-int range is an explicit error instead of Java wraparound.

The caller supplies the datatype and position explicitly, as the retained
`ModelRule.assignAddress` does. Prototype parameter IDs and return ID are all
validated before predicate evaluation. The first variable slot must lie within
or at the end of the input list. Filters reached after short-circuiting are
validated on demand; invalid unreachable predicates are not evaluated. Hand-built
size lists mixed with explicit bounds are rejected rather than inventing XML
attribute order. Class-irrelevant fields remain ignored.

Construction costs `O(types + references)` time/storage with no recursion.
Canonical aliases and HFA leaf counts are cached once, including billion-element
arrays; queries do not walk member graphs. Work includes dependency visits,
summary combinations, prototype validation and conservative size-list scans.
Each construction/query receives a fresh work budget, with no nested analysis
budget. `max_types`, `max_references` and `max_depth` apply to construction;
`max_size_items`, `max_qualifiers` and `max_parameters` apply per query. The size
item count accumulates across reached `datatype_at` filters as well as the main
filter. All caps are checked before protected allocation/visits. Errors return
no partial fact snapshot or match result.

Default tests cover the source quirks, first rejection, malformed IDs/filters,
short-circuiting, exact/one-below limits and every lower work budget. A 100,000-ID
alias chain scales linearly and a billion-element array uses two fact records.
The independent small-graph reference expands leaves recursively, comparing
7,192 filter queries and 1,344 qualifier queries without production fact helpers.
Every one of the 230 retained rules is also compared on synthetic type graphs
under pointer-size profiles 2/4/8 from all 107 referenced compiler specs: 42,780
filter queries and 6,900 qualifier queries. This checks declaration evaluation,
not argument allocation for those processor ABIs. Seven compiling mutations of
source-sensitive branches and budget charges are caught by the default tests.
These predicates are not yet connected to rule actions, signature allocation,
SSA call effects, the desktop or a command-line report.

Independent review approved the predicate layer at `2ee4122b7c`, with no
correctness/resource findings, and added over one million filter and 143,272
rule comparisons. Its test-gap notes are addressed by absolute work formulas
for field combinations, parameter preflight and size scans, plus explicit
signed-int boundary tests. These catch the five previously surviving mutations.

This API follows the Java compiler-spec datatype view. The retained C++
decompiler uses a different type factory: an alias of an array still has array
metatype, float aliases retain distinct HFA identities, void has its own
metatype, and code has size one. A named Go array can therefore match the
`x86-64-golang.cspec` array-to-stack rule in C++ but fail Java's direct-array
check. The separate decompiler view is `NativeTypeGraph` below; this Java API
is unchanged, and neither is wired into signature recovery yet. HFA's ignored size bounds are shared
by both source layers: the first HFA join rule in `AARCH64_win.cspec` can match
varargs HFAs larger than its declared maximum 16. Later action code must preserve
that source behavior. Repeated `matches_rule` calls validate the input list each
time; a prevalidated prototype handle remains a later scaling improvement.

## General primitive extraction

`PrimitiveExtraction::new(Arc<DatatypePredicates>, root, options, limits)`
extracts an owned list of scalar pieces from the declared datatype snapshot.
This is the Java-layer `PrimitiveExtractor` needed by ABI join/member rules,
separate from the cached HFA predicate summary. Each `Primitive` retains its
canonical datatype or wrapper identity, byte offset, meta-type, raw length, aligned length
and alignment. No bytes of the described value are allocated or evaluated.

```rust
use std::sync::Arc;
use ghidra_abi::{DatatypePredicates, PrimitiveExtraction, PrimitiveSource};
use ghidra_languages::DataOrganization;
use ghidra_types::{Composite, Field, TypeDefinition, TypeId, TypeKind, TypeLayouts};

let layouts = Arc::new(TypeLayouts::new(vec![
    TypeDefinition::new("int", TypeKind::Integer { bytes: 4, signed: true }),
    TypeDefinition::new("double", TypeKind::Float { bytes: 8 }),
    TypeDefinition::new("record", TypeKind::Structure(Composite {
        fields: vec![Field::new("a", TypeId(0)), Field::new("b", TypeId(1))],
        ..Default::default()
    })),
].into(), DataOrganization::default().resolve(8), Default::default())?);
let predicates = Arc::new(DatatypePredicates::new(layouts, Default::default())?);
let pieces = PrimitiveExtraction::new(predicates, TypeId(2),
    Default::default(), Default::default())?;
assert_eq!(pieces.primitives().len(), 2);
assert_eq!(pieces.primitives()[0].source, PrimitiveSource::Type(TypeId(0)));
assert_eq!(pieces.primitives()[1].offset, 8);
# Ok::<(), Box<dyn std::error::Error>>(())
```

Arrays normally expand with their element's aligned length as stride.
`nested_arrays_are_primitives` collapses arrays below the current extraction
root into one array primitive, including a nested zero array's one-byte display
length. A root array still expands. Each union member starts a fresh context at
depth zero, so a direct union-member array expands even inside a nested union.
Canonical aliases do not introduce additional array depth. Lazy array frames
bound memory independently of the declared count; cached empty summaries skip
empty subgraphs when nested arrays are expanded.

Unions can be rejected by policy or refined in member order. Source refinement
uses **aligned** lengths, retaining disjoint/touching pieces. The larger piece
is selected as the window; a length tie selects the first. A nonfloat window
keeps that piece, while a float window yields to the overlapping smaller pieces.
No type equality, full-coverage or leading-start containment check is invented.
Only a smaller piece ending past the window's end rejects the overlap. Thus
shifted overlap can be order-sensitive. Intermediate refinement can exceed the
semantic primitive maximum and later shrink; it is bounded separately by the
live-scratch limit. Every union member gets the full semantic maximum, and the
final append checks the parent result's total. This preserves the retained Java
behavior rather than treating unions as interval-set normalization.

Flags follow that layer too. Java copies union-member lists without propagating
child unknown/alignment/hole flags. `contains_unknown()` exposes that context-
local flag, while `output_contains_unknown()` separately reports unknown meta-
types actually present in the final list. Both supported structure packing
modes enable automatic packing; Java skips manual-field alignment/hole checks
there, so `is_aligned()` is true and `contains_holes()` is false for the current
model. Trailing padding does not create a hole. Manual-layout extraction still
requires implementation when those layouts are added.

Void extracts as an unknown zero-length primitive and function definitions as
code with raw/aligned length -1, matching the retained Java classification.
Empty structures and expanded zero arrays succeed with no pieces; empty unions
fail, while a union of empty structures succeeds empty. Incomplete types error.
Unsigned byte offsets use checked arithmetic and aligned storage windows must
fit the 64-bit byte domain, allowing the extended exclusive end at 2^64. There
is no Java signed-int wrapping. This describes geometry, not readable memory or
an emulated ABI value.

Each call shares its exact immutable fact snapshot, and the result is
`Clone + Send + Sync`. Limits bound the source semantic primitive count,
simultaneous live records across contexts/refinement scratch, active nesting
and total work. Counts are checked before protected growth. Vector allocation
uses normal Rust amortized capacity and allocation-failure behavior. Production
traversal, nested union contexts and refinement use no recursion; no allocation
is proportional to the object's byte span. Worst-case repeated union refinement
can be quadratic and is bounded by work. Temporary lists and all deferred
traversal frames are bounded by live/depth limits. Errors discard the partial
prefix, unlike Java's invalid extractor objects; no incomplete result escapes.

Sixteen directed tests cover source ordering/ties, float preference, shifted
overlap, intermediate scratch exceeding the semantic maximum, flags and array
depth, zero/unsized types, exact limits/every lower work budget, offset bounds,
100,000 nested structures, 20,000 nested union contexts and billion-element
array handling. An independent recursive/queue reference checks 26,208 cases,
including 12,396 valid outputs/flags and 13,812 semantic rejections.
Bitfields use `PrimitiveSource::BitField { owner, field, base }` wrapper identity
and unknown metatype. Raw/aligned wrapper lengths use minimal `storage_bytes`,
including one for a zero-width component; base allocation width and component
bytes are not substituted. Wrapper alignment is the declared base's natural
alignment, including enum alignment that differs from its integer counterpart.
Normalized bit metadata remains available through the owner's field in the
shared layout. Adjacent wrappers can share bytes, as in the source extractor.
In particular, a trailing zero-width wrapper can start at the owner's byte
length and extend one byte beyond it. Future member actions must retain the
source's negative-padding failure for that case rather than clamp the wrapper.
Sixteen compiling mutations across predicate budget/range checks, refinement,
wrapper storage and widened bitfield comparisons are caught. The probes exposed
a missing raw-versus-aligned refinement regression; the new directed test now
pins that difference explicitly.
Independent review approved the extraction and bitfield integration at
`3299780b59`, with about 3.28 million valid release reference comparisons,
327,000 rejections and 225,000 bitfield pieces. Its low-severity trailing-empty-
member finding is fixed: traversal now carries widened offsets, and converts
only when emitting a primitive. A zero-size tail at or beyond the exclusive
end 2^64 therefore succeeds when it emits nothing. A collapsed zero-array wrapper or
zero-width bitfield there still fails because it emits a real piece outside
the address domain. Directed tests cover empty arrays, structures, aliases,
unions and both nested-array modes.

No join/member action,
signature allocation, CLI or desktop flow uses this extractor yet.

## Allocation operations for rule actions

`AllocationState::assign_pool(resources, PoolRequest, limits)` assigns a
specific pentry without searching other entries or checking storage class.
The request supplies size, alignment and justification explicitly; actions
choose raw or aligned size as their source contract requires. The state
supplies the current cursor. Exclusion/group consumption, physical overlap
checks, occupied extents and nested placement accounting use the same path
as fallback. `NoFit` retains alignment holes; an error restores all changes.
No list rule or `pointermax` is dispatched by this explicit operation.

`AllocationState::apply_effects(resources, effects, context, indexing, limits)`
executes parsed `RuleSideEffect` values in order. Its context carries raw size,
alignment and the representative result space, independently of datatype
predicates. This is usable for either a staged precondition list or a committed
side-effect list:

- `ConsumeExtra` visits exact-class, exclusion, single-group tiles in declaration
  order, skipping every nonzero status. Default `matchsize=true` counts down raw
  bytes; false consumes at most one untouched tile. Nonpositive raw sizes consume
  none. Exhaustion is successful even if the requested size is not covered.
- `ConsumeRemaining` consumes every untouched eligible tile, independently of
  the datatype size. Missing eligible tiles is an error for both operations,
  including a zero-size request, as in upstream action initialization.
- `ExtraStack` selects only the final aligned stack pentry. An already-stack
  representative suppresses it; a join containing a stack piece does not.
  A positive threshold sums full declared pool widths for matching nonzero
  statuses, without deduplicating shared groups. Missing/negative/zero thresholds
  are unconditional. It reserves raw size/alignment, ignores the generated
  address, and leaves occupied value extents unchanged. `StackReserved` reports
  both cursor values and whether placement fit; a no-fit can retain alignment
  holes, matching upstream's unconditional success response.

Threshold indexing is mandatory and explicit. `NativeGroup` follows C++
`modelrules.cc` by indexing each pentry's first resource group. `JavaEntry`
reproduces the Java loop's pentry-index behavior, which can count different
resources for grouped alternatives; an out-of-range status index returns
`ThresholdIndex` instead of Java's array exception. Neither policy is silently
selected for the caller. Counters use checked arithmetic rather than signed
Java overflow. A nonpositive/oversized stack width, consumed stack group or
address-domain escape fails explicitly. These are checked refusals of upstream
invalid-address success cases, not invented storage.

The batch uses one work budget, including stack placement, and bounds effects,
entry visits, group reads and journaled group writes before protected growth.
It examines at most effects × (pentries + 1) entries, including each stack-entry
check; no byte-sized allocation or recursion is
used. Outcomes are owned, state remains tied to its original compiler overlay,
and every actual error rolls back the entire batch. Effects consume logical
resources rather than creating value extents. The future rule dispatcher must
separately preserve upstream's filter/precondition/action/commit/effect ordering.

Thirteen directed tests pin raw sizing, justification, representative-space
checks, threshold order, exact work charges, every lower work budget and error
rollback. Five independent oracle tests compare 5,184 executions over fixture-
owned declaration/group maps in both source policies, with grouped alternatives,
alias pools, aligned pools, exhaustion and all effect budgets.
Fourteen compiling semantic/accounting mutations are caught. The first run
exposed a positive-cursor test gap: an exclusion tile sharing an aligned pool's
nonzero cursor must be skipped. A new explicit regression pins that behavior.
Independent review approved this increment at `504e0d486f` and compared 96,000
additional source-shaped executions. Its error-classification finding is fixed:
all budget exhaustion now returns `EffectError::Limit`, including nested
placement work. Invalid placement remains a distinct error. A directed test
checks every cap and all 28 lower work budgets, including rollback.

Complete rule matching/dispatch, pointer synthesis, hidden-return control flow,
member/dual composition and shared-stack signatures remain required. The
single-class `<join>` action is described next. These operations are not yet
connected to datatype-driven signature allocation, SSA call effects, the CLI or
desktop.

## Native join action

`AllocationState::assign_join(resources, &JoinAttributes, JoinRequest, JoinLimits)`
runs one native `<join>` rule action (`MultiSlotAssign`, modelrules.cc:856-1072)
on an input or output state. `JoinAttributes::from_action` takes the declared
attributes of a parsed `RuleAction::Join`; `None` keeps the constructor default.
The request is the datatype's raw `getSize` and `getAlignment`, each in
`1..=i32::MAX`. No datatype graph, rule filter, precondition or prototype is
consulted, and nothing is inferred from P-code `RETURN`. The caller supplies
the request after a rule has matched; this is not rule dispatch.

```rust
use std::sync::Arc;
use ghidra_abi::*;
use ghidra_languages::CompilerSpec;
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
<rule><datatype name="any"/><join/></rule>
</input><output/></prototype></default_proto></compiler_spec>"#,
    None, &Default::default())?;
let join = JoinAttributes::from_action(&spec.prototypes[0].input.rules[0].action)
    .expect("a <join> action");
let storage = CompilerStorage::new(Arc::new(spec), file, Default::default())?;
let resources = CompilerResources::new(Arc::new(storage), Default::default())?;
let mut state = AllocationState::new(&resources, 0, ParameterDirection::Input,
    Default::default())?;
// Ten bytes: r0, r1, then two bytes spilled to the stack.
let result = state.assign_join(&resources, &join, JoinRequest::new(10, 4),
    Default::default())?;
let JoinOutcome::Assigned(allocation) = &result.outcome else { unreachable!() };
let JoinStorage::Pieces(pieces) = &allocation.storage else { unreachable!() };
// Most significant first, with each piece's significance in the whole value.
let layout: Vec<_> = pieces.iter().map(|p| (p.piece.storage.address.space,
    p.piece.storage.address.offset, p.piece.lsb_byte)).collect();
let register = AbiSpace::Language(SpaceId(1));
assert_eq!(layout, [(AbiSpace::Stack, 4, 8), (register, 4, 4), (register, 0, 0)]);
assert_eq!(state.groups(), [GroupState::Consumed, GroupState::Consumed,
    GroupState::Available { used_slots: 1 }]);
# Ok(())
# }
```

### Configuration and initialization

`JoinAssignment::config` reports the resolved fields. The storage class is
`General` by default; alignment enforcement and backfill are off; stack spill is
on for input lists and off for output lists. `big_endian` is
`ParamListStandard::isBigEndian`, the byte order of the list's *first entry*,
not of its first tile. Most-significant-first consumption and right
justification default to it; `reversejustify` and `reversesignif` toggle a
default only when declared `true`.

Tiles are the exclusion entries of exactly the action's class with exactly one
resource group, in declaration order (`extractTiles`). Join pools and grouped
alternatives (one shared group) qualify. A list without tiles is `NoTiles`,
including a stack-only list. With spill enabled, the last entry must be an
aligned stack pool (`getStackEntry`), otherwise `MissingStack`. Both are
initialization errors, raised before any allocation and in that order.

### Allocation

- **Start search.** A tile can start the value if its status is exactly
  untouched. With alignment enforcement and a datatype alignment larger than
  the tile, the full widths of the tiles already passed must also be a multiple
  of that alignment. The source `checkFit` adjacency loop never advances its
  iterator: it repeats the start tile's own test. Its observable selection is
  therefore this single test (computed in constant work), not the stronger
  "adjacent unused tiles" check its comment describes. Each rejected tile adds
  its full width to the skipped count and, unless backfill is enabled, becomes
  consumed, even if it held a positive slot cursor.
- **Tiles.** From the start, each later untouched tile is taken at its *full*
  declared width until the value is covered. Tiles with any nonzero status are
  passed over unchanged, so a value can span gaps. The datatype alignment
  applies until the first tile is taken, then becomes one.
- **Stack.** Remaining bytes go to the stack pool at its cursor, justified by
  the action's `justifyRight` (an explicit left/right placement, not the pool's
  default). Disabled spill, or a stack placement that fails its minimum size or
  slots, is `NoFit` with the uncovered byte count.
- **Excess** can only come from the final tile. A `float` action that used
  exactly one tile records `FloatConversion` over that tile's whole container,
  with the raw size as logical width. Otherwise `justifyPieces` removes the
  excess from the first consumed tile when justifying right, else from the last.
  The kept slice starts `excess` bytes into the tile iff
  `big_endian ^ consume_most_significant ^ justify_right`.
- **Order.** Pieces are reported most significant first: consumption order,
  reversed unless the first consumed tile is most significant.

The result keeps the logical width, `JoinStorage::Pieces` (each `JoinPiece` has
its entry site, consumption step and a `PlacedPiece` with the physical range,
significance in the whole value, source piece/offset and role) or
`FloatConversion`. `steps` lists consumed tiles and the stack spill in
consumption order, with their groups, slot ranges and value bytes.
`skipped_tiles` and `excess` are also reported.

### Transactions and stricter policies

Success commits every change: taken tiles, skipped tiles and the stack cursor.
`NoFit` and every error restore the state exactly, including skipped tiles and
stack alignment holes, as upstream's `tmpStatus` copy does. This differs from
bare fallback, whose `NoFit` keeps holes.

Native code reuses resources or builds invalid storage in a few layouts. This
action refuses them and returns no partial allocation:

- **Held storage.** A taken tile holds its whole declared pool (every
  nonconstant join piece); the spill holds its used slots; skipped tiles hold
  nothing. Returning storage that overlaps held storage is `Overlap`. A used
  non-first group of the stack pool is `GroupInUse`, and a consumed first stack
  group is `Unsupported` (upstream would compute slots from status -1). These
  checks run only when the action would succeed, because a `NoFit` returns no
  storage. For a consumed first stack group, native minimum/capacity rejection
  is checked with its actual -1 cursor first; an invented cursor zero would
  incorrectly reject allocations that native would attempt. Native-int
  overflow during that check remains an explicit refusal.
- **Join-pool tiles.** Upstream nests the tile's join-space varnode in the new
  join. Here the tile contributes its own physical pieces in place, with the
  same significance; constant padding stays unheld padding. The following are
  `Unsupported`: truncating a join tile, a float conversion of a join or
  padding tile, a join tile narrower than its join storage, a floating-extension
  pentry tile inside a compound or truncated join, and truncating constant
  padding. An exact single floating-extension tile yields its conversion.
- **Invalid justification.** With variable-width tiles and right
  justification, the excess can equal or exceed the first piece. Upstream would
  then build a zero or wrapped width; this is `Unsupported` instead, and no
  multi-piece crop is guessed.
- **Domains and native ints.** A spill that leaves the signed stack domain is
  `Unsupported`, never wrapped. If alignment enforcement reads a skipped-byte
  count beyond `i32::MAX` (native signed overflow), that is also
  `Unsupported`; an unread count is never refused.
- **Representation.** `JoinRecord::mergeSequence` merges contiguous pieces that
  form a named register or stack range; pieces here stay unmerged, with the
  same bytes and significance. Zero-width tiles, which would never finish the
  source fit loop, are `InvalidDeclaration` (the parser rejects them first).

Byte order is inherited policy. Native ordinary spaces and the join space use
the translator's byte order, but native `OtherSpace` is explicitly little
endian. The per-space model maps the first entry: a register entry uses its
space (the SLEIGH source's global order in the adapter), a stack entry its
backing space, and a join or `OTHER` entry the default space. Tile placement
and join-piece traversal keep the per-space rules of `place_parameter`. Stack
slot alignment uses its exact congruence, which matches native floor division
for power-of-two alignments.

### Bounds and cost

`JoinLimits` bounds tiles (default 100,000), examined entries (4 million),
group references (8 million), journaled group updates (1 million), nested
placements (65,536), output pieces (65,536), occupied extents held after the
call (65,536), source pieces per nested placement (1,024) and work (64
million). Each nested placement gets only the remaining work and piece budget,
and its work is included. Every exhaustion is `JoinError::Limit(name)`, with a
nested output-piece limit reported as `"pieces"`. Invalid requests, state
mismatches, initialization errors, unsupported layouts, safeguard refusals and
invalid placement declarations are separate variants. Already-held extents are
bounded on entry.

Work charges, with `lookup(n) = bits(n) + 1`, are:

- 1 for the header, plus a binding and a space lookup for the list byte order.
- 1 per scanned entry and 1 per collected tile; a binding lookup checks the
  stack when spilling.
- 2 per tile visit in either loop (entry plus status read), and 1 per status
  write.
- For the spill: 1 status read, the nested placement and 1 write. A consumed
  first group instead adds 1 for the bounded native -1-cursor rejection check.
- For each taken tile: the nested placement, a binding lookup, the join-piece
  count for a bit-slice join pool, the held-span charges shared with fallback,
  and an occupied-extent lookup per held span.
- For the spill's safeguards: 1 per stack group, its spans and lookups.
- 1 per output piece for ordering and significance.

The action is iterative, has no recursion and allocates nothing per payload
byte. Its vectors are bounded by tiles and pieces, checked before growth.
Work is linear in tiles, plus logarithmic lookups.

### Validation evidence

`tests/join_action.rs` has 27 directed tests with hand-derived expectations.
They cover defaults and true-only toggles, the first-entry byte order in a
mixed-endian layout, and `RuleAction` attributes. They work all eight
byte-order/significance/justification combinations by hand. Further cases:
alignment skips, ARM-style float backfill, and positive cursors at and after
the start tile. Gaps, spills with the action's justification and the original
alignment, and the alignment reset after a register are covered. Each kind of
`NoFit` is checked for transactional rollback. So are float conversion versus
truncation, join and padding tiles, and every unmodeled join-tile refusal.
Variable-width excess, initialization and tile eligibility, invalid requests,
signed stack bounds and domain escapes are tested. So are overlap, group-in-use
and consumed-stack refusals, and the native-int refusal. Absolute work charges
(64, 87 and 20 units) are derived by hand. Every limit is checked at its exact
value and one below, every lower work budget fails, and each failure restores
the state. Two more tests check linear scaling over 1,000 versus 4,000 tiles,
and determinism and thread safety.

`tests/join_oracle.rs` transcribes the retained `checkFit` (including its
non-advancing loop), `assignAddress`, `justifyPieces`, `extractTiles`,
`getStackEntry`, `getAddrBySlot` (native floor division) and
`assignAddressFromPieces` over `int4` statuses and a fixture-owned layout. It
also models held extents independently. Over 6,000 generated layouts it
matched 18,044 requests in both byte orders, input and output lists and both
stack growth directions. The comparisons cover 6,514 assignments, 3,021 spills,
2,230 truncations, 358 float conversions, 2,541 start skips (626 with
backfill, 292 over positive cursors) and 272 gap spans. They also include
4,286 disabled-spill and 2,676 stack no-fits, 340 invalid justifications, and
2,888 no-tile and 1,340 missing-stack errors. Statuses and held byte extents
are compared after every request. The oracle covers single-range tiles; join
tiles are covered by the directed tests.

On builder commit `990469108e`, all 41 compiling mutations of `join.rs` were caught by
`join_action` and `join_oracle`. The mutations cover defaults and toggles, the
list byte order, tile and stack eligibility, the start search, backfill and
positive cursors, the alignment reset, stack justification and cursor, float
conversion, cropping, ordering, rollback, safeguards, budget charges and limit
classification.

Independent review at `3cfb331be8` returned **Changes requested: one verified
P2.** The consumed first stack group incorrectly masked a spill below its
minimum size. The fix preserves native minimum/capacity rejection using the
actual -1 cursor before refusing an allocation from that consumed group.
Regressions cover both stack growth directions, partial-slot rounding,
alignment, native-int overflow, whole-state rollback, later fallback and every
smaller work budget; the rejection path has a hand-derived 21-unit work pin.
The review also reran all five real probes and found no other blocking issue.
Its `OtherSpace` byte-order clarification is reflected above. A root-run copy
of the reviewer's original failing probe now passes. Ten additional compiling
mutations of the rejection preflight are caught, including a fake zero cursor,
wrong signed remainder/rounding, exact minimum/capacity boundaries, work charges
and native-int limits. The fixed tree's five real-profile probes pass on Rust
1.88 release too.

`tests/join_real.rs` is ignored by default; run
`cargo test --release -p ghidra-abi --test join_real -- --ignored`. It compiles
real SLEIGH register files and uses the parsed `<join>` rules after pinning
their attributes to the `.cspec` text:

- x86-64 Go `abi-internal`: input and output int128 joins.
- ARMv7 LE and BE `__stdcall`: float backfill, HFA and AAPCS core-register
  alignment, and output float and core joins.
- MIPS32 BE: struct `reversejustify`, scalar right justification, alignment
  and both stack justifications.
- AArch64 LE and BE `__cdecl`: `__int128` alignment and stack spill.

Expected registers come from retained entry order and compiled offsets. The
x86-64 Windows and GCC specs declare no `<join>` action, so they are not
probed. The five probes ran in about 3 s after a release build. These checks
cover the action, not the rule filters or dispatch.

Still required, for a full calling convention: rule matching and dispatch,
`pointermax`, hidden returns, `sharestack`, per-member joins, datatype-driven
`<join>` requests from the native graph, output-trial recovery
(`fillinOutputMap`) and SSA call effects. A source oracle for join tiles,
which upstream nests, is also missing.

## Native dual-class join action

`AllocationState::assign_dual_join(resources, &DualJoinAttributes,
Arc<NativeTypeGraph>, NativeTypeId, DualJoinLimits)` runs one native
`<join_dual_class>` rule action (`MultiSlotDualAssign`,
modelrules.cc:1213-1470) on an input or output state. It is the first
allocation operation driven by the converted native datatype graph: the raw
size (`getSize`), alignment (`getAlignment`) and primitives
(`PrimitiveExtractor`) all come from the graph, never from a caller-supplied
width or from P-code. `DualJoinAttributes::from_action` adapts a parsed
`RuleAction::JoinDualClass`. No rule filter, precondition or prototype is
consulted; this is not rule dispatch.

```rust
use std::sync::Arc;
use ghidra_abi::*;
use ghidra_languages::{CompilerSpec, DataOrganization};
use ghidra_pcode::{AddressSpace, Endianness, SpaceId, SpaceKind};
use ghidra_types::{Composite, Field, MinimumAlignment, Packing, TypeDefinition, TypeId,
    TypeKind, TypeLayouts};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let space = |id, name: &str, kind| AddressSpace { id: SpaceId(id), name: name.into(),
    kind, address_size: 4, word_size: 1, endianness: Endianness::Little };
let registers = [("r0", 0), ("d0", 0x10), ("sp", 0x20)].iter().map(|&(name, offset)|
    RegisterDefinition { name: name.into(), space: SpaceId(1), offset, size: 8 }).collect();
let file = Arc::new(RegisterFile::new(vec![space(0, "ram", SpaceKind::Ram),
    space(1, "register", SpaceKind::Register)], SpaceId(0), registers,
    Default::default())?);
let spec = CompilerSpec::parse_str(r#"<compiler_spec>
<stackpointer register="sp" space="ram"/><default_proto>
<prototype name="p" extrapop="0" stackshift="0"><input>
<pentry minsize="1" maxsize="8" storage="float"><register name="d0"/></pentry>
<pentry minsize="1" maxsize="8"><register name="r0"/></pentry>
<rule><datatype name="any" maxsize="16"/><join_dual_class/></rule>
</input><output/></prototype></default_proto></compiler_spec>"#,
    None, &Default::default())?;
let action = DualJoinAttributes::from_action(&spec.prototypes[0].input.rules[0].action)
    .expect("a <join_dual_class> action");
let storage = CompilerStorage::new(Arc::new(spec), file, Default::default())?;
let resources = CompilerResources::new(Arc::new(storage), Default::default())?;
// struct { double d; long l; }, decoded as the native decompiler sees it.
let pair = Composite { fields: vec![Field::new("d", TypeId(0)), Field::new("l", TypeId(1))],
    packing: Packing::Default, minimum_alignment: MinimumAlignment::Default };
let layouts = Arc::new(TypeLayouts::new(vec![
    TypeDefinition::new("double", TypeKind::Float { bytes: 8 }),
    TypeDefinition::new("long", TypeKind::Integer { bytes: 8, signed: true }),
    TypeDefinition::new("pair", TypeKind::Structure(pair)),
].into(), DataOrganization::default().resolve(4), Default::default())?);
let map = NativeAlignmentMap::from_organization(layouts.organization(), Default::default())?;
let graph = Arc::new(NativeTypeGraph::new(layouts, &map, Default::default(),
    Default::default())?);
let mut state = AllocationState::new(&resources, 0, ParameterDirection::Input,
    Default::default())?;
let result = state.assign_dual_join(&resources, &action, graph.clone(),
    graph.native(TypeId(2))?, Default::default())?;
let DualJoinOutcome::Assigned(allocation) = &result.outcome else { unreachable!() };
let JoinStorage::Pieces(pieces) = &allocation.storage else { unreachable!() };
// The double's window took d0 and the long's took r0. Little endian lists the
// most significant piece (r0) first.
let layout: Vec<_> = pieces.iter().map(|p| (p.piece.storage.address.offset,
    p.piece.lsb_byte)).collect();
assert_eq!(layout, [(0, 8), (0x10, 0)]);
assert!(Arc::ptr_eq(&result.graph, &graph));
# Ok(())
# }
```

### Configuration and initialization

`DualJoinAssignment::config` reports the resolved fields. The constructor
defaults are a `General` base class, a `Float` alternate class, no stack spill
for input *and* output lists (unlike `<join>`), and no fill-alternate.
Most-significant-first consumption and right justification default to the
list byte order, which is the same first-entry policy and shared helper as
`<join>`. `reversejustify` and `reversesignif` toggle only when declared
`true`. `storage` and `a` are synonyms. The `ghidra-languages` parser follows
native decode: the later attribute wins, and every declared value must decode.

`initializeEntries` runs in one scan. Each tile list holds the exclusion
entries of exactly its class that have exactly one resource group, in
declaration order (`extractTiles`). Equal base and alternate classes put an
entry in both lists. Zero or over-`i32::MAX` tile widths are
`InvalidDeclaration` during the scan, as for `<join>`. Then come `NoTiles`
(the base class is checked first) and `TileSizeMismatch`, which compares only
the *first* base and alternate widths and records `tile_size`. Last is
`MissingStack`, raised only with spill enabled when the last entry is not an
aligned stack pool (`getStackEntry`; `align == maxsize` decodes to an
exclusion entry, which is not a pool). These initialization errors retain that
source order. The API first validates the supplied datatype ID, conversion and
byte order; extraction follows initialization.

### Datatype and primitives

The root is extracted with `PrimitiveExtractor(dt, false, false, 0, 1024)`.
Unions are legal, arrays are expanded and 1,024 primitives per context is the
semantic maximum. An invalid extraction (including the 1,025th primitive),
then an empty one, then one with holes is a `NoFit` that carries the
extractor's reason. None of these is a fabricated layout or an error. As in
the source, `containsUnknown` and `aligned` are not tested. In the native
extractor an unaligned structure field always also makes a hole, so an
unaligned primitive is accepted only where a union dropped its member's
flags. Non-byte bitfields are invisible and leave holes; byte-range bitfields
are ordinary primitives. Extraction runs on the remaining shared work budget,
with its own live-primitive and depth limits.

The result keeps the `Arc<NativeTypeGraph>` it was given (compared by
identity), the root ID and the extracted primitives with their native IDs and
offsets, so every ID in a result or `NoFit` reason stays interpretable.
Unknown IDs and failed conversions are `DualJoinError::Type`.

### Windows and tiles

The loop walks windows of exactly `tile_size` bytes from offset
`typeSize - sizeLeft`. `getTileClass` fails (`DualJoinNoFit::Window`) when no
primitive is left, when the next primitive starts before the window, when a
primitive's *raw* extent (`getSize`, not the aligned size) crosses the window
end, or when no primitive starts inside the window. A window is alternate only
if every primitive in it maps to the alternate class under
`metatype2typeclass`: `Float` is float, `Ptr` is ptr, and everything else,
including Unknown, Code, Bool, enums and integers, is general. With
`fillalternate`, an alternate window must also hold exactly one primitive
whose raw size equals `tile_size`.

The window's class is chosen before its list is searched. `getFirstUnused`
keeps one cursor per list and skips any nonzero status, positive slot cursors
included, without changing it. A shared group consumed through one list, as in
MIPS64's float/general `<group>` pairs, is therefore skipped in the other.
Each chosen tile is consumed (its group to -1) at its full declared width, and
the offset advances by that width. Later tiles may be narrower or wider than
`tile_size`, since the source checks only the first widths. This is modeled
exactly: windows keep `tile_size`, so a wider tile can leave the next
primitive before the window (`StartsBeforeWindow`). Step provenance
(`first_primitive..primitive_end`) is the window's classification, not
physical containment.

### Exhaustion, spill, excess and order

If the chosen class has no unused tile, the action is `DualJoinNoFit::Exhausted`
without spill. With spill it does not switch classes: the *entire* remaining
suffix goes to the stack pool. The stack uses the datatype's own alignment
(not one) and the action's justification. Native `getAddrBySlot` floor
division is reproduced for the slot waste, so an alignment that is not a
power of two wastes exactly the native slots. (`<join>` uses exact congruence;
the two agree for power-of-two alignments.) A stack minimum or capacity
rejection is `DualJoinNoFit::Stack`. A consumed first stack group keeps the reviewed
`<join>` priority: native rejection with the actual -1 cursor first, then an
`Unsupported` refusal if native code would allocate from it.

Excess bytes arise only when the tiles overrun the value without a spill.
`justifyPieces` removes them from the first piece when justifying right, else
from the last, starting `excess` bytes in iff `big_endian ^
consume_most_significant ^ justify_right`. Unlike `<join>` there is no
floating-extension shortcut: a 4-byte float in an 8-byte float tile is a 4-byte
slice of that register. Pieces are reported most significant first
(`assignAddressFromPieces`), reusing `JoinPiece` and `JoinStorage`; steps are
in consumption order with class, list position, offset, value bytes and the
stack slot range.

### Transactions and stricter policies

Success commits every status change and held extent; `NoFit` and every error
restore the state through a bounded journal, never a cloned state. The
following are refused with no partial allocation. The refusals run only when
the action would otherwise succeed, so they never mask a source `NoFit`.

- **Held storage.** A tile holds its whole declared pool, not just the cropped
  bytes, and the spill holds its used slots. Resource groups alone do not
  prevent physical aliasing: two join tiles sharing a register, or a tile
  whose bytes an aligned pool already holds, have distinct groups. Returning
  such storage is `Overlap`; a used non-first stack group is `GroupInUse`.
- **Join-pool tiles** contribute their own physical pieces in place, with
  constant padding kept as unheld padding. Truncating a join tile, a join
  tile narrower than its join storage, and a floating-extension join tile
  inside a compound or truncated value are `Unsupported`. An exact single
  floating-extension tile is that recorded conversion. Excess at least as
  large as the justified piece, possible only when justifying right and a
  later tile is wider than the first one, is `Unsupported` rather than a zero
  or wrapped width.
- **Native ints.** A window or primitive end beyond `i32::MAX`, or stack slot
  arithmetic beyond it, is a refusal, never a wrapped value. Window-end
  arithmetic precedes primitive exhaustion, and stack cursor addition precedes
  capacity rejection, matching the order in which native code evaluates them.
- **Snapshot.** The state must belong to the same `CompilerResources`
  overlay (`StateMismatch`). A graph whose layouts declare a byte order other
  than the language's default space is `ByteOrderMismatch`; its byte-range
  bitfield offsets would describe another byte order. The native decompiler
  has one architecture, so it cannot mismatch here.

### Bounds and cost

`DualJoinLimits` bounds tiles in both lists together (default 100,000),
examined entries (4 million), `getTileClass` primitive visits (4 million),
group references (8 million), journaled group updates (1 million), nested
placements (65,536), output pieces (65,536), occupied extents held after the
call (65,536), source pieces per nested placement (1,024), extraction live
primitives (1 million), extraction depth (100,000) and work (64 million).
Each limit is `DualJoinError::Limit(name)` with the field's resource name, a
nested output-piece limit as `"pieces"` and extraction limits as `"extraction
live primitives"`/`"extraction depth"`. Already-held extents are bounded on
entry. Other error classes are separate variants.

Work charges, with `lookup(n) = bits(n) + 1`, are:

- 1 for the header, 1 for the datatype, a space lookup when the graph declares
  a byte order, and a binding and a space lookup for the list byte order.
- 1 per scanned entry plus 1 per list membership; a binding lookup checks the
  stack when spilling.
- The nested extraction's own work.
- 1 per window, 1 per primitive visit, 2 per tile visit (entry plus status
  read) and 1 per status write.
- For the spill: 1 status read, 1 for the native cursor (or -1 rejection), the
  nested placement and 1 write.
- For each tile: the nested placement, a binding lookup, the join-piece count
  for a join pool, the held-span charges and an occupied lookup per span.
- For the spill's safeguards: 1 per stack group, its spans and lookups.
- 1 per output piece for ordering and significance.

The action is iterative and allocates nothing per payload byte. Its vectors
(tiles, choices, steps, pieces) are bounded by checked counts before growth.
Work is linear in entries, tiles, windows and primitive visits, plus
logarithmic lookups.

### Validation evidence

`tests/dual_join_action.rs` has 27 directed tests with hand-derived
expectations, covering:

- Defaults, true-only toggles and parsed `storage`/`a`/`b` attributes, and
  independent base and alternate cursors over mixed scalar structures.
- Every `metatype2typeclass` class: pointer as base or as the alternate,
  Unknown, Bool, enum, Code and aliases, with containsUnknown accepted. Union
  refinement, and an unaligned packed member accepted through a union.
- Fill-alternate on counts and on the raw size, and raw versus aligned sizes
  with a 10-byte float (16-byte tiles crop 6 bytes; 12-byte windows accept
  what the aligned extent would cross).
- Holes from a non-byte bitfield, empty, void, empty and incompatible unions,
  and exactly 1,024 versus 1,025 primitives.
- All four window rejections, and later tiles narrower and wider than
  `tile_size`.
- The 8-way byte-order, significance and justification matrix, the first
  entry's byte order in a mixed-endian layout, and the graph byte-order
  mismatch.
- Independent class exhaustion with the whole suffix spilled, and window
  failures that precede exhaustion.
- MIPS-style shared groups, kept positive cursors and double ownership.
- Stack minimum, capacity, type alignment 16 and a native floor-division
  alignment of 12, and four consumed-cursor cases (minimum, refusal, and
  alignment-driven exhaustion).
- Join and padding tiles, floating-extension tiles and a shared-register
  overlap, plus initialization, ID, conversion and state errors.
- Rollback after partial success.
- Absolute work pins derived by hand: 78 for `{double, long}` over d0/x0 and
  115 for `{double, long, long}` spilling one doubleword. Every smaller work
  budget fails with the state unchanged.
- Every limit at its usage and one below, including extraction live/depth
  and nested source pieces, and the held-extent cap on entry.
- 4x scaling (200 to 800 tiles and primitives) within 4x-5x work, plus
  determinism, thread safety and graph identity.

`tests/dual_join_oracle.rs` transcribes `PrimitiveExtractor` (recursively,
with `handleUnion`, `commonRefinement` and `checkOverlap`, over the public
graph accessors), `initializeEntries`, `getFirstUnused`, `getTileClass`,
`assignAddress`, `justifyPieces`, `extractTiles`, `getStackEntry`,
`getAddrBySlot` (native floor division) and `assignAddressFromPieces` over
`int4` statuses. It also independently models held extents and the refusal
order. It never calls the production extractor, placement or the action's
helpers. Over 8,000 generated layouts it compared 35,776 calls. The layouts
cover both byte orders, input and output lists, both growth directions,
MIPS-style declared pairs, aligned pools with seeded cursors and random graphs
of scalars, structures, packed structures, arrays, unions, aliases and
bitfields. The results include 12,800 assignments (242 with both classes,
2,005 with heterogeneous widths, 1,087 spills, 6,287 crops, 690
fill-alternate demotions, 87 shared-group skips and 290 positive-cursor
skips). They also include every window rejection, both exhaustion classes,
stack no-fits, invalid/empty/holey extractions, initialization errors, 54
invalid justifications, 195 overlaps and 1,049 datatype errors. Primitives,
pieces, steps, statuses and held extents are compared after every call.

Forty-six compiling mutations of `dual.rs` were run against `dual_join_action`
and `dual_join_oracle`; the source was restored and hash-checked after each
run, and 45 were caught. The caught mutations cover:

- Defaults and toggles, `metatype2typeclass`, the four window checks, raw
  versus aligned sizes, the fill-alternate size test and empty windows.
- The initial class, positive cursors, independent list cursors and advancing
  by the tile's own width.
- Stack alignment (including native floor division versus exact congruence),
  the consumed-cursor alignment, and the stack cursor and justification.
- Cropping, ordering and rollback.
- Extraction options and the 1,024 maximum, the hole gate, an added unknown
  gate, whole-suffix spill, tile eligibility and initialization errors.
- Held extents, work charges, the byte-order check, provenance and the
  held-extent cap.

The survivor changes fill-alternate's `count > 1` to `count > 2`, and it is
equivalent. `decodeField` drops a field that starts before the previous raw
end, array strides are aligned sizes and refinement never overlaps. So a
window whose first primitive has raw size `tile_size` holds exactly one
primitive, and any window with two primitives already fails the size test.

`tests/dual_join_real.rs` is ignored by default; run
`cargo test --release -p ghidra-abi --test dual_join_real -- --ignored`. It
compiles real SLEIGH register files, pins the parsed `<join_dual_class>`
attributes to the `.cspec` text, and converts C declarations with each spec's
own data organization:

- x86-64 GCC `__stdcall` (bare `<join_dual_class/>`). `{double, long}` is
  XMM0_Qa then RDI, and `{float, float, int, int}` is XMM1_Qa then RSI.
  `{float, int}` is RDX, `{float}` is the low four bytes of XMM2_Qa, and
  `{long, double}` is RCX then XMM3_Qa. `{long double}` crosses the first
  eightbyte and is a `NoFit`. A value that exhausts XMM0-7 is a `NoFit` that
  changes nothing. Outputs use XMM0_Qa/XMM1_Qa and RAX/RDX.
- MIPS64 BE and LE `__stdcall` (`stackspill`, `fillalternate`, BE
  `reversejustify`). `{double, long}` is f12 then a1, because f12 consumed
  a0's group. `{float, float}` is general under fill-alternate. `{int}` and
  `{float}` use a0's first four bytes: the most significant half on big
  endian, the least significant on little. Nine doubles are f12-f19 plus 8
  stack bytes at offset 0, and ten longs are a0-t3 plus 16 stack bytes.

Expected registers come from retained entry order, `<group>` structure and
compiled offsets, and byte significance from the declared byte order. The
results match the SysV x86-64 eightbyte classification and the MIPS N64 rule
for these types. The probes run in about 1.3 s after a release build. They
cover only the listed pairs and types, not processor-wide parity or rule
dispatch.

Still required for a full calling convention: output-trial recovery
(`fillinOutputMap`), rule matching and dispatch with preconditions and side
effects, `pointermax`, hidden returns, per-member joins
(`join_per_primitive`), whole-signature allocation, `sharestack`, SSA call
effects and desktop exports.

Independent re-review approved `51850a14ba` after the two native-int
evaluation-order fixes, with no correctness defects. It checked the action,
shared helpers and ordered compiler-spec aliases against retained native and
Java source. It reran the 25 then-current directed tests, the 35,776-case
reference, three real profiles, compiler-spec hardening and scoped Clippy.
Five external probes additionally checked inclusive signed-int spill limits,
alignment overflow versus minimum-size rejection, swapped classes, attribute
order and the wider-later-tile crop refusal. Spills ending exactly at
`i32::MAX` and that crop refusal now have directed regressions in this crate.
This is source/probe evidence, not a
live Java or native decompiler comparison.

## Native fallback primitive

`AllocationState::assign_native_fallback(&resources, NativeFallbackRequest,
FallbackPolicy, NativeFallbackLimits)` runs native
`ParamListStandard::assignAddressFallback` (fspec.cc:731-758) for one value
and evaluates `ParamEntry::getAddrBySlot` (fspec.cc:453-494) with the source's
own arithmetic. It is the explicit fallback primitive: no model rule or
`pointermax` runs, so it is not `assignAddress`, which tries rules first. It
is the foundation for per-member rule actions (`MultiMemberAssign`), which
are not implemented. The published `assign_fallback`, `assign_pool` and
`place_parameter` keep their exact-congruence alignment and their results.

```rust
use std::sync::Arc;
use ghidra_abi::*;
use ghidra_languages::{CompilerSpec, StorageClass};
use ghidra_pcode::{AddressSpace, Endianness, SpaceId, SpaceKind};
# fn main() -> Result<(), Box<dyn std::error::Error>> {
let space = |id, name: &str, kind| AddressSpace { id: SpaceId(id), name: name.into(),
    kind, address_size: 4, word_size: 1, endianness: Endianness::Little };
let registers = vec![RegisterDefinition { name: "sp".into(), space: SpaceId(1),
    offset: 0, size: 4 }];
let file = Arc::new(RegisterFile::new(vec![space(0, "ram", SpaceKind::Ram),
    space(1, "register", SpaceKind::Register)], SpaceId(0), registers,
    Default::default())?);
let spec = CompilerSpec::parse_str(r#"<compiler_spec>
<stackpointer register="sp" space="ram"/><default_proto>
<prototype name="p" extrapop="0" stackshift="0"><input>
<pentry minsize="1" maxsize="64" align="8"><addr space="stack" offset="0"/></pentry>
</input><output/></prototype></default_proto></compiler_spec>"#,
    None, &Default::default())?;
let storage = CompilerStorage::new(Arc::new(spec), file, Default::default())?;
let resources = CompilerResources::new(Arc::new(storage), Default::default())?;
let mut state = AllocationState::new(&resources, 0, ParameterDirection::Input,
    Default::default())?;
let mut place = |size, align| state.assign_native_fallback(&resources,
    NativeFallbackRequest::new(size, align, StorageClass::General),
    FallbackPolicy::default(), NativeFallbackLimits::default());
place(8, 8)?;
// Cursor 1, type alignment 12: (1 * 8) % 12 = 8, and (12 - 8) / 8 = 0 slots.
let result = place(12, 12)?;
let NativeFallbackOutcome::Assigned(value) = &result.outcome else { unreachable!() };
assert_eq!(value.slots, Some(SlotRange { first: 1, next: 3 }));
assert_eq!(state.groups(), [GroupState::Available { used_slots: 3 }]);
# Ok(())
# }
```

### Request and selection

A `NativeFallbackRequest` holds the native `getAlignSize()` as
`aligned_size`, `getAlignment()` as `alignment` (each in `1..=i32::MAX`) and
an explicit class. The raw `getSize()` is not part of the request:
`NativeFallbackRequest::for_type(&NativeType, class)` copies the two native
widths, and a raw-three/aligned-four enum is requested as four bytes. In an
eight-byte big-endian register it lands at `base+4`; re-requesting its raw
width would move it to `base+5`. Callers that emit only raw bytes must keep
this placement's address. The class is never derived from a metatype here.

Every list entry is visited in declaration order, whatever its kind:
exclusion registers and stack slots, joins, aligned register pools and stack
pools. An entry whose *first* group is consumed is skipped before the class
test. `ClassMatch::Exact` (`matchExact == true`, as `MultiMemberAssign` with
declared storage and `ConsumeAs` use) needs the requested class;
`GeneralAcceptsAny` also lets a `General` entry take any class. The audited
native callers are `assignAddress`'s metatype fallback (fspec.cc:784, not
exact), `MultiMemberAssign` with declared storage (modelrules.cc:1146, exact
unless its stack flag is set), `ConsumeAs` (modelrules.cc:1486, exact) and
`HiddenReturnAction` (modelrules.cc:1868, `hiddenret` class, not exact). A
tried candidate then follows the source order:

1. A width below the minimum is rejected before anything else.
2. An exclusion entry rejects a nonzero cursor, then a width above its
   maximum. A declared float extension with a smaller width becomes a
   `FloatConversion` of the whole container, before (and instead of)
   justification.
3. An aligned pool with a type alignment larger than its own computes
   `(cursor * pool_alignment) % type_alignment` and adds the
   *floor-divided* waste `(type_alignment - remainder) / pool_alignment`.
4. The value's slots are ceiling-divided and `cursor + slots` is evaluated
   before it is compared with the capacity. A rejected candidate writes its
   waste back to the status, as the source's status reference does, and the
   scan continues.
5. Only after a fit are the slot index (counted from the pool end for
   positive growth), physical storage, justification and next cursor
   computed, through `place_parameter` at the already aligned cursor with
   relative alignment one.

Floor division can differ from the exact-congruence placement policy only
when the type alignment is larger than the pool alignment but not a multiple
of it. With pool alignment 8, type alignment 12 and cursor 1, native waste is
`(12 - 8) / 8 = 0`, so the cursor stays 1 (byte 8, not a multiple of 12).
The published fallback moves it to cursor 3. Power-of-two alignments, and
type 12 in a 4-byte pool, agree. Success consumes every group of an exclusion
entry, or advances only the first group's cursor of an aligned pool.

### Native int range

The aligned-branch operations of `getAddrBySlot` are checked against
`i32::MAX` where the source evaluates them. An overflow is
`NativeIntRange { site, operation }` with a `NativeSlotOverflow` of
`CursorBytes` (`slotnum * alignment`), `AlignedCursor` (`slotnum` plus waste)
or `CursorPlusSlots`, never a capacity `NoFit` and never a wrapped value.
Results equal to `i32::MAX` are allowed: a cursor plus slots of exactly
`i32::MAX` can still fit a pool of `i32::MAX` one-byte slots. A fourth
variant, `Cursor`, refuses a status the native `int4` cannot hold; only the
exact-congruence APIs can leave one (for example `u32::MAX` after a failed
fit), and it is refused where aligned arithmetic would read it. Everything
the source tests first wins: the consumed and class gates, an earlier fit,
the minimum, and an exclusion entry's nonzero-cursor test. Requests outside
`1..=i32::MAX` are `InvalidRequest`. Declared geometry outside the int range
and positive-growth pools that are not a whole number of slots are refused by
resource construction; the kernel repeats both checks, for tried candidates
only, as `InvalidDeclaration`.

### Results, transactions and stricter policies

The owned, `Send`, `Sync` and serializable `NativeFallbackAssignment` records
the model and direction, the request and policy, every rejected candidate
(entry, site, first group, cursor before and after, and the `NoFit` reason),
the outcome and the unexecuted declarations. `Assigned` gives the entry,
site, first group, exclusion flag, cursor, slot range, alignment waste and
the unchanged `PlacedValue` (pieces with provenance, constant padding, or a
float conversion with the aligned width as logical size). `NoFit` is the
source's `fail`; it is not a void return or hidden-return decision.

`Assigned` commits the selected storage and every earlier candidate's waste.
`NoFit` keeps the waste, matching the source status array and the published
fallback. Every error restores the entire query, including waste written by
earlier candidates. With the default `DeclaredRules::Reject`, a list that
declares rules or `pointermax` is `RulesNotExecuted`; `BypassUnexecuted` runs
the primitive and reports `UnexecutedDeclarations`.

The selected entry passes the same safeguards as the published fallback,
where native code would reuse resources or wrap addresses instead:
`GroupInUse` (another group of the entry is not untouched), `Overlap` (the
held exclusion pool or used slots share a byte with held storage),
`Unsupported` for a value leaving its address domain or an aligned join
pool, and `Placement` for declarations `place_parameter` refuses, such as a
partial floating join or little-endian reverse stack justification.
Per-space byte order, join slicing, signed stack coordinates and float
containers are `place_parameter`'s policies. These checks run only for the
candidate that fits, so a rejected or skipped candidate never exposes them.

The crate-private kernel behind this API takes the caller's budget, undo
journal and rejection vector. It charges one request per call, journals every
status write and extent, and never rolls back by itself. It neither reads nor
gates on declared rules. A per-member action can therefore run it for each
member under one budget and restore all members, including the waste of a
failed member, with one rollback; it needs no state clone per member.

### Bounds and cost

`NativeFallbackLimits` bounds examined entries (default 4 million), group
references (8 million), journaled group updates (1 million), nested
placements (4,096; at most one per call), output pieces (65,536), occupied
extents held after the call (65,536, also checked on entry), source pieces of
the nested placement (1,024) and work (64 million). The nested placement
receives only the remaining work and pieces. Every exhaustion is
`NativeFallbackError::Limit(name)`; a nested output-piece limit is reported as
`"pieces"`. Invalid requests and declarations, state mismatches, native-int
overflow, safeguard refusals and placement errors are separate variants.

Work charges, with `lookup(n) = bits(n) + 1`, are 1 for the call, 1 for the
request, 2 per examined entry (visit and first-group read), 1 per tried
candidate and 1 per waste write. A fit adds the nested placement's work, 1
per group of the entry, the held-span charges shared with fallback, an
occupied-extent lookup per held span, and 1 per status write. The scan is
linear in entries, with logarithmic lookups; there is no recursion, dense
state copy, or allocation per payload byte. Rejection records are bounded by
examined entries.

### Validation evidence

`tests/native_fallback.rs` has 13 tests with hand-derived statuses and
addresses: floor versus exact alignment (type alignments 12 and 6, and
positive growth), retained holes on a later success and on `NoFit`,
below-minimum and class gates before a `CursorBytes` overflow, overflow
before capacity at `i32::MAX` and one above for every operation, a fit ending
exactly at `i32::MAX`, exact versus General matching, declaration order, the
first-group gate and `GroupInUse`, exclusion, multi-group join, aligned
register and stack pools, big-endian and reverse justification, output
lists, raw versus aligned width and float conversion. Every refusal restores
the state, including a late domain error after an earlier candidate's waste.
One representative call pins all usage counters and 36 work units, derived
term by term; every cap passes at its exact value and fails one below, and
every smaller work budget fails without side effects. Work grows by two units
per added entry. Three kernel unit tests check one shared budget and journal
across members with full rollback, the request cap across calls, that a
declared `pointermax` is not gated, defensive declaration checks only for
tried candidates, and the slot arithmetic boundaries.

`tests/native_fallback_oracle.rs` transcribes the two source functions over
its own declarations, with a signed status array, floor-division waste and
checked `int4` operations, and computes values, held extents and safeguards
in interval form. Over 5,000 generated layouts (4,269 valid) with
non-power-of-two pool and type alignments, huge cursors and sizes, alias
groups, joins with padding, both byte orders and both growth directions, it
matched 10,494 assignments and 7,712 no-fits with every rejection record,
plus 387 native-int refusals, 303 domain, 152 group-in-use and 125 overlap
refusals. Group status and held extents are compared after every step.

`tests/native_fallback_real.rs` is ignored by default; run
`cargo test --release -p ghidra-abi --test native_fallback_real -- --ignored`.
It compiles AArch64 v8A and MIPS64 big-endian and probes their
`join_per_primitive` lists with bypassed rules: exact-class float members in
`q0..q7` and `f0`/`f2`, General acceptance, minimum rejections, shared
float/integer groups, right-justified big-endian registers and stack slots,
stack alignment waste, and a 24-byte struct placed on the stack where the
bypassed `convert_to_ptr` rule would pass a pointer. The two probes took
about 3 s after a release build.

In a scratch copy outside the repository (fresh source timestamps; this
crate's file hashes checked unchanged afterwards), all 19 compiling mutations
were caught: floor-division waste made ceiling or removed, the published
exact-congruence step reintroduced, failed-candidate waste not written or
misreported, slot arithmetic moved before the minimum, the exclusion maximum
tested before its cursor, an `i32::MAX` check removed or made exclusive,
missing rollback, General acceptance removed, partial exclusion consumption,
the other-group safeguard removed, an uncharged candidate, an unnormalized
nested piece limit and an unbounded held-extent preflight. The interpreter
alone catches 14 of them. Two mutations of the shared slot arithmetic and of
the dual-class spill's error mapping are caught by the unchanged dual-class
tests. Moving the consumed test after the class test is not observable (both
only skip an entry), so it has no mutation.

Independent review approved `48c91d72ac` at the integrated `259f6159da`
checkpoint, with no required changes. It reran the default ABI tests and
both real native-fallback probes, then added six external probes covering
4,466 arithmetic comparisons, all nine storage classes, word-size/endian
boundaries and 65 multi-span budget/rollback cases. This is source-derived
review evidence, not execution against the native C++ decompiler.

### Remaining work

The per-member action itself is not implemented: extraction gates, raw-width
emission and padding, significance reversal, nested conversions, the
stack-status guard and omitted-storage recursion. Omitted storage needs full
rule dispatch over synthesized `NativeTypeId` objects and must not be
replaced by this fallback. Rule dispatch, `pointermax`, hidden returns and
signature allocation also remain.

## Native primitive alignment

`NativeAlignmentMap` ports the retained C++ `TypeFactory` alignment decoder and
primitive geometry, independently of Java's datatype layout rules. It uses
sorted sparse breakpoints rather than the native vector indexed by byte size;
a key at `i32::MAX` therefore requires two records, not billions of slots.

`new(None, limits)` selects the native 1/2/4/8 defaults. `new(Some(entries),
limits)` imports exactly those records, with no added positive-size defaults.
Duplicates are last-wins, alignment at size zero is always one, gaps inherit
the preceding value and sizes beyond the final key use its value. An explicit
empty map is an error. Positive-size entries require positive alignments;
sizes/alignments outside signed-int range fail instead of invoking native
overflow or division-by-zero behavior.

`from_organization(&resolved, limits)` models the compiler-organization bridge.
`DecompInterface.initializeProcess` calls `compilerSpec.encode`, and
`DataOrganizationImpl.encode` emits the complete resolved nonempty map,
including Java's seeded entries. An empty organization map is omitted and
selects native defaults. Passing only a compiler spec's raw override vector
to `new` is a standalone native-map decode, not this resolved bridge.

`primitive_geometry(size)` first rounds the raw size using its map alignment,
then queries alignment again at that rounded size. Native pointer and enum
objects use this primitive path too. Java's absolute alignment cap, default
alignment and default pointer alignment do not enter this calculation. This
is a two-lookup rule, not repeated rounding until alignment stabilizes. The
result must remain within positive signed-int size, with zero yielding
void-compatible `(0,0,1)` geometry. Queries allocate nothing, use logarithmic
lookup and leave construction usage unchanged.

Construction bounds declaration count (including duplicates) and work before
protected visits/allocations. Fixed defaults take five records and six work
units even when the declaration cap is zero. Declared maps take `O(N log N)`
time and `O(N)` storage; no storage is proportional to the largest size key.
This is a native geometry component, not a converted native datatype graph,
type factory, decompiler or calling-convention allocator.

```rust
use ghidra_abi::{NativeAlignmentMap, NativeAlignmentError};
use ghidra_languages::{DataOrganization, SizeAlignment};

let organization = DataOrganization::default().resolve(8);
let bridge = NativeAlignmentMap::from_organization(&organization, Default::default())?;
assert_eq!(bridge.primitive_geometry(3)?.aligned_size, 4);
let raw = NativeAlignmentMap::new(Some(&[SizeAlignment { size: 4, alignment: 2 }]),
    Default::default())?;
assert_eq!(raw.alignment(2), 1); // A raw native map does not add Java's seeded keys.
# Ok::<(), NativeAlignmentError>(())
```

Ten directed tests cover decoder defaults versus explicit maps, the resolved
bridge, raw/padded alignment lookup, signed-int bounds, sparse huge keys, exact
construction budgets and immutable ownership. Independent dense-table and
declaration-scan references compare 5,047 maps and 6,863,920 alignment/geometry
answers, including all 107 retained specs and 321 resolved organization inputs.
These are source-derived Rust oracles; no C++ or Java process was run.

## Native datatype graph

`NativeTypeGraph::new(Arc<TypeLayouts>, &NativeAlignmentMap, NativeTypeOptions,
NativeTypeLimits)` converts every declared type into the form the retained
native decompiler decodes after Java transport: `PcodeDataTypeManager`'s
encoders followed by the `TypeFactory` decoders in `type.cc`. It is a separate
view. `TypeLayouts`, `DatatypePredicates` and `PrimitiveExtraction` keep their
Java semantics, defaults, work charges and callers; nothing is reinterpreted.
The graph retains the original `Arc<TypeLayouts>` and an owned copy of the
alignment map, and is `Clone + Send + Sync`. The map is an explicit input:
`NativeAlignmentMap::from_organization(layouts.organization())` models the
Java bridge, while `NativeAlignmentMap::new` is a standalone native decode.

```rust
use std::sync::Arc;
use ghidra_abi::{NativeAlignmentMap, NativeTypeGraph, NativeTypeId};
use ghidra_languages::{DataOrganization, MetaType};
use ghidra_types::{TypeDefinition, TypeId, TypeKind, TypeLayouts};

let layouts = Arc::new(TypeLayouts::new(vec![
    TypeDefinition::new("f32", TypeKind::Float { bytes: 4 }),
    TypeDefinition::new("alias", TypeKind::Alias(TypeId(0))),
    TypeDefinition::new("void", TypeKind::Void),
    TypeDefinition::new("fn", TypeKind::Function { result: TypeId(2),
        parameters: vec![], variadic: false }),
].into(), DataOrganization::default().resolve(8), Default::default())?);
let map = NativeAlignmentMap::from_organization(layouts.organization(), Default::default())?;
let graph = NativeTypeGraph::new(layouts, &map, Default::default(), Default::default())?;
let alias = graph.get(graph.native(TypeId(1))?)?;
assert_eq!((alias.alias_of, alias.canonical), (Some(NativeTypeId(0)), NativeTypeId(0)));
let code = graph.get(graph.native(TypeId(3))?)?;
assert_eq!((code.meta, code.size, code.aligned_size), (MetaType::Code, 1, 1));
# Ok::<(), Box<dyn std::error::Error>>(())
```

### Identity contract

- `NativeTypeId(i)` for `i` below the source count is the decoded form of
  `TypeId(i)`. Distinct source IDs denote distinct source datatype objects and
  always produce distinct native objects; nothing is merged by width or
  structure, so two `Float { bytes: 4 }` definitions are different HFA
  identities. A caller wanting two uses to share an identity must reference
  one source definition.
- A converted alias is a typedef clone with its own identity and origin. It
  copies meta-type, geometry and the enum flag; `alias_of` is the immediate
  target (`typedefImm`) and `canonical` the first non-alias object. Its shape
  is the canonical object's ranges into shared field storage, so an alias
  costs O(1) and never copies fields. Fields, array elements and bitfield
  bases keep the declared object, including aliases.
- Decoder-synthesized objects follow the source objects in deterministic
  first-use order. `SyntheticBase { size, meta }` (`getBase`) and
  `SyntheticByteArray { count }` are interned by key; `UnionBitfield { owner,
  field }` is one object per union field. They never alias converted source
  objects here. A real `TypeFactory` may resolve them to core types, or merge
  equally named wrappers, through names and native IDs that the declared graph
  does not contain; complete `TypeFactory` interning is not modeled. None is a
  float, so HFA identity does not depend on that choice.

### Conversion policy

| Declared kind | Decoded native form |
| --- | --- |
| Void | Void, size and aligned size 0, alignment 1 (`TypeVoid`) |
| Function | Code, size/aligned size/alignment 1 under every map (`TypeCode`) |
| Integer, float, builtin, pointer | Int/Uint/Bool/Float/Ptr with `primitive_geometry` of the Java raw length; char signedness from the organization; wide char is Int |
| Enum | Int/Uint (transport `enum_int`/`enum_uint` is normalized at type.cc:1572), `enumeration` set, primitive geometry |
| Opaque below 16 bytes | Unknown primitive |
| Opaque of 16 bytes or more | Fieldless Struct, size = aligned size = width, alignment 1 |
| Zero-count array | Opaque transport of its public length 1: normally Unknown size 1, aligned per the map; never Array; the element is not transported |
| Nonzero array | Array keeps the encoded public size. The count, `count × element aligned size` and the size must be native ints, and the product must equal the size; otherwise `ArraySizeMismatch`/`Arithmetic`. Alignment is the element's; aligned size equals size |
| Structure, union | Public length (one for empty composites), the explicit Java alignment, and native aligned size rounded up to it; layout field offsets |
| Alias | Typedef clone, above |
| Incomplete | `NativeConversionError::Incomplete` |

Composite conversion follows `encodeStructure`/`encodeUnion` and then
`decodeFields`. Zero-length components are not transported. Structure fields
replicate `decodeField`/`decodeBitField` checks in source order: dependency,
void field, non-integer bitfield base, out-of-order, overlap drop (reported by
`dropped_fields()`), int arithmetic and fit. Union fields must fit. Examples:
a Java enum or pointer of three bytes has aligned length 3, so an array of two
encodes 6 while native needs 8 and fails. An empty structure with minimum
alignment 16 has Java public and aligned length 1 but native aligned size 16;
an array of two encodes 2 against an expected 32 and fails.

**Bitfields.** Structure bitfields are decoded from the transported effective
width, normalized bit offset and byte offset, with the layout byte order (taken
to be the default data space's). A range is byte aligned iff width and bit
offset are multiples of 8. It is minimized as in `address.cc` and becomes an
ordinary visible field at its offset: the declared base object (alias and enum
identity kept) when its native size equals the range, otherwise `getBase` of
the width with the base's Int/Uint meta-type (others become Unknown). A resized
enum is therefore a plain Int/Uint. Widths above `max_basetype_size` (default
10 from `Architecture::resetDefaultsInternal`; validated `8..=i32::MAX`) become
`SyntheticByteArray`: the actual native array of the Unknown size-one base,
whose size doubles if the map pads one byte to two. Other bitfields are kept in
`bitfields()` with byte offset/size, least significant bit, width and base;
extraction never visits them. Union bitfields are opaque objects of their
storage width (Unknown below 16 bytes, fieldless Struct otherwise). Zero-width
bitfields are omitted.

**Failures and loadability.** Conversion failures are per type and typed. They
are returned by `native()`/`get()` only for that type, and by-value dependents
fail with `Dependency { root }`. Pointer targets and function signatures are not
by-value dependencies: a pointer to an incomplete or mismatched type is an
ordinary queryable Ptr. `load_blocker()` separately reports a failed type
reachable through by-value, pointer and function references, distinguishing
this queryable snapshot from a fully loadable one. Loadable means converted
under this contract; it does not prove a real factory accepts the stream.
Sizes, alignments, counts, offsets, products and sums are checked against the
native int range; no value wraps.

**Bounds.** Source types, fields and references are checked before allocation,
synthetic objects before each allocation, plus dependency depth and work.
Construction is iterative and `O(types + fields + references + s log s)` for
`s` synthetic objects. A failed decode rolls back its fields and new synthetic
objects. Accessors allocate nothing.

## Native primitive extraction

`NativePrimitiveExtraction::new(Arc<NativeTypeGraph>, root, options, limits)`
ports `PrimitiveExtractor` (modelrules.cc:142-249) to the native shapes. The
options are the source arguments: start offset (a nonnegative native int),
union rejection, nested arrays as primitives, and the semantic per-context
`max_primitives`. The outcome is `Valid { primitives, contains_unknown,
aligned, contains_holes }` or `Invalid(reason)`: the maximum, a rejected, empty
or incompatible union, or an unsupported meta-type such as Void. Semantic
invalidity is an outcome; resource limits, root conversion failures, invalid
options and int overflow are errors. Each primitive keeps its exact native
object and origin.

- Unknown sets the unknown flag and is emitted; Int, Uint, Bool, Code, Float
  and Ptr are emitted. Arrays expand with the native element aligned size as
  stride, unless nested arrays are primitives and the array is below the
  current context root.
- Every visible structure field is checked, packed or not. The absolute
  offset is the structure start plus the field offset; it is unaligned when not
  a multiple of the field alignment. The expected offset starts at the
  structure's start, is rounded to that alignment, and a mismatch is a hole;
  then it becomes the field offset plus native aligned size. There is no
  trailing check and no direct alignment check of roots or array elements.
  Fieldless and empty-output structures still have their field checks.
- Each union member is a fresh context at array depth zero that permits
  unions. Members are refined in source order on native aligned sizes with the
  float preference and overlap rule of `commonRefinement`; member flags are
  dropped; the result must fit the parent's maximum.

Offsets are checked when used. The expected offset is kept wide and checked
when the next field consumes it; the value after the last field or element is
unused, as in the source. Traversal uses explicit task stacks, one per
context, and expands arrays lazily. An array whose elements are inert
(fieldless structures or arrays of them) is skipped only when the exact
traversal could not fail on depth or offset, so outcomes are unchanged; only
work and statistics differ. Live records include refinement scratch. Limits
are checked before growth, refinement is work-bounded, and errors return no
partial prefix.

For example, packed `{float, opaque16}` emits one aligned float. Natural
`{u8, u32}` is aligned without holes from start 0 but unaligned with holes from
start 1; packed `{u8, u32}` is the reverse from starts 0 and 3. A float array
started at offset 1 has no alignment flag. `{float}` with minimum alignment 8
repeats without a trailing check. A nonbyte bitfield before a float leaves a
native hole. Under the default map Java pads a 17-byte opaque component to 24
bytes; with a map entry `16 -> 1` the packed `{float, opaque17}` element is 21
bytes and its second array element's float is unaligned.

## Native datatype predicates

`NativeTypeGraph::matches_filter`, `matches_rule` and
`homogeneous_float_aggregate` evaluate parsed filters and qualifiers against
decoded types, with the query boundaries of `DatatypePredicates`: prototype
IDs, qualifier/parameter counts and the first variable slot are validated
first; each filter is validated when reached; qualifiers short-circuit in
declaration order. No action, precondition or side effect runs. Native
differences:

- Sizes are native `getSize`: void 0, code 1, zero arrays 1.
- Meta-types are native: aliases keep their target's; Void matches void; Code
  matches functions; enums are Int/Uint, so `enum_int`/`enum_uint` never match;
  Struct matches opaque data of 16 bytes or more. `partenum` is an invalid
  filter because native `string2metatype` has no such name.
- The array filter tests the native meta-type, so an alias of an array
  matches. A named Go array matches the `x86-64-golang.cspec` array-to-stack
  rule natively but not in Java.
- HFA requires Array/Struct, then native extraction from offset 0 with unions
  rejected, arrays expanded and `maxprimitives` (default 4, including 0). The
  result must be valid, nonempty, without unknowns, aligned and without holes,
  with a Float first leaf and every leaf the same native object. Size bounds
  are ignored, as in both source layers. With F, A = alias F and B = alias A,
  `{F, A}` and `{A, B}` fail natively while `{A, A}` matches; Java accepts all
  three. Opaque tails emit nothing, and invisible bitfields can leave holes.

One work budget covers each query. Each reached HFA filter runs extraction with
the remaining work and the query's live/depth limits, and its work is added.
Semantic rejection, including the primitive maximum, is `false`; resource
exhaustion is a `Limit` error. A conversion failure is an error only when a
reached filter evaluates that type.

The source-ID methods address converted source objects and use the same
native filter semantics. Direct native
objects can be queried with `matches_filter_native`, `matches_rule_native`
and `homogeneous_float_aggregate_native`. `NativePrototypeTypes` carries
native IDs for the result and parameter list. These entry points accept
decoder-synthesized bitfield bases, Unknown-byte arrays and opaque union
fields; no source ID is invented for them. IDs belong to the supplied graph;
an equally numbered ID from another graph cannot be detected.
Unknown native IDs retain the native error namespace, while failed source
conversions remain deferred until a reached filter reads the object.

Both ID paths share the same evaluator and work accounting. Prototype
validation borrows the supplied slice and creates no translated parameter
list. Seven directed native-ID test groups cover synthetic objects in both
byte orders, native prototype qualifiers, short-circuit/error precedence,
HFA details and every lower work budget. An absolute 21-unit rule pin checks
header, parameter, size-list and qualifier charges. Source/native queries
on corresponding source slots compare complete results, errors and usage,
including failed conversions. All ten compiling scratch mutations are caught:
wrong ID-domain bounds/resolution, forced conversion during preflight, missing
parameter charges or ID checks, conversion before filter validation, wrong
datatype-at targets and source/native error-domain confusion. The scratch
source was restored and the parent source hash stayed unchanged. This API
extension received independent approval at `0123268173`. The reviewer checked
the retained native source, reran the directed/native/source-oracle suites on
stable and Rust 1.88, and added six separate probes covering invalid HFA IDs,
preflight order, reached failed qualifier targets, old/new equivalence across
budget combinations, graph-local IDs and maximal work limits. Committed
regressions now also pin those public boundary paths. Full rule dispatch and
action execution remain separate work.

## Native validation evidence

The native alignment dependency was re-audited against type.cc:3805, 3821,
3921-3944, 5172 and 5200 and against `parseCompilerConfig` running before core
types are decoded. Decode, defaults, floor lookup and the two-lookup padding
agree; no defect was found, so it is unchanged.

Default tests include 13 graph tests, 14 extraction tests, 9 predicate tests
and 2 unit tests of the private bit-range logic, all with hand-derived
expectations. They cover every kind, odd and nonmonotonic maps, aliases,
forward IDs, bitfields in both byte orders, exact and one-below limits, every
lower work budget, and 100,000-deep alias, structure and extraction chains.
A separate oracle decodes maps into the dense native vector, converts types
recursively from the Java transport facts and runs a literal recursive port of
the extractor, refinement, HFA and filters. Over 1,200 generated graph/map
instances (random organizations, both byte orders, bridge, default and
declared maps, basetype limits 8/10/12) it compares about 22,800 conversions,
1.04 million extractions, 64,000 HFA answers, 518,000 filter answers and
loadability; counters require every failure, invalid and HFA class. A fixed
graph under all 107 retained compiler organizations at pointer sizes 4 and 8
adds 188,000 extractions and 282,000 filter answers. The oracle shares only
`TypeLayouts` with production. Twenty-three compiling semantic mutations of the
new modules are all caught: union flags and depth, expected-offset rules,
refinement sizes, float preference, the inert skip, bitfield base selection,
the basetype boundary, array mismatch, the opaque threshold, composite
rounding, alias identity, code geometry, zero arrays, HFA holes, native sizes,
array bounds and loadability. These are source-derived Rust
references; the author ran no C++ or Java process.

Independent review approved the integrated code at `4d8c4ebd88` with no required
changes. A separate harness compiled the retained C++ extractor/refinement
method bodies with minimal datatype scaffolding and compared 290,784 queries
across 120 converted graphs against Rust 1.88 release results. Validity, flags,
primitive identity/order and offsets agreed. Further probes covered a
100,000-level union chain and its exact depth boundary, cleanup without stack
overflow, synthetic-array failure rollback, and pointer/function loadability
cycles. Conversion also received independent source inspection and targeted
probes; this was not a full Java/TypeFactory transport round trip. These
external test harnesses add no Java or C++ runtime dependency to the library.

## Native gaps and remaining work

- Only the `<join_dual_class>` action consumes the graph and extractor so
  far. The native fallback primitive exists, but there is no rule
  dispatcher, per-member join action, signature allocation, SSA call
  effect, CLI or desktop flow.
- `TypeFactory` names, native IDs, core-type caches and interning; typedef
  formats; pointer typedef settings and relative pointers; string and unicode
  transports; spacebase and partial types; variable-length and native
  incomplete flags; and function prototype decoding are not modeled.
- The decoder's overlap-drop, out-of-order and fit failures are implemented,
  but validated layouts never reach them in the tests.
- Bitfield byte order is the layout's, assumed equal to the default data space.
- Large arrays are traversed exactly within the work budget unless their
  elements are inert; there is no general cached summary. An HFA query on 100
  million `{opaque16}` structures (nothing emitted, but one visible field check
  each) is therefore a work error where the source loop would finish.
- Repeated queries re-validate prototypes and rerun extraction.
