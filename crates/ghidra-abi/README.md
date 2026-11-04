# Native compiler storage

This crate resolves compiler-spec storage declarations against actual language
registers and address spaces. It keeps signed stack addresses, register aliases
and join significance explicit. It is a native Rust layer and uses no Java or
Ghidra C++ process.

Whole-signature allocation, complete prototype-rule dispatch, injection
compilation and type recovery remain separate stages. Resource-group planning, placement in
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
join/member/dual composition and shared-stack signatures remain required.
These operations are not yet connected to datatype-driven signature allocation,
SSA call effects, the CLI or desktop.

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

- Nothing consumes these APIs yet: no rule dispatcher, join/member actions,
  signature allocation, SSA call effects, CLI or desktop flow.
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
