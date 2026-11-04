# Native fallback and per-member allocation contract

This source audit defines the next ABI stages. It is not an implemented
`join_per_primitive` action, rule dispatcher or complete calling convention.
The retained native references are `modelrules.cc`, `fspec.cc`, `fspec.hh` and
`translate.cc` in the decompiler source directory.

## Required native fallback primitive

`ParamListStandard::assignAddressFallback` (`fspec.cc:731–758`) scans every
entry in declaration order. It skips a consumed first group before checking
the class. Exact matching accepts only the requested class; ordinary matching
also accepts a General entry. The request width is the datatype's aligned
size, and its alignment is the datatype's native alignment. Success consumes
all groups of an exclusion entry or advances an aligned pool's first cursor.
Failed aligned candidates retain alignment waste, including when a later
candidate succeeds or the whole fallback finds no fit.

The existing public placement API deliberately uses exact-congruence
alignment. Native fallback needs the source floor-division rule, so blindly
calling the existing fallback batch changes results. For pool alignment 8,
type alignment 12 and cursor 1, native alignment waste is `(12-8)/8 = 0`;
the cursor remains 1. Exact congruence moves it to 3.

A reusable private candidate/fallback kernel should share `Budget` and
`Undo` with future actions. Its native placement order (`fspec.cc:458–490`):

1. Reject a width below the minimum.
2. For an exclusion entry, reject a nonzero cursor, then excessive width;
   preserve declared float-extension handling on success.
3. For an aligned pool, if type alignment exceeds pool alignment, evaluate
   `(cursor * pool_alignment) % type_alignment` and add floor-divided waste.
4. Compute ceiling-divided slots and evaluate cursor plus slots before
   comparing it with capacity. A capacity failure retains alignment waste.
5. Only after a fit, calculate the index, physical span, address and next
   cursor, using the source's stack growth and justification rules.

Refuse native signed-int overflow when the source evaluates that operation;
wide arithmetic must not turn it into an ordinary capacity failure. Do not
move a later arithmetic/storage check ahead of a guaranteed earlier NoFit.
The dual-class spill helper demonstrates precomputing native alignment and
then calling placement with type alignment one, but it is stack-specific and
does not supply complete candidate or fallback semantics.

Keep the existing fallback API and its exact-alignment policies stable.
Expose any new native primitive as explicit fallback, with declared rules and
`pointermax` visibly unexecuted. It is not `assignAddress`, which tries rules
first. Preserve current secondary-group, physical-overlap and address-domain
safeguards as typed refusals. A private kernel must allow an outer action to
roll back its successful members and failed candidates through one journal;
do not create an independent full budget or clone all occupied state for
every member.

## Per-member action setup and extraction

`MultiMemberAssign` (`modelrules.cc:650–683,1196–1209`) defaults to General,
recursive mode, stack consumption disabled and significance from the first
list entry's space. XML recognizes only `storage`: its presence selects
nonrecursive mode, even `storage="general"`. There are no XML spill,
justification, reverse-significance or primitive-limit attributes.

This action does not call `extractTiles`. Aligned pools, multiple groups,
different entry widths, join-backed pools and same-class stack entries must
remain eligible where ordinary fallback accepts them.

Extraction is exactly `PrimitiveExtractor(dt, false, isRecursive, 0, 16)`
(`modelrules.cc:1114–1117`). Invalid extraction, no primitives, root unknown,
unaligned or holes means NoFit. Sixteen primitives is permitted; seventeen
is semantic invalidity. Explicit-class mode expands nested arrays; recursive
mode treats arrays below each extractor root as primitives. Union members
restart that root/depth state. Union refinement uses aligned widths and
discards member flags, so a valid result may contain an Unknown primitive
while the root's unknown flag is false. Do not add a per-member rejection.
The action itself is not an HFA filter and does not require identical float
identities or a particular aggregate root kind.

## Allocation widths, padding and ordering

For every primitive in extraction order (`modelrules.cc:1124–1154`):

1. Allocate using its aligned width and native alignment.
2. In recursive mode, apply the stack-status guard described below.
3. Append padding equal to `primitive.offset - emitted_end`: zero emits
   nothing, negative means NoFit, positive means a constant-zero padding node.
4. Set the new end to primitive offset plus its raw width.
5. Emit the allocated address with that raw width.

Finally append root raw width minus the last emitted end, with the same
padding rules. Do not prevalidate all padding before allocation: an earlier
allocation failure wins over a later bad padding or address condition.

A raw-three/aligned-four enum in an eight-byte BE entry is allocated at
`base+4`, then emits three bytes at that same address. Rejustifying a new
three-byte request would incorrectly move it to `base+5`. Member output
must preserve the original allocation and represent the raw-width view.

`assignAddressFromPieces` (`fspec.cc:2191–2200`) reverses the entire emitted
list for least-significant-first consumption, including padding. The list
order comes from its first entry (`fspec.hh:635`), while member placement
retains the selected pool's byte order and justification. Keeping unmerged
pieces follows the existing Rust join policy; native merging also considers
formal register names (`translate.cc:199–231,783–791`).

Declared float-extension placement can create nested conversions; class
Float alone does not imply one. A compound result can contain several such
members. Existing whole-value `JoinStorage::FloatConversion` cannot encode
that. Retain ordered member nodes, their original `PlacedStorage`, allocated
and emitted widths, native primitive provenance, and separate padding nodes
that do not pretend to have a supplying binding site. Model partial
conversion/join views explicitly or refuse them; do not flatten away their
meaning.

## Explicit-class and recursive assignment

With declared storage, fallback uses that exact class for decoded XML
(`modelrules.cc:1142–1154`). It bypasses declared rules and `pointermax` as an
action-internal primitive. An explicit General entry may reach a General
stack pool even though the action's stack-consumption flag is false; this
branch has no stack-status guard.

With omitted storage, each primitive invokes full `resource->assignAddress`
with the same prototype and position (`modelrules.cc:1119–1140`). That method
tries rules in declaration order before metatype-derived fallback
(`fspec.cc:764–784`). Returning the identical native object as the original
root immediately fails to prevent self-recursion. Every child response except
fail is accepted; replacement types/flags do not replace the original raw
width used for emission.

Capture the final stack pool's first-group status once before recursive
allocation. When stack consumption is disabled, it must remain equal after
each successful child. This is a status check, not a physical-address check:
a rejected stack candidate can change alignment waste before another pool
succeeds. A child failure wins immediately.

Full rule dispatch does not exist yet. Extraction can return synthesized
NativeTypeId objects with no source TypeId. New direct native-ID predicate
entry points and `NativePrototypeTypes` address that representation gap,
with independent review approval at `0123268173`. The future dispatcher must use those
native objects directly instead of inventing a source-ID translation.
Class-only support can be a staged API, but omitted storage must remain
explicitly unsupported until its actual dispatch contract is available.

## Transactions, bounds and evidence

Native code copies status and commits before final join construction
(`modelrules.cc:1157`), with another model-rule transaction outside it
(`1790–1814`). Retain the Rust action convention that every NoFit and error
rolls back the entire action, including output-construction failures.
One budget covers extraction, members, candidate scans, groups, nested
placements, output nodes/pieces, journal writes and occupied extents. Nested
work/piece limits receive only the remaining allowance. Counts and arithmetic
are checked before growth; no recursion or payload-sized allocation is needed.

Required native fallback evidence includes floor versus exact alignment,
failed-candidate holes, minimum before arithmetic, native overflow before
capacity, both matching modes, declaration order, every pool kind, overlap
safeguards and rollback. Per-member evidence must additionally cover:

- Extraction gates and 16/17 limits; aliases, unions and discarded flags;
  recursive identity and nested-array behavior.
- Natural and packed `{u8,u32}`, raw-three/aligned-four members, repeated
  padded structures, tail padding and fieldless opaque subobjects.
- Invisible nonbyte bitfields versus holes/tail padding, omitted zero-width
  bitfields, and native array conversion failures remaining failures.
- Exact-class refusal versus General fallback, explicit General stack
  allocation, aligned and multiple-group pools, joins and nested conversions.
- Padding/significance reversal, failure ordering, every budget boundary,
  absolute work pins, and rollback after a later member or output failure.
- On dispatcher integration: native synthetic identities, ordered rules,
  unchanged prototype/position, accepted non-fail child responses and the
  stack-status guard.

Sixteen occurrences in ten retained cspecs provide real fixtures. Explicit
class forms include AArch64, RISC-V floating conventions and MIPS BE output.
Go x86-64 uses omitted storage and exercises the recursive dependency.
`fillinOutputMap` (`modelrules.cc:1164–1193`) is separate reverse inference;
allocating output storage does not implement it.
