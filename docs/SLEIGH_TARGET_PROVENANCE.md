# Preserving direct-target provenance in the Rust compiler

This is a source-audited implementation contract for a confirmed compiler
defect, not a claim of processor parity. Implementation evidence follows the
contract below; independent review is still required.

## Reproduction and loss

A sub-table exporting `*[aux]:2 0x10:1`, used as a direct `goto` or `call`
target, currently lowers to a default-`ram` target with offset `0x10` and
size 1. The correct target retains `aux`, exported size 2, and byte offset
`0x10` for word size 1 or `0x30` for word size 3. The defect also exists for
byte-addressed auxiliary spaces; it predates word-storage support.

The pinned `wazabin-sleigh` runtime loses the space and exported width in
`runtime/pcode/view.rs:392–395`, converting `RuntimeValue::Address` into only
its pointer expression. `Scope::target` uses that conversion for table
operands; owned materialization loses the same information. The pinned
`wazabin-pcode` emitter then uses `context.default_space()` for literal
targets (`instruction.rs:1062–1072`). The public expanded AST and streaming
interfaces cannot recover the lost runtime provenance. Matching raw opcode
positions to separately expanded ASTs or guessing from numeric offsets is
not a valid repair.

## Compiler contract

Patch only the two pinned Rust compiler crates. Add a target-specific
qualified-address variant to owned `LabelOrNode` and streaming `TargetNode`,
carrying the destination space, pointer expression, exported width, and
explicit byte/address units. Preserve it through runtime target resolution,
transitive exported operands, materialization, serialization and streaming.
Ordinary expression targets keep their existing default-space behavior;
symbolic local labels keep their existing branch-label mechanism.

Use one target-resolution implementation for planning and emission. Static
qualified starred targets become a flat varnode with the destination space,
normalized byte offset and export size. The export size is not the pointer
expression's width. Do not truncate a constant pointer to its suffix width
before converting it. Planning must preserve qualified destinations too:
equal offsets in distinct spaces must not be deduplicated into one target.
No current workspace caller requires the old space-less plan getters.

The lowerer needs explicit space dimensions from its context, including word
size. An unknown space or dimension must fail explicitly, rather than default
to byte addressing. The owned, callback and streamed routes must agree. Keep
the existing sink's ordered operations, local-label callbacks and collector
resolution; they already preserve operation indices without post-processing.
Update exhaustive target matches, pretty printing, span removal, live-local
walking, macro resolution/validation and the adapter's word-space address-of
audit. Append enum variants without reordering existing variants.

## Native offset semantics

The retained `semantics.cc:666–674` fixes a starred constant export using the
destination space and exported size. It converts address units to bytes, then
wraps the byte offset. `space.cc:34–38` includes the final complete word in
the byte domain. `space.hh:523–525` scales with unsigned 64-bit multiplication;
`space.hh:384–391` wraps an offset above the highest byte with signed
remainder. A plain wide-integer modulo can differ for high-bit or overflowing
inputs and non-power-of-two word sizes. Reproduce this arithmetic exactly or
return an explicit unsupported error for cases not modeled; never silently
mask to the pointer suffix or space's address width.

Dynamic starred exports take a different native path
(`semantics.cc:676–679`, `sleigh.cc:209–226`), which can insert a load. Keep
them explicitly unsupported in this increment. Do not guess an indirect
branch from the pointer storage or fall back to a default-space literal.
Unstarred register/bitrange exports, compound constant-pointer expressions,
constant-space direct destinations and general dynamic handles require
separate source semantics before expanding coverage.

Keep cross-space Machine execution and CFG construction explicitly
unsupported. Preserve the default word-addressed-code refusal, word-space
address-of refusal and generic CSR pointer-width checks. Corrected targets
fit the existing flat IR and CLI space/offset/size encoding; no flat schema
change is required.

## Vendoring and identity

Vendor only these pinned packages using their normalized registry manifests,
not workspace-inheriting original manifests. Retain each complete MIT license
and the `Copyright (c) 2025 Jack Royer` notice. Leave `wazabin-jstd` and other
dependencies pinned through the lockfile. Exclude standalone vendor packages
from the root workspace to avoid inheriting their development target graph.

| Package | Upstream commit | Registry checksum |
| --- | --- | --- |
| `wazabin-sleigh 0.1.15` | `ad1a84a932bf2fb32053be3c60a119077fe0d02e` (`core`) | `aa80a0a5cada1a21b7674e589653fec61f26854dcd2b7a8f67da28eaacdf26a9` |
| `wazabin-pcode 0.1.4` | `b471d6b6c970c543227fd74bdb289a3e551d8c0a` | `16981334ae27b1d9b775db4aff5438742ff352342d4fba4b2ed50fb096d4eae1` |

Both upstream packages declare Rust 1.85; this workspace must continue to
build on Rust 1.88. Record local changes and origin in the vendor directory.
`SpecFingerprint::of_compilation` currently hashes package version and
preprocessed text (`runtime.rs:121–134`). Include an explicit fork semantics
revision so patched compilation cannot impersonate upstream. A fingerprint
is not a serialized-blob version gate: pcode's own `lib.rs:10–13` requires
producers to version their formats. Do not promise cross-version blob
compatibility merely because enum variants were appended.

## Acceptance evidence

- Branch, conditional branch and call through starred exports, both byte
  orders and auxiliary word sizes 1 through 8 where their byte domains fit.
- Export width different from pointer width, default-space starred exports,
  transitive exports, and equal offsets in distinct spaces in the plan.
- Byte-domain boundaries, signed high-bit constants, multiplication overflow,
  invalid/unknown dimensions and zero widths, with source-derived expected
  normalization or explicit errors.
- Owned AST preservation and serde round trips; identical owned, callback and
  streamed flat operations; qualified planner destinations.
- Forward, backward and terminal local labels, generated condition
  temporaries, macro/sub-table and delay-slot label scopes, and unchanged
  signed relative constants.
- Explicit dynamic-target errors and successful unrelated instructions after
  refusal, without leaked context commits.
- Machine and CFG refusal of preserved auxiliary-space targets; unchanged
  correctly modeled byte-only fixtures and CLI snapshots.
- Formatting, workspace tests and documentation, lint with warnings denied,
  Rust 1.88 validation, release build and existing Java-free source probes.

An independent review must inspect the compiler diff and its boundary probes
before this defect is considered resolved.

## Implementation evidence (awaiting independent review)

The repair is implemented in the vendored forks (`vendor/README.md` lists every
local change). It is not yet independently reviewed, so this defect is not yet
considered resolved.

### What changed

- Owned `LabelOrNode::Address` and streaming `TargetNode::Address` carry a
  `QualifiedTarget { space, ptr, size, units }`, with `PointerUnits::Bytes`
  or `AddressUnits`. Both are appended variants.
- A sub-table export used as a direct target becomes a qualified target in
  `View`. A starred export keeps its space and exported width, with its pointer
  in address units. An unstarred constant export becomes the constant-space
  byte handle native SLEIGH gives it. Pass-through exports keep the inner
  value. Other unstarred exports remain ordinary targets, which reject non-literals as before.
  Owned materialization, serde, span removal, pretty printing, live-local
  walking, macro reference collection, template validation and resolution
  cover the variant.
- `Planner` and `Emitter` call one resolver. Plan destinations are
  `DirectDestination { space, offset }`, so equal offsets in distinct spaces
  stay distinct. `Planner::new` takes the lowering context.
- `PcodeLoweringContext::word_size` defaults to `None`, so an unknown
  dimension fails closed. The SLEIGH runtime reports each space's word size.
- `SpecFingerprint` digests `FORK_SEMANTICS_REVISION` after the package
  version, so a fork compilation cannot have upstream 0.1.15's fingerprint.
- The adapter's word-space address-of audit also visits qualified target
  pointers.

### Native arithmetic and refusals

For a constant pointer `p` in a space with address size `a` and word size `w`,
the byte domain has `D = 256^min(a, 8) * w` bytes. The offset is
`p * w` in wrapping `u64`, or `p` for byte units. If that is at least `D`, it
is reduced with a signed truncating remainder modulo `D`; a negative result
then has `D` added (`wrapOffset`). The destination width is the export's size. Domains of at least 2^63 bytes, other
than exactly 2^64, give native a wrapped `highest` or a non-positive signed
modulus. These are refused with `UnsupportedSpaceDimensions`. So are zero
address or word sizes. Unknown spaces return `UnknownSpaceDimensions`, zero
export widths return `ZeroSize`, dynamic or compound pointers return
`Unsupported`, as do constant- and unique-space destinations. The emitter
never falls back to an indirect branch or a default-space literal. Ordinary
literal targets keep their unchanged default-space behavior.

### Tests

Expected values were derived by hand from the native formulas above.

- `wazabin-pcode` (`qualified_target_tests`, 16 tests): word sizes 1–8; export width
  above and below the pointer width; an untruncated `0x110:1`; the final
  complete word (byte 765 of a 768-byte domain); the next unit wrapping to 0;
  `0x8000000000000000 * 3` giving 256 (unsigned: 512; unwrapped: 0); `-16 * 3`
  giving 720; `0x5555555555555556 * 3` giving 2 (unwrapped: 258); a full
  2^64-byte domain; byte units; every refused dimension; zero width;
  constant, unique, dynamic and compound pointers; distinct-space plan
  destinations matching emission; labels; serde variant indices; printing.
- `wazabin-sleigh` (`tests::qualified_target`, 5 tests, plus a new fixture swept by
  the all-encodings owned/streamed equivalence test): branch, conditional
  branch and call for both byte orders and word sizes 1–8. These cover owned
  AST shape and JSON round trips; identical owned, slice-callback and streamed
  operations and plans; and wider or narrower exports. They also cover a
  decoded field pointer, a high-bit literal, a default-space starred export
  and a two-level pass-through. Other cases are three spaces sharing byte
  offset 0x10, and labels from macros and delay slots around a qualified call.
  The forward, backward and terminal relative constants are unchanged. Dynamic,
  constant-space and unstarred register targets give explicit errors, and the
  next instruction lowers. A fingerprint test checks that the fork's digest
  differs from upstream's formula.
- `ghidra-sleigh` (`tests/direct_targets.rs`, 5 tests): the reviewed
  reproduction for word sizes 1–8 and both byte orders, including `BRANCH
  aux:0x10:2` for word size 1 and `aux:0x30:2` for word size 3. The machine
  returns `CrossSpaceTransfer`, and the CFG returns `CrossSpaceLabel` for the
  preserved `aux` target. A refused dynamic target does not commit its
  `globalset`, and the same commit from a valid instruction does. The
  address-of audit visits qualified pointers.
- Fifteen source mutations were each killed by failing tests, not by compile
  errors. They covered a lost space, lost width, double or missing scaling,
  suffix truncation, a `u128` modulo, an unsigned remainder, a missing final
  word, an assumed byte word size, space-less plan entries, an off-by-one label
  distance, a dynamic fallback, pointer-only views and materialization, and a
  fingerprint without the revision.

### Retained-source impact

A template survey of every retained `.slaspec` used the forked compiler's
introspection. `hexagon` and `V850e3` do not compile with it. No sub-table used
as a direct target exports an unstarred literal or field; pass-through chains
end in starred default-space fields. A differential lift compared 31 real
instructions on the pristine and patched executables. In this sample, x86-64
and x86-32 near branches and 32-bit far jumps, AArch64, ARM and Thumb `b`,
MIPS and eBPF `ja` are byte-identical. The changes follow from the source:

- eBPF `call SysCall` (`export *[syscall]:1 imm`): `CALL ram:5:8` becomes
  `CALL syscall:5:1`.
- RISC-V AndeStar `ex9.it`/`exec.it` (`export *[ExecTable]:2 val`):
  `ram:32:4` becomes `ExecTable:32:2`.
- Narrower exports keep their exported width: PowerPC `addressLI`/`addressBD`
  (`*[ram]:4`) on PPC64 change 8 to 4, 6502/8048 change 2 to 1, and x86-64's
  legacy 16-bit `JMPF/CALLF ptr1616` changes 8 to 4. The survey lists other
  specifications with the same kind of change, such as 8051-family, HC0x/HCS,
  Z80, Dalvik, MSP430X and AVR.
- ARM Thumb `adr.w pc, ...` branches through `*[const]:4`, which native
  SLEIGH lowers as a constant-space, p-code-relative branch. It is now refused
  instead of becoming a default-space branch.

### Validation

Validation used Windows, Rust 1.99.1 and Rust 1.88, with private target directories:
`cargo fmt --check`; workspace clippy `--all-targets -D warnings`; 842 workspace
tests and 23 doctests on both toolchains (837 before); rustdoc with warnings
denied; and a release build. The opt-in sources were also run:
`upstream_specs` (11), Thumb IT, x86 function, WinHello reduced/copy and
dual-join ABI. Java-free integrated probes were byte-identical to the prior
references: sum-loop 43,235 B, alias 46,158 B, and WinHello `401E46` at
9,305,623 B, with an unchanged 6,237,526-byte default output. WinHello still has
135 instructions, 151 nodes, 10,953 SSA values and 2,192 phis. Both forks pass
their own suites and clippy with warnings denied. The only exception is
`wazabin-sleigh`'s `allocations` probe, which needs an external x86-64 source.
When that probe is pointed at this checkout's x86 source, every allocation
count matches pristine. Streamed bytes grow by 32 B when a plan has a direct
destination. Owned ASTs grow by 64–480 B per instruction because the target
enum is larger.

### Remaining limits

`globalset` through a table export still folds only its pointer
(`ContextScope::At(u64)` has no space). Dynamic starred exports, which native
lowers with a `LOAD`, and the other unstarred handle shapes need their own
source semantics. Cross-space execution and CFG construction remain refused.
The CI workflow's path filter does not yet include `vendor/**`.
