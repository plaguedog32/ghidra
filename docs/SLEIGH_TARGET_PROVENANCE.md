# Preserving direct-target provenance in the Rust compiler

This is a source-audited implementation contract for a confirmed compiler
defect, not a completed fix or a claim of processor parity.

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
