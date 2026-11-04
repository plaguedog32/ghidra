# Vendored SLEIGH compiler forks

These are local forks of the two pinned Rust crates that compile SLEIGH source
and lower it to raw p-code. They exist only to repair direct branch/call target
provenance (`docs/SLEIGH_TARGET_PROVENANCE.md`). They are standalone packages:
the root manifest excludes them from the workspace and selects them with
`[patch.crates-io]`, so their development dependencies never join the
workspace graph. Every other dependency, including `wazabin-jstd 0.2.2`, stays
pinned from crates.io through the root `Cargo.lock`.

| Directory | Package | Upstream commit (path) | Registry checksum (SHA-256 of `.crate`) |
| --- | --- | --- | --- |
| `wazabin-sleigh/` | `wazabin-sleigh 0.1.15` | `ad1a84a932bf2fb32053be3c60a119077fe0d02e` (`core`) | `aa80a0a5cada1a21b7674e589653fec61f26854dcd2b7a8f67da28eaacdf26a9` |
| `wazabin-pcode/` | `wazabin-pcode 0.1.4` | `b471d6b6c970c543227fd74bdb289a3e551d8c0a` (root) | `16981334ae27b1d9b775db4aff5438742ff352342d4fba4b2ed50fb096d4eae1` |

## Origin

Each directory was extracted from the local Cargo registry cache archive
(`~/.cargo/registry/cache/index.crates.io-*/<name>-<version>.crate`) whose
SHA-256 equals the checksum above, the one the root lockfile pinned before this
fork. The extracted tree is the published package byte for byte, including its
normalized `Cargo.toml`, `Cargo.toml.orig`, `.cargo_vcs_info.json` (which
records the commits above), its own `Cargo.lock`, and its complete MIT
`LICENSE` (`Copyright (c) 2025 Jack Royer`). `.gitattributes` here disables
line-ending conversion so a checkout stays byte-identical to the archives.
Root ignore rules for `*.sla` and `*.lock` would otherwise hide package files,
so `.gitignore` here re-includes them.

To audit the fork, extract the same archives elsewhere and compare:

```sh
tar -xzf wazabin-pcode-0.1.4.crate && diff -r wazabin-pcode-0.1.4 vendor/wazabin-pcode
tar -xzf wazabin-sleigh-0.1.15.crate && diff -r wazabin-sleigh-0.1.15 vendor/wazabin-sleigh
```

The packages keep their published versions so the existing exact requirement
and the root patch select them. A version number therefore does not identify
the fork; `SpecFingerprint::FORK_SEMANTICS_REVISION` does (below).

## Local changes

`wazabin-pcode`:

- `src/statement.rs`: appended `LabelOrNode::Address(QualifiedTarget<..>)`, and
  the `QualifiedTarget` (space, pointer, exported width, pointer units) and
  `PointerUnits` (`Bytes`, `AddressUnits`) types; span stripping and pretty
  printing cover them.
- `src/streaming.rs`: appended `TargetNode::Address`, built from the owned
  variant.
- `src/instruction.rs`: one direct-target resolver shared by `Planner` and
  `Emitter`. Qualified targets reproduce native `HandleTpl::fix` /
  `generateLocation` byte offsets (64-bit wrapping scale, signed `wrapOffset`)
  and refuse dynamic pointers, constant/unique-space destinations, zero widths
  and unmodeled or unknown space dimensions. `PcodeLoweringContext::word_size`
  (default `None`, so unknown dimensions fail closed), two appended
  `PcodeLowerError` variants, and space-qualified `DirectDestination` plan
  entries replacing space-less `u64` ones. `Planner::new` now takes the
  lowering context. Directed tests with hand-derived native expectations.
- `src/lib.rs`: re-exports.

`wazabin-sleigh`:

- `src/runtime/pcode/view.rs`: a table export used as a direct target becomes
  a qualified target (starred: export space, width, address units; unstarred
  constant: constant space, bytes) instead of its bare pointer.
- `src/runtime/pcode.rs`: owned materialization keeps the qualified target;
  the streamed planner gets the lowering context.
- `src/runtime.rs`: the lowering context reports word sizes; the compilation
  fingerprint absorbs `FORK_SEMANTICS_REVISION` after the package version.
- `src/pmacro.rs`, `src/pmacro/validate.rs`, `src/resolve.rs`: exhaustive
  target matches cover the new variant.
- Tests: `src/tests/qualified_target.rs` and
  `src/tests/fixtures/semantics/qualified_target.sla` (new); the streamed
  equivalence harness derives plan destinations from emitted operations and
  sweeps the new fixture; one facade test now expects the qualified AST shape;
  a fingerprint test in `src/compile.rs`.
- Test-only: the published package omits `web/`, so its highlighter test could
  not compile. `src/tests/fixtures/upstream_web_presets/toy16.slaspec` is
  `web/presets/toy16.slaspec` fetched from upstream commit
  `ad1a84a932bf2fb32053be3c60a119077fe0d02e` (MIT, same repository; SHA-256
  `b7ff5099dfdb211db666c3b5fd5e7599d0bc2ebeba0ed3b0ba34c01fa00d7b60`), and
  `src/highlight.rs` includes it from there.

## Identity and compatibility

`SpecFingerprint::of_compilation` digests the package version, then
`FORK_SEMANTICS_REVISION`, then the preprocessed source, so a specification
compiled here never claims the fingerprint upstream 0.1.15 would give it. Bump
the revision whenever these forks change what a specification compiles or
lowers to. A fingerprint identifies content; it is not a blob-format version.
Appending enum variants keeps existing variant indices, but that does not make
serialized specifications interchangeable across compiler versions or forks;
producers must still version their blobs.

## Testing the forks on their own

Both packages declare Rust 1.85 and are built here with stable and 1.88.
From the repository root, use Python 3.12 or newer to run their suites in
isolated temporary copies:

```sh
python scripts/Test-VendoredSleigh.py
python scripts/Test-VendoredSleigh.py --toolchain 1.88.0
```

The helper runs all-feature P-code tests, SLEIGH library tests and both
packages' documentation tests. It patches the copied SLEIGH package to the
copied P-code fork and gives them a separate target directory. Only the
temporary SLEIGH lockfile may change to select that path dependency; hashes
verify that checked-in sources and lockfiles stay unchanged. Temporary
copies and logs remain available for inspection. CI runs the helper with
Python 3.13 in both toolchain matrices, including for vendor-only changes.

Its development dependencies (`clap`, `criterion`, `serde_json`, `bincode`) are
fetched for these runs only. Its `allocations` integration test reads an x86-64
specification from an `open_sleigh` checkout outside the package and fails
without one; it measures allocations rather than checking semantics and is
excluded by the helper's SLEIGH library/documentation selection.
