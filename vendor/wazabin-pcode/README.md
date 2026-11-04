# wazabin-pcode

[![CI](https://github.com/wazabin/pcode/actions/workflows/ci.yml/badge.svg)](https://github.com/wazabin/pcode/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/wazabin-pcode.svg)](https://crates.io/crates/wazabin-pcode)

Shared vocabulary and source-shaped SLEIGH p-code AST types for producers and
consumers. It covers address spaces, registers, expression and statement ASTs,
operators, builtins, diagnostics, and user-defined operation identifiers.

Developed by [Thalium](https://blog.thalium.re/about/).

## Scope

`PcodeAst` models the p-code **written in a SLEIGH semantic section**. It
preserves nested expressions and source constructs such as `macro`, `build`,
`export`, and `delayslot`.

`InstructionPcode` models Ghidra's flat `PcodeOp`/varnode instruction IR. The
crate exposes `lower_instruction` and `PcodeLoweringContext`, the
producer-supplied specification information required by the AST-to-operations
lowerer. The initial raw lowerer covers expanded scalar expressions, memory,
userops, and control flow; named and source bit ranges are rejected until their
raw-op expansion is implemented.

`PcodeAst::pretty_print` is producer-independent through `PcodeResolver`.
A SLEIGH compiler supplies the resolver, so this crate has no dependency on a
decoder implementation.

## Development

The current development setup requires a sibling checkout of `wazabin-jstd`:

```text
parent/
├── wazabin-jstd/
└── wazabin-pcode/
```

Run the quality gates with:

```sh
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
cargo llvm-cov --all-features --fail-under-lines 75
cargo doc --no-deps
```

## License

Licensed under the [MIT License](LICENSE).
