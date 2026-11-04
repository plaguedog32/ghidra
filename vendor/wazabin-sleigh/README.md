# wazabin-sleigh

[![CI](https://github.com/wazabin/sleigh/actions/workflows/ci.yml/badge.svg)](https://github.com/wazabin/sleigh/actions/workflows/ci.yml)
[![crates.io](https://img.shields.io/crates/v/wazabin-sleigh.svg)](https://crates.io/crates/wazabin-sleigh)

A Rust implementation of [SLEIGH](https://ghidra.re/ghidra_docs/languages/html/sleigh.html), the processor-specification language Ghidra uses to describe instruction sets.
Give it a `.slaspec` and some bytes; it gives you back the instruction, its assembly text, and its p-code semantics.

```rust
use sleigh::{Compiler, Decoder, SourceDb};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // A whole (very small) processor.
    let spec_source = r#"
        define endian=little;
        define space ram      type=ram_space      size=4 default;
        define space register type=register_space size=4;
        define register offset=0 size=4 [ r0 r1 ];

        define token instr(8) op=(0,3) reg=(4,7);
        attach variables [ reg ] [ r0 r1 _ _ _ _ _ _ _ _ _ _ _ _ _ _ ];

        :inc reg is op=1 & reg { reg = reg + 1; }
    "#;

    // 1. Compile the specification. Do this once; it is the expensive part.
    let mut sources = SourceDb::new();
    let root = sources.add_file("tiny.slaspec", spec_source);
    let spec = Compiler::new(&mut sources).compile(root)?;

    // 2. Decode. The context carries decode state between instructions —
    //    start from the specification's default.
    let decoder = Decoder::new(&spec);
    let instruction = decoder.decode_one(0x1000, &[0x11], &spec.new_context())?;

    assert_eq!(instruction.display()?, "inc r1");
    assert_eq!(instruction.len(), 1);

    // 3. Ask what it *does*.
    assert_eq!(
        instruction.pcode_ast()?.pretty_print(&spec),
        "r1 = (r1 + 1);"
    );

    Ok(())
}
```

Developed by [Thalium](https://blog.thalium.re/about/).

## Features

- **Decoding** — [`Decoder::decode_one`] matches one instruction against the compiled specification and reports a typed error rather when it fails.
- **Disassembly** — [`Instruction::display`] renders the specification's display section.
- **Semantics** — [`Instruction::pcode_ast`] gives a source-shaped p-code AST with macros, sub-tables and delay slots already expanded.
See the [`semantics`] module for the type graph and the conventions it follows.
- **Source tooling** — [`analyze`] reports diagnostics and lints without building a runtime specification.
`wazabin-sleigh-fmt` formats specification text.

## Two phase architecture

This project work in two seperate stages.

**Compilation** turns specification text into a [`CompiledSpec`].
preprocess and parse the `@include` graph, resolve symbols, then concretize every pattern and p-code template.
This is slow (~1s) for a real architecture, so it belongs at startup, or not in your process at all (see [Skipping the compile](#skipping-the-compile)).

**Decoding** walks the compiled decision tree for one instruction.
This is the hot path and is meant to be called in a loop.
A [`CompiledSpec`] is immutable once built, so a [`Decoder`] borrows it and many can share one specification.

```text
.slaspec ── compile ─> CompiledSpec ──decode─> Instruction ─> display / p-code
```

### Context

SLEIGH specifications decode against a *context*:
a bit vector holding the processor state that changes what the same bytes mean.
**This is the single most common way to get plausible-looking wrong answers.**

In x86-64, A zero-initialized context reads as 16-bit, so a 64-bit program decodes into nonsense.
Set the context :)

```rust,ignore
let mut context = spec.new_context();
let long_mode = spec.field("longMode").expect("x86 defines longMode");
spec.set_context_field(&mut context, long_mode.id, 1)?;

// Now 48 89 d8 is MOV RAX,RBX, not two 16-bit instructions.
let instruction = decoder.decode_one(0x1000, &[0x48, 0x89, 0xd8], &context)?;
```

Specifications can also *write* context as they decode.
`globalset` and context flow, used for things as ordinary as ARM/Thumb mode switching.
When you decode a stream rather than one instruction, carry the context forward instead of starting fresh each time; [`Instruction::context_effects`] reports what an instruction changed.

### Chose your p-code

Pick the lowest one that answers your question:

| Method                       | Gives you                                         | Use when                                            |
|------------------------------|---------------------------------------------------|-----------------------------------------------------|
| [`Instruction::pcode_ast`]   | Source-shaped AST, macros and sub-tables expanded | You want to read, print, or pattern-match semantics |
| [`Instruction::pcode_ops`]   | Flat Ghidra-style ops                             | You want the classic p-code array                   |
| [`Instruction::pcode_ops_streamed`] | The same ops, streamed into your sink, with a [`PcodePlan`] first | You are lifting at volume    |

The streamed form hands your sink the plan (every label and branch target in the instruction) before the first operation arrives.
A consumer can size its state up front and never re-scan.

### Skipping the compile

`wazabin-sleigh-precompile` compiles a fixed set of architectures during *its* build and embeds them, so loading is a deserialisation behind a `OnceLock`:

```rust,ignore
let spec = sleigh_precompile::x64::spec();
let decoder = sleigh::Decoder::new(spec);
```

Use it for tests and for tools that ship a known architecture (x64..).
Use this crate directly when the specification is chosen at runtime, or is not one of the embedded set.

## Compared to Ghidra

Ghidra's SLEIGH is two programs: a compiler that turns `.slaspec` into a built `.sla`, and a runtime that decodes against it

|                | Ghidra                                            | wazabin-sleigh                         |
|----------------|---------------------------------------------------|----------------------------------------|
| Input          | `.slaspec` → built `.sla`, then decode the `.sla` | `.slaspec` source, compiled in-process |
| `.sla` files   | Produces and consumes them                        | **Not supported** — source only        |
| Embedding      | Via Ghidra, or by linking the C++ decompiler      | `cargo add wazabin-sleigh`             |
| Corpus         | Ships all 149 specifications                      | Compiles 142 of 149 (see [Status](#status)) |
| Diagnostics    | Compiler messages                                 | [`Diagnostic`] values with spans, renderable as annotated snippets |
| Source tooling | —                                                 | [`analyze`] lints, `wazabin-sleigh-fmt` formats, `unstable-syntax` exposes the AST |

Two consequences worth stating plainly:

- **No `.sla` interop.** If you have a built `.sla` from Ghidra, this crate cannot read it.
Point it at the `.slaspec` sources instead.
Conversely nothing here produces a `.sla` for Ghidra to consume.
- **Compiling is not free.** Ghidra pays the compile cost once, offline, and ships the result.
Doing it in-process is what makes this embeddable, but it is why `wazabin-sleigh-precompile` exists.

Where behaviour is comparable, the goal is to match Ghidra: p-code opcodes, the unique space, context flow, and delay-slot expansion all follow it.

## Status

The compatibility figure is re-derived rather than asserted — the `corpus`
example compiles every specification in the vendored Ghidra corpus:

```text
$ cargo run -p wazabin-sleigh --example corpus
142/149 specifications compiled
```

Working: big-endian tokens, context flow and `globalset`, delay slots, variable-length register lists, `with` blocks, p-code macros, and sub-table export.

The seven that do not compile fall into three causes, and they are gaps here rather than defects in Ghidra's files:

| Specifications                               | Cause                         |
|----------------------------------------------|-------------------------------|
| `ARM6_be`, `ARM6_le`                         | Unimplemented builtin: `sdiv` |
| `ARM8_be`, `ARM8_le`, `ARM8m_be`, `ARM8m_le` | `ARMv8.sinc` leaves an `@if` unclosed; Ghidra's preprocessor tolerates this, ours does not |
| `hexagon`                                    | The `<<COMMIT>>` construct is not parsed |

## `sleigh-decode`

A small command-line decoder ships with the crate:

```text
$ cargo run -p wazabin-sleigh --bin sleigh-decode -- ./src/tests/fixtures/example.sla 108c
[0x0000] and r3,r4
```

It looks the specification up in the nearest `build_config.toml` and applies that architecture's defines and initial context, so it decodes the same way the embedded specifications do rather than from a zero context.

## Unstable features

Two feature flags expose the compiler's own representations. Both are exempt from this crate's semantic versioning and change whenever the internals do:

- `unstable-syntax` — the source AST, for tooling that works on specification *text*.
`wazabin-sleigh-fmt` is the intended consumer.
- `unstable-introspect` — read-only views over the decision tree and over constructor p-code with operands still unresolved.

## License

Licensed under the [MIT License](https://github.com/wazabin/sleigh/blob/main/LICENSE).
