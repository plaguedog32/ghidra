# Native P-code foundation

`ghidra-pcode` ports the operation model and concrete integer behavior from the retained Ghidra source. Opcode numbers and mnemonics are checked against `PcodeOp.java`, including its unused slot 45 and current `INSERT`, `ZPULL`, and `SPULL` definitions.

The value model preserves widths from 1 to 512 bytes. Integer arithmetic wraps at that width, signed views use two's complement, and oversized shifts have bounded behavior. The evaluator implements 41 pure integer, boolean, pointer, copy/cast, piece/subpiece, and bit-range/count operations, plus all 18 floating-point operations for the supported encodings. Operations requiring SSA, types, heap, or external userop context currently return explicit errors.

Floating-point arithmetic uses the Rust APFloat implementation, with integer-based correctly rounded square root. Supported encodings are IEEE binary16/32/64/128 and canonical x87 binary80. Exotic formats and noncanonical x87 encodings are rejected. Comparisons use unordered NaNs and equal signed zeros. `TRUNC` rejects nonfinite inputs and signed integer overflow; `ROUND` uses exact ties toward positive infinity. These rules deliberately avoid inconsistent results between Ghidra's Java long and BigInteger overloads, including nonstandard x87 special encodings. This is documented native behavior, not a claim of bit-for-bit parity with those Java edge cases. Floating-point status flags are not exposed.

The concrete machine adds LOAD/STORE and branch/call/return control transfers. Its state is byte-addressed, including overlapping register varnodes. Every address space has endianness and a word size; only LOAD/STORE scale pointer values into byte offsets, matching the P-code reference. Uninitialized reads are errors, rather than invented zero values. Calls do not synthesize native stack effects: those must be represented by the supplied architecture P-code.

Execution has instruction, operation, memory, and trace limits. Relative branches inside an instruction follow the signed operation-index offset convention used by `PcodeFrame`. Transfers outside the supplied instruction set are reported explicitly, and operation budget exhaustion is distinguished from ordinary fallthrough. The machine does not execute native host instructions, make system calls, or implement OS services.

Run the checked-in example:

```sh
cargo run -p ghidra-desktop -- --run-pcode examples/pcode/sum-loop.json
```

It computes `3 + 2 + 1` in a register using an instruction-local conditional loop. JSON output is streamed and includes a bounded trace and initialized state ranges. Snapshots are limited to 1 MiB of bytes and 4096 ranges; `memory.truncated` reports omitted state. Exit status 3 means the execution budget was exhausted; status 1 reports an invalid program or unsupported operation. Input JSON and machine memory are limited to 16 MiB by this command.

This is an intermediate representation and execution foundation, not a completed decompiler or a claim that arbitrary native programs can be emulated. Userops, architecture state initialization, operating-system models, and higher-level analysis remain separate work.

## Source-based instruction lifting

The desktop P-code tab can inspect any selected file-backed executable address. Choose a language ID from the catalog and select **Lift selected instruction**. Its `.pspec` decode defaults are applied automatically; optional context overrides take precedence. A raw `.slaspec` source can also be selected with caller-supplied defaults. **Follow selection** updates the view when the selected address changes; **Next instruction** advances by the lifter's semantic extent, including delay slots. Compilation runs in a persistent background worker and is reused until the language settings change or **Reload source** is selected. Queued requests are coalesced, and results from old programs or selections are discarded. Failed compilations are also cached until settings change or an explicit reload.

Processor defaults can vary by address. The adapter reads only context sets for the compiled language's code space, applies matching ranges in file order, and keeps tracked register values separate. Values exceeding the decoder's 64-bit context API are rejected. Explicit overrides win over processor defaults. The lower-level lifter preserves recorded `globalset` commits for callers implementing a flow analysis; the desktop resets these before every independent inspection so unrelated selections cannot change one another's decoding. Flow-dependent modes currently require explicit overrides. The native desktop can select addresses in non-x86 programs without interpreting their bytes through the x86 decoder.

`ghidra-languages` reads the real `.ldefs` and `.pspec` files in Rust. This checkout contains 202 language variants in 53 catalog files; all their processor specs parse without diagnostics. XML and file discovery are bounded, DTDs are rejected, and asset references stay within the chosen root without following symlinks or junctions. Missing and ambiguous assets are reported. Compiler specs are recorded as references; their calling-convention semantics are not implemented.

`ghidra-sleigh` compiles raw `.slaspec`/`.sinc` source using pinned `wazabin-sleigh` 0.1.15 and adapts operations explicitly to the native P-code model. It does not invoke Java, a Ghidra C++ compiler, or a precompiled `.sla` file. Catalog loading validates instruction byte order separately from RAM data byte order, preserving register alias layout for mixed-endian variants. Catalog presence does not prove that a language compiles or has correct instruction semantics.

```sh
cargo run -p ghidra-desktop -- --languages Ghidra/Processors
cargo run -p ghidra-desktop -- --lift-language \
  Ghidra/Processors x86:LE:64:default 1000 4889d8
```

The desktop finds assets in an ancestor checkout's `Ghidra/Processors` directory, or uses `GHIDRA_RS_LANGUAGE_ROOT`. **Choose folder** selects another catalog root. No processor is guessed from ambiguous binary metadata. The source assets remain external to the executable. Language choices and overrides are not yet saved in `.ghrs` projects.

The raw source command remains available:

```sh
cargo run -p ghidra-desktop -- --lift-pcode \
  Ghidra/Processors/x86/data/languages/x86-64.slaspec \
  1000 4889d8 longMode=1 addrsize=2 opsize=1
```

The CLI and desktop **Copy lift JSON** use schema `ghidra-rs.lifted-instruction`, version 1. Output includes disassembly, register storage, named userops, delay slots, and a `program` object in the execution command's input format. Extract that object and initialize any registers or memory it reads before executing it. A single lifted instruction does not initialize an emulated process.

Fourteen default compiler/lifter integration tests pass, including endian-aware memory, context precedence, tracked/context separation, delay slots, and concrete Rust execution. Six additional opt-in probes passed through the catalog path for this checkout's x86-64, ARM7 LE/BE, MIPS32 LE/BE, and ARM7 little-instruction/big-data sources:

```sh
cargo test -p ghidra-sleigh --test upstream_specs -- --ignored --test-threads=1
```

These are bounded instruction probes, not processor-wide parity. The adapter rejects ROM and word-addressed spaces, catalog space truncation, changing defaults within a delay-slot bundle, and unsupported operations; current source/compiler coverage must be established per specification. The compiler dependency's older opcode 71 is not cast to the newer `ZPULL` opcode. Its same-width extensions are explicitly converted to identity `COPY` operations while retaining strict P-code validation.
