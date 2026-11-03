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

The desktop P-code tab can inspect any selected file-backed executable address. Choose a `.slaspec` source, supply the processor context defaults, and select **Lift selected instruction**. **Follow selection** updates the view when the selected address changes; **Next instruction** advances by the lifter's semantic extent, including delay slots. Compilation runs in a persistent background worker and is reused until the language settings change or **Reload source** is selected. Queued requests are coalesced, and results from old programs or selections are discarded.

Processor defaults can vary by address. They form the decode baseline beneath previously recorded `globalset` context commits. Loading another binary resets those commits without requiring a source recompile. The native desktop can select addresses in non-x86 programs without interpreting their bytes through the x86 decoder.

`ghidra-sleigh` compiles raw `.slaspec`/`.sinc` source using pinned `wazabin-sleigh` 0.1.15 and adapts operations explicitly to the native P-code model. It does not invoke Java, a Ghidra C++ compiler, or a precompiled `.sla` file. Context defaults must currently be supplied explicitly; automatic `.pspec`/`.ldefs` language selection remains work to do.

```sh
cargo run -p ghidra-desktop -- --lift-pcode \
  Ghidra/Processors/x86/data/languages/x86-64.slaspec \
  1000 4889d8 longMode=1 addrsize=2 opsize=1
```

Output includes disassembly, register storage, named userops, delay slots, and a `program` object in the execution command's input format. Initialize any registers or memory read by that program before executing it. A single lifted instruction does not initialize an emulated process.

Nine default compiler/lifter fixtures pass, including endian-aware memory, context commits, delay slots, and concrete Rust execution. Additional opt-in probes passed for this checkout's x86-64, ARM7 LE/BE, and MIPS32 LE/BE sources:

```sh
cargo test -p ghidra-sleigh --test upstream_specs -- --ignored --test-threads=1
```

These are bounded instruction probes, not processor-wide parity. The adapter rejects ROM and word-addressed spaces and unsupported operations; current source/compiler coverage must be established per specification. The compiler dependency's older opcode 71 is not cast to the newer `ZPULL` opcode. Its same-width extensions are explicitly converted to identity `COPY` operations while retaining strict P-code validation.
