# SLEIGH source lifting foundation

This crate compiles SLEIGH `.slaspec` and included `.sinc` source in process
with `wazabin-sleigh = 0.1.15`, then explicitly adapts its raw p-code to
`ghidra-pcode`. The root manifest patches that package and its
`wazabin-pcode 0.1.4` dependency to local forks in `vendor/`, which preserve
direct-target provenance; `vendor/README.md` records their origin and changes. It does not launch Java, JNI, the upstream C++ compiler,
or the native decompiler, and does not consume precompiled Ghidra `.sla` files.

`SleighLanguage::from_spec(path, &context)` accepts processor-context values.
The caller must load the correct language defaults, normally from `.pspec`;
zero context is not a valid substitute for choosing an x86/ARM/MIPS mode.
`decode(&mut self, address, bytes)` retains address-specific `globalset` effects.
`reset_context()` clears those effects while retaining the supplied defaults.

The returned `LiftedInstruction.length` describes the displayed instruction.
Its `next_address` includes any delay slots. Expanded delay-slot semantics are
already inside `instruction.ops`, and `instruction.length` spans the bundle;
do not evaluate its `delay_slots` a second time. `spaces()`, `code_space()`,
`registers()`, and `userops()` provide the storage identities needed by a
consumer. Space IDs and byte offsets are preserved rather than renumbered.

The adapter uses byte-addressed instruction addresses. Non-default data/register
spaces may have address units of 1..=8 bytes, including non-power-of-two sizes,
when the full byte domain fits within 64 bits. Declared varnode offsets and
widths stay in bytes; only LOAD/STORE pointers are in address units. The machine
scales those pointers once. ROM permissions and word-addressed code spaces are
still rejected explicitly. Unknown or analysis-only operations are rejected. In particular,
the dependency's old `EXTRACT` opcode 71 is not reinterpreted as this checkout's
`ZPULL` opcode 71; no `SPULL` support is invented. Same-width sign/zero extensions
are normalized to their exact identity operation, `COPY`, while the strict
`ghidra-pcode` validator remains unchanged. `CALLOTHER` and its declared userop
ID are preserved; this does not implement that userop's execution semantics.

The pinned lowerer has two remaining word-space limitations. Address-of a
declared word-space register currently returns its byte offset without the
native fixed-symbol conversion to address units. A bounded per-instruction AST
audit rejects such address-of expressions, including resolved operand registers,
instead of emitting that wrong literal. Expansion has lost the distinction
between fixed symbols and operand handles, so dividing every resolved offset
would not faithfully repair both forms. Byte-space address-of remains available.
The extra audit admits at most 131,072 statement/expression nodes, uses an
iterative worklist, and releases its source-shaped AST before the existing
lowerer expands its own; byte-only languages keep their original lowering path.
This bounds the additional audit, not the dependency's earlier AST expansion.

Generic CSR exports in the RISC-V and NDS32 sources can still resolve a pointer
at default-code width rather than their CSR space's width; those instructions
fail explicitly during lowering. Selected RISC-V fixed CSR reads/writes and
NDS32 word-pointer user-register reads/writes and fixed interrupt returns have
real-source execution probes. NDS32's little-endian catalog variant also remains
incompatible with its source's hardcoded big-endian declaration. None of this
models CSR privilege, interrupt entry, or hardware side effects.

Direct `goto`/`call` through a sub-table's starred export keeps the export's
space and width; the forked compiler carries them from the decoded export to
raw lowering instead of reconstructing them from a flattened literal. For
`export *[aux]:2 0x10:1` the target is two bytes at `aux` byte 0x10, or 0x30
when `aux` has three-byte words, as native SLEIGH computes it. Dynamic exported
pointers and constant-space destinations are lowering errors rather than
guessed branches, and a failed instruction commits no context. The machine and
CFG builder still refuse transfers outside the code space, so such a target is
lifted faithfully but not executed. The word-space address-of audit also visits
these targets' pointers. `globalset` through a table export still uses only its
pointer. The selected processor probes do not establish cross-space behavior.

Always-on tests compile self-contained source and includes, run adapted p-code
in the Rust evaluator, and check context, delay slots, endian memory access,
identity extensions, word-space byte extents and pointer scaling, explicit
unsupported code-address units, space-qualified direct targets and their
machine/CFG refusal, and the opcode-71 boundary. Opt-in tests compile this checkout's x86-64, ARM7 LE/BE/mixed-endian,
MIPS32 LE/BE, AArch64 BE64 and SH-2A sources. An ARM v8 probe compiles all seven
catalog variants (A32/Thumb, LE/BE, little-instruction/big-data and v8-M),
executes LDA/LDAB and both VSELEQ outcomes, and checks that VPNOT executes only
in the M variants. The retained ARMv8 source has a redundant nested VERSION_8M
guard removed; closing it at EOF instead would incorrectly hide VSEL from
non-M variants. These probes cover selected instructions, not full ISA semantics,
memory-ordering behavior, or processor-wide parity.

```sh
cargo test --locked -p ghidra-sleigh
cargo test --locked -p ghidra-sleigh --test upstream_specs -- --ignored --test-threads=1
```

On Windows, use a Visual Studio Developer PowerShell or dot-source the root
`scripts/Enter-NativeBuild.ps1` before Cargo. Transitive parser stack helpers
(`stacker`/`psm`) require a native compiler and SDK; the SLEIGH compiler and
runtime themselves are Rust and require no JDK/JRE or Ghidra C++ runtime.

This crate is Apache-2.0. `wazabin-sleigh` and its p-code dependency, including
the vendored forks, are MIT;
retained Ghidra processor specifications retain their upstream notices and
licenses. Further dependency licenses are recorded by their own packages.
