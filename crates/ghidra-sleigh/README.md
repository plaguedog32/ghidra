# SLEIGH source lifting foundation

This crate compiles SLEIGH `.slaspec` and included `.sinc` source in process
with pinned `wazabin-sleigh = 0.1.15`, then explicitly adapts its raw p-code
to `ghidra-pcode`. It does not launch Java, JNI, the upstream C++ compiler,
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

The adapter supports byte-addressed RAM/register/unique/constant spaces with
addresses up to 64 bits. ROM permissions and word-addressed spaces are rejected
explicitly. Unknown or analysis-only operations are rejected. In particular,
the dependency's old `EXTRACT` opcode 71 is not reinterpreted as this checkout's
`ZPULL` opcode 71; no `SPULL` support is invented. Same-width sign/zero extensions
are normalized to their exact identity operation, `COPY`, while the strict
`ghidra-pcode` validator remains unchanged. `CALLOTHER` and its declared userop
ID are preserved; this does not implement that userop's execution semantics.

Always-on tests compile self-contained source and includes, run adapted p-code
in the Rust evaluator, and check context, delay slots, endian memory access,
identity extensions, explicit unsupported address units, and the opcode-71
boundary. Opt-in tests compile this checkout's x86-64, ARM7 LE/BE/mixed-endian,
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

This crate is Apache-2.0. `wazabin-sleigh` and its p-code dependency are MIT;
retained Ghidra processor specifications retain their upstream notices and
licenses. Further dependency licenses are recorded by their own packages.
