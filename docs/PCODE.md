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

## Native control flow and SSA

Analyze a supplied P-code program without opening a window:

```sh
cargo run -p ghidra-desktop -- --analyze-pcode examples/pcode/sum-loop.json
cargo run -p ghidra-desktop -- --analyze-pcode \
  examples/pcode/alias-branch.json --instruction-uniques
cargo run -p ghidra-desktop -- --analyze-pcode \
  examples/pcode/alias-branch.json --expressions
```

Input uses the same `ExecutionInput` JSON format as `--run-pcode`. The analysis is
symbolic: it does not execute instructions or apply the `memory` initializers.
The output reports that choice and the number of ignored initialization regions
and bytes. Both branches in `alias-branch.json` therefore remain in the CFG,
although concrete execution with its supplied condition takes only one. Its
one-byte register writes merge through a phi while the other seven bytes retain
their preceding definition.

Output uses `ghidra-rs.pcode-analysis`, version 1. It contains the original
spaces/instructions, partitioned storage variables, semantic CFG edges, typed
terminal outcomes, calls/userops, SSA graph nodes, phi operands, source statement
mappings, renamed values, natural loops, and immediate dominators and
post-dominators. The SSA verifier runs before output. Phi operand order follows
that node's `incoming` list; a virtual `entry` predecessor remains distinct from
real backedges. Raw statement `uses`/`definitions` contain storage variable IDs;
their `renamed` fields contain SSA value IDs. Unreachable statements retain source
metadata with `renamed: null`. A value's origin maps back to its entry declaration,
phi or definition slot.

By default unique-space state is program-scoped, matching explicit concrete
P-code execution. `--instruction-uniques` instead creates fresh undefined
temporaries on native instruction entry and re-entry. Internal relative branches,
including branches to op 0, retain the frame. Synthetic reset graph nodes are
linked from CFG edges through `reset_node`; resets inside merged blocks remain
explicit statements. Undefined reset definitions are not zero-valued assignments.

Unknown call, userop and runtime effects are rejected by default. `--havoc-unknown`
retains them as marked opaque operations that read and redefine every observed
storage variable. This is conservative within the analyzed domain; it does not
recover an ABI or additional hidden machine state. Calls have a possible return
edge and a separate no-return exit; callees are not intra-procedural successors.
Post-dominance considers finite paths to all reported terminal exits, including
call-no-return outcomes. Indirect targets remain unresolved, and userop traps or
nonreturning behavior remain unmodeled.

Memory uses abstract whole-space dependency tokens. Aliased registers use
disjoint scalar cells with the byte order of their own space. Neither is pointer
disambiguation or type recovery. SSA uses liveness pruning, omitting phis for
storage that is dead on entry to a join. Resource limits bound live-in pairs,
phis and work; exhaustion is an error. The JSON `policies.ssa_form` records the
actual placement mode. This output is an analysis format,
not structured decompiled code or an execution-input format.

`--expressions` is opt-in and may be combined with the other options. It adds
one top-level `expressions` field (described in
[Typed expression inspection](#typed-expression-inspection)) to the same
`ghidra-rs.pcode-analysis` version 1 document. It is built from the verified
SSA in that document, so its value, phi and statement IDs index the report's
`values` and `nodes`. Without the flag, the report has no `expressions` field
and is otherwise unchanged. The 64 MiB output cap applies to the whole
document, including expressions.

Input is limited to a regular JSON file of 16 MiB. Native analysis phases have
separate instruction, operation, operand, graph, storage, phi and work limits.
Output is buffered under a 64 MiB cap before writing to stdout, so analysis or
serialization-limit errors leave stdout empty. Status 1 reports those failures;
status 2 reports missing or invalid command arguments. The command uses no Java
runtime, JNI, external decompiler process or native target execution.

## Recovered binary functions

Choose a matching x86 catalog language in **P-code**, select an instruction in a
recovered function, then open **Dataflow** and choose **Analyze selected function**.
The background worker reuses source compilation and keeps only the newest queued
request. Image, processor and effect-policy changes invalidate stale results.
The view has three modes: **CFG & SSA** (nodes, terminal exits, phi values and
SSA operations), **Storage variables**, and **Expressions** (see
[Typed expression inspection](#typed-expression-inspection)). **Copy analysis
JSON** exports the result. Analysis does not modify project metadata or
annotations.

The same pipeline is available without a window:

```sh
cargo run -p ghidra-desktop -- --analyze-function \
  GhidraDocs/GhidraClass/ExerciseFiles/WinhelloCPP/WinHelloCPP.exe \
  Ghidra/Processors x86:LE:32:default 401E46 --havoc-unknown
```

The address is a hexadecimal entry of a function found by current binary
recovery. Optional `context=value` arguments override processor defaults. The
explicit command language/context is used for this analysis; no project settings
are changed. Raw source mode is not accepted for function analysis. The catalog
processor, data/instruction byte order, language bitness and compiled code-space
width must match the x86/x64 image. Source bytes and instruction boundaries are
checked against recovery. A mismatch fails the analysis.

Constant P-code RETURN targets retain their literal width, including the narrow
sentinels emitted for x86 INT1/INT3. Computed return targets still require the
language's code-pointer width. Exit kinds describe the lifted P-code; they do
not establish an ABI return value or distinguish every native trap.

This initial function path decodes with independent processor defaults.
Instructions emitting global context commits and delay-slot bundles are rejected
because they need flow-aware decoding. Single-instruction lifting and checked
**Next instruction** retain their existing multi-processor support. Lift exports
now include `context_commits` so emitted decode effects are visible.

Calls and userops require **Conservative unknown effects** in the UI or
`--havoc-unknown` in the command. This preserves marked opaque full-domain effects
rather than guessing a calling convention. Incomplete function recovery remains
explicit, including branches outside the supplied domain. Output uses
`ghidra-rs.function-analysis`, version 1: `function` records native bytes,
disassembly, recovery status, declared language version, context and boundary
policy; `analysis` contains the P-code analysis schema described above;
`expressions` contains the `ghidra-rs.expressions` version 1 report built from
that same analysis. `expressions` is an additive field: the function schema
version remains 1, and earlier fields are unchanged. The command always
includes it.

Each function is limited to 5,000 native instructions, 100,000 lifted operations,
4,096 bytes of display text per instruction and 4 MiB total display text, plus
the native analysis and expression budgets and a 64 MiB JSON cap. The cap covers
the complete document: expressions are serialized into the bytes left after the
fixed prefix, function metadata, analysis report and closing brace, and the
final buffer is reserved once at its exact size. SSA uses liveness pruning.
There is no ABI/type recovery, indirect-target resolution, expression
simplification or structured decompiled output yet. Instruction-boundary checks
and SSA verification do not establish complete instruction-semantic parity.

An opt-in probe compiles the real x86-64 source, lifts a recovered loop function
from the synthetic PE sample, checks its SSA/loop structure and executes its
P-code to produce 3:

```sh
cargo test -p ghidra-desktop upstream_x86_function -- --ignored
```

## Typed expression inspection

`ghidra_analysis::PcodeExpressions` reconstructs typed P-code terms from a
verified SSA snapshot. The desktop and both headless commands use that one
engine and one report module; there is no second expression implementation.
Function analysis builds expressions on its background worker, after SSA
verification, and shares the SSA allocation with them. These are inspection
terms: opcodes are not evaluated or folded, and no types, calling convention or
C source are recovered.

**Dataflow → Expressions** lists either **SSA values** or **Operations** in
virtualized rows. A value row shows its ID, width or memory space, storage
variable and definition. An operation row shows the source statement and
address, opcode, operands and result. The detail panel shows the selected
item's type, storage, definition, operand roles, memory version, definitions
and direct inputs, plus **Go to** the source instruction where one exists.

Previews render one term level only. `vN` is an SSA value and `tN` is a term
node; children are shown by reference, never expanded. Phis list their
incoming values, so loops remain references. Joins, operand lists and phi
inputs show at most 8 items; detail lists show at most 16; literals show at
most 16 hexadecimal digits. Omitted items are counted. Join pieces are listed
from least to most significant, with byte position and width. Slices name their
low byte and width. Memory terms show their space, byte order and the exact
memory version read or written. Fixed varnodes show **byte** offsets; LOAD/STORE
pointers show their pointer width and word size. Instruction resets are labelled
**UNDEFINED** and conservative-effect outputs **OPAQUE**. Neither is shown as a
computed value. A RETURN input is labelled a control target, not an ABI return
value. Selections are clamped when the view changes. Image, processor and policy
changes invalidate the view as before. Expression inspection does not modify
project metadata or annotations.

### `ghidra-rs.expressions` version 1

The report is streamed from borrowed data and contains:

| Field | Contents |
| --- | --- |
| `schema`, `schema_version` | `"ghidra-rs.expressions"`, `1` |
| `policies` | Accompanying SSA schema (`ghidra-rs.pcode-analysis` v1), and fixed statements: unexpanded acyclic terms, no evaluation, byte offsets, word-scaled pointers, versioned whole-space memory, explicit undefined values, opaque unknown effects, `type_recovery: false`, `decompiled_output: false` |
| `counts` | `nodes`, `values`, `operations`, stored `references`, owned `constant_bytes`, reconstruction `build_work` |
| `nodes` | `{id, type, term}` in ID order. Each term references only earlier node IDs. |
| `values` | One entry for every SSA value: `{id, variable, type, definition}` |
| `operations` | One entry for every reachable explicit or opaque operation, in node/statement order |

`type` is `{"kind":"bits","bytes":N}` or `{"kind":"memory","space":S}`.
Bit vectors and memory states are separate types. `term.kind` is one of:

- `constant`: `bytes` and unsigned `hex` bit pattern.
- `ssa_value`: an SSA `value` reference. Its definition is not expanded.
- `join`: `pieces` of `{node, lsb_byte, bytes}` in ascending significance,
  covering the whole width without gaps.
- `extract`: the `lsb_byte` slice of `node`; width is the term's type.
- `apply`: an unevaluated `opcode` mnemonic over `inputs`. The operation may trap,
  for example on division by zero.
- `read_memory` / `write_memory`: `space`, prior memory `version` (an SSA value
  ID), `endianness` (`little`/`big`) of that space and `address`. Writes add
  the stored `node`, and their type is the new memory state. `address` is
  `{"kind":"byte_offset","offset":N}` for a fixed varnode, or
  `{"kind":"word_pointer","node":N,"word_size":W,"address_bytes":A}` for
  LOAD/STORE. Pointer values are in addressable words.

`definition.kind` is one of:

- `entry`: a symbolic `state` (`input`/`undefined`).
- `phi`: SSA `node` and `index`. Its operands are in the SSA report.
- `expression`: a `root` term.
- `undefined_reset`: a fresh temporary at `instruction`, from SSA `statement`.
  It is never zero.
- `opaque`: `statement` and `definition_slot`. No term is reconstructed.

Each operation records its SSA `statement {node, index}`, source `point`,
`opcode` and `effects`. `effects` is `{"kind":"explicit"}` or
`{"kind":"conservative","class":C}`. `operands` keep source order and roles:

- `value`: a term.
- `constant_metadata`: a term plus its `source` varnode.
- `relative_target`, `direct_target`: control labels, not memory reads.
- `space_selector`, `userop`, `operation_reference`.

`result` is `expression` (`output` is the complete bit result before alias
splitting or memory writes), `none` (STORE and control operations), or `opaque`.
`indirect_memory` is `{space, version, access}` for LOAD/STORE. `definitions`
are the SSA values the statement defines. An opaque operation's full-domain
uses are its SSA statement's `renamed.uses`; they are not copied. No-op,
reset and unreachable statements have no operation entry.

Expression construction uses separate limits: 500,000 graph nodes and
statements, 2,000,000 values, 4,000,000 term nodes, 8,000,000 references,
16 MiB of literal bytes and 100,000,000 work units. Exhaustion fails the
analysis with no partial result.

## Source-based instruction lifting

The desktop P-code tab can inspect any selected file-backed executable address. Choose a language ID from the catalog and select **Lift selected instruction**. Its `.pspec` decode defaults are applied automatically; optional context overrides take precedence. A raw `.slaspec` source can also be selected with caller-supplied defaults. **Follow selection** updates the view when the selected address changes; **Next instruction** advances by the lifter's semantic extent, including delay slots. Compilation runs in a persistent background worker and is reused until the language settings change or **Reload source** is selected. Queued requests are coalesced, and results from old programs or selections are discarded. Failed compilations are also cached until settings change or an explicit reload.

Processor defaults can vary by address. The adapter reads only context sets for the compiled language's code space, applies matching ranges in file order, and keeps tracked register values separate. Values exceeding the decoder's 64-bit context API are rejected. Explicit overrides win over processor and per-request defaults for both raw and catalog loading; recorded SLEIGH context commits sit above that baseline. The desktop resets commits for arbitrary selections so unrelated selections cannot change one another's decoding. **Next instruction** immediately lifts the next address with the displayed instruction's context, including when Follow selection is off. The worker checks the previous request ID, next address, program generation, and unchanged language settings; unavailable continuation state is an error. A failed decode breaks that chain. The view identifies continued versus independent context. Independent decoding can still require surrounding flow context, such as entry into a Thumb IT block. Full flow-aware disassembly analysis remains pending.

`ghidra-languages` reads the real `.ldefs`, `.pspec`, and `.cspec` files in Rust. This checkout contains 202 language variants in 53 catalog files; all their processor specs parse without diagnostics. XML and file discovery are bounded, DTDs are rejected, and asset references stay within the chosen root without following symlinks or junctions. Missing and ambiguous assets are reported. Compiler declarations are now typed data; their calling-convention allocation and execution are not implemented.

`ghidra-sleigh` compiles raw `.slaspec`/`.sinc` source using pinned `wazabin-sleigh` 0.1.15 and adapts operations explicitly to the native P-code model. It does not invoke Java, a Ghidra C++ compiler, or a precompiled `.sla` file. Catalog loading uses Ghidra's compatibility rule for the source's global storage order and the declared data/instruction orders. Instruction tokens may override the global order, as AArch64 BE does. `source_endianness()` reports the global declaration, not the order of every instruction token. RAM data order is set independently, preserving source register alias layout for mixed-endian variants. Catalog presence does not prove that a language compiles or has correct instruction semantics.

```sh
cargo run -p ghidra-desktop -- --languages Ghidra/Processors
cargo run -p ghidra-desktop -- --lift-language \
  Ghidra/Processors x86:LE:64:default 1000 4889d8
```

The desktop finds assets in an ancestor checkout's `Ghidra/Processors` directory, or uses `GHIDRA_RS_LANGUAGE_ROOT`. **Choose folder** selects another catalog root. No processor is guessed from ambiguous binary metadata. The source assets remain external to the executable. Version 2 `.ghrs` projects preserve the selected catalog language ID, declared major/minor version, and context overrides. Local source paths are not saved. Missing or mismatched assets leave the saved choice intact and block lifting until matching assets are supplied or the choice is explicitly replaced. Language versions are declared identifiers, not source-content fingerprints. Raw source selections and their overrides apply only to the current session.

Processor edits participate in the unsaved-project guard. Saving rejects malformed context drafts instead of storing the previous valid settings. Project loading validates bounded IDs and unique context fields, but resolving field names/widths and full processor semantics still belongs to the lifter. A project with an unsupported or unavailable processor can still retain its annotations and saved choice.

The raw source command remains available:

```sh
cargo run -p ghidra-desktop -- --lift-pcode \
  Ghidra/Processors/x86/data/languages/x86-64.slaspec \
  1000 4889d8 longMode=1 addrsize=2 opsize=1
```

The CLI and desktop **Copy lift JSON** use schema `ghidra-rs.lifted-instruction`, version 1. Output includes disassembly, register storage, named userops, delay slots, and a `program` object in the execution command's input format. Extract that object and initialize any registers or memory it reads before executing it. A single lifted instruction does not initialize an emulated process.

Sixteen default compiler/lifter integration tests pass, including per-token byte order, context precedence, tracked/context separation, delay slots, and concrete Rust execution. Seven opt-in source probes cover this checkout's x86-64, ARM7 LE/BE, MIPS32 LE/BE, ARM7 little-instruction/big-data, and AArch64 BE64 sources. An eighth probe exercises the desktop worker's Thumb IT continuation, verifying that the following MOV remains conditional:

```sh
cargo test -p ghidra-sleigh --test upstream_specs -- --ignored --test-threads=1
cargo test -p ghidra-desktop upstream_thumb_it -- --ignored
```

These are bounded instruction probes, not processor-wide parity. The adapter rejects ROM and word-addressed spaces, catalog space truncation, changing defaults within a delay-slot bundle, and unsupported operations; current source/compiler coverage must be established per specification. The compiler dependency's older opcode 71 is not cast to the newer `ZPULL` opcode. Its same-width extensions are explicitly converted to identity `COPY` operations while retaining strict P-code validation.

## Compiler specification data

Inspect a compiler specification without opening a window:

```sh
cargo run -p ghidra-desktop -- --compiler-spec \
  Ghidra/Processors x86:LE:64:default windows
```

The `ghidra-rs.compiler-spec` version 1 JSON contains the typed declarations and coverage diagnostics. It captures data organization, stack and return-address metadata, ordered parameter entries/groups/joins, prototype rules, aliases and merged models, clobbered/unaffected registers, and injection text. All 107 distinct referenced compiler specs parse with no diagnostics; 178 prototypes, 1551 entries, 230 rules, 28 groups and 92 join entries are captured. Those counts establish data coverage, not ABI correctness for native calls.

Register names and address spaces remain unresolved. No parameter storage is allocated, model rule is evaluated, merged ABI is scored, or injection text is compiled/executed. Compiler context/tracked settings are captured but are not yet applied by the instruction lifter. `is_fully_modeled()` describes captured declarations, not an executable calling convention. The empty upstream emulator `mock.cspec` is rejected as malformed XML. ABI resolution, argument/return assignment, and integration with function analysis remain required.

Compiler-spec reading has separate semantic-work, diagnostic-count and diagnostic-byte
budgets in addition to the XML bounds. Exhaustion returns an error instead of a
partial specification. Conflicting parameter groups stop at the first conflict;
large valid groups can exhaust the configurable work budget. Static injection
bodies must be nonempty and last in their payload; their original text is retained,
without compilation. Numeric size lists and nonnegative Java-int fields are
validated separately from address offsets.

## Resolved compiler storage

Resolve compiler locations against a compiled language's register layout:

```sh
cargo run -p ghidra-desktop -- --compiler-storage \
  Ghidra/Processors x86:LE:64:default windows
```

This command compiles the selected SLEIGH source and emits
`ghidra-rs.compiler-storage` version 1 JSON. The declarative `--compiler-spec`
command above remains available without compilation. The new report includes
the original compiler specification and diagnostics, the language register file,
and resolved locations indexed by source model/list positions. Its policy flags
explicitly report that argument allocation, prototype rules, injection
compilation and overlap resource groups are not implemented.

`RegisterId` indexes `registers.registers`; each physical alias retains its
actual space ID, byte offset and size. `resolved_storage` contains bindings,
ranges, stack properties, space bases and dead-code delays. Compiler-only
`Stack`/`Other` are separate space variants. Stack offsets are sign-extended
64-bit bits; interpret them as signed byte offsets. Joined pieces are in
most-significant-first order with explicit significance; floating logical-size
extensions are marked conversions with no slice offset. Unsized parameter
pool addresses stay unsized even when their maximum capacity is large.

The command accepts exactly ROOT, LANGUAGE_ID and COMPILER_ID. Argument failures
exit 2; discovery/compilation/resolution/output failures exit 1. Serialization
is buffered under a 64 MiB cap including the final newline, so failed analysis
does not print a partial JSON document. ABI construction bounds records, pieces,
names and work independently of compiler/parser budgets. A successfully resolved
report does not mean its calling convention can allocate arguments or execute
calls; source capture diagnostics remain visible. Initial real-source probes
and further validation are recorded in [RUST_PORT.md](RUST_PORT.md).
