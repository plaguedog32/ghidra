# Rust port: status and development

The goal is a Ghidra replacement that builds and runs without Java. The current deliverable is a native desktop and analysis foundation with projects, function recovery, P-code execution, and source-based instruction lifting. It does not claim feature parity with Ghidra.

## Current architecture

| Component | Responsibility |
| --- | --- |
| `crates/ghidra-core` | Binary parsing, section/address mapping, symbols, ASCII strings, x86/x64 decoding, direct references, and basic blocks |
| `crates/ghidra-core/src/functions.rs` | Bounded recursive function discovery and reachable control-flow blocks |
| `crates/ghidra-core/src/linkage.rs` | Imports, exports, and relocation records with format-specific coverage warnings |
| `crates/ghidra-project` | Portable projects, annotations, source integrity, bounded deserialization, and atomic saves |
| `crates/ghidra-pcode` | Exact opcode model, bounded integer/software-float semantics, and concrete P-code execution |
| `crates/ghidra-graph` | Bounded traversal, SCCs, dominators/frontiers, natural loops, and finite-exit-path post-dominators |
| `crates/ghidra-cfg` | Raw P-code control flow, operation identities, instruction-entry provenance, calls and explicit terminal outcomes |
| `crates/ghidra-ssa` | Bounded generic unpruned/liveness-pruned SSA construction and independent reaching-definition verification |
| `crates/ghidra-analysis` | Alias-aware storage, memory dependencies, temporary lifetimes, opaque effects, P-code-to-SSA adaptation and typed expression reconstruction |
| `crates/ghidra-languages` | Bounded catalog discovery, asset resolution, processor context/tracked settings, and typed compiler/ABI declarations |
| `crates/ghidra-abi` | Compiler storage, resource groups/effects, explicit fallback, Java datatype predicates/extraction and native primitive alignment |
| `crates/ghidra-types` | Bounded datatype graphs, compiler-driven ordinary layouts and GCC/MS bitfield storage |
| `crates/ghidra-sleigh` | Raw SLEIGH source compilation, context-aware decoding, and explicit P-code adaptation |
| `crates/ghidra-desktop` | Native desktop UI, file selection, navigation, and a headless JSON analysis command |
| `object` | Rust PE, ELF, and Mach-O parsing |
| `iced-x86` | Rust x86/x64 instruction decoding and instruction flow information |
| `eframe` / `egui` | Native application window and immediate-mode interface, using the Glow renderer |
| `rfd` | Native file selection |

The executable does not launch the imported program. It reads binary data for inspection. Input parsing and decoding are bounded; malformed and unsupported inputs should produce errors rather than launch another tool.

### Required UI and automation architecture

The user requires strict separation between UI execution and application work,
plus native MCP control of every available feature and reliable discovery and
targeting of multiple concurrent instances. The
[architecture contract](UI_AND_MCP_ARCHITECTURE.md) defines the shared
application API, bounded background jobs, immutable views, revision checks,
instance/document identities and acceptance gates. It applies to future
native work and the migration of existing paths.

Existing workers offload import, lifting and Dataflow analysis, but report
export, some copying/disposal and frame-wide scans still need migration.
There is no native MCP server/discovery implementation yet. The full-port goal
has resumed with this foundation prioritized; the requirements are not a
claim of runtime support.

The root Cargo workspace builds the Rust crates and their native platform helpers. It does not compile the retained Java/C++ application or invoke Gradle. Tests read the upstream opcode table as text, and source-lifting probes use retained processor language data. No Java runtime, JNI bridge, Ghidra C++ decompiler process, or Java-backed extension is used.

## Feature status

| Capability | First milestone | Remaining work |
| --- | --- | --- |
| Native desktop | Rust window, linked inspection views, background instruction lifting and function Dataflow inspection | Full docking/workspace system, accessibility and workflow refinement |
| Binary formats | PE, ELF, and single-architecture Mach-O inspection | Additional formats, universal/fat Mach-O selection, richer loader semantics and relocations |
| Processor support | x86/x64 listing; 202 catalog definitions; processor defaults and checked Next-instruction context; lifting probes for x86-64, ARM7, all seven ARM v8 variants, MIPS32 LE/BE, AArch64 BE64, SH-2A and Thumb IT | Automatic binary-to-language matching, full flow-aware context analysis, broader semantic coverage, architecture-neutral function recovery |
| Metadata | Entry point, sections, symbols, ASCII strings, imports/exports, relocation records | Remaining linkage formats, relocation application, debug information and types |
| Code analysis | Linear listing and bounded recursive discovery from entry points, symbols and direct calls; reachable basic blocks | Indirect targets, jump tables, exception paths, speculative discovery, data/code separation |
| Navigation | Addresses, functions, discovered incoming references, labels, comments, bookmarks and linked binary views | Rich search, full cross-reference model and workflow refinement |
| Headless analysis | JSON output from the same Rust core | Stable automation API and batch processing |
| Native MCP control | Architecture and acceptance contract; runtime not implemented | Shared application commands, MCP tools/resources/jobs, instance discovery/identity, GUI controls and multi-instance routing |
| P-code | 74-opcode model, 59 pure integer/software-float operations, bounded concrete memory/control execution, source lifting | Userops, SSA context, architecture/OS state models, full format coverage |
| Decompilation | Native P-code CFGs, alias-aware liveness-pruned SSA, typed expressions, constant facts and value simplification; x86/x64 function lifting, Dataflow inspection and headless reports | Other processor function flows, broader IR optimization, ABI/type recovery and structured output |
| Projects | Self-contained `.ghrs` projects with embedded binary, integrity checks, annotations and atomic saves | Project collections, migration, upstream `.gpr`/`.gzf` compatibility and database semantics |
| Debugger | Not implemented | Native debugger backends, memory/register views and trace support |
| Extensions and scripting | Not implemented | Native plugin boundary and a Java-free scripting strategy |
| Collaboration | Not implemented | Shared projects, synchronization and access controls |

The normal disassembly listing is a linear sweep of a bounded executable region, not proof that every decoded byte is reachable code. The Functions view instead follows reachable branches and direct calls, avoiding a sweep after returns and unconditional jumps. Discovery is globally bounded, reports instruction conflicts and shared tails, and does not resolve indirect targets, jump tables or exception paths. A function marked complete means this traversal found no known gap; it does not prove a complete semantic function. Stripped binaries may have few or no symbols.

The Linkage view reads PE32/64 normal imports with IAT slot addresses, named/ordinal exports and base relocations; ELF traditional imports/exports and section/dynamic relocation records; and traditional Mach-O symbol-table/section relocation metadata. Delayed imports, forwarded exports, sectionless ELF dynamic tables, RELR, and newer Mach-O dyld formats have explicit coverage warnings. Relocations are inspected, not applied; in-place implicit addends are not evaluated.

Native projects preserve the original binary, labels, comments, bookmarks, last selected address, and catalog processor identity/context overrides. `.ghrs` version 2 uses the same fixed header, bounded JSON metadata, original image bytes, and separate SHA-256 integrity checks as version 1. Existing version 1 projects migrate on load; saves write version 2, which older executables reject explicitly. These checks detect corruption and do not authenticate authorship. Saving validates mapped addresses and uses a temporary sibling plus atomic replacement. The desktop prompts before discarding unsaved annotations or processor settings and blocks edits while replacing or saving a project. Missing language assets preserve the saved choice; a different declared version must be selected explicitly. Source paths are local catalog settings, and raw source choices remain session-only. This format is separate from upstream Ghidra projects.

Metadata support does not imply decoder support: an ARM executable can be inspected without pretending its bytes are x86 instructions. Address mapping and decoding errors must be presented explicitly.

## Build prerequisites

- Stable Rust, version 1.88 or newer, installed with `rustup`.
- Windows: Visual Studio C++ build tools and a Windows SDK for the Rust MSVC linker.
- macOS: Xcode command-line tools.
- Linux: a C compiler, native windowing and graphics development libraries, and a working graphical desktop for interactive use. The headless JSON command does not open a window.

On Ubuntu/Debian, the CI dependency set is:

```sh
sudo apt-get update
sudo apt-get install -y build-essential pkg-config libgtk-3-dev \
  libxkbcommon-dev libwayland-dev libgl1-mesa-dev libx11-dev libxi-dev \
  libxcursor-dev libxrandr-dev libxinerama-dev libxcb-shape0-dev libxcb-xfixes0-dev
```

These are native application build requirements. Neither the Cargo workflow nor the executable needs a JDK or JRE. Runtime graphics drivers and platform libraries are still required. Linux file dialogs may use the desktop portal service.

On Windows, use a Visual Studio developer shell or initialize its compiler/SDK environment in the current PowerShell process before building:

```powershell
. ./scripts/Enter-NativeBuild.ps1
cargo build --locked --release -p ghidra-desktop
```

The SLEIGH dependency is a Rust source compiler/lifter. Its stack-management dependency uses small platform-native build helpers, so Windows SDK headers are needed in addition to the linker. This does not introduce a Java or Ghidra C++ runtime dependency.

## Commands

From the repository root:

```sh
# Native desktop
cargo run --release -p ghidra-desktop

# Load a binary at startup
cargo run --release -p ghidra-desktop -- /path/to/program

# Embedded x64 demonstration
cargo run --release -p ghidra-desktop -- --demo

# JSON analysis without opening a desktop window
cargo run --release -p ghidra-desktop -- --analyze /path/to/program

# Create or reopen a portable native project
cargo run --release -p ghidra-desktop -- --create-project /path/to/program analysis.ghrs
cargo run --release -p ghidra-desktop -- analysis.ghrs

# Reproducible release build
cargo build --locked --release -p ghidra-desktop
```

The executable is `target/release/ghidra-rs` on Linux/macOS and `target/release/ghidra-rs.exe` on Windows. The root `Cargo.lock` pins application dependencies and should be committed.

The repository toolchain tracks stable Rust for development. To select the
declared minimum explicitly, install Rust 1.88.0 and run:

```sh
rustup toolchain install 1.88.0 --profile minimal
cargo +1.88.0 test --locked --workspace --all-targets
cargo +1.88.0 test --locked --workspace --doc
```

Workspace resolver 3 prefers dependencies compatible with the declared Rust
version; this is a preference, so the fixed-toolchain CI check remains
necessary. See [Cargo's resolver documentation](https://doc.rust-lang.org/cargo/reference/resolver.html#rust-version).
Keep `--locked` for reproducible application builds.

Development checks:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
```

The dedicated `.github/workflows/rust-desktop.yml` runs these checks and produces native release executables on Windows, Linux, and both ARM64 and Intel macOS hosts. A matching four-host matrix tests all workspace targets and doctests with exactly Rust 1.88.0. It contains no Java installation or Gradle step. The old `build-ghidra.yml` remains restricted to the upstream `master` branch for reference maintenance; it is not the Rust build.

## Validation of this milestone

Local validation on Windows with Rust 1.99.1:

- Workspace tests cover binary formats/linkage, recursive discovery, project integrity/atomic replacement and version migration, asynchronous desktop state, restored processor settings, P-code integer/software-float semantics, execution bounds, language/processor/compiler XML data, context precedence, per-token byte order, mixed-endian source lifting, compiled-source reuse, checked continuation and stale-result rejection. The desktop tests also render every inspection view through egui without requiring a native window. Nine opt-in processor probes cover seven source configurations, the worker's Thumb IT continuation, and recovered x86 function lifting/SSA/execution.
- The graph crate contributes 12 integration tests and a doctest, including 1,600 fixed-seed oracle comparisons and a 100,000-node chain. Its post-dominators describe finite paths to explicit terminal exits; infinite paths are excluded. P-code CFG/SSA uses the graph crate; the desktop lists function CFG nodes, while graphical layout remains pending.
- P-code CFG tests cover relative/native control flow, calls, explicit terminal exits, no-ops, delay extents and instruction-frame provenance. SSA tests include path-execution oracles, undefined entry values, entry loops, irreducible graphs, exact limits and 100,000-node inputs. The adapter adds register-alias joins, memory versions, opaque effects, frame resets, concrete-machine trace comparisons, and bounded large-loop behavior. Application analysis now uses liveness-pruned SSA; whole-space memory tokens are conservative dependencies, not pointer disambiguation or decompiled output.
- The headless analysis command passes nine report/schema tests and two process-level tests, including a Java-free subprocess and empty stdout on argument/input failures. The optimized executable also analyzed `alias-branch.json` with `JAVA_HOME` empty and `PATH` restricted to Windows system files: 5 nodes, 10 SSA values and 1 phi, with verification enabled. Concrete `sum-loop.json` execution still returns 6 in 14 operations in the same environment.
- Function analysis tests cover binary/source boundary agreement, catalog compatibility, context-commit rejection, incomplete recovery, bounded display text, compilation reuse, unknown calls, queue coalescing and stale responses. Populated function/storage views render through egui without changing project state. The real x86 source probe lifts a recovered PE loop function to verified SSA and executes its P-code to return 3.
- The optimized `--analyze-function` command also lifts the retained PE32 WinHelloCPP entry at `401E46` with no Java available: 135 recovered instructions, 151 graph nodes, 10,953 SSA values and 2,192 phis. Its 32 calls use marked conservative effects, and incomplete recovery remains explicit. This is native dataflow inspection, not structured decompiled output.
- Typed compiler declarations cover all 107 distinct referenced `.cspec` files without diagnostics, including 178 prototype models. Register/space resolution, resource planning and explicit-request fallback allocation are available separately; datatype-driven signature allocation, rule execution and injection compilation remain pending. Parser coverage is not executable ABI support.
- Formatting and Clippy with warnings denied pass; the optimized executable builds.
- The executable analyzed the retained WinHelloCPP PE32 example, the retained `little.elf` example, and its own PE64 executable.
- Analysis succeeds with `JAVA_HOME` empty and `PATH` restricted to Windows system files.
- The same Java-free environment compiled this checkout's x86-64 SLEIGH source, lifted `MOV RAX,42`, and executed the resulting P-code to produce `RAX = 42`.
- The catalog-based CLI also discovered 202 languages and lifted/executed that instruction without explicit context arguments in the same restricted environment.
- Version 1 project migration and version 2 processor-configuration round trips also succeed in that Java-free environment, preserving the embedded image and unavailable language choices.
- The same environment lifts and executes AArch64 BE64 `mov x0, #1`, and inspects the Windows x64 compiler specification with zero diagnostics.
- Independent floating-point review verdict: "implementation approved; no P1/P2 findings."
- Independent review of the graph/project increment returned "Verdict: approve." It added 21,200 graph-oracle comparisons, including irreducible/nested cycles and larger random graphs.
- Independent CFG and SSA reviews at `89cd38c6a6` both approved their changes. Separate probes checked 13,650 CFG cases and 3,000 concrete traces, and 17,288 SSA oracle cases plus deliberately corrupted operands/phis. The later storage/adapter increment received separate approval at `b9b26eed4e`.
- The desktop sample creates a responsive native window; its loaded modules contain no JVM. Automated visual and click-through verification was unavailable because the local Windows computer-use helper could not connect.

The initial desktop commit passed all three host builds in [CI run 41733853407](https://github.com/plaguedog32/ghidra/actions/runs/41733853407), project/function/linkage in [CI run 41735800993](https://github.com/plaguedog32/ghidra/actions/runs/41735800993), P-code/SLEIGH commit `8829d3875d` in [CI run 41739187343](https://github.com/plaguedog32/ghidra/actions/runs/41739187343), the background P-code view in [CI run 41741071127](https://github.com/plaguedog32/ghidra/actions/runs/41741071127), and catalog lifting in [CI run 41743436295](https://github.com/plaguedog32/ghidra/actions/runs/41743436295). Later increments must pass their own runs before inheriting that cross-platform claim.

## Development checkpoint

### Active continuation with UI and MCP requirements

The full replacement goal has resumed after the saved checkpoint below.
Prioritize extraction of the shared application/document/job service and
migration of the existing UI operations, then build native MCP control and
protected multi-instance discovery on that API. Independent review is still
required for the integrated compiler provenance repair (`da2b34ea83`) and
native one-value fallback allocator (`48c91d72ac`). Their passing tests do not
establish approval. Structuring and ELF RELR work remain separate open gates.

### Paused checkpoint: 2026-11-04

Work is paused at the user's requested stopping point. The full replacement
goal remains unfinished. The last pushed, independently reviewed checkpoint
is `3a2f78686db1db905f508c4bc8e26c48a309984c` on `rust-desktop`.

Three additional commits are integrated locally and have not been pushed:

- `c5328b9c0a`: unchanged, pinned SLEIGH/P-code compiler packages with retained
  licenses and verified registry provenance.
- `da2b34ea83`: preserve qualified direct-target space, exported width and
  address units through the owned and streamed compiler paths.
- `48c91d72ac`: native one-value fallback allocation, including shared
  floor-alignment arithmetic and a reusable budget/journal kernel.

The compiler repair and native fallback allocator still require independent
review. Their passing tests do not establish approval. The combined tree
passes 868 default workspace tests and 24 doctests on Windows with stable
1.99.1 and Rust 1.88.0, plus formatting and workspace all-target Clippy with
warnings denied. Release/Java-free output evidence in the preceding approved
checkpoint applies to that earlier tree; it has not been repeated here.

Compiler-fork tests now have an isolated-copy CI helper,
`scripts/Test-VendoredSleigh.py`; see [the vendor testing instructions](../vendor/README.md#testing-the-forks-on-their-own).
Vendor changes trigger both workflow matrices. The helper requires Python
3.12 or newer for testing only; the Rust executable does not require Python.
All six selected fork suites pass on stable 1.99.1 and Rust 1.88.0, with
checked-in compiler sources and lockfiles unchanged. The external-checkout
allocation benchmark is excluded, as documented in the vendor instructions.

The separate structuring implementation task was asked to stop and preserve
its checkout. No structuring implementation is integrated. Resume by
reviewing the two local increments and any preserved structuring draft before
starting another feature. ELF RELR inspection remains design-only under its
[port contract](ELF_RELR_PORT_CONTRACT.md). Existing stashes are retained.
Native window/clipboard checks and fresh cross-platform CI remain open gates.

### Previous approved verification checkpoint

The current analysis/ABI/datatype/SSA tree passes 846 default workspace tests and
23 doctests on stable and Rust 1.88.0, formatting, workspace Clippy and
Rust 1.88 rustdoc with warnings denied,
and the optimized Windows build. Java-free release probes still cover raw
P-code analysis and the recovered WinHelloCPP `401E46` function. Bitfield
storage, compiler datatype predicates and primitive/union extraction are
integrated. Independent review approved the extraction and bitfield fixes;
its trailing-empty-member boundary finding is addressed below. The newer
selected-pool assignment and resource-effect operations also received
independent approval. Their budget errors now have one typed classification.
Native primitive alignment has directed and independent oracle coverage.
The converted native datatype graph, native primitive extraction and native
filter/qualifier/HFA evaluation are integrated as separate APIs, with
independent review approval. Bitfield value reads and numeric formatting now
have directed and independent-bigint evidence and cross-lab approval. The
review's guard-specific test gap is fixed. Opt-in typed expression
simplification/export has independent approval. Parallel-copy and phi
lowering APIs have independent approval. Native general ABI join allocation
has been reviewed, and its stack-rejection-order finding is fixed.
Native dual-class ABI join allocation now consumes the converted native
datatype graph, classifies primitive windows and allocates across two register
classes with optional stack spill. Its initial review found two native-int
evaluation-order gaps; both have regression fixes and independent re-review
approval at `51850a14ba`. Compiler `storage`/`a` aliases now follow document order
and validate both values. Eight opt-in native general/dual-class join probes
pass in a Rust 1.88 release build, including x86-64 GCC and MIPS64 LE/BE.
Native-object predicate queries now accept synthesized datatype identities
directly, with independent approval at `0123268173`; details are recorded below.
Source changes
are committed on `rust-desktop`; the minimum-version validation below applies
to this integrated checkpoint.

Native visual and click-through verification was attempted again on
2026-11-04. The computer-use helper returned `Computer Use native pipe is
unavailable` on discovery, retry, and retry after session reset. No desktop
application was launched or changed during that attempt. The headless egui
checks do not establish native window, file-dialog or display-scaling
behavior. Restore the desktop helper and verify binary opening, navigation,
disassembly and Dataflow inspection in the real window before closing that
milestone gate. Rust 1.88 and stable CI validation on Windows, Linux and
macOS is now recorded below.

### ARM v8 source coverage

The retained `ARMv8.sinc` opened `VERSION_8M` twice before VPNOT and closed
it once before the later NEON block. Removing the redundant second opening
repairs compilation without moving VSEL under the M-profile condition. An
independent source audit checked the include chain, original change and
conditional nesting; the Rust preprocessor is unchanged.

The new opt-in source test compiles all seven v8 catalog variants. It executes
A32/Thumb LDA and LDAB with LE, BE and mixed instruction/data byte order,
checks both VSELEQ outcomes after the repaired block, and complements only
VPR's low 16 bits with VPNOT in the two v8-M variants. The same Thumb encoding
does not decode as VPNOT in the five other variants. Encodings and expected
effects come from the retained constructors and token fields. These selected
P-code checks do not validate hardware memory ordering or the full ISA.

On Windows, the new test passes in stable debug and Rust 1.88 release builds.
All 22 default SLEIGH tests and all nine opt-in source tests pass together
under Rust 1.88 release. Stable crate tests, all-target Clippy with warnings
denied, formatting and workflow actionlint also pass. The existing Rust 1.88
release command resolves compiler storage and resource groups for all 17
compiler/language pairs in these seven variants with `JAVA_HOME` empty and
`PATH` restricted to System32. This is storage-resolution evidence, not
datatype-driven signature allocation. The CI path filter now includes
processor data changes so future source-only fixes run the native checks.
This increment does not claim a new whole-workspace or cross-platform result;
the earlier checkpoint evidence remains recorded separately.

### Non-default word-addressed storage

The SLEIGH adapter now preserves word sizes on non-default spaces instead of
rejecting every language that declares them. Declared register/varnode offsets
and sizes remain bytes; LOAD/STORE pointers remain address units for the
machine to scale once. Byte extent checks include the final word. Source units
must be 1..=8 bytes and the full byte domain must fit in 64 bits, matching the
retained source-compiler bounds. The default code space must still be
byte-addressed because semantic and disassembly instruction addresses need
different conversions in word-addressed code.

An independent source audit traced the native compiler, pinned Rust lowerer
and machine. It found a remaining lowerer bug: address-of fixed word storage
returns bytes without conversion to words. The expanded AST loses the original
fixed-symbol versus operand-handle distinction, so an instruction-level audit
refuses these expressions rather than guessing the missing conversion. The
audit is iterative and capped at 131,072 statement/expression nodes; it uses
one extra AST expansion for word-space languages and preserves the original
lowerer for exact register bit ranges. Byte-only languages retain their old
path. Independent review approved `b802794ab0`. It exercised all 80 source
dimension combinations, macro/operand/delay-slot address-of refusals, context
commit isolation and broad real CSR/user-register sweeps. Its nonzero byte-
space address-of test gap is fixed by checking register byte offset 4.

Synthetic checks cover units 1..8, both byte orders, fixed and indirect reads
and writes, exported pointers, exact byte boundaries, dimensions, bit ranges
and address-of refusals in memory/control/userop expressions. Real probes
execute RV32/RV64 FRCSR, FRRM and FSCSR at the declared CSR byte offsets, and
NDS32 BE MFUSR/MTUSR at word pointer 0x201 (byte 0x804) plus IRET through the
unaligned fixed IPC register at byte 0xa9. Generic CSR exports still fail with
the dependency's explicit pointer-width error. NDS32 LE's hardcoded BE source,
CSR privilege and interrupt entry/side effects remain unmodeled. Selected
source execution does not establish full processor or calling-convention support.

Validation passes 798 default workspace tests and 22 doctests on stable and
Rust 1.88.0, workspace/all-target Clippy and Rust 1.88 rustdoc with warnings
denied, formatting and the Rust 1.88 optimized desktop build. All 28 default
SLEIGH tests and eleven opt-in source tests also pass together in Rust 1.88
release. Java-free command probes lift RV32, RV64 and NDS32 instructions,
execute them to 0x12345678, then export verified SSA, expressions, constants and
simplification while preserving the CSR word metadata and byte/word address
forms. This is local Windows evidence; a new cross-platform result is still
required.

That review separately reproduced a pre-existing dependency bug: direct
`goto`/`call` through a non-default-space sub-table export loses its space
before raw lowering. A word-size-3 export at address 0x10 becomes default-space
byte 0x10 rather than `aux` byte 0x30. Root reproduced both byte- and word-space
cases. No newly admitted catalog instruction in the review sweeps used this
form; correct exported-target provenance remains a required compiler fix.

### Minimum Rust version validation

Local Windows checks on 2026-11-04 now use installed Rust 1.88.0, not just API
inspection with a newer compiler. All workspace targets compile, all 660 tests
and 16 doctests pass, and the optimized desktop executable builds. The
development toolchain remains unchanged. This validates the checked-in lockfile
and default workspace features, not every optional dependency configuration.
The Rust 1.88 release executable also runs the raw examples and recovered
WinHelloCPP function with `JAVA_HOME` empty and `PATH` restricted to Windows
System32. Its analysis counts and output match the newer-toolchain probes.

The initial dependency audit found a real Linux gap: `rfd`'s portal dependency
chain selected `uuid 1.29.0`, which requires Rust 1.89. Resolver 3 now selects
`uuid 1.26.1`; that version and checksum are the only lockfile changes. A
stable-Cargo dry run also keeps the compatible version. Selected dependency
metadata for Windows MSVC, Linux GNU and Apple ARM now declares no Rust version
above 1.88; metadata compatibility alone does not prove those platforms build.

The workflow adds exact Rust 1.88.0 all-target and documentation tests on all
three hosts, retaining the separate stable checks/source probes/release builds.
The workflow passes actionlint, and an independent configuration review found
no actionable findings. [CI run 41833473619](https://github.com/plaguedog32/ghidra/actions/runs/41833473619)
passed all six jobs for source commit `816047b9c0`: Rust 1.88 tests/doc examples
and stable checks/source probes/release builds on Windows, Linux and macOS.
Native executables are available in that run's artifacts. These checks do not
verify native window interaction or full Ghidra parity. Historical checkpoints
below retain the validation limits that applied when they were recorded.

### Earlier continuation: compiler storage

This continuation followed the earlier saved pause below.
`ghidra-abi` now resolves compiler declarations against physical language registers
and address spaces. The `--compiler-storage ROOT LANGUAGE_ID COMPILER_ID` command
compiles the selected SLEIGH source and exports the register layout, original
compiler declarations/diagnostics and bounded resolved storage. It checks missing
registers/spaces, physical parameter widths and address extents while preserving
unsized stack-pool capacity, signed stack offsets and join significance.

Initial Java-free debug-command probes succeed for x86-64 Windows, GCC and Go,
ARM v7's default AAPCS, MIPS32 big-endian default, and AArch64 Go. These are six
compiler/language combinations, not all 107 compiler specs or 202 languages.
The x86-64 source exposes 1,440 physical aliases; the Windows overlay resolves
71 bindings and six ranges. AArch64 Go resolves 157 bindings and 194 pieces.
Three initial library tests, three report/argument tests and a Java-free process
test pass. The workspace passes 406 default tests and nine doctests;
formatting, ABI/desktop Clippy and rustdoc with warnings denied pass. The release
build succeeds, and Java-free release probes resolve x86-64 Windows and AArch64
Go storage. The Windows probe also checks register order and its stack pool's
offset 40 without assigning the pool's maximum capacity as a value width.
The behavioral validation at `25d83be90d` adds 30 tests and four real-source
probes, including independent normalization/alias models and mutation checks.
Review at `e6cbc63357` returned **changes requested**: RAM-mapped registers were
rejected, and real-mode segmented metadata could produce an incorrect flat
range. Implementation fixes accept register/RAM aliases and reject unmodeled
real segmentation in the shared catalog loader; protected 32-bit spaces still
load. This also disables catalog-based real-mode instruction lifting and
function analysis, including desktop lifting, until segmented addresses are
implemented. Raw source loading does not apply processor-spec metadata.
All 20 formerly
RAM-rejected language/compiler pairs now pass Java-free command probes.
Global-style reversed ranges now swap bounds; unsupported spacebase-relative
ranges are documented. Registry word/byte domains match Ghidra's bounds.
Independent re-review at `fdb61172e6` approved the fixes and resource pass.

Optional `--resources` reports now derive declaration-ordered resource groups,
containing aliases, join sharing and pool slot capacities. The independent
review's source-derived oracle matched input/output resource plans for all 196
compiler/language pairs that compiled at `fdb61172e6`, out of 296 pairs swept; the
remaining 100 fail explicitly in source compilation/address-space support.
This validates group planning, not complete processor semantics. The
work-budgeted pair scan can be quadratic. A review follow-up now also checks
upward-growth alignment on caller-built specs. Resource planning preserves
capacity metadata and does not allocate value extents.

`ghidra-abi` now also places an explicitly sized value in a selected input/output
pool. The bounded immutable query implements relative slot alignment, endian
justification, upward growth, joined-register slices, physical address checks
and explicit floating-conversion metadata. Nineteen placement tests and 827
real pool placements across seven checked-in probe pairs pass; expanded
byte-address and compiling-mutation tests add evidence. Independent placement
review at `f6b57e116a` approved the engine with no blocking findings: 1,574,316
synthetic and 3,472,470 real-catalog comparisons matched a separate native-source
oracle over 196 compiling pairs. Five suggested regressions and explicit README
examples now pin/document the noted edge cases and Java/native disagreements.
All 13 compiling placement mutations are caught. Whole-signature resource consumption, datatype/model
selection, output-part inference, rule/merged-model evaluation,
injection compilation, type recovery and SSA call-effect integration remain.
Sparse conditional constant-propagation facts are integrated as a library at
`596c39a505`: `PcodeConstants` uses def-use scheduling, exact-width values and
augmented-graph feasibility. Undefined/reset/memory/opaque state stays unknown;
faults do not prune paths. Independent review at `fdb61172e6` approved the engine
with no actionable findings. It added 7,200 solver comparisons, 310,306 concrete
observations and 14,213,072 observations from a separate byte interpreter across
both temporary scopes and phi placements. These are bounded tests, not a proof
or an independent check of every arithmetic opcode. Desktop/JSON integration
is now implemented at `4497eab30e`: Dataflow has a Constants mode with known,
unknown and unreached facts, conservative edge feasibility and final-fixpoint
faults. `--analyze-pcode --constants` also includes expressions; every function
report now includes both. Reports borrow the same immutable snapshots and
include the final newline in the 64 MiB command cap. Independent frontend review
found one P2 layout bug: headers pushed the Constants panes outside the clip
in a 1000×650 workbench with both side panels. The parent fix adds page scrolling
with finite, nonzero nested inspection panes. A full-workbench test now scrolls
all four row kinds into view at 14/28-point fonts and clicks source navigation
without dirtying the project. Independent re-review approved `354cce2dbf`,
including fault/phi navigation, all inspection modes, and bounded virtualization
on an 18,003-value function. The small spacing note and exact-row/address/fault
test hardening were addressed at `505c792a87`. CLI/schema/provenance checks also
passed the earlier review. No IR rewrite, type recovery or structured output is claimed.

The combined tree before the layout/metadata follow-ups passed 501 default
workspace tests and ten doctests on
Windows/Rust 1.99.1. Java-free release runs succeed for both raw examples and
WinHelloCPP `401E46`; the latter reports 113 known constants, 10,840 unknown
values, all 102 supplied CFG edges feasible and no evaluation faults. Binary
recovery stays incomplete (135 native instructions). The opt-in real x86-64
probe also passes with two known and 67 unknown values. These observations do
not establish runtime reachability, complete processor behavior or a decompiler.

The combined continuation passes 474 default workspace tests and ten doctests
on Windows/Rust 1.99.1 at `fdb61172e6`. The SCCP engine, resource pass and ABI
review fixes have independent approvals. Existing source
compiler/lifter gaps, spacebase-relative ranges, segmented real-mode support
and Rust 1.88/cross-platform validation remain open.

### Wide register metadata continuation

SLEIGH register inspection no longer validates declaration widths as executable
P-code values. `register_metadata(name)` and `registers()` preserve nonzero
`u32` widths and check physical extents without allocating register contents.
The executable `register(name)` and instruction lifting retain the 512-byte
value bound. SH-2A's 40,960-byte bank register now reaches native compiler-
storage/resource inspection: the Java-free release command reports 51 registers,
23 bindings, one range and 24 pieces. Its ordinary NOP also lifts. Five real
ABI probes pass across seven pairs, including 827 concrete pool placements.
This is additional SH-2A metadata evidence, not a fresh sweep of all 296 pairs
or complete instruction semantics. The source compiler still has an overflow
when a declaration ends at the final 64-bit byte address; adapter extent tests
cover that boundary directly, without claiming that the compiler can parse it.

The metadata/layout checkpoint passed 504 default workspace tests and ten
doctests on Windows/Rust 1.99.1.

### Compiler-spec loading semantics

Explicit stack-space references now require an earlier parsed `<stackpointer>`.
The reader retains premature declarations with bounded error diagnostics and
marks affected prototypes incomplete, rather than treating the end-of-file
fallback stack as already available. Storage, joins, ranges, context blocks,
stack backing spaces and dead-code delays follow this check. Global-style
compiler-frame ranges keep Java's `readExtraRange` exception. Six new tests
cover load order on the same XML line, ignored subtrees, that frame exception
and exact diagnostic count/byte budgets. Synthetic valid fixtures now declare
their stack before referring to it.

Language-aware resolution also rejects compiler space-base names that collide
with processor spaces. Names stay case-sensitive. Frames shadowing `stack`,
`join` or `OTHER` fail explicitly as unsupported, because their relative ranges
must not be misinterpreted as the overlay's synthetic spaces; that can be
stricter than Java. Namespace tests pin these behaviors. All 107 referenced
compiler specs still parse with zero diagnostics. That checkpoint passed 518
default workspace tests and ten doctests, workspace Clippy and rustdoc with
warnings denied. Independent review approved `594ed535df` with no blocking
findings. Its small explicit-space-on-register-range gap is fixed, and new
tests catch all three previously surviving name/lookup/constant-extent mutations.
Empty frame names now report unsupported storage rather than a resource limit.
Standalone storage resolution still supports post-load fallback geometry.

### Explicit ABI fallback and native datatype layout

`AllocationState` now consumes list-local resources for batches of explicit
width/alignment/storage-class requests. It follows declaration order, shared
exclusion groups, aligned-pool cursors and alignment holes. Lists with rules or
`pointermax` require an explicit bypass that records unexecuted declarations.
Physical overlap and unsafe multi-group/alias layouts fail with bounded errors
and roll back the state. This is the retained fallback primitive, not complete
signature allocation or rule evaluation. Independent review approved the pass
after fixing a later-batch occupied-extent limit gap. Twenty default tests and
five real-source probes pass; the separate generated oracle checks 2,129 valid
layouts. See [the ABI crate](../crates/ghidra-abi/README.md) for exact policies.

`ghidra-types` adds immutable declared datatype graphs and compiler-driven
storage geometry for scalars, enum storage, pointers, aliases, arrays and
ordinary automatically packed structs/unions. Raw size, aligned length and
logical zero size remain distinct. An iterative dependency walk rejects
by-value cycles while permitting recursive pointer types. Counts, byte
extents, depth and work are bounded, without per-array-element allocation.
Sixteen core tests and seven independent oracle tests pass, including 24,000
generated layouts, their shuffled-ID permutations and a 100,000-type alias chain.
Independent review approved the foundation at `e17225c4db`, adding about 142,000
source-derived layout comparisons and allocation/deep-graph probes. Its small
logical-zero/array-detail documentation notes and forward-reference test gap
are addressed separately; no arithmetic or storage corrections were required.

This crate does not yet implement bitfields, manual composite offsets,
datatype-manager/archive workflows, type recovery or datatype-driven ABI rules.
It takes a final resolved data organization. XML primitive sizes remain independent,
matching direct assignment in the retained loader; coupled Java setters are a
separate API and are not invoked while reading compiler specs. The full port stays
unfinished. See [the datatype crate](../crates/ghidra-types/README.md).

The combined fallback/datatype tree passes 565 default workspace tests and
12 doctests, formatting, workspace Clippy and rustdoc with warnings denied,
and the release build on Windows/Rust 1.99.1. Java-free release probes retain
the raw-example and WinHelloCPP constant-analysis results above; namespace and
stack-loading CLI probes also pass with empty stdout on failures. Rust 1.88,
other operating systems and native GUI click-through were not verified here.

### Datatype rule predicates

`DatatypePredicates` now derives bounded canonical aliases, Java meta-types and
homogeneous-float summaries from an owned layout snapshot. It evaluates captured
datatype filters and ordered position/varargs/other-datatype qualifiers. Array
counts are summarized without per-element allocation; a 100,000-ID alias chain
has linear work. Source quirks are explicit: public lengths drive size filters,
array filters require direct arrays, HFA uses datatype identity and ignores size
bounds, and void/function meta-type behavior follows the retained Java layer.

Eleven boundary/behavior tests, independent reference comparisons (7,192 filters
and 1,344 qualifier combinations), and all 230 retained rules over synthetic
type/pointer profiles pass. The real declaration corpus adds 42,780 filter and
6,900 qualifier comparisons. Seven compiling mutations are caught. This is a
library predicate API; actions, resource preconditions, side effects, hidden
returns, signature allocation, SSA call effects and desktop/report integration
remain unfinished. Independent review approved `2ee4122b7c`, adding over one
million filter and 143,272 rule comparisons without a correctness/resource
finding. Absolute work formulas and signed-int boundary tests now close the
five mutation gaps it identified. This is the Java compiler-spec type view;
the C++ decompiler's array aliases, float-alias identity and void/code types
behave differently. A decompiler-specific type view remains a required gate
before native signature recovery uses these predicates.

The predicate tree passes 583 default workspace tests and 13 doctests,
formatting, workspace Clippy/rustdoc with warnings denied, and the release
build on Windows/Rust 1.99.1. Java-free release runs retain the raw-example and
WinHelloCPP analysis results. The declared minimum Rust version and native GUI
behavior were not revalidated by these library checks.

### Bitfield layouts and general primitive extraction

Native datatype layout now includes compiler-specific bitfield structures and
unions, with explicit data byte order, declared/effective widths, normalized
bit offsets, minimal wrapper storage and separate allocation units. The
implementation preserves GCC/MS grouping and zero-width behavior. All 156
retained Java expectations and independent generated references pass. Its
independent review found a comparison-window overflow when callers explicitly
raise the byte cap near `u64::MAX`; the comparison math now uses `u128` while
stored offsets stay checked `u64`. Six boundary cases in both byte orders and
four compiling reversions pin the fix. Manual layouts, edit-history behavior,
member pragmas, bitfield value access and real-compiler comparison remain open.

`PrimitiveExtraction` now builds general scalar pieces with canonical or
bitfield-wrapper provenance, raw/aligned widths and byte offsets. It expands
arrays lazily and refines unions in source order, retaining the Java layer's
float preference, context-local flags and array-depth resets. Semantic output
limits are separate from bounded intermediate scratch, since a union's
temporary list can grow and later shrink. Production traversal/refinement is
iterative, including nested union contexts. Bitfields retain field identity and
one-byte storage for zero-width wrappers instead of becoming whole base integers.

Sixteen directed tests and 26,208 independent recursive-reference cases cover
these rules, errors, bounds, 100,000 nested structures, 20,000 union contexts
and huge arrays without payload allocation. Mutation probes exposed a missing
raw-versus-aligned union case, now pinned. All 16 compiling mutations across
predicate accounting, extraction and the bitfield fix are caught. General
extraction and its bitfield integration received independent approval at
`3299780b59`, including about 3.28 million valid release comparisons against a
separate reference. A low-severity exclusive-address-end finding is fixed:
empty tails can be traversed at 2^64 without emitting an unrepresentable piece;
real collapsed wrappers there remain errors. Rule
dispatch, complete signature allocation, native decompiler type views and SSA
call effects remain required; there is no C output or inferred signature yet.

The combined bitfield/extraction tree passes 627 default workspace tests and
15 doctests, formatting, workspace Clippy/rustdoc with warnings denied, and the
release build on Windows/Rust 1.99.1. Java-free raw-example and WinHelloCPP
analysis probes retain their prior results. Rust 1.88, cross-platform execution
and native GUI click-through remain unverified by this increment.

### Resource operations for compiler rules

Allocation state now supports explicit selected-pentry assignment, preserving
caller-selected raw/aligned width and justification, plus ordered
`consume_extra`, `consume_remaining` and `extra_stack` effects. These use the
existing resource/group state and bounded placement engine. Exhaustion and
alignment-hole no-fit remain distinct from actual errors; actual errors roll
back the whole operation batch. Effects change logical resources without
creating value extents or modifying the parameter's result.

Raw-size countdown, exact tile classes and declaration order follow the
retained action implementations. Stack thresholds offer explicit Java
pentry-index and native C++ group-index policies, including a checked error
for Java's out-of-range grouped-alternative case. Thirteen directed tests and
5,184 independent reference executions cover both policies and resource
limits. Full model-rule dispatch, compound joins, pointer transformation,
hidden-return/shared-stack signatures and datatype-driven call effects remain
required; these APIs are not yet desktop or CLI signature inference.

All 646 default workspace tests and 15 doctests pass, as do formatting,
workspace Clippy/rustdoc with warnings denied and the release build. Fourteen
compiling semantic/accounting mutations fail behavioral tests. One initial
survivor exposed a test gap around positive cursors shared with exclusion
tiles; the new directed regression closes it. Java-free release example and
WinHelloCPP analysis reports retain their prior results. Rust 1.88,
cross-platform and native GUI verification remain open.

Independent review approved `504e0d486f`, adding 96,000 source-shaped effect
executions without a correctness/resource failure. Its error-classification
finding is fixed: all effect-budget exhaustion is now `EffectError::Limit`,
including nested placement work, while invalid placement remains distinct.
The scan bound includes the extra stack-entry check per effect.

### Native datatype geometry foundation

`NativeAlignmentMap` now decodes the native factory's alignment rules with
sparse storage, checked construction limits and signed-int geometry bounds.
It distinguishes a missing map from a declared map, preserves last-wins
entries, fills gaps by floor lookup and performs the native raw-size padding
followed by final alignment lookup. Its compiler-organization helper imports
the resolved map sent by the upstream bridge. Java's absolute/default/pointer
alignment rules remain separate.

Ten directed tests and independent dense/scan references compare 5,047 maps
and 6,863,920 answers, including all 107 retained specs and 321 resolved
organization inputs. Ten compiling mutations are caught. The integrated tree
passes 660 default tests, 16 doctests, formatting, workspace Clippy/rustdoc
with warnings denied and the release build on Windows/Rust 1.99.1.

Source audits show the full native datatype view also needs graph conversion:
distinct alias identity, native scalar/composite geometry, array decode-size
checks, opaque/zero-array normalization, bitfield filtering/promotion and
absolute field alignment/hole checks. The ABI README records this contract.
The existing Java predicate/extraction APIs are unchanged. Native graph
conversion and native predicates/extraction are now implemented separately,
as described below; complete signature recovery remains required.
This alignment component does not imply C output or inferred
types, native GUI verification, MSRV validation or cross-platform parity.

### Converted native datatype graph and rule predicates

`ghidra-abi` now converts declared layouts into an immutable native datatype
view. It models the retained Java transport and C++ decoder rather than
changing the existing Java layout/predicate APIs. Source IDs keep their
identity, typedefs retain distinct objects with shared field storage, and
decoder-created bitfield bases follow the source objects. Native scalar and
composite geometry, zero-array and opaque transport, array-size validation,
and byte/non-byte/union bitfield handling are explicit. Conversion failures
are typed per object and propagate through by-value dependencies; pointer
queries and whole-graph load blockers remain distinct.

Native primitive extraction and datatype filters/qualifiers/HFA checks use
that graph. In particular, native array aliases match array filters and HFA
compares exact float-object identity. Extraction checks absolute field
alignment and holes, and keeps native union refinement and flag behavior.
Traversal is iterative, arrays expand lazily, and work, live records, depth,
fields, references and synthetic objects have checked bounds.

The author added 40 tests and one doctest, including source-derived directed
cases, a separate recursive/dense-map oracle, all 107 referenced compiler
organizations and 23 compiling mutations. Local integrated checks pass on
Windows: 700 workspace tests and 17 doctests on both stable and Rust 1.88.0,
formatting, workspace Clippy with warnings denied, Rust 1.88 rustdoc with
warnings denied, and the Rust 1.88 release build. Java-free sample runs retain
their previous results. Independent review approved `4d8c4ebd88` with no
required changes: 290,784 extraction queries matched a harness compiled from
the retained C++ method bodies; deep-union, cleanup, failure-rollback and
loadability probes also passed. Conversion was source-inspected and
target-probed rather than tested by a full Java/TypeFactory round trip. These
checks do not establish cross-platform behavior for this increment.

No rule dispatcher, allocation action, CLI or desktop path consumes the new
APIs yet. Native factory names/IDs/core caches and interning, pointer typedef
settings, string transports, function prototype decoding, signature recovery
and call effects remain unfinished. Distinct source IDs deliberately stay
distinct even where a real factory could intern equivalent builtin/array
objects; callers must not treat this identity policy as full TypeFactory
parity. See [the ABI contract](../crates/ghidra-abi/README.md#native-datatype-graph).

The datatype checkpoint `8db50e041e` passed all six jobs in
[CI run 41839264716](https://github.com/plaguedog32/ghidra/actions/runs/41839264716):
locked Rust 1.88 workspace targets/doctests and stable checks, processor probes
and release builds on Windows, Linux and macOS. This predates the value-access
increment below and does not verify native GUI interaction.

### Bitfield value access and numeric representation

Declared bitfield layouts now read exact values from minimal component bytes
or a containing aggregate, including packed and unaligned fields. Reads take
the program byte order and explicit primitive-base signedness, mask the
selected bits, and return typed errors for missing bytes or invalid public
layout records. No bytes are read for zero width. Values through 255 bits use
fixed storage and retain both the raw pattern and signed interpretation.
Hex/decimal/binary/octal and boolean representations follow the retained
datatype routines; bounded padding works beyond the old Java helper's fixed
64-zero limit.

Eleven behavioral tests and one doctest cover signed and width boundaries,
33-byte input components, aggregate offsets and ordinary layout integration.
A u128 reference checks 11,616 reads and their numeric formats; a separate
Python-bigint oracle matches 58,944 component and 58,944 aggregate reads,
117,440 short-buffer failures and 471,552 numeric format checks. All 19
compiling semantic mutations are caught. Current
Windows workspace gates pass on stable and Rust 1.88: 710 tests, 18 doctests,
formatting, workspace Clippy and Rust 1.88 rustdoc with warnings denied. The
Rust 1.88 release build and Java-free CLI sample runs also pass.
Cross-lab review approved `5ab87b9564`, including 3.4 million malformed-layout
probes, 857,690 library-built members and a separate 120,000-case bigint
oracle. Its test-gap finding is fixed with isolated guard cases and three
additional compiling mutations; the value suite passes on Rust 1.88. This
API has no program-memory/UI consumer yet;
enum names/masks, character encodings, settings and editing are still open.

### Typed expression simplification

`PcodeSimplification` builds a canonical value-term projection over the exact
constant/expression/SSA snapshot. It folds exact literals, propagates safe
definitions, applies width-checked integer/normalized-boolean identities and
reduces join/extract shapes. Original operations remain the required
evaluation stream. Faulting and memory terms keep distinct identities;
faulting/memory definitions stay leaves, and rewrites cannot discard a
faulting subterm. There is no memory CSE/forwarding, unsafe float identity,
annihilator shortcut, CFG pruning, operation removal or C output.

Both headless analysis commands accept opt-in `--simplify`, implying constants
and expressions and adding `ghidra-rs.simplification` version 1. Reports retain
source IDs and snapshot guards, deterministic term IDs and the shared 64 MiB
cap including the newline. Without the flag, all previous output bytes remain
unchanged. A lazy desktop reduced-expression worker/view is connected below.
CI now has a raw
P-code `--simplify` smoke step on each stable host; the new run must pass before
claiming that increment's cross-platform behavior.

Independent review approved `e518c4cac9` with no findings. It checked 193,286
operation/SSA observations and 244,327 canonical-term observations across 120
programs, both byte orders, overlapping slices and widths through 512 bytes.
CLI probes confirmed default byte identity and actual output-cap failure with
empty stdout. Local Java-free Rust 1.88 release runs reproduce unchanged
default sum-loop/alias-branch/WinHelloCPP documents. With `--simplify`, the
respective outputs are 43,235, 46,158 and 9,305,623 bytes. WinHelloCPP has 113
literal values and 283 propagated definitions, with its incomplete 135-
instruction recovery still explicit. These reductions do not imply recovered
types, ABI return values or structured decompilation.

The preceding value checkpoint's CI run `41844505885` passed stable and Rust
1.88 jobs on Windows and Linux. Both macOS jobs were cancelled before any
runner was assigned; GitHub annotated hosted ARM64 capacity constraints, with
no failed test/build step. The simplification run `41847716217` likewise passed
all four Windows/Linux jobs, while its two macOS jobs never acquired a runner.
The combined run `41854064085` and ARM v8 source run `41857803833` likewise
passed all four Windows/Linux jobs. In the ARM run both macOS jobs were
cancelled with runner ID 0 and no steps; GitHub again annotated hosted ARM64
capacity constraints. macOS verification of these increments remains open
until those jobs execute; the ARM64 matrix target is retained.

Desktop integration run `41865643693` and dual-class ABI run `41871171918`
also passed all four Windows/Linux jobs. The latter included all three compiled
dual-class source profiles. Its two macOS jobs were cancelled with runner ID 0;
the native job again recorded hosted ARM64 capacity constraints. The workflow
now additionally includes the supported `macos-15-intel` host in both matrices,
with architecture-specific artifact names. This expands host coverage; the
new Intel jobs and the existing ARM64 jobs must execute before inheriting a
cross-platform claim for the current increment.

### Desktop reduced-expression inspection

Dataflow now offers **Reduced expressions**, built lazily from the completed
function's existing constant facts. A dedicated worker computes and caches the
optional projection, preserving the other inspection modes after an error.
It keeps one running task, one replaceable queued task and one result slot.
Request keys and shared snapshot identity reject stale builds and exports;
program, function and processor changes invalidate the view. Already-running
bounded work completes before its stale result is discarded.

Virtualized lists compare original SSA values/operations with canonical terms,
list actual reductions, and expose faults/refused folds. Details stay one level
deep with capped operands and literals. UNDEFINED, OPAQUE, phi and memory-state
leaves retain their meaning. Term links reveal their selected row, and source
navigation uses the first executed operation containing an expression-origin
node. Copying reduced JSON serializes on the worker through the CLI's shared
producer and preserves a valid view if the 64 MiB export cap fails. The copy
plus its newline matches the function command's `--simplify` output.

Independent review approved `4be9970ab2` with no actionable findings. It checked
32 actual-worker interleavings, pending-operation controls and exhaustive
per-operation source-node ownership using separate probes. Both toolchains
pass 810 default workspace tests and 22 doctests. Stable workspace/all-target
Clippy, Rust 1.88 rustdoc and formatting pass; the Rust 1.88 release build
succeeds. Headless tests exercise the complete 1000x650
workbench at fonts 14/28, exact row selection/source navigation, a single copy,
stale/foreign responses, panic/disconnect recovery and bounded visible-row
formatting without changing project metadata. Java-free release probes retain
the original default and simplified command bytes. The real WinHelloCPP
`401E46` desktop export is 9,305,622 bytes and, with its final newline, matches
the 9,305,623-byte CLI document exactly: 10,990 terms, 113 literal values and
283 propagated values. Recovery remains incomplete. Native app discovery was
retried after integration and still returned `Computer Use native pipe is
unavailable`; no app was launched. Real window, dialogs, display scaling and
the OS clipboard remain unverified.

### Parallel-copy scheduling and phi lowering

`ghidra-ssa` now schedules simultaneous copies with sparse deterministic
bookkeeping and one reused scratch for cycles. A separate `PhiLowering` plan
keeps source statement/value IDs and places scheduled copies on their selected
incoming edges. Critical edges receive their own blocks; a virtual-entry
prologue runs once while entry-loop backedges bypass it. Identity-only copies
need no new block. Input/Undefined values retain their source meanings, and
original multi-definition statements still read all uses before writing defs.

The owned plan retains its immutable source. Work and input/output counts are
bounded, nested scheduling uses only remaining budgets, and rebuilt graph
limits are separate. No dense value table is allocated per edge. Sixteen
scheduler tests and thirteen lowering tests cover cyclic/fanout copies,
entry/irreducible loops, critical edges, undefined state, unreachable edges,
exact limits and 100,000-element cases. A committed raw-path reference compares
1,561,607 uses on 750 programs in both SSA modes; an external interpreter adds
29,716,765 observations on 12,010 lowerings. All 21 compiling mutations are
caught. The combined tree passes 764 tests and 21 doctests on stable and Rust
1.88, workspace Clippy/rustdoc with warnings denied and the Rust 1.88 release
build. Independent cross-lab review approved `698383f147`, including 438,378
schedules in three input orders and 120,000 lowerings with 51.2 million use
comparisons. It found no correctness defects; its documentation wording nit
is fixed. This evidence does not validate future downstream consumers.

This is generic SSA lowering, with no location coalescing/interference pass or
P-code/export/code-generation consumer yet. Abstract memory tokens are not
concrete memory-copy operations. Complete signature allocation, structuring,
type propagation and readable decompiled output remain required.

### Native general ABI join allocation

`AllocationState::assign_join` now implements the native `MultiSlotAssign`
action over explicit raw size/alignment requests. It selects exact-class
single-group exclusion tiles, follows start/alignment/backfill behavior,
spills uncovered bytes when enabled, and returns most-significant-first pieces
or a float-conversion recipe with provenance. Success commits resource state;
NoFit and errors restore skipped tiles, cursors and occupied extents. Nested
placement work and allocations have checked shared budgets.

The source's non-advancing adjacency fit loop is preserved, so allocation can
span consumed gaps. Defaults use the first list entry's byte order, with true
reverse flags toggling it. Per-space endian/exact-alignment policy and explicit
refusals for unsafe overlap, invalid geometry and unsupported nested joins
remain visible. Native OTHER space's little endian is an exception to the
ordinary translator-order rule; the inherited OTHER-to-default mapping is
documented as a model policy.

Review at `3cfb331be8` returned **Changes requested: one verified P2.** A
consumed stack-group safeguard masked native minimum-size NoFit. The fix
preserves minimum/capacity rejection with the native -1 cursor before applying
that refusal. Regression tests cover signed remainder/alignment, partial-slot
rounding, native-int overflow, both stack growth directions, complete rollback,
later fallback, all lower work budgets and an absolute work pin. The reviewer's
original failing probe now passes; ten additional compiling mutations are
caught. No other blocking finding was reported. The builder's 41 mutations,
6,000-layout/18,044-request oracle and five compiled real-profile probes remain
separate evidence. The combined tree passes 792 tests and 22 doctests on both
local toolchains, workspace Clippy and Rust 1.88 rustdoc with warnings denied.
The Rust 1.88 release build and all five opt-in real-profile probes also pass.

This action is not full calling-convention allocation. Rule dispatch, pointer
conversion, hidden returns, shared stacks, member joins, output recovery and
SSA call effects remain required. Datatype-driven dual-class joins are a
separate action described below.

### Native dual-class ABI join allocation

`AllocationState::assign_dual_join` now implements `MultiSlotDualAssign` over
an owned `Arc<NativeTypeGraph>`. It uses the native extractor's fixed
1,024-primitive maximum, classifies fixed-size windows by raw primitive sizes,
and consumes exact-class single-group tiles from two independent lists.
Shared groups remain shared across the lists. Class exhaustion can spill the
entire suffix onto a final aligned stack pool, using the datatype's alignment
and native floor division. Defaults, fill-alternate, heterogeneous later tile
widths, cropping and piece significance follow the retained native source.
Every NoFit/error restores previous statuses and occupied extents; unsafe
overlap and unmodeled layouts remain explicit refusals.

The first independent review at `43550e25d5` requested two fixes: signed-int
spill cursor addition must be checked before capacity rejection, and window
end arithmetic before primitive exhaustion. `51850a14ba` fixes both in source
evaluation order and adds regressions that preserve the complete prior state.
A fresh review approved `51850a14ba` with no correctness defects. That commit
also corrects compiler-spec `storage`/`a` precedence: later aliases win, but
invalid earlier values still fail. The inclusive signed-int spill boundary and
right-justified wider-tile crop refusal now have directed regression tests.

The combined tree passes 839 default tests and 23 doctests on stable and Rust
1.88, formatting, workspace Clippy and Rust 1.88 rustdoc with warnings denied,
and both Windows release builds. The 27 directed action tests include exact
work/limit boundaries and the two large-number regressions without allocation
per payload byte. The builder's source-derived reference checks 35,776 calls
across 8,000 layouts; these bounded tests are separate from independent review.
Eight general/dual join real-profile probes pass in Rust 1.88 release, including
x86-64 GCC and MIPS64 LE/BE dual-class register sharing, justification and spill.
Existing Java-free raw/function simplification outputs remain byte-identical.
CI now runs the three dual-class compiled-source profiles explicitly.

This supplies one datatype-driven rule action, not whole-signature allocation,
rule dispatch, call effects or a desktop calling-convention workflow.

### Rule matching on native objects

`NativeTypeGraph` now exposes direct native-ID filter, rule and HFA queries,
with `NativePrototypeTypes` carrying result/parameter IDs. Decoder-synthesized
bitfield bases, byte arrays and opaque union fields can be tested without a
fabricated source ID. Both public ID paths share the native evaluator;
source-ID results, errors, deferred conversions and work charges remain
unchanged. Prototype validation borrows the supplied slice, performs bounded
ID checks and leaves conversions to filters that are actually reached.

Independent review approved `0123268173` with no required changes. Six
separate probes checked native error domains, result/candidate/parameter
validation order, reached failed qualifier targets, detailed equivalence
across budgets and graph-local identities. Seven committed test groups now
pin those paths, synthetic objects in both byte orders, HFA behavior, exact
limits and an absolute 21-unit rule cost. All ten compiling scratch mutations
were caught, with source restoration and an unchanged parent source hash.

The combined tree passes 846 default workspace tests and 23 doctests on
stable and Rust 1.88, workspace Clippy and Rust 1.88 rustdoc with warnings
denied, formatting and both Windows release builds. Java-free raw/function
default and simplified report bytes remain unchanged. These are query APIs;
the full dispatcher, actions, signatures and call effects remain incomplete.

### Saved pause: expression inspection milestone

Work was paused at the user's request. The integrated native desktop can open
binaries, inspect disassembly and recovered functions, lift P-code, and inspect
CFG/SSA and typed expressions. Dataflow has value/operation expression views;
`--analyze-pcode --expressions` optionally exports expressions, and every
`--analyze-function` report includes them. These are inspection tools, not
structured decompiled source. The full replacement goal remains unfinished.

Expression reconstruction received independent approval at `fae5fda5a0`.
Independent review of the UI integration at `1b44a8ffd3` requested a fix for
virtual rows whose declared height differed from wrapped/padded buttons.
Both expression lists now use compact single-line rows with a shared measured
height. The regression checks actual row height, pitch, scroll extent and
single-line text with production spacing, long labels and two font sizes.
A fresh review approved these fixes, including strict hexadecimal addresses,
constant trap RETURN execution and source-lookup work accounting.

The closing Windows/Rust 1.99.1 validation passes 399 default workspace tests
and eight doctests, formatting and workspace/all-target Clippy with warnings
denied, workspace rustdoc with warnings denied, and the optimized release build.
Nine processor/source probes remain opt-in. Release checks with `JAVA_HOME`
empty and `PATH` restricted to System32 export the alias example (14 expression
nodes, 10 SSA values), export WinHelloCPP `401E46` (1,231 expression nodes,
10,953 SSA values, 5,867,539 JSON bytes), and execute a one-byte constant trap
RETURN with an explicit return stop. The release executable is
`target/release/ghidra-rs.exe`; native window click-through and Rust 1.88 remain
unverified. The newer local increments have not been pushed or validated by
cross-platform CI.

The unfinished ABI storage resolver is preserved separately in Git stash
`2d33deafb43242253153a271d31174838c40a7b9`, titled
`WIP-native-ABI-storage-resolver--expression-milestone-pause`. It is not a
workspace member or a verified feature. Background constant-propagation work
was stopped and is not integrated. To resume the implementation path, finish
bounded value propagation/simplification, ABI storage and parameter allocation,
type/signature recovery, control-flow structuring and source generation, then
the remaining coverage gates in [the full worklist](FULL_PORT_WORKLIST.md).

### Changes since the earlier pause

Work resumed after the saved pause below. Generic liveness-pruned SSA is now
integrated at `f95bede4b6`, preserving the original unpruned constructor. Its
independent review approved the change: 43 supplied tests passed, an exhaustive
oracle checked 332,940 small programs, and focused probes rejected 57,593 removed
live phis and 34,032 dead-phi mutations. These finite probes do not prove all inputs.

The P-code adapter now requests pruning by default, preserves instruction-entry
temporary resets, and reports the actual mode in JSON and the desktop. Library
callers can still request unpruned placement. A 10,000-instruction loop retains
all frame resets and needs zero temporary phis under a 100-phi cap; unpruned
construction still fails explicitly at that cap. Expression simplification,
ABI/type recovery and structured decompiler output remain required.

The compiler context-diagnostic budget gap has an implementation fix: the shared
reader emits diagnostics directly into the compiler reader's budgets, stops when
rejected, clips quoted text before formatting, and checks budgets before cloning
paths. All 90 language tests and language Clippy pass, including real catalog
specs, exact long-path budget boundaries and early cancellation regressions.
Independent re-review of the complete compiler hardening approved the changes
at `ea14839619`. Allocation probes confirmed constant path-copy counts under
zero diagnostic budgets and clipped formatting of very large context values.
Independent review of the function worker, Dataflow UI and application pruning
wiring also approved `ea14839619`, including about 1.26 million reaching-use
comparisons across several recovered Windows x86/x64 binaries. Its narrow
constant RETURN compatibility finding is addressed separately; ELF/Mach-O
function flow and native GUI click-through remain outside that review's coverage.

Owned bounded def-use indexing is integrated at `afc919fb1d`; its independent
review approved exact use mapping, CSR accounting and 16,384 small reference
cases. The next decompiler stages are
dataflow simplification, ABI/storage resolution, type propagation and structured output.
The full replacement goal remains unfinished.

`PcodeExpressions` now reconstructs typed terms from an owned SSA snapshot:
scalar joins/slices, literal and SSA operands, versioned memory reads/writes,
control metadata, undefined resets, phi identities and opaque results. It keeps
loops as SSA references and has finite expression/reference/literal/work limits.
Fourteen expression tests include 400 concrete-machine comparisons of generated
alias/memory programs, mixed byte orders, all four memory word sizes, 512-byte
aliases, exact limits and 25k/50k scaling. Processor-defined `SEGMENTOP` now
requires an explicit opaque-effect policy rather than assuming injection semantics.

The `fae5fda5a0` source passed 386 default workspace tests, eight doctests, formatting,
workspace Clippy, analysis rustdoc with warnings denied, and the release build.
Java-free release checks preserve the earlier sample counts and now accept the
two retained INT3-containing functions `40170E` and `40475A`. Subsequent independent
review approved the expression library, and `1b44a8ffd3` integrated desktop/JSON
inspection. It does not yet propagate values, infer types or generate structured source.

The earlier `ea14839619` checkpoint passed 361 default tests, six doctests, formatting
and workspace Clippy with warnings denied. The release executable builds and
reports verified pruned SSA with `JAVA_HOME` empty and `PATH` restricted to
Windows System32. `alias-branch.json` retains its one live phi. The retained
WinHelloCPP entry still has 135 instructions and 151 graph nodes, now with
10,953 values and 2,192 phis. Its opaque calls retain conservative dependencies
and incomplete recovery remains explicit. These checks do not establish full
Ghidra parity or cross-platform validation of this unpublished increment.

### Previous pause

Work was paused at the user's request. The latest integrated feature commit then was
`fcd1c108cda0b48e5fb8b270dbf8e922778e2caa` on `rust-desktop`. The source and
documentation are committed locally; these later increments have not been pushed.
The full Ghidra replacement goal remains unfinished.

The local Windows executable is `target/release/ghidra-rs.exe`. The release build,
formatting, workspace Clippy with warnings denied, and all 340 default workspace
tests pass. Processor probes are opt-in; the new real-source function probe was
run separately and passed. Java-free release checks cover supplied P-code and
the retained PE32 function described above. The Dataflow views have headless egui
render tests; native click-through verification remains unavailable.

Outstanding items recorded at that pause (the continuation above supersedes their
implementation status):

1. Review the new binary-function worker, Dataflow UI, context-commit reporting
   and `--analyze-function` command. The earlier storage/SSA adapter and
   `--analyze-pcode` command received independent approval at `b9b26eed4e`, but
   that approval does not cover the later function increment.
2. Finish independent review of compiler-spec hardening at `c87b41e8a1`. Its
   86 language tests pass and all seven earlier findings have implementation
   fixes. The follow-up review ended with a provider error and no final verdict.
   It raised an **unverified** possible budget gap: `.cspec` `context_data`
   diagnostics are built by the shared processor-spec reader before the cspec
   diagnostic budget checks, potentially amplifying long diagnostic paths.
   Reproduce and address that path before treating parser hardening as approved.
3. Review and integrate opt-in liveness-pruned SSA. Its completed implementation
   is preserved at `1263485e82` on local branch
   `checkpoint/liveness-pruned-ssa` (also `t3/f6573c1b`), based on `b9b26eed4e`.
   It is **not merged or independently reviewed**. The implementation adds
   `PhiPlacement`, `construct_pruned`, mode-aware verification and bounded sparse
   live-in analysis. Current application analysis still uses unpruned SSA.
   After review, connect the mode to the P-code adapter, report the actual mode
   in JSON/UI, and retain regression evidence for temporary frame resets and
   large loops.
4. Continue expression simplification, ABI/storage resolution, type propagation
   and structured decompiler output, then the remaining processor, loader,
   scripting, debugger, project and framework coverage gates in
   [the full worklist](FULL_PORT_WORKLIST.md).

No delegate runs remain active at this checkpoint. Completed commits and their
worktrees are preserved. No PR was created, and no full-parity claim is made.

## Path to full replacement

1. **Harden the desktop foundation.** Extend the current project, annotation, navigation and function workflows with project collections, richer loaders, searching, and dependable error recovery.
2. **Extend the analysis model.** Add types, data references, memory regions and analysis dependencies. Extend the current x86/x64 function-lifting path to other processors and flow-aware context analysis.
3. **Expand processors and executable formats.** Extend the loaded language catalogs and processor defaults with binary matching, calling conventions and broader source/semantic audits. Validate instruction/ABI/loader behavior before claiming compatibility.
4. **Add native decompilation.** Build SSA/dataflow, optimization, type recovery and structured-code generation on the P-code foundation. The retained C++ implementation is reference material; the native Rust application does not invoke it.
5. **Replace larger workflows.** Add debugger backends, tracing, scripting, extensions, project compatibility and collaboration in independently testable stages.

The existing C++ decompiler is not a drop-in replacement for the Java framework. Its Ghidra-facing process asks the Java client for memory, symbols, types, p-code, and other services. A Rust decompiler must implement those services or use a standalone architecture. The current Rust SLEIGH path replaces upstream Gradle processor compilation for explicitly tested source probes; complete processor coverage remains unverified.

Full parity remains a larger project. Each stage should ship a usable native result and record its verified support rather than counting a launcher change as a completed port.

See [PCODE.md](PCODE.md) for executable examples and documented semantic boundaries, and [FULL_PORT_WORKLIST.md](FULL_PORT_WORKLIST.md) for the remaining framework coverage gates.

## Upstream and licensing

The original README is preserved verbatim at [UPSTREAM_README.md](UPSTREAM_README.md). Its build instructions apply to the original Java application, not this Rust workspace. Relative links within that preserved document still reflect its original repository-root location.

The upstream [LICENSE](../LICENSE) and [NOTICE](../NOTICE) remain in place. New workspace code is Apache-2.0, and third-party crates remain subject to their own licenses. This fork is not an official NSA distribution.
