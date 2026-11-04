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
| `crates/ghidra-abi` | Register-backed compiler storage, resource groups, per-pool placement and explicit-request fallback allocation |
| `crates/ghidra-types` | Bounded declared datatype graphs and compiler-driven scalar, pointer, array and ordinary aggregate layouts |
| `crates/ghidra-sleigh` | Raw SLEIGH source compilation, context-aware decoding, and explicit P-code adaptation |
| `crates/ghidra-desktop` | Native desktop UI, file selection, navigation, and a headless JSON analysis command |
| `object` | Rust PE, ELF, and Mach-O parsing |
| `iced-x86` | Rust x86/x64 instruction decoding and instruction flow information |
| `eframe` / `egui` | Native application window and immediate-mode interface, using the Glow renderer |
| `rfd` | Native file selection |

The executable does not launch the imported program. It reads binary data for inspection. Input parsing and decoding are bounded; malformed and unsupported inputs should produce errors rather than launch another tool.

The root Cargo workspace builds the Rust crates and their native platform helpers. It does not compile the retained Java/C++ application or invoke Gradle. Tests read the upstream opcode table as text, and source-lifting probes use retained processor language data. No Java runtime, JNI bridge, Ghidra C++ decompiler process, or Java-backed extension is used.

## Feature status

| Capability | First milestone | Remaining work |
| --- | --- | --- |
| Native desktop | Rust window, linked inspection views, background instruction lifting and function Dataflow inspection | Full docking/workspace system, accessibility and workflow refinement |
| Binary formats | PE, ELF, and single-architecture Mach-O inspection | Additional formats, universal/fat Mach-O selection, richer loader semantics and relocations |
| Processor support | x86/x64 listing; 202 catalog definitions; processor defaults and checked Next-instruction context; lifting probes for x86-64, ARM7 LE/BE/mixed-endian, MIPS32 LE/BE, AArch64 BE64 and Thumb IT | Automatic binary-to-language matching, full flow-aware context analysis, broader semantic coverage, architecture-neutral function recovery |
| Metadata | Entry point, sections, symbols, ASCII strings, imports/exports, relocation records | Remaining linkage formats, relocation application, debug information and types |
| Code analysis | Linear listing and bounded recursive discovery from entry points, symbols and direct calls; reachable basic blocks | Indirect targets, jump tables, exception paths, speculative discovery, data/code separation |
| Navigation | Addresses, functions, discovered incoming references, labels, comments, bookmarks and linked binary views | Rich search, full cross-reference model and workflow refinement |
| Headless analysis | JSON output from the same Rust core | Stable automation API and batch processing |
| P-code | 74-opcode model, 59 pure integer/software-float operations, bounded concrete memory/control execution, source lifting | Userops, SSA context, architecture/OS state models, full format coverage |
| Decompilation | Native P-code CFGs, alias-aware liveness-pruned SSA, typed expression reconstruction/inspection/export; x86/x64 function lifting, Dataflow view and headless reports | Other processor function flows, dataflow simplification, ABI/type recovery and structured output |
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

Development checks:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
```

The dedicated `.github/workflows/rust-desktop.yml` runs these checks and produces native release executables on Windows, Linux, and macOS. It contains no Java installation or Gradle step. The old `build-ghidra.yml` remains restricted to the upstream `master` branch for reference maintenance; it is not the Rust build.

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

### Active continuation: compiler storage

The full replacement goal is active again after the saved pause below.
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
generated layouts and a 100,000-type alias chain. Full independent review of
this first datatype increment is pending.

This crate does not yet implement bitfields, manual composite offsets,
datatype-manager/archive workflows, type recovery or datatype-driven ABI rules.
It takes a final resolved data organization; XML setter-order coupling between
primitive sizes remains a documented loader limitation. The full port stays
unfinished. See [the datatype crate](../crates/ghidra-types/README.md).

The combined fallback/datatype tree passes 565 default workspace tests and
12 doctests, formatting, workspace Clippy and rustdoc with warnings denied,
and the release build on Windows/Rust 1.99.1. Java-free release probes retain
the raw-example and WinHelloCPP constant-analysis results above; namespace and
stack-loading CLI probes also pass with empty stdout on failures. Rust 1.88,
other operating systems and native GUI click-through were not verified here.

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
