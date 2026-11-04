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
| `crates/ghidra-ssa` | Bounded generic unpruned SSA construction and independent reaching-definition verification |
| `crates/ghidra-analysis` | Alias-aware scalar storage, abstract memory dependencies, temporary lifetimes, opaque effects and P-code-to-SSA adaptation |
| `crates/ghidra-languages` | Bounded catalog discovery, asset resolution, processor context/tracked settings, and typed compiler/ABI declarations |
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
| Native desktop | Rust window, file opening, linked inspection views, cached background P-code lifting | Full docking/workspace system, accessibility and workflow refinement |
| Binary formats | PE, ELF, and single-architecture Mach-O inspection | Additional formats, universal/fat Mach-O selection, richer loader semantics and relocations |
| Processor support | x86/x64 listing; 202 catalog definitions; processor defaults and checked Next-instruction context; lifting probes for x86-64, ARM7 LE/BE/mixed-endian, MIPS32 LE/BE, AArch64 BE64 and Thumb IT | Automatic binary-to-language matching, full flow-aware context analysis, broader semantic coverage, architecture-neutral function recovery |
| Metadata | Entry point, sections, symbols, ASCII strings, imports/exports, relocation records | Remaining linkage formats, relocation application, debug information and types |
| Code analysis | Linear listing and bounded recursive discovery from entry points, symbols and direct calls; reachable basic blocks | Indirect targets, jump tables, exception paths, speculative discovery, data/code separation |
| Navigation | Addresses, functions, discovered incoming references, labels, comments, bookmarks and linked binary views | Rich search, full cross-reference model and workflow refinement |
| Headless analysis | JSON output from the same Rust core | Stable automation API and batch processing |
| P-code | 74-opcode model, 59 pure integer/software-float operations, bounded concrete memory/control execution, source lifting | Userops, SSA context, architecture/OS state models, full format coverage |
| Decompilation | Native P-code CFGs and alias-aware SSA with abstract memory dependencies; headless `--analyze-pcode` report | Desktop/function integration, liveness pruning, dataflow simplification, ABI/type recovery and structured output |
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

- Workspace tests cover binary formats/linkage, recursive discovery, project integrity/atomic replacement and version migration, asynchronous desktop state, restored processor settings, P-code integer/software-float semantics, execution bounds, language/processor/compiler XML data, context precedence, per-token byte order, mixed-endian source lifting, compiled-source reuse, checked continuation and stale-result rejection. The desktop tests also render every inspection view through egui without requiring a native window. Eight opt-in processor probes cover seven source configurations and the desktop worker's Thumb IT continuation.
- The graph crate contributes 12 integration tests and a doctest, including 1,600 fixed-seed oracle comparisons and a 100,000-node chain. Its post-dominators describe finite paths to explicit terminal exits; infinite paths are excluded. P-code CFG/SSA now uses the graph crate; desktop function-graph integration remains pending.
- P-code CFG tests cover relative/native control flow, calls, explicit terminal exits, no-ops, delay extents and instruction-frame provenance. SSA tests include path-execution oracles, undefined entry values, entry loops, irreducible graphs, exact limits and 100,000-node inputs. The adapter adds register-alias joins, memory versions, opaque effects, frame resets, concrete-machine trace comparisons, and bounded large-loop behavior. SSA is unpruned; whole-space memory tokens are conservative dependencies, not pointer disambiguation or decompiled output.
- Typed compiler declarations cover all 107 distinct referenced `.cspec` files without diagnostics, including 178 prototype models. Register/space resolution, argument allocation, rule execution and injection compilation remain pending; parser coverage is not executable ABI support.
- Formatting and Clippy with warnings denied pass; the optimized executable builds.
- The executable analyzed the retained WinHelloCPP PE32 example, the retained `little.elf` example, and its own PE64 executable.
- Analysis succeeds with `JAVA_HOME` empty and `PATH` restricted to Windows system files.
- The same Java-free environment compiled this checkout's x86-64 SLEIGH source, lifted `MOV RAX,42`, and executed the resulting P-code to produce `RAX = 42`.
- The catalog-based CLI also discovered 202 languages and lifted/executed that instruction without explicit context arguments in the same restricted environment.
- Version 1 project migration and version 2 processor-configuration round trips also succeed in that Java-free environment, preserving the embedded image and unavailable language choices.
- The same environment lifts and executes AArch64 BE64 `mov x0, #1`, and inspects the Windows x64 compiler specification with zero diagnostics.
- Independent floating-point review verdict: "implementation approved; no P1/P2 findings."
- Independent review of the graph/project increment returned "Verdict: approve." It added 21,200 graph-oracle comparisons, including irreducible/nested cycles and larger random graphs.
- Independent CFG and SSA reviews at `89cd38c6a6` both approved their changes. Separate probes checked 13,650 CFG cases and 3,000 concrete traces, and 17,288 SSA oracle cases plus deliberately corrupted operands/phis. The later storage/adapter increment requires its own review.
- The desktop sample creates a responsive native window; its loaded modules contain no JVM. Automated visual and click-through verification was unavailable because the local Windows computer-use helper could not connect.

The initial desktop commit passed all three host builds in [CI run 41733853407](https://github.com/plaguedog32/ghidra/actions/runs/41733853407), project/function/linkage in [CI run 41735800993](https://github.com/plaguedog32/ghidra/actions/runs/41735800993), P-code/SLEIGH commit `8829d3875d` in [CI run 41739187343](https://github.com/plaguedog32/ghidra/actions/runs/41739187343), the background P-code view in [CI run 41741071127](https://github.com/plaguedog32/ghidra/actions/runs/41741071127), and catalog lifting in [CI run 41743436295](https://github.com/plaguedog32/ghidra/actions/runs/41743436295). Later increments must pass their own runs before inheriting that cross-platform claim.

## Path to full replacement

1. **Harden the desktop foundation.** Extend the current project, annotation, navigation and function workflows with project collections, richer loaders, searching, and dependable error recovery.
2. **Extend the analysis model.** Add types, data references, memory regions and analysis dependencies. Integrate the current source lifter with function recovery and desktop views.
3. **Expand processors and executable formats.** Extend the loaded language catalogs and processor defaults with binary matching, calling conventions and broader source/semantic audits. Validate instruction/ABI/loader behavior before claiming compatibility.
4. **Add native decompilation.** Build SSA/dataflow, optimization, type recovery and structured-code generation on the P-code foundation. The retained C++ implementation is reference material; the native Rust application does not invoke it.
5. **Replace larger workflows.** Add debugger backends, tracing, scripting, extensions, project compatibility and collaboration in independently testable stages.

The existing C++ decompiler is not a drop-in replacement for the Java framework. Its Ghidra-facing process asks the Java client for memory, symbols, types, p-code, and other services. A Rust decompiler must implement those services or use a standalone architecture. The current Rust SLEIGH path replaces upstream Gradle processor compilation for explicitly tested source probes; complete processor coverage remains unverified.

Full parity remains a larger project. Each stage should ship a usable native result and record its verified support rather than counting a launcher change as a completed port.

See [PCODE.md](PCODE.md) for executable examples and documented semantic boundaries, and [FULL_PORT_WORKLIST.md](FULL_PORT_WORKLIST.md) for the remaining framework coverage gates.

## Upstream and licensing

The original README is preserved verbatim at [UPSTREAM_README.md](UPSTREAM_README.md). Its build instructions apply to the original Java application, not this Rust workspace. Relative links within that preserved document still reflect its original repository-root location.

The upstream [LICENSE](../LICENSE) and [NOTICE](../NOTICE) remain in place. New workspace code is Apache-2.0, and third-party crates remain subject to their own licenses. This fork is not an official NSA distribution.
