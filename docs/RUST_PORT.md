# Rust port: status and development

The goal is a useful Ghidra replacement that builds and runs without Java. The current deliverable is an initial native desktop application with a Rust binary-analysis core. It does not claim feature parity with Ghidra.

## Current architecture

| Component | Responsibility |
| --- | --- |
| `crates/ghidra-core` | Binary parsing, section/address mapping, symbols, ASCII strings, x86/x64 decoding, direct references, and basic blocks |
| `crates/ghidra-core/src/functions.rs` | Bounded recursive function discovery and reachable control-flow blocks |
| `crates/ghidra-core/src/linkage.rs` | Imports, exports, and relocation records with format-specific coverage warnings |
| `crates/ghidra-project` | Portable projects, annotations, source integrity, bounded deserialization, and atomic saves |
| `crates/ghidra-desktop` | Native desktop UI, file selection, navigation, and a headless JSON analysis command |
| `object` | Rust PE, ELF, and Mach-O parsing |
| `iced-x86` | Rust x86/x64 instruction decoding and instruction flow information |
| `eframe` / `egui` | Native application window and immediate-mode interface, using the Glow renderer |
| `rfd` | Native file selection |

The executable does not launch the imported program. It reads binary data for inspection. Input parsing and decoding are bounded; malformed and unsupported inputs should produce errors rather than launch another tool.

The root Cargo workspace builds only the Rust crates. The retained `Ghidra/`, `GhidraBuild/`, `GPL/`, and Gradle source trees are upstream reference material, not Cargo build inputs. No Java runtime, JNI bridge, C++ decompiler process, or Java-backed extension is used by this milestone.

## Feature status

| Capability | First milestone | Remaining work |
| --- | --- | --- |
| Native desktop | Rust window, file opening, linked inspection views | Full docking/workspace system, accessibility and workflow refinement |
| Binary formats | PE, ELF, and single-architecture Mach-O inspection | Additional formats, universal/fat Mach-O selection, richer loader semantics and relocations |
| Processor support | x86 and x86-64 instruction decoding | Other processors, processor language selection, SLEIGH compatibility |
| Metadata | Entry point, sections, symbols, ASCII strings, imports/exports, relocation records | Remaining linkage formats, relocation application, debug information and types |
| Code analysis | Linear listing and bounded recursive discovery from entry points, symbols and direct calls; reachable basic blocks | Indirect targets, jump tables, exception paths, speculative discovery, data/code separation |
| Navigation | Addresses, functions, discovered incoming references, labels, comments, bookmarks and linked binary views | Rich search, full cross-reference model and workflow refinement |
| Headless analysis | JSON output from the same Rust core | Stable automation API and batch processing |
| Decompilation | Not implemented | P-code or another lifting IR, dataflow, type recovery, structured output |
| Projects | Self-contained `.ghrs` projects with embedded binary, integrity checks, annotations and atomic saves | Project collections, migration, upstream `.gpr`/`.gzf` compatibility and database semantics |
| Debugger | Not implemented | Native debugger backends, memory/register views and trace support |
| Extensions and scripting | Not implemented | Native plugin boundary and a Java-free scripting strategy |
| Collaboration | Not implemented | Shared projects, synchronization and access controls |

The normal disassembly listing is a linear sweep of a bounded executable region, not proof that every decoded byte is reachable code. The Functions view instead follows reachable branches and direct calls, avoiding a sweep after returns and unconditional jumps. Discovery is globally bounded, reports instruction conflicts and shared tails, and does not resolve indirect targets, jump tables or exception paths. A function marked complete means this traversal found no known gap; it does not prove a complete semantic function. Stripped binaries may have few or no symbols.

The Linkage view reads PE32/64 normal imports with IAT slot addresses, named/ordinal exports and base relocations; ELF traditional imports/exports and section/dynamic relocation records; and traditional Mach-O symbol-table/section relocation metadata. Delayed imports, forwarded exports, sectionless ELF dynamic tables, RELR, and newer Mach-O dyld formats have explicit coverage warnings. Relocations are inspected, not applied; in-place implicit addends are not evaluated.

Native projects preserve the original binary, labels, comments, bookmarks, and the last selected address. `.ghrs` version 1 uses a fixed header, bounded JSON metadata, original image bytes, and separate SHA-256 integrity checks. These checks detect corruption and do not authenticate authorship. Saving validates mapped addresses and uses a temporary sibling plus atomic replacement. The desktop prompts before discarding unsaved annotations and blocks edits while replacing or saving a project. This format is separate from upstream Ghidra projects.

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

- All 49 workspace tests pass. They cover generated PE/ELF/Mach-O, linkage addresses and relocations, malformed input, address overflow, recursive discovery and budgets, portable project integrity/atomic replacement, and asynchronous desktop state preservation. The desktop tests also render every inspection view through egui without requiring a native window.
- Formatting and Clippy with warnings denied pass; the optimized executable builds.
- The executable analyzed the retained WinHelloCPP PE32 example, the retained `little.elf` example, and its own PE64 executable.
- Analysis succeeds with `JAVA_HOME` empty and `PATH` restricted to Windows system files.
- The desktop sample creates a responsive native window; its loaded modules contain no JVM. Automated visual and click-through verification was unavailable because the local Windows computer-use helper could not connect.

The initial desktop commit `dd4736d2a1` passed Windows, Linux, and macOS checks and release builds in [CI run 41733853407](https://github.com/plaguedog32/ghidra/actions/runs/41733853407). The expanded project/function/linkage increment must pass its own CI run before inheriting that cross-platform claim.

## Path to full replacement

1. **Harden the desktop foundation.** Broaden real-binary fixtures, improve imports/exports and relocations, add address navigation, project persistence, annotations, and dependable error recovery.
2. **Build a reusable analysis model.** Represent functions, types, data references, memory regions, and analysis dependencies independently of the UI. Add instruction-to-IR lifting and recursive discovery with explicit confidence and bounds.
3. **Expand processors and executable formats.** Introduce decoder/lifter interfaces and processor-specific calling conventions. Validate against known instruction, ABI, and loader fixtures before claiming compatibility.
4. **Add native decompilation.** Implement or port lifting, dataflow, type recovery, and structured-code generation. Ghidra's native C++ decompiler is useful reference material, but using it would create a Rust+C++ application, not an all-Rust implementation.
5. **Replace larger workflows.** Add debugger backends, tracing, scripting, extensions, project compatibility and collaboration in independently testable stages.

The existing native decompiler is not a drop-in replacement for the Java framework. Its Ghidra-facing process asks the Java client for memory, symbols, types, p-code, and other services. A future native integration must implement those services or use a standalone architecture. Likewise, upstream processor compilation through Gradle still invokes Java; a Java-free SLEIGH path would need the native compiler or a Rust replacement.

Full parity remains a larger project. Each stage should ship a usable native result and record its verified support rather than counting a launcher change as a completed port.

## Upstream and licensing

The original README is preserved verbatim at [UPSTREAM_README.md](UPSTREAM_README.md). Its build instructions apply to the original Java application, not this Rust workspace. Relative links within that preserved document still reflect its original repository-root location.

The upstream [LICENSE](../LICENSE) and [NOTICE](../NOTICE) remain in place. New workspace code is Apache-2.0, and third-party crates remain subject to their own licenses. This fork is not an official NSA distribution.
