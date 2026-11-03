# Rust port: status and development

The goal is a useful Ghidra replacement that builds and runs without Java. The current deliverable is an initial native desktop application with a Rust binary-analysis core. It does not claim feature parity with Ghidra.

## Current architecture

| Component | Responsibility |
| --- | --- |
| `crates/ghidra-core` | Binary parsing, section/address mapping, symbols, ASCII strings, x86/x64 decoding, direct references, and basic blocks |
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
| Metadata | Entry point, sections, symbols, ASCII strings | Rich imports/exports, relocations, debug information and types |
| Code analysis | Bounded linear disassembly, direct branch/call references, local basic blocks | Recursive discovery, reliable function recovery, data/code separation, indirect target resolution |
| Navigation | Addresses and selectable binary/analysis items | Full cross-reference navigation and annotations |
| Headless analysis | JSON output from the same Rust core | Stable automation API and batch processing |
| Decompilation | Not implemented | P-code or another lifting IR, dataflow, type recovery, structured output |
| Projects | No upstream project compatibility | Native project storage, persistence, migration and optional import of Ghidra projects |
| Debugger | Not implemented | Native debugger backends, memory/register views and trace support |
| Extensions and scripting | Not implemented | Native plugin boundary and a Java-free scripting strategy |
| Collaboration | Not implemented | Shared projects, synchronization and access controls |

Disassembly is a linear sweep of a bounded executable region, not proof that every decoded byte is reachable code. References cover direct control-flow targets; indirect calls and jumps are not resolved. The basic blocks describe that decoded region rather than a recovered whole-program control-flow graph. Stripped binaries may have few or no symbols.

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

- All 12 workspace tests pass, including generated PE, ELF, thin Mach-O, malformed-input, address-overflow, branch/block, and desktop import/report tests.
- Formatting and Clippy with warnings denied pass; the optimized executable builds.
- The executable analyzed the retained WinHelloCPP PE32 example, the retained `little.elf` example, and its own PE64 executable.
- Analysis succeeds with `JAVA_HOME` empty and `PATH` restricted to Windows system files.
- The desktop sample creates a responsive native window; its loaded modules contain no JVM. Automated visual and click-through verification was unavailable because the local Windows computer-use helper could not connect.

Linux and macOS checks are configured in CI. Their status must be read from the actual run; the Windows checks do not establish cross-platform success.

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
