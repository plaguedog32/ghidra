# Ghidra Rust desktop

A native Rust desktop rewrite of [Ghidra](https://github.com/NationalSecurityAgency/ghidra), developed in this fork toward removing the Java runtime requirement.

**This is an ongoing port, not a complete Ghidra replacement.** The Rust application opens binaries, recovers directly reachable x86/x64 functions, inspects linkage, and saves portable projects with annotations. Its Cargo build and runtime do not invoke Java, JNI, Gradle, or the upstream Java application.

## First milestone

- Open PE, ELF, and single-architecture Mach-O binaries.
- Inspect entry points, sections, symbols, and printable ASCII strings.
- Disassemble x86 and x86-64 executable code.
- Inspect direct branch/call references and basic blocks from bounded linear disassembly.
- Discover functions by following direct calls and reachable branches, with explicit recovery limits.
- Inspect imports, exports, and relocation records, including PE import address table slots.
- Add labels, comments, and bookmarks; save them with the original binary in an integrity-checked `.ghrs` project.
- Navigate linked desktop views and export structured analysis as JSON.
- Execute bounded, supplied integer P-code programs through the native [P-code foundation](docs/PCODE.md).
- Lift instructions from SLEIGH source and evaluate supported software floating-point operations; processor coverage is tracked by explicit tests.
- Inspect selected instructions in the desktop P-code view with cached background source compilation and register-aware operations.
- Discover 202 shipped language definitions and select a language for P-code inspection with automatic processor context defaults.

The linear listing and recursive function recovery currently support x86/x64. The P-code view can lift selected addresses through a chosen SLEIGH language; tested probes cover x86-64, ARM7, and MIPS32, including ARM mixed-endian data access. Catalog discovery does not establish support for every processor. Decompilation, debugging, Ghidra project compatibility, scripting, and complete processor coverage remain future work. See the [port status and roadmap](docs/RUST_PORT.md).

## Build and run

Install the stable [Rust toolchain](https://rust-lang.org/tools/install/). The workspace requires Rust 1.88 or newer. Windows builds also require the Visual Studio C++ build tools and Windows SDK. Linux builds need the native windowing libraries listed in the [build guide](docs/RUST_PORT.md#build-prerequisites).

```sh
cargo run --release -p ghidra-desktop
```

Open a binary on startup:

```sh
cargo run --release -p ghidra-desktop -- /path/to/program
```

Try the embedded x64 sample or obtain a JSON analysis without opening a window:

```sh
cargo run --release -p ghidra-desktop -- --demo
cargo run --release -p ghidra-desktop -- --analyze /path/to/program
cargo run --release -p ghidra-desktop -- --create-project /path/to/program analysis.ghrs
cargo run --release -p ghidra-desktop -- analysis.ghrs
```

Build the executable with `cargo build --release -p ghidra-desktop`. It is written to `target/release/ghidra-rs` (`ghidra-rs.exe` on Windows). Rust is required to build it; Java is not required to build or run it. Normal operating-system graphics and native library requirements still apply.

The P-code tab discovers language assets from this checkout's `Ghidra/Processors` folder. For a standalone executable, choose an assets folder in the tab or set `GHIDRA_RS_LANGUAGE_ROOT`. These source data files are required for SLEIGH lifting and are not embedded in the executable. Language selection and overrides currently last for the open binary; saving them in projects remains pending.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
```

The [Rust workflow](.github/workflows/rust-desktop.yml) checks and builds the native application on Windows, Linux, and macOS, and uploads the executables as workflow artifacts. Platform support should be assessed from those workflow results; a configured build matrix alone is not evidence that every platform has passed.

## Upstream source and license

The original Ghidra source remains as a reference for subsequent porting. Cargo does not compile its Java/C++ application; tests read opcode definitions as text and the Rust lifter uses processor language data. The [original README](docs/UPSTREAM_README.md) describes the upstream Java application and its separate build process.

This fork is not an official NSA release. The upstream [LICENSE](LICENSE) and [NOTICE](NOTICE) are retained. New Rust workspace code uses Apache-2.0; dependencies retain their own licenses.
