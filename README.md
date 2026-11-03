# Ghidra Rust desktop

A native Rust desktop rewrite of [Ghidra](https://github.com/NationalSecurityAgency/ghidra), developed in this fork toward removing the Java runtime requirement.

**This is the first desktop milestone, not a complete Ghidra replacement.** The Rust application opens binaries and provides inspection, x86/x64 disassembly, and basic analysis. Its Cargo build and runtime do not invoke Java, JNI, Gradle, or the upstream Java application.

## First milestone

- Open PE, ELF, and single-architecture Mach-O binaries.
- Inspect entry points, sections, symbols, and printable ASCII strings.
- Disassemble x86 and x86-64 executable code.
- Inspect direct branch/call references and basic blocks from bounded linear disassembly.
- Navigate the desktop views and export analysis through the headless JSON command.

Other architectures can be inspected as binary metadata; their instructions are not decoded yet. Decompilation, debugging, Ghidra project compatibility, scripting, and the full upstream processor set remain future work. See the [port status and roadmap](docs/RUST_PORT.md).

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
```

Build the executable with `cargo build --release -p ghidra-desktop`. It is written to `target/release/ghidra-rs` (`ghidra-rs.exe` on Windows). Rust is required to build it; Java is not required to build or run it. Normal operating-system graphics and native library requirements still apply.

## Development

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --all-targets
```

The [Rust workflow](.github/workflows/rust-desktop.yml) checks and builds the native application on Windows, Linux, and macOS, and uploads the executables as workflow artifacts. Platform support should be assessed from those workflow results; a configured build matrix alone is not evidence that every platform has passed.

## Upstream source and license

The original Ghidra source remains in this fork as a reference for subsequent porting. It is not part of the Rust Cargo build. The [original README](docs/UPSTREAM_README.md) describes the upstream Java application and its separate build process.

This fork is not an official NSA release. The upstream [LICENSE](LICENSE) and [NOTICE](NOTICE) are retained. New Rust workspace code uses Apache-2.0; dependencies retain their own licenses.
