# Full Rust replacement worklist

The active objective is to replace Ghidra's functionality without a Java build or runtime requirement. The current native milestones do not complete that objective. The retained source has 114 module manifests and 150 SLEIGH specifications under `Ghidra/`; neither those counts nor a successful source compilation establish functional parity.

The main framework areas still require these coverage gates:

| Upstream framework | Current Rust coverage | Required before full replacement |
| --- | --- | --- |
| DB | Atomic portable project file | Transactional program database, upgrade/migration, recovery, indexed records |
| Docking | Native resizable inspection panels | Workspaces, tool/plugin lifecycle, docking, dialogs and accessibility |
| Emulation | Bounded concrete P-code machine | Complete processor/userop models, OS models, tracing, breakpoints, symbolic/taint workflows |
| FileSystem | Direct binary/project reads | Archives, nested containers, file-system providers, caching and access controls |
| Generic | Selected behavior supplied by Rust crates | Audit utility APIs required by every migrated subsystem |
| Graph | Local reachable CFG blocks; independent bounded SCC, dominance/frontier, natural-loop and finite-path post-dominance algorithms | Connect graph analyses to P-code/SSA, graph display/layout, graph matching and diff workflows |
| Gui | Core workbench views | Data/type editing, search, navigation history, tool options and full workflow coverage |
| Help | Repository documentation and CLI help | In-app contextual help and migrated training/workflow documentation |
| Project | Single self-contained program project | Project collections, versioning, repository workflows and upstream project import |
| Pty | None | Portable terminal/process integration for debugger and scripting workflows |
| SoftwareModeling | Loaders, sections, symbols, functions, P-code, source lifting | Complete address/memory models, data types, references, ABI/calling conventions, analysis services and compatibility |
| Utility | Rust runtime and selected libraries | Audit remaining logging, task/progress, configuration and lifecycle needs |

Feature families also remain: full decompiler, assembler/patching, debugger and trace backends, symbol/debug formats, data archives, strings/encodings, diff/version tracking, function matching/BSim, scripting, extension APIs, shared repositories and collaboration. Java plugins and scripts require a native replacement/migration path; the Rust application cannot execute Java bytecode while also removing its JVM dependency.

The processor gate is per-language: compile this checkout's source, load `.ldefs`/`.pspec` context defaults and ABI configuration, decode/lift reference instructions, validate register aliases and endian/memory behavior, then test control flow, delay slots, userops and unusual widths. All 202 shipped language definitions and their processor specs are read natively. Seven source probes plus the desktop worker's Thumb IT continuation probe pass. ABI parsing, full flow-aware context analysis, address-space truncation (including AArch64 ILP32), the remaining specs and complete ISA semantics remain unverified.

The decompiler gate requires a genuine P-code-to-structured-output pipeline: P-code CFG construction, SSA, alias/memory modeling, dataflow, simplification, type propagation, function signatures, control-flow structuring and readable output. Native graph foundations now exist, but they still need connection to P-code analysis. A disassembly listing or an operation dump does not satisfy the decompiler gate.

Each increment must preserve a working Java-free build, add behavioral regression evidence, update these boundaries, and leave the overarching goal active until all coverage gates are satisfied.
