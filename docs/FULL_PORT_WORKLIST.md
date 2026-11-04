# Full Rust replacement worklist

The active, unfinished objective is to replace Ghidra's functionality without a Java build or runtime requirement. Work has resumed after the saved pause; the current native milestones do not complete that objective. The retained source has 114 module manifests and 150 SLEIGH specifications under `Ghidra/`; neither those counts nor a successful source compilation establish functional parity.

The main framework areas still require these coverage gates:

| Upstream framework | Current Rust coverage | Required before full replacement |
| --- | --- | --- |
| DB | Atomic portable project file | Transactional program database, upgrade/migration, recovery, indexed records |
| Docking | Native resizable inspection panels | Workspaces, tool/plugin lifecycle, docking, dialogs and accessibility |
| Emulation | Bounded concrete P-code machine | Complete processor/userop models, OS models, tracing, breakpoints, symbolic/taint workflows |
| FileSystem | Direct binary/project reads | Archives, nested containers, file-system providers, caching and access controls |
| Generic | Selected behavior supplied by Rust crates | Audit utility APIs required by every migrated subsystem |
| Graph | Native P-code CFGs; bounded SCC, dominance/frontier, natural-loop and finite-path post-dominance algorithms connected to SSA | Desktop graph display/layout, graph matching and diff workflows |
| Gui | Core workbench views | Data/type editing, search, navigation history, tool options and full workflow coverage |
| Help | Repository documentation and CLI help | In-app contextual help and migrated training/workflow documentation |
| Project | Single self-contained program project | Project collections, versioning, repository workflows and upstream project import |
| Pty | None | Portable terminal/process integration for debugger and scripting workflows |
| SoftwareModeling | Loaders, sections, symbols, functions, P-code, source lifting, declared datatype geometry and explicit ABI fallback | Complete address/memory and datatype workflows, references, ABI/calling conventions, analysis services and compatibility |
| Utility | Rust runtime and selected libraries | Audit remaining logging, task/progress, configuration and lifecycle needs |

Feature families also remain: full decompiler, assembler/patching, debugger and trace backends, symbol/debug formats, data archives, strings/encodings, diff/version tracking, function matching/BSim, scripting, extension APIs, shared repositories and collaboration. Java plugins and scripts require a native replacement/migration path; the Rust application cannot execute Java bytecode while also removing its JVM dependency.

The processor gate is per-language: compile this checkout's source, load `.ldefs`/`.pspec` context defaults and ABI configuration, decode/lift reference instructions, validate register aliases and endian/memory behavior, then test control flow, delay slots, userops and unusual widths. All 202 shipped language definitions and their processor specs are read natively. All 107 distinct referenced compiler specs have typed data models. Native register/space resolution and overlap resource planning have source-derived oracle evidence across all 196 compiler/language pairs that compiled at the fdb61172e6 review checkpoint, out of 296 swept; complete datatype-driven signature allocation and ISA semantics remain. Seven source probes plus the desktop worker's Thumb IT continuation probe pass. Full flow-aware context analysis, address-space truncation (including AArch64 ILP32), segmented real-mode addressing and the remaining source/compiler gaps remain unfinished. The shared catalog loader currently refuses real mode for lifting and function analysis as well as ABI inspection.

The decompiler gate requires a genuine P-code-to-structured-output pipeline: P-code CFG construction, SSA, alias/memory modeling, dataflow, simplification, type propagation, function signatures, control-flow structuring and readable output. Native P-code CFGs, an alias-aware pruned SSA adapter, owned def-use indexing and typed expression reconstruction now exist, with abstract whole-space memory dependencies and explicit unknown effects. Recovered x86/x64 function lifting is connected to a desktop Dataflow view and JSON command. Typed expression inspection/export is available in desktop Dataflow, optional `--analyze-pcode --expressions` output, and every `--analyze-function` report. Sparse conditional constant-propagation facts have independent library approval and desktop/JSON integration, with its compact-window layout fix independently approved; undefined/reset/memory/opaque state stays unknown. Typed expression simplification has independent approval and opt-in --simplify CLI export, with a source-preserving value projection, guarded fault/memory semantics and no operation/CFG rewriting. Generic parallel-copy scheduling and edge-specific phi lowering now have independent raw-path evidence; cross-lab review and P-code/code-generation wiring remain.

ABI storage inspection has an independently reviewed resource-group planner, per-pool placement engine and explicit-request fallback allocator. Java-view datatype-filter and qualifier evaluation has independent approval. General primitive extraction and union refinement have independent approval; a trailing-empty-member address-boundary finding is fixed. Explicit selected-pentry assignments and ordered extra-register/stack consumption effects now operate on allocation state, with separate Java/native threshold-index policies and bounded rollback. Full datatype-driven signature allocation, model-rule dispatch and compound actions, pointer/hidden-return/shared-stack handling, and call-effect integration remain. The Java compiler-spec and C++ decompiler datatype views differ, including named Go array matching and float-alias identity; a separate converted native graph and native predicates/extraction now have independent review approval, with no allocation callers yet.

Compiler-spec stack load-order and frame-namespace checks have independent approval and follow-up fixes; wide-register metadata enumeration includes SH-2A. Historical stack-geometry changes, virtual-frame ranges and remaining source/address-space gaps still need follow-up. Native declared datatype geometry covers scalars, pointers, aliases, arrays and ordinary automatic aggregates, with independent review approval. GCC/MS bitfield layout is implemented; a review's raised-cap comparison-overflow finding is fixed with widened arithmetic and targeted regressions. Bitfield wrapper extraction is connected to the primitive layer. Bitfield value reads and numeric formatting have independent-bigint evidence and cross-lab approval, with the guard-test gap fixed; program-memory/UI integration remains. Manual layouts, explicit mutable datatype setters, archives, mutable datatype managers, member pragmas, enum/character display and type inference remain. Other processor function flows, pointer disambiguation, wider expression/IR optimization, type propagation and structured output remain. A disassembly listing or an operation dump does not satisfy the decompiler gate.

Each increment must preserve a working Java-free build, add behavioral regression evidence and update these boundaries. The overarching goal stays unfinished until all coverage gates are satisfied; a requested pause does not imply completion.

Native desktop click-through remains an open verification gate. A 2026-11-04
attempt could not discover applications because the computer-use helper's
native pipe was unavailable, including after its recovery sequence. No app
was launched or changed. Headless layout tests remain separate evidence;
binary opening, native dialogs, navigation and inspection still need a real
window check when that helper is available.

Native datatype conversion follows a source-derived contract in the ABI crate
README. Bounded native alignment-map decoding and primitive geometry include
the resolved compiler-organization bridge. A separate native graph now adds
converted identities, array-size validation, opaque/zero-array normalization,
bitfield promotion/filtering and absolute field checks, with native extraction
and predicates. Factory names/IDs/core caches and interning, pointer typedef
settings, string transports and function prototype decoding remain unmodeled.
The APIs have independent review approval and still need integration into
signature allocation and call effects; graph conversion alone does not meet
the decompiler gate.

The minimum Rust version gate now has local Windows Rust 1.88.0 evidence:
all workspace targets, 764 tests, 21 doctests and the release executable pass.
MSRV-aware dependency resolution fixes a Linux-only UUID dependency mismatch.
CI run 41839264716 passed the locked Rust 1.88 tests/doc examples and stable
checks/source probes/release builds on Windows, Linux and macOS at source
commit `8db50e041e`, before the bitfield value increment. Future increments must pass their own runs before
inheriting that claim; native GUI interaction remains a separate open gate.
