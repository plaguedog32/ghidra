# Full Rust replacement worklist

The active, unfinished objective is to replace Ghidra's functionality without a Java build or runtime requirement. Work has resumed with UI/work separation and native multi-instance MCP control prioritized; the current native milestones do not complete that objective. The retained source has 114 module manifests and 150 SLEIGH specifications under `Ghidra/`; neither those counts nor a successful source compilation establish functional parity. The preceding saved handoff is recorded in [RUST_PORT.md](RUST_PORT.md#paused-checkpoint-2026-11-04).

Two user requirements govern every native subsystem: UI callbacks must remain
responsive while work runs, and the full application must be controllable
through native MCP with discovery and explicit targeting of concurrent
instances. The [UI and MCP architecture contract](UI_AND_MCP_ARCHITECTURE.md)
defines shared commands/queries, bounded jobs, instance/document identity,
protocol boundaries and acceptance tests. Existing workers only partially
satisfy the first requirement; native MCP/discovery is not implemented yet.
Prioritize the application/job boundary and the first usable multi-instance
MCP surface when implementation resumes, then expand command coverage with
each subsystem.

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
| MCP and automation | CLI JSON commands; no native MCP endpoint | Shared application API, native MCP tools/resources/jobs, protected instance discovery, explicit targeting and cross-platform multi-instance tests |

Feature families also remain: full decompiler, assembler/patching, debugger and trace backends, symbol/debug formats, data archives, strings/encodings, diff/version tracking, function matching/BSim, scripting, extension APIs, shared repositories and collaboration. Java plugins and scripts require a native replacement/migration path; the Rust application cannot execute Java bytecode while also removing its JVM dependency.

The processor gate is per-language: compile this checkout's source, load `.ldefs`/`.pspec` context defaults and ABI configuration, decode/lift reference instructions, validate register aliases and endian/memory behavior, then test control flow, delay slots, userops and unusual widths. All 202 shipped language definitions and their processor specs are read natively. All 107 distinct referenced compiler specs have typed data models. Native register/space resolution and overlap resource planning have source-derived oracle evidence across all 196 compiler/language pairs that compiled at the fdb61172e6 review checkpoint, out of 296 swept; complete datatype-driven signature allocation and ISA semantics remain. Source probes cover selected x86-64, ARM7, MIPS32, AArch64 BE64 and SH-2A instructions, plus the desktop worker's Thumb IT continuation. Removing a redundant conditional in the retained ARMv8 source enables all seven v8 catalog variants, with LDA/LDAB, VSEL and v8-M feature-gating regressions. This does not establish complete ARM v8 semantics or memory ordering. Full flow-aware context analysis, address-space truncation (including AArch64 ILP32), segmented real-mode addressing and the remaining source/compiler gaps remain unfinished. The shared catalog loader currently refuses real mode for lifting and function analysis as well as ABI inspection.

Non-default word-addressed storage is now admitted by the SLEIGH adapter with
byte offsets for declared varnodes, preserved word-size metadata and checked
full byte extents. Selected RISC-V fixed CSR and NDS32 user-register/return
instructions execute in source probes. Independent review approved the
increment; its nonzero byte-space address-of test gap is fixed.
Word-addressed code, word-space address-of provenance/conversion,
generic CSR pointer-width lowering and the NDS32 LE source/catalog mismatch
remain explicit gaps; CSR privilege and interrupt side effects are unmodeled.

Desktop Dataflow now includes lazy reduced-expression inspection and worker
exports through the same producer as CLI `--simplify`. Independent review
approved the integration and stale-result/clipboard guards. Whole-workbench
headless interaction and real-function byte-identity checks pass; native
window and OS clipboard verification still require the unavailable computer-use
helper. The projection does not rewrite operations or produce structured C.

A pre-existing compiler defect lost the address-space identity of direct
branches/calls through non-default-space sub-table exports. A repair is
integrated locally at `da2b34ea83`, following the source-audited
[compiler repair contract](SLEIGH_TARGET_PROVENANCE.md). It preserves
owned/streamed targets, exported widths, address units, local labels and
vendored compiler identity. It has not been independently reviewed or pushed.
The next control-flow structurer must follow the source-audited
[execution and closure contract](CONTROL_FLOW_STRUCTURING.md). That contract is
design groundwork; no structuring implementation or C emitter is claimed yet.

The decompiler gate requires a genuine P-code-to-structured-output pipeline: P-code CFG construction, SSA, alias/memory modeling, dataflow, simplification, type propagation, function signatures, control-flow structuring and readable output. Native P-code CFGs, an alias-aware pruned SSA adapter, owned def-use indexing and typed expression reconstruction now exist, with abstract whole-space memory dependencies and explicit unknown effects. Recovered x86/x64 function lifting is connected to a desktop Dataflow view and JSON command. Typed expression inspection/export is available in desktop Dataflow, optional `--analyze-pcode --expressions` output, and every `--analyze-function` report. Sparse conditional constant-propagation facts have independent library approval and desktop/JSON integration, with its compact-window layout fix independently approved; undefined/reset/memory/opaque state stays unknown. Typed expression simplification has independent approval and opt-in --simplify CLI export, with a source-preserving value projection, guarded fault/memory semantics and no operation/CFG rewriting. Generic parallel-copy scheduling and edge-specific phi lowering have independent raw-path evidence and cross-lab approval; P-code/code-generation wiring remains.

ABI storage inspection has an independently reviewed resource-group planner, per-pool placement engine and explicit-request fallback allocator. Java-view datatype-filter and qualifier evaluation has independent approval. General primitive extraction and union refinement have independent approval; a trailing-empty-member address-boundary finding is fixed. Explicit selected-pentry assignments and ordered extra-register/stack consumption effects now operate on allocation state, with separate Java/native threshold-index policies and bounded rollback. The native general join action is implemented and reviewed, with its consumed-stack NoFit finding fixed. Native dual-class join allocation is implemented over the converted native datatype graph, with two review findings fixed and independent re-review approval at `51850a14ba`. Full datatype-driven signature allocation, model-rule dispatch, member joins, pointer/hidden-return/shared-stack handling, and call-effect integration remain. The Java compiler-spec and C++ decompiler datatype views differ, including named Go array matching and float-alias identity; the independently approved native graph and predicates/extraction remain separate from the Java view.

Compiler-spec stack load-order and frame-namespace checks have independent approval and follow-up fixes; wide-register metadata enumeration includes SH-2A. Historical stack-geometry changes, virtual-frame ranges and remaining source/address-space gaps still need follow-up. Native declared datatype geometry covers scalars, pointers, aliases, arrays and ordinary automatic aggregates, with independent review approval. GCC/MS bitfield layout is implemented; a review's raised-cap comparison-overflow finding is fixed with widened arithmetic and targeted regressions. Bitfield wrapper extraction is connected to the primitive layer. Bitfield value reads and numeric formatting have independent-bigint evidence and cross-lab approval, with the guard-test gap fixed; program-memory/UI integration remains. Manual layouts, explicit mutable datatype setters, archives, mutable datatype managers, member pragmas, enum/character display and type inference remain. Other processor function flows, pointer disambiguation, wider expression/IR optimization, type propagation and structured output remain. A disassembly listing or an operation dump does not satisfy the decompiler gate.

Each increment must preserve a working Java-free build, add behavioral regression evidence and update these boundaries. The overarching goal stays unfinished until all coverage gates are satisfied; a requested pause does not imply completion.

UI responsiveness and MCP coverage are also release gates. Migrate report
export, function-listing clones, large result disposal and frame-wide queries
out of UI callbacks. Establish the shared service and job layer before adding
MCP handlers, so automation cannot bypass project/revision rules or create a
second implementation of application behavior. A discoverable endpoint alone
does not meet the full-control or multiple-instance requirements.

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

Direct native-object predicate queries now cover synthesized types and native
prototype IDs, with independent approval at `0123268173`. Full rule dispatch
and per-member actions remain governed by the source-derived
[native allocation contract](NATIVE_MEMBER_ALLOCATION.md).
Native one-value fallback allocation and its shared budget/journal kernel are
integrated locally at `48c91d72ac`, with native floor-alignment and failure
ordering. Independent review approved it without required changes; this is
not rule dispatch or whole-signature allocation.
ELF RELR metadata inspection remains pending under its
[loader contract](ELF_RELR_PORT_CONTRACT.md); relocations are not applied.

The local combined checkpoint passes 871 workspace tests and 24 doctests on
Windows with stable 1.99.1 and Rust 1.88.0. The earlier approved checkpoint's
846 tests, 23 doctests and release executable also passed. The combined tree
now has fresh Rust 1.88 Windows release/source-probe and Java-free report
identity evidence, but has no fresh cross-platform validation claim.
MSRV-aware dependency resolution fixes a Linux-only UUID dependency mismatch.
CI run 41839264716 passed the locked Rust 1.88 tests/doc examples and stable
checks/source probes/release builds on Windows, Linux and macOS at source
commit `8db50e041e`, before the bitfield value increment. Future increments must pass their own runs before
inheriting that claim; native GUI interaction remains a separate open gate.
