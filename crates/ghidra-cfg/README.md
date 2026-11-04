# ghidra-cfg

Native Rust intra-procedural control-flow graphs built from raw P-code.
Rust 1.88, edition 2024, Apache-2.0, version 0.3.0. No Java or C++ process or
runtime is used. This is a CFG foundation: it is not function discovery, jump
table recovery, SSA, or decompiled output.

```rust
use ghidra_cfg::{Arrival, Cfg, CfgInput, EdgeRole, ExitKind, Limits, ProgramPoint};
use ghidra_pcode::{
    AddressSpace, Endianness, Opcode, PcodeInstruction, PcodeOperation, SpaceId, SpaceKind,
    Varnode,
};

let space = |id, name: &str, kind| AddressSpace {
    id: SpaceId(id),
    name: name.into(),
    kind,
    address_size: 8,
    word_size: 1,
    endianness: Endianness::Little,
};
let node = |space, offset, size| Varnode { space: SpaceId(space), offset, size };
let flag = node(3, 0, 1);
let copy = PcodeOperation { opcode: Opcode::Copy, output: Some(flag), inputs: vec![node(0, 1, 1)] };
// 0x1000: COPY; COPY; CBRANCH back to operation 1 (displacement -1 from op 2).
let instruction = PcodeInstruction {
    address: 0x1000,
    length: 4,
    ops: vec![
        copy.clone(),
        copy,
        PcodeOperation {
            opcode: Opcode::Cbranch,
            output: None,
            inputs: vec![node(0, u64::from(-1_i32 as u32), 4), flag],
        },
    ],
};
let spaces = vec![
    space(0, "const", SpaceKind::Constant),
    space(1, "ram", SpaceKind::Ram),
    space(3, "unique", SpaceKind::Unique),
];
let cfg = Cfg::new(
    CfgInput::new(spaces, SpaceId(1), 0x1000, vec![instruction]),
    Limits::default(),
)?;

// Two blocks ([op0], [op1, op2]) and one terminal exit node.
assert_eq!((cfg.block_count(), cfg.exit_count()), (2, 1));
let loop_points = [ProgramPoint::new(0x1000, 1), ProgramPoint::new(0x1000, 2)];
assert_eq!(cfg.block_points(1).unwrap(), loop_points);
let out = cfg.out_edges(1).unwrap();
assert_eq!(out[0].role, EdgeRole::ConditionFalse);
assert_eq!(cfg.exits()[0].kind, ExitKind::OutsideFallthrough { target: 0x1004 });
assert_eq!((out[1].role, out[1].to, out[1].arrival), (EdgeRole::ConditionTrue, 1, Arrival::SameInstruction));

let dominators = cfg.graph().dominators(cfg.entry())?;
assert_eq!(dominators.natural_loops()?[0].header, 1);
let post = cfg.graph().post_dominators(cfg.exit_nodes())?;
assert!(post.post_dominates(1, 0)?);
# Ok::<(), Box<dyn std::error::Error>>(())
```

## Ownership and identity

`Cfg::new(CfgInput, Limits)` takes ownership of `Arc<[AddressSpace]>` and
`Arc<[PcodeInstruction]>` (a `Vec` converts through `CfgInput::new`). The
backing data is kept exactly as supplied and shared through
`shared_instructions()`/`shared_spaces()`; nothing borrows from the caller and
no operation is deleted, reordered, or rewritten. `canonical_instructions()`
iterates the same data in address order.

The graph is `Arc<ghidra_graph::Graph>`, available as `graph()` or
`shared_graph()`, with `entry()` as its entry node. Graph node IDs are dense:

- `0..block_count()` are basic blocks, ordered by their first point.
- `block_count()..node_count()` are terminal exit nodes, ordered by source block
  and then outcome order.

`node(id)` returns `NodeKind::Block(points)` or `NodeKind::Exit(&Exit)`.
Exit nodes have no statements and no outgoing edges. A consumer such as SSA can
pair `shared_graph()` with per-node statement lists built from
`block_points(id)` and `statement(point)`; IDs are the same in both.

`ProgramPoint { address, operation_index }` names one operation. A supplied
instruction with no operations has one explicit `Statement::NoOp` point at
operation index 0, so it remains an entry/branch target instead of being
skipped. `points()` lists every point in canonical order, including unreachable
points. `block_of(point)` and `instruction_at(address)` are binary searches.

Everything canonical, including node, edge, exit, call, and userop order and
`build_work()`, depends only on instruction addresses and contents, not their
input order. Fields are private and all accessors return shared references or
owned copies, so a built CFG is immutable.

## Control-flow semantics

Blocks are split from raw P-code opcodes, never from machine mnemonics. A point
starts a block if it is the first point, the entry instruction's first point,
the first point after a block-ending operation, a relative or direct branch
target, or the first point after an address gap. Block-ending operations are
`BRANCH`, `CBRANCH`, `BRANCHIND`, `CALL`, `CALLIND`, `RETURN`, and
`UNIMPLEMENTED`. Every supplied point belongs to exactly one block, so dead
operations after a branch remain explicit, unreachable blocks.

Each block's outgoing edges are, in order:

| Last operation | Outcomes (edge roles) |
| --- | --- |
| Non-control operation or no-op | `Fallthrough` |
| `BRANCH` | `Branch` |
| `CBRANCH` | `ConditionFalse`, then `ConditionTrue` |
| `BRANCHIND` | `IndirectBranch` to an `UnresolvedIndirectBranch` exit |
| `CALL`/`CALLIND` | `CallReturn` continuation, then `CallNoReturn` exit |
| `RETURN` | `Return` exit |
| `UNIMPLEMENTED` | `Unimplemented` exit |

Sequential flow past an instruction's last operation goes to
`address + length`. `length` must already cover any expanded delay-slot bundle.

Labels in a constant space are relative: the low 32 bits of the offset are a
signed displacement added to the **current operation index**, as in
`PcodeFrame` and `ghidra_pcode::machine`. The target must be in
`0..=ops.len()`; `ops.len()` means flow to `address + length`, never a numeric
machine address. Other direct labels must be in the code space and are matched
against supplied instruction starts.

Every edge records an `Arrival`:

- `SameInstruction`: a relative branch, including one to operation 0, or
  sequential flow inside one instruction. Instruction-local temporaries persist.
- `InstructionEntry`: a new native frame begins at the target instruction's
  first point. This includes fallthrough from the previous instruction, a direct
  code-address branch (including to its own instruction), and a relative branch
  to the instruction end.
- `Exit`: the edge enters a terminal outcome node.

Blocks can span adjacent instructions. Inside a block, a change of point
`address` is a native fallthrough into a new instruction frame, exactly like an
`InstructionEntry` edge, but it has no separate edge record. Per-instruction
state handling must therefore check point addresses as well as edge arrivals.

A relative branch to operation 0 and a direct jump to the same instruction
reach the same block but remain distinguishable. Edge roles and arrival also
survive when `Graph` collapses semantic edges with the same endpoints, such as a
`CBRANCH` whose true and false targets are the same point. The function entry is
an instruction entry.

Each external, indirect, return, or unknown outcome has its own terminal node
and `Exit { node, from, source, role, kind }`:

- `Return`: a `RETURN`; the runtime target is not resolved.
- `OutsideFallthrough { target }`: `address + length` is not a supplied start.
- `SpaceEndFallthrough`: `address + length` is past the code space.
- `ExternalBranch { target }`: direct branch to an address no instruction covers.
- `InteriorBranch { target, instruction }`: direct branch strictly inside a
  supplied instruction. This is reported as unsupported; it is never treated as
  an ordinary outside target or as the containing instruction.
- `UnresolvedIndirectBranch`: `BRANCHIND`; no table or target is recovered.
- `CallNoReturn`: the call did not return to its continuation.
- `Unimplemented`: `UNIMPLEMENTED`; behavior is unknown and flow stops.

A `CBRANCH` with one internal and one external outcome keeps both paths. A
cycle without exits gets no exit node and is never reported as a return.

`CallSite` records each call's point, block, target, continuation node, and
no-return exit node. A direct target also has a `TargetLocation`: an
instruction start, an instruction interior, or unsupplied. A callee never gets an
intra-procedural edge, even when it is a supplied instruction. The
`CallReturn` edge is a possible continuation, not a claim that the callee
returns or has known effects.

`CALLOTHER` is not a P-code control-flow operation. It stays inside its block
with unknown effects, and every site is listed in `userops()` with its constant
userop index. No OS, ABI, injection, or userop behavior is modeled.
`gaps()` lists unsupplied byte ranges between adjacent supplied instructions.

## Post-dominance policy

`exit_nodes()` designates every terminal outcome for
`Graph::post_dominators`. Callers can select exits by kind. For example, omitting
`CallNoReturn` exits makes those nodes nonterminating sinks, which
finite-exit-path post-dominance ignores; this models only completed calls. The
CFG does not choose that policy.

## Validation

Validation rejects the input instead of guessing:

- Spaces: 1 to `max_spaces`, each valid, with unique IDs and names. The code
  space must exist, be `Ram` or `Other`, and have word size 1. Word-addressed
  code is rejected; addresses are never rescaled.
- Instructions: nonzero length, a nonwrapping extent inside the code space,
  unique addresses, and no overlap. The entry must be a supplied start.
- Operations: `PcodeOperation::validate` arity and widths. `MULTIEQUAL` and
  `INDIRECT` are analysis-only SSA operations and are rejected.
- Operands: every space is declared. Outputs are not constant, and every
  nonconstant value varnode fits its space. Required constants are
  `CALLOTHER` input0, `SUBPIECE` input1, `PTRADD` input2, `INSERT` inputs 2-3,
  and `ZPULL`/`SPULL` inputs 1-2. `LOAD`/`STORE` input0 is a constant naming a
  declared nonconstant space, and input1 has that space's address width.
  `BRANCHIND` and `CALLIND` input0 has the code address width. A computed
  `RETURN` target has that width too; constant RETURN targets retain their
  literal width (including x86 SLEIGH's `return [0:1]` for INT1/INT3).
- Direct labels: a `BRANCH`/`CBRANCH` label is either relative or in the code
  space. A `CALL` label must be in the code space. A label is an address, so only
  its offset must lie in the space; its size is not treated as a memory read.
  Other spaces are cross-space errors. Relative targets outside `0..=ops.len()`
  are errors.

Instruction extents, duplicates, overlaps, operations, and targets are
validated in canonical address order, so the first such error does not depend
on input order. Invalid-space errors follow the supplied space order. When several
instructions or operations exceed the per-item 16,384-operation or
1,024-input bounds, the length-only scan reports the first in supplied order.

## Bounds and work

Checks happen in this order, before the work each protects:

1. Space count, then instruction count.
2. A length-only pass: per-instruction operations (16,384) and total
   operations.
3. A length-only pass: per-operation inputs (1,024) and total operand
   references. No operand contents are processed before these totals fit.
4. Sorting and extent checks, then operation validation and leader marking.
5. Block count before block arrays exist; edge, exit, and graph node/edge
   counts before edge or exit records exist.

`Limits` defaults are 256 spaces, 1,000,000 instructions, 4,000,000
operations, 16,000,000 operand references, 1,000,000 blocks, 2,000,000 edges,
1,000,000 exits, and 1,000,000,000 work units. `Limits::graph` is retained by
the built `Graph`.

`max_work` is a deterministic abstract budget for one build. It charges scans
of instructions, operations, points, leaders, blocks, edges, nodes, and userop
sites. Sorts are precharged at `n * (ceil(log2 n) + 1)`. Each binary search costs
`floor(log2 n) + 2`. Each operation costs
`(references + 2) * (space-lookup cost + 2)`. Space-name comparisons are bounded
by 256 bytes and charged as single units. `build_work()` reports the total.
`Graph::new` and every later graph analysis have their own `Limits::graph`
budgets. Accessors are constant time or binary searches and are not charged.
Allocator overhead and constant-factor initialization are not counted.

No pass recurses, and no whole-graph scan repeats per node. Construction is
`O(S log S + I log I + (R + T) log S + T log I + P + E log B)` for spaces,
instructions, operand references, control-transfer operations, points, blocks,
and edges. Block outcomes are computed once to count and once to fill, rather
than stored per block.

## Limitations

- One explicit code space; byte-addressed code only. Cross-space flow is
  rejected rather than modeled.
- No jump-table recovery or indirect target resolution. Constant
  `BRANCHIND`/`RETURN` operands also stay unresolved.
- Calls return possibly, never certainly. No calling convention, stack effect,
  no-return analysis, inlining, or injection is applied.
- `CALLOTHER` stays sequential with unknown effects; userops that trap or do
  not return are not modeled.
- Branches into instruction interiors are reported, not decoded.
- This crate does not discover instructions or function boundaries. It builds
  a CFG for exactly the supplied instructions.

## References and verification

Semantics were checked against retained sources: `flow.cc`
(`xrefControlFlow`, `findRelTarget`, `splitBasic`, `connectBasic`, and
`fallthruOp`), `PcodeFrame.java`, and `ghidra_pcode::machine`. Unlike
`flow.cc`, dead operations after a branch are retained as explicit unreachable
blocks, and zero-operation instructions get explicit no-op points.

Tests cover the checked-in `sum-loop` example's natural loop; relative branch
direction and edge cases; calls, returns, indirect flow, userops, no-ops, gaps,
delay bundles, and arrival provenance; invalid operands, targets, extents, and
limits; input-order determinism; and a 100,000-instruction chain. They also
compare native `Machine` execution traces with CFG paths as an independent
semantic check.
