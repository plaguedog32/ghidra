# Native control-flow structuring contract

This is the next decompiler implementation contract, derived from the retained
`blockaction.cc`, `block.hh`, `block.cc` and `printc.cc`. It is not an implemented
structurer or a claim of decompiled C. The full replacement goal still requires
P-code integration, types/signatures, readable output and the other framework
gates in [the full worklist](FULL_PORT_WORKLIST.md).

## Input and identity

The structural core should consume an owned `Arc<ghidra_graph::Graph>` and an
explicit entry. It must accept arbitrary directed graphs, including self-loops,
irreducible components and disconnected nodes. Invalid entries and exhausted
budgets return errors; unsupported graph shapes remain explicit control flow.

Each source node denotes its entire body followed by its original transfer.
There is one static leaf for every original node, with unchanged source ID.
Loops revisit leaves dynamically. Contractions never duplicate, omit, hoist or
split that body, and never invent an expression to replace its transfer.
Entry-unreachable leaves remain inspectable but are not appended to the
entry's executable sequence.

Enumerate canonical graph edges by ascending `(from, to)` to assign stable
structural edge IDs. Keep provenance for every edge, including edges made
implicit by a sequence, join or loop. Quotient-edge deduplication combines
provenance; it cannot discard an original edge. The selected entry is an
implicit incoming port when testing region boundaries. Outside predecessors,
including unreachable ones, must not become entries into a region's interior.

Graph successors have no boolean polarity. An ordinal structural choice must
identify the actual source decision node and original edge, not the enclosing
sequence's entry. A later CFG adapter must supply semantic edge IDs, true/false
roles and instruction-entry arrivals. It must also state its call return/no-
return policy. These facts cannot be recovered from Graph, which collapses
parallel endpoints. Do not silently choose or infer that policy in this core.

## Region and execution model

Use a flat owned arena with checked IDs and nonrecursive traversal/destruction.
Regions must expose their entry, children, source decision/edge association,
normal continuation and any explicit abrupt transfers. A public interpreter
or equivalent independently testable execution view should be able to follow
the plan without consulting the original adjacency lists.

Recover real sequence, if/if-else, terminal-arm, pretest, posttest and infinite-
loop regions. Apply local contractions repeatedly so nesting is recovered.
Retain a dispatch/goto representation for the residual quotient. That fallback
must represent every remaining transfer, including irreducible cycles and
multiway choices; it is not permission to leave ordinary reducible examples
entirely flat. No switch case values may be invented without case metadata.

Original body visits and edge-taking events define semantics. Structured
control must choose the next child/continuation from its region kind and port
mapping. Looking up the next source node in an unmodified graph while ignoring
the recovered region tree does not validate structured execution.

## Source-derived contraction gates

These are sufficient local shapes after earlier contractions, not a complete
port of Ghidra's rule ordering or goto-selection heuristics.

| Form | Required shape | Retained reference |
| --- | --- | --- |
| Sequence | A has only B as continuation; B has no other entry; edge is not a self-loop or explicit abrupt transfer | `blockaction.cc:1284–1313` |
| If | H has B/J alternatives; B has only H as entry and only J as continuation | `1378–1408` |
| If/else | H has distinct single-entry arms T/F; each has only the same outside J as continuation | `1416–1443` |
| Terminal arm | A single-entry arm has no continuation; terminal execution cannot fall into the following arm/region | `1481–1519` |
| Pretest | H has B/E alternatives; B has only H as entry and returns only to H | `1526–1556` |
| Posttest | A region's two alternatives return to its own entry or leave the region | `1563–1581` |
| Infinite loop | A region's only remaining transfer returns to its own entry | `1587–1600` |

A pretest must run the complete header on every attempt, including the final
exiting test. An effectful header is an overflow-style `while (true)` body with
an explicit exit test, not a hoisted expression (`block.hh:734–743`,
`printc.cc:3170–3196`). A conditional self-loop visits its body before choosing
whether to repeat; treating it as an empty pretest loses body execution.

Keep exact targets for abrupt edges. A pretest continue returns to the full
header. A posttest continue goes to its latch/test; an edge to the body entry
can bypass that test and is not the same continue. A break requires the exact
owning loop continuation. Other destinations remain gotos. Upstream structures
ordinary loops after extracting these transfers (`blockaction.cc:1522–1524`,
`1559–1560`) and retains goto targets (`block.hh:569–606`).

Do not fold arbitrary graph decisions into boolean AND/OR expressions. Upstream
uses complexity and data-flow restrictions unavailable in Graph
(`blockaction.cc:1335–1342`, `block.cc:2417–2472`). Nested body/choice regions can
preserve short-circuit behavior without claiming expression folding.

## Nontermination and closure

The graph crate's post-dominance quantifies over finite paths to designated
exits. It is not by itself a proof of a closed structured region. For
`H -> A or J`, `A -> J or X`, `X -> X`, J post-dominates H on finite exit paths,
but the X execution never reaches J. Region construction must retain that
divergence rather than discard exit-unreachable members or append J after an
incorrectly terminating arm. Use explicit local edge/entry closure.

Do not terminalize source nodes by cutting outgoing edges merely because a
caller designates them exits. Sinks are structural stopping points; their
meaning as RETURN, trap or external transfer belongs to the CFG adapter.

## Bounds and determinism

Validate source shape caps before output growth. Bound nodes, canonical edges,
regions/child references, transfer/provenance references and all work with
overflow-safe counters. Every failure exposes no partial plan. Any nested
graph analysis keeps an explicit, separately reported budget/call count.

Avoid recursive DFS, node-squared matrices, repeated full-graph convergence
scans and copying a growing sequence/body set at every contraction. A flat
binary/nested arena can preserve 100,000-node chains without quadratic child
copying or recursive drop. Recheck only affected candidates in deterministic
order; charge indexed-set operations and adjacency/provenance processing.
Worst-case expensive outputs must fail through a documented bound.

Equivalent canonical graphs, including shuffled/duplicate input edge records,
must give identical IDs and plans. Root ownership and all accessors must be
safe for invalid caller IDs. Results retain their source, are immutable, owned,
and `Send + Sync`.

## Required behavioral evidence

An independent iterative plan interpreter must execute actual region kinds,
using an explicit dispatch table only for fallback regions. Drive it and a
separately written source walker with predetermined choices keyed by source
node and dynamic visit count. Compare complete `Visit(node)` and `Take(edge)`
event prefixes, termination and bounded nontermination. Bound silent plan
steps as well as source visits.

Directed cases must assert that common sequences, nested diamonds, terminal
arms, pretest/posttest and infinite loops really become structured regions.
Also cover effectful/final tests, both self-loop forms, entry backedges,
unreachable incoming edges, critical edges, multiple exits/continue targets,
irreducible components, high-degree choices and the post-dominance example.
Relabel IDs to change sorted adjacency and expose polarity assumptions.

Generated graphs and decision streams must exercise both structured and
fallback paths. Deliberately broken child order, choice mapping, loop timing,
implicit edge recording and closure checks must fail the trace oracle. Exact
and one-below resource limits, absolute small work pins, deep-chain scaling
and nonrecursive drop are required. Tests cannot merely compare a plan's
copied adjacency to the graph that produced it.

This stage must remain Java-free and pass stable/Rust 1.88 checks. A later
independent implementation review is required before claiming the library is
approved. P-code wiring, semantic branch polarity, phi-copy execution,
types/ABI recovery, switch metadata and C emission remain separate work.
