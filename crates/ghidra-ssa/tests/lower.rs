//! Independent raw-variable versus lowered-slot execution. The interpreter
//! follows actual lowered graph edges and never executes SSA phis. Inputs and
//! undefined entry values stay distinct, other slots start uninitialized, and
//! every ordinary use must observe the same dynamic definition event.
//! Structural checks also cover dead phi slots, provenance, omitted identity
//! copies, unreachable edges, deterministic IDs, and separate resource caps.
use ghidra_graph::{Error as GraphError, Graph, Limits as GraphLimits, Resource as GraphResource};
use ghidra_ssa::{
    Block, CopyLocation, EntryState, Limits, LoweredNode, PhiLowering, PhiLoweringError,
    PhiLoweringLimits, PhiLoweringResource, PhiPlacement, Predecessor, RawProgram, RawStatement,
    Ssa, ValueOrigin, VariableId,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Token {
    Input(usize),
    Undefined(usize),
    Event(u64),
    Slot(usize),
}
struct Random(u64);
impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}
#[derive(Default, Debug)]
struct Counts {
    cases: usize,
    paths: usize,
    ordinary_uses: usize,
    undefined_uses: usize,
    executed_moves: usize,
    copy_blocks: usize,
    entry_prologues: usize,
    identity_copies: usize,
    critical_splits: usize,
    self_edge_splits: usize,
    unreachable_nodes: usize,
    unreachable_to_reachable_edges: usize,
    cap_suites: usize,
}
fn stmt(uses: &[usize], defs: &[usize]) -> RawStatement {
    RawStatement::new(
        uses.iter().copied().map(VariableId),
        defs.iter().copied().map(VariableId),
    )
}
fn init(state: EntryState, var: usize) -> Token {
    match state {
        EntryState::Input => Token::Input(var),
        EntryState::Undefined => Token::Undefined(var),
    }
}
fn read(loc: CopyLocation, slots: &[Option<Token>], temp: Option<Token>) -> Token {
    match loc {
        CopyLocation::Slot(s) => slots[s.0].expect("uninitialized slot read"),
        CopyLocation::Temporary => temp.expect("scratch read before write"),
    }
}
fn moves(lower: &PhiLowering, node: usize, slots: &mut [Option<Token>]) -> usize {
    let mut temp = None;
    let moves = lower.block_moves(node).expect("synthetic moves");
    for m in moves {
        let token = read(m.source, slots, temp);
        match m.destination {
            CopyLocation::Slot(s) => slots[s.0] = Some(token),
            CopyLocation::Temporary => temp = Some(token),
        }
    }
    moves.len()
}
fn edges(g: &Graph) -> BTreeSet<(usize, usize)> {
    g.nodes()
        .flat_map(|a| g.successors(a).unwrap().iter().map(move |&b| (a, b)))
        .collect()
}
fn structure(lower: &PhiLowering, raw: &RawProgram, counts: &mut Counts) {
    let ssa = lower.source();
    let n = ssa.node_count();
    let mut expected = BTreeMap::new();
    let mut phis = 0;
    let mut operands = 0;
    let mut identities = 0;
    let mut flattened = Vec::new();
    let mut nonidentities = 0;
    for (target, block) in ssa.blocks().iter().enumerate() {
        match (block, lower.node(target).unwrap()) {
            (Block::Reachable(b), LoweredNode::Block { source, statements }) => {
                assert_eq!(source, target);
                assert_eq!(statements, b.statements());
                assert_eq!(statements.len(), raw.blocks[target].len());
                phis += b.phis().len();
                for (idx, &pred) in b.incoming().iter().enumerate() {
                    let copies: Vec<_> = b
                        .phis()
                        .iter()
                        .filter_map(|p| {
                            operands += 1;
                            assert_eq!(ssa.values()[p.operands()[idx].0].variable, p.variable());
                            if p.value() == p.operands()[idx] {
                                identities += 1;
                                None
                            } else {
                                Some((p.value().0, p.operands()[idx].0))
                            }
                        })
                        .collect();
                    if copies.is_empty() {
                        assert_eq!(lower.copy_block_for(pred, target), None);
                        continue;
                    }
                    let synthetic = n + expected.len();
                    assert_eq!(lower.copy_block_for(pred, target), Some(synthetic));
                    let cb = &lower.copy_blocks()[expected.len()];
                    assert_eq!(
                        (cb.node, cb.predecessor, cb.target),
                        (synthetic, pred, target)
                    );
                    assert!(
                        matches!(lower.node(synthetic),Some(LoweredNode::Copies(b)) if b == cb)
                    );
                    assert_eq!(lower.graph().successors(synthetic).unwrap(), &[target]);
                    let expected_preds = match pred {
                        Predecessor::Entry => vec![],
                        Predecessor::Node(p) => vec![p],
                    };
                    assert_eq!(
                        lower.graph().predecessors(synthetic).unwrap(),
                        expected_preds
                    );
                    let mut actual: Vec<_> = (0..ssa.values().len())
                        .map(|v| Some(Token::Slot(v)))
                        .collect();
                    let before = actual.clone();
                    moves(lower, synthetic, &mut actual);
                    let copy_by_dest: BTreeMap<_, _> = copies.iter().copied().collect();
                    assert_eq!(copy_by_dest.len(), copies.len());
                    for (slot, value) in actual.iter().enumerate() {
                        assert_eq!(*value, before[*copy_by_dest.get(&slot).unwrap_or(&slot)]);
                    }
                    assert!(!lower.block_moves(synthetic).unwrap().is_empty());
                    flattened.extend_from_slice(lower.block_moves(synthetic).unwrap());
                    nonidentities += copies.len();
                    match pred {
                        Predecessor::Entry => counts.entry_prologues += 1,
                        Predecessor::Node(p) => {
                            if ssa.graph().successors(p).unwrap().len() > 1
                                && ssa.graph().predecessors(target).unwrap().len() > 1
                            {
                                counts.critical_splits += 1;
                            }
                            if p == target {
                                counts.self_edge_splits += 1;
                            }
                        }
                    }
                    expected.insert((pred, target), synthetic);
                }
            }
            (
                Block::Unreachable { statement_count },
                LoweredNode::Unreachable {
                    source,
                    statement_count: count,
                },
            ) => {
                assert_eq!(source, target);
                assert_eq!(*statement_count, count);
                assert_eq!(count, raw.blocks[target].len());
                counts.unreachable_nodes += 1;
            }
            pair => panic!("mismatched original node {target}: {pair:?}"),
        }
        assert_eq!(lower.block_moves(target), None);
    }
    let mut want_edges = BTreeSet::new();
    for (a, b) in edges(ssa.graph()) {
        if let Some(&via) = expected.get(&(Predecessor::Node(a), b)) {
            want_edges.insert((a, via));
            want_edges.insert((via, b));
        } else {
            want_edges.insert((a, b));
        }
        if !ssa.is_reachable(a).unwrap() && ssa.is_reachable(b).unwrap() {
            assert!(!expected.contains_key(&(Predecessor::Node(a), b)));
            counts.unreachable_to_reachable_edges += 1;
        }
    }
    let entry = expected
        .get(&(Predecessor::Entry, ssa.entry()))
        .copied()
        .unwrap_or(ssa.entry());
    if entry != ssa.entry() {
        want_edges.insert((entry, ssa.entry()));
    }
    assert_eq!(lower.entry(), entry);
    assert_eq!(edges(lower.graph()), want_edges);
    assert_eq!(lower.graph().node_count(), n + expected.len());
    assert_eq!(
        lower.graph().edge_count(),
        ssa.graph().edge_count() + expected.len()
    );
    assert_eq!(lower.copy_blocks().len(), expected.len());
    assert_eq!(flattened, lower.moves());
    let st = lower.stats();
    assert_eq!(
        (st.values, st.eliminated_phis, st.phi_operands),
        (ssa.values().len(), phis, operands)
    );
    assert_eq!(
        (
            st.identity_copies,
            st.parallel_copies,
            st.copy_blocks,
            st.moves
        ),
        (identities, nonidentities, expected.len(), flattened.len())
    );
    assert_eq!(st.graph_rebuilt, !expected.is_empty());
    assert_eq!(st.temporaries, 0);
    assert_eq!(st.moves, nonidentities);
    if expected.is_empty() {
        assert!(Arc::ptr_eq(lower.graph(), ssa.graph()));
    }
    assert!(lower.node(lower.graph().node_count()).is_none());
    assert!(lower.node(usize::MAX).is_none());
    assert!(lower.block_moves(lower.graph().node_count()).is_none());
    assert!(lower.block_moves(usize::MAX).is_none());
    assert_eq!(
        lower.copy_block_for(Predecessor::Node(usize::MAX), usize::MAX),
        None
    );
    counts.copy_blocks += expected.len();
    counts.identity_copies += identities;
}
fn execute(lower: &PhiLowering, raw: &RawProgram, path: &[usize], counts: &mut Counts) {
    let ssa = lower.source();
    let n = ssa.node_count();
    assert_eq!(path[0], ssa.entry());
    let mut variables: Vec<_> = raw
        .variables
        .iter()
        .enumerate()
        .map(|(x, &s)| init(s, x))
        .collect();
    let mut slots = vec![None; ssa.values().len()];
    for (id, value) in ssa.values().iter().enumerate() {
        if let ValueOrigin::Entry(state) = value.origin {
            slots[id] = Some(init(state, value.variable.0));
        }
    }
    let mut actual = lower.entry();
    if actual >= n {
        assert!(
            matches!(lower.node(actual),Some(LoweredNode::Copies(b)) if b.predecessor == Predecessor::Entry && b.target == ssa.entry())
        );
        counts.executed_moves += moves(lower, actual, &mut slots);
        actual = lower.graph().successors(actual).unwrap()[0];
    }
    let mut event = 0;
    for (step, &node) in path.iter().enumerate() {
        assert_eq!(actual, node);
        let LoweredNode::Block { source, statements } = lower.node(actual).unwrap() else {
            panic!("executing unreachable block")
        };
        assert_eq!(source, node);
        // Independently raw variable state must also agree with phi result slots,
        // including dead results that have no ordinary use on this path.
        for phi in ssa.block(node).unwrap().renamed().unwrap().phis() {
            assert_eq!(
                slots[phi.value().0],
                Some(variables[phi.variable().0]),
                "stale phi slot node {node} step {step} path {path:?}"
            );
        }
        for (index, (r, s)) in raw.blocks[node].iter().zip(statements).enumerate() {
            assert_eq!(
                (r.uses.len(), r.defs.len()),
                (s.uses().len(), s.defs().len())
            );
            // Read the entire use vector before changing any variable or SSA slot.
            let inputs: Vec<_> = r.uses.iter().map(|v| variables[v.0]).collect();
            for ((&var, &value), &want) in r.uses.iter().zip(s.uses()).zip(&inputs) {
                assert_eq!(ssa.values()[value.0].variable, var);
                assert_eq!(
                    slots[value.0],
                    Some(want),
                    "stale ordinary use n={node} statement={index} step={step} path={path:?}"
                );
                counts.ordinary_uses += 1;
                if matches!(want, Token::Undefined(_)) {
                    counts.undefined_uses += 1;
                }
            }
            let outputs: Vec<_> = r
                .defs
                .iter()
                .map(|_| {
                    event += 1;
                    Token::Event(event)
                })
                .collect();
            for ((&var, &value), &token) in r.defs.iter().zip(s.defs()).zip(&outputs) {
                assert_eq!(ssa.values()[value.0].variable, var);
                variables[var.0] = token;
                slots[value.0] = Some(token);
            }
        }
        if let Some(&next) = path.get(step + 1) {
            assert!(ssa.graph().successors(node).unwrap().contains(&next));
            let candidates: Vec<_> = lower
                .graph()
                .successors(actual)
                .unwrap()
                .iter()
                .copied()
                .filter(|&succ| {
                    if succ < n {
                        succ == next
                    } else {
                        matches!(lower.node(succ),Some(LoweredNode::Copies(b)) if b.target == next)
                    }
                })
                .collect();
            assert_eq!(
                candidates.len(),
                1,
                "missing or duplicate projected successor"
            );
            actual = candidates[0];
            if actual >= n {
                assert!(
                    matches!(lower.node(actual),Some(LoweredNode::Copies(b)) if b.predecessor == Predecessor::Node(node) && b.target == next)
                );
                counts.executed_moves += moves(lower, actual, &mut slots);
                actual = lower.graph().successors(actual).unwrap()[0];
            }
            assert_eq!(actual, next);
        }
    }
    counts.paths += 1;
}
fn expect_limit(ssa: &Arc<Ssa>, lim: PhiLoweringLimits, resource: PhiLoweringResource) {
    assert!(
        matches!(PhiLowering::new(ssa.clone(),lim),Err(PhiLoweringError::LimitExceeded { resource: r }) if r == resource)
    );
}
fn expect_graph(ssa: &Arc<Ssa>, lim: PhiLoweringLimits, resource: GraphResource) {
    assert!(
        matches!(PhiLowering::new(ssa.clone(),lim),Err(PhiLoweringError::Graph(GraphError::LimitExceeded { resource: r })) if r == resource)
    );
}
fn caps(lower: &PhiLowering, counts: &mut Counts) {
    let ssa = lower.source();
    let st = lower.stats();
    let d = PhiLoweringLimits::default();
    let mut graph_work = 2 * lower.graph().node_count() + 3 * lower.graph().edge_count();
    for node in lower.graph().nodes() {
        let n = lower.graph().successors(node).unwrap().len();
        if n > 1 {
            graph_work += n * ((usize::BITS - (n - 1).leading_zeros()) as usize + 1);
        }
    }
    let exact = PhiLoweringLimits {
        max_values: st.values,
        max_phi_operands: st.phi_operands,
        max_copy_blocks: st.copy_blocks,
        max_moves: st.moves,
        max_work: st.work,
        graph: GraphLimits {
            max_nodes: lower.graph().node_count(),
            max_edges: lower.graph().edge_count(),
            max_work: if st.graph_rebuilt {
                graph_work as u64
            } else {
                0
            },
            max_frontier_entries: 0,
            max_loop_entries: 0,
        },
    };
    let got = PhiLowering::new(ssa.clone(), exact).unwrap();
    assert_eq!(got.stats(), st);
    assert_eq!(got.limits(), exact);
    assert_eq!(edges(got.graph()), edges(lower.graph()));
    assert_eq!(got.moves(), lower.moves());
    if st.values > 0 {
        expect_limit(
            ssa,
            PhiLoweringLimits {
                max_values: st.values - 1,
                ..d
            },
            PhiLoweringResource::Values,
        );
    }
    if st.phi_operands > 0 {
        expect_limit(
            ssa,
            PhiLoweringLimits {
                max_phi_operands: st.phi_operands - 1,
                ..d
            },
            PhiLoweringResource::PhiOperands,
        );
    }
    if st.copy_blocks > 0 {
        expect_limit(
            ssa,
            PhiLoweringLimits {
                max_copy_blocks: st.copy_blocks - 1,
                ..d
            },
            PhiLoweringResource::CopyBlocks,
        );
    }
    if st.moves > 0 {
        expect_limit(
            ssa,
            PhiLoweringLimits {
                max_moves: st.moves - 1,
                ..d
            },
            PhiLoweringResource::Moves,
        );
    }
    assert!(st.work > 0);
    expect_limit(
        ssa,
        PhiLoweringLimits {
            max_work: st.work - 1,
            ..d
        },
        PhiLoweringResource::Work,
    );
    if lower.graph().node_count() > 0 {
        expect_graph(
            ssa,
            PhiLoweringLimits {
                graph: GraphLimits {
                    max_nodes: lower.graph().node_count() - 1,
                    ..d.graph
                },
                ..d
            },
            GraphResource::Nodes,
        );
    }
    if lower.graph().edge_count() > 0 {
        expect_graph(
            ssa,
            PhiLoweringLimits {
                graph: GraphLimits {
                    max_edges: lower.graph().edge_count() - 1,
                    ..d.graph
                },
                ..d
            },
            GraphResource::Edges,
        );
    }
    if st.graph_rebuilt {
        assert!(graph_work > 0);
        expect_graph(
            ssa,
            PhiLoweringLimits {
                graph: GraphLimits {
                    max_work: graph_work as u64 - 1,
                    ..d.graph
                },
                ..d
            },
            GraphResource::Work,
        );
    }
    counts.cap_suites += 1;
}
fn random_case(r: &mut Random, case: usize) -> (usize, Vec<(usize, usize)>, usize, RawProgram) {
    let n = 1 + r.below(10);
    let entry = r.below(n);
    let vars = r.below(7);
    let variables = (0..vars)
        .map(|_| {
            if r.below(2) == 0 {
                EntryState::Input
            } else {
                EntryState::Undefined
            }
        })
        .collect();
    let density = 1 + case % 7;
    let mut edges = Vec::new();
    for a in 0..n {
        for b in 0..n {
            if r.below(12) < density {
                edges.push((a, b));
                if r.below(7) == 0 {
                    edges.push((a, b));
                }
            }
        }
    }
    let blocks = (0..n)
        .map(|_| {
            (0..r.below(5))
                .map(|_| {
                    let uses = if vars == 0 {
                        vec![]
                    } else {
                        (0..r.below(7)).map(|_| VariableId(r.below(vars))).collect()
                    };
                    let mut defs: Vec<_> = (0..vars)
                        .filter(|_| r.below(4) == 0)
                        .map(VariableId)
                        .collect();
                    for i in (1..defs.len()).rev() {
                        defs.swap(i, r.below(i + 1));
                    }
                    RawStatement { uses, defs }
                })
                .collect()
        })
        .collect();
    (n, edges, entry, RawProgram { variables, blocks })
}
// Keep the raw case and bounded-execution controls explicit in this fixture.
#[allow(clippy::too_many_arguments)]
fn run_case(
    n: usize,
    es: Vec<(usize, usize)>,
    entry: usize,
    raw: RawProgram,
    r: &mut Random,
    exhaustive: bool,
    do_caps: bool,
    counts: &mut Counts,
) {
    let graph = Arc::new(Graph::new(n, es, GraphLimits::default()).unwrap());
    for placement in [PhiPlacement::Unpruned, PhiPlacement::Pruned] {
        let ssa = Arc::new(
            Ssa::construct_with(graph.clone(), entry, &raw, Limits::default(), placement).unwrap(),
        );
        ssa.verify(&raw).unwrap();
        let lower = PhiLowering::new(ssa.clone(), PhiLoweringLimits::default()).unwrap();
        assert!(Arc::ptr_eq(lower.source(), &ssa));
        structure(&lower, &raw, counts);
        if do_caps {
            caps(&lower, counts);
        }
        for _ in 0..16 {
            let mut path = vec![entry];
            for _ in 0..(8 + r.below(24)) {
                let successors = graph.successors(*path.last().unwrap()).unwrap();
                if successors.is_empty() {
                    break;
                }
                path.push(successors[r.below(successors.len())]);
            }
            execute(&lower, &raw, &path, counts);
        }
        if exhaustive {
            let mut stack = vec![vec![entry]];
            while let Some(path) = stack.pop() {
                execute(&lower, &raw, &path, counts);
                if path.len() < 8 {
                    for &next in graph.successors(*path.last().unwrap()).unwrap() {
                        let mut new = path.clone();
                        new.push(next);
                        stack.push(new);
                    }
                }
            }
        }
        counts.cases += 1;
    }
}
fn make_lowering(
    nodes: usize,
    edges: &[(usize, usize)],
    entry: usize,
    raw: &RawProgram,
    placement: PhiPlacement,
) -> PhiLowering {
    let graph = Arc::new(Graph::new(nodes, edges.iter().copied(), GraphLimits::default()).unwrap());
    let source =
        Arc::new(Ssa::construct_with(graph, entry, raw, Limits::default(), placement).unwrap());
    PhiLowering::new(source, PhiLoweringLimits::default()).unwrap()
}
fn directed(nodes: usize, edges: Vec<(usize, usize)>, entry: usize, raw: RawProgram) -> Counts {
    let mut counts = Counts::default();
    run_case(
        nodes,
        edges,
        entry,
        raw,
        &mut Random(0x9f80_33ab_11c5),
        true,
        true,
        &mut counts,
    );
    counts
}
#[test]
fn diamond_preserves_undefined_and_input_values_on_each_arm() {
    let raw = RawProgram {
        variables: vec![EntryState::Undefined, EntryState::Input],
        blocks: vec![
            vec![],
            vec![stmt(&[0, 1], &[0])],
            vec![stmt(&[0, 1], &[1])],
            vec![stmt(&[0, 1, 0, 1], &[])],
        ],
    };
    let counts = directed(4, vec![(0, 1), (0, 2), (1, 3), (2, 3)], 0, raw);
    assert_eq!(counts.cases, 2);
    assert_eq!(counts.copy_blocks, 4);
    assert!(counts.undefined_uses > 0);
    assert!(counts.ordinary_uses > 0);
}

#[test]
fn lowering_work_has_absolute_pins_and_graph_reuse_spends_no_graph_work() {
    let es = [(0, 1), (0, 2), (1, 3), (2, 3)];
    let raw = RawProgram {
        variables: vec![EntryState::Input],
        blocks: vec![
            vec![],
            vec![stmt(&[], &[0])],
            vec![stmt(&[], &[0])],
            vec![stmt(&[0], &[])],
        ],
    };
    let lower = make_lowering(4, &es, 0, &raw, PhiPlacement::Pruned);
    assert_eq!(
        (lower.stats().eliminated_phis, lower.stats().phi_operands),
        (1, 2)
    );
    assert_eq!((lower.stats().copy_blocks, lower.stats().moves), (2, 2));
    // 1 start +4 nodes +2 incoming +2 operand scans +26 scheduling
    // +2 move appends +5 redirect inserts +4 graph nodes +6 output edges
    // +12 redirect lookups +2 prologue-scan visits =66, before Graph's budget.
    assert_eq!(lower.stats().work, 66);
    let raw = RawProgram {
        variables: vec![EntryState::Input],
        blocks: vec![vec![]; 4],
    };
    let no_phis = make_lowering(4, &es, 0, &raw, PhiPlacement::Pruned);
    let limits = PhiLoweringLimits {
        max_work: 5,
        graph: GraphLimits {
            max_work: 0,
            ..GraphLimits::default()
        },
        ..PhiLoweringLimits::default()
    };
    let reused = PhiLowering::new(no_phis.source().clone(), limits).unwrap();
    assert_eq!(reused.stats().work, 5); // Start +one visit per original node.
    assert!(!reused.stats().graph_rebuilt);
    assert!(Arc::ptr_eq(reused.graph(), reused.source().graph()));
    assert_eq!(reused.graph().limits(), reused.source().graph().limits());
}

#[test]
fn source_shape_caps_are_checked_before_work_and_output_growth() {
    let raw = RawProgram {
        variables: vec![EntryState::Input],
        blocks: vec![
            vec![],
            vec![stmt(&[], &[0])],
            vec![stmt(&[], &[0])],
            vec![stmt(&[0], &[])],
        ],
    };
    let lower = make_lowering(
        4,
        &[(0, 1), (0, 2), (1, 3), (2, 3)],
        0,
        &raw,
        PhiPlacement::Pruned,
    );
    let no_work = PhiLoweringLimits {
        max_work: 0,
        ..PhiLoweringLimits::default()
    };
    expect_limit(
        lower.source(),
        PhiLoweringLimits {
            max_values: 0,
            ..no_work
        },
        PhiLoweringResource::Values,
    );
    expect_limit(
        lower.source(),
        PhiLoweringLimits {
            max_phi_operands: 0,
            ..no_work
        },
        PhiLoweringResource::PhiOperands,
    );
    expect_graph(
        lower.source(),
        PhiLoweringLimits {
            graph: GraphLimits {
                max_nodes: 0,
                ..GraphLimits::default()
            },
            ..no_work
        },
        GraphResource::Nodes,
    );
    expect_graph(
        lower.source(),
        PhiLoweringLimits {
            graph: GraphLimits {
                max_edges: 0,
                ..GraphLimits::default()
            },
            ..no_work
        },
        GraphResource::Edges,
    );
}
#[test]
fn critical_edge_copies_execute_only_on_the_selected_branch() {
    let es = [(0, 1), (0, 2), (1, 2), (2, 3)];
    let raw = RawProgram {
        variables: vec![EntryState::Undefined],
        blocks: vec![
            vec![stmt(&[0], &[])],
            vec![stmt(&[0], &[0])],
            vec![stmt(&[0], &[])],
            vec![stmt(&[0], &[])],
        ],
    };
    let lower = make_lowering(4, &es, 0, &raw, PhiPlacement::Pruned);
    let via = lower.copy_block_for(Predecessor::Node(0), 2).unwrap();
    assert_eq!(lower.graph().successors(0).unwrap(), &[1, via]);
    assert_eq!(lower.graph().successors(via).unwrap(), &[2]);
    let counts = directed(4, es.to_vec(), 0, raw);
    assert_eq!(counts.critical_splits, 2);
}
#[test]
fn nonfirst_entry_self_loop_runs_the_prologue_once_and_preserves_unreachable_edges() {
    let es = [(2, 2), (0, 2), (0, 1), (1, 0)];
    let raw = RawProgram {
        variables: vec![EntryState::Undefined, EntryState::Input],
        blocks: vec![
            vec![stmt(&[0], &[0])],
            vec![stmt(&[1], &[1])],
            vec![stmt(&[0, 1, 0], &[1, 0]), stmt(&[0, 1], &[])],
        ],
    };
    let lower = make_lowering(3, &es, 2, &raw, PhiPlacement::Pruned);
    let prologue = lower.copy_block_for(Predecessor::Entry, 2).unwrap();
    let backedge = lower.copy_block_for(Predecessor::Node(2), 2).unwrap();
    assert_eq!(lower.entry(), prologue);
    assert_ne!(prologue, backedge);
    assert!(lower.graph().predecessors(prologue).unwrap().is_empty());
    assert_eq!(lower.graph().successors(backedge).unwrap(), &[2]);
    assert!(lower.graph().successors(0).unwrap().contains(&2));
    assert_eq!(lower.copy_block_for(Predecessor::Node(0), 2), None);
    let counts = directed(3, es.to_vec(), 2, raw);
    assert_eq!(counts.entry_prologues, 2);
    assert_eq!(counts.self_edge_splits, 2);
    assert_eq!(counts.unreachable_nodes, 4);
    assert_eq!(counts.unreachable_to_reachable_edges, 2);
}
#[test]
fn identity_phi_operand_keeps_the_original_edge_without_a_copy_block() {
    // Node 2 carries the header phi value unchanged back into the same phi.
    let es = [(0, 1), (1, 2), (1, 3), (2, 1), (3, 1)];
    let raw = RawProgram {
        variables: vec![EntryState::Undefined],
        blocks: vec![
            vec![],
            vec![stmt(&[0], &[])],
            vec![stmt(&[0], &[])],
            vec![stmt(&[0], &[0])],
        ],
    };
    let lower = make_lowering(4, &es, 0, &raw, PhiPlacement::Pruned);
    assert_eq!(lower.stats().identity_copies, 1);
    assert_eq!(lower.copy_block_for(Predecessor::Node(2), 1), None);
    assert_eq!(lower.graph().successors(2).unwrap(), &[1]);
    let counts = directed(4, es.to_vec(), 0, raw);
    assert_eq!(counts.identity_copies, 2);
}
#[test]
fn irreducible_loops_preserve_copies_and_original_unreachable_predecessors() {
    // Entry 4 feeds both sides of 1 <-> 3; node 3 is also a self-loop and
    // reaches entry again. The disconnected 5 <-> 6 component enters node 3.
    let es = vec![
        (4, 1),
        (4, 2),
        (1, 3),
        (2, 3),
        (3, 4),
        (3, 1),
        (3, 3),
        (5, 3),
        (5, 6),
        (6, 5),
    ];
    let raw = RawProgram {
        variables: vec![
            EntryState::Undefined,
            EntryState::Input,
            EntryState::Undefined,
        ],
        blocks: vec![
            vec![stmt(&[0], &[0])],
            vec![stmt(&[0, 1, 2], &[2, 0])],
            vec![stmt(&[2, 1, 0], &[1])],
            vec![stmt(&[0, 1, 2, 0], &[2, 1])],
            vec![stmt(&[0, 1, 2], &[0])],
            vec![stmt(&[0, 2], &[2, 0])],
            vec![stmt(&[1], &[1])],
        ],
    };
    let counts = directed(7, es, 4, raw);
    assert!(counts.entry_prologues > 0);
    assert!(counts.critical_splits > 0);
    assert!(counts.self_edge_splits > 0);
    assert_eq!(counts.unreachable_to_reachable_edges, 2);
}
#[test]
fn repeated_uses_observe_values_before_all_simultaneous_definitions() {
    let raw = RawProgram {
        variables: vec![
            EntryState::Undefined,
            EntryState::Input,
            EntryState::Undefined,
        ],
        blocks: vec![vec![
            stmt(&[0, 1, 0, 2], &[2, 0, 1]),
            stmt(&[0, 1, 2, 0], &[1, 2]),
            stmt(&[0, 1, 2], &[]),
        ]],
    };
    let counts = directed(1, vec![(0, 0)], 0, raw);
    assert!(counts.undefined_uses > 0);
    assert_eq!(counts.entry_prologues, 2);
    assert!(counts.executed_moves > counts.copy_blocks);
}
#[test]
fn zero_variables_and_empty_statements_share_the_source_graph() {
    let raw = RawProgram {
        variables: vec![],
        blocks: vec![
            vec![],
            vec![stmt(&[], &[])],
            vec![stmt(&[], &[]), stmt(&[], &[])],
            vec![],
            vec![],
        ],
    };
    let counts = directed(5, vec![(2, 2), (0, 1), (1, 0), (3, 2), (3, 4)], 2, raw);
    assert_eq!(counts.copy_blocks, 0);
    assert_eq!(counts.ordinary_uses, 0);
    assert_eq!(counts.unreachable_nodes, 8);
    assert_eq!(counts.cap_suites, 2);
}
#[test]
fn dead_unpruned_phis_are_lowered_while_pruned_form_shares_the_graph() {
    let es = [(0, 1), (0, 2), (1, 3), (2, 3), (3, 0)];
    let raw = RawProgram {
        variables: vec![EntryState::Undefined, EntryState::Input],
        blocks: vec![vec![], vec![stmt(&[], &[0, 1])], vec![], vec![]],
    };
    let unpruned = make_lowering(4, &es, 0, &raw, PhiPlacement::Unpruned);
    let pruned = make_lowering(4, &es, 0, &raw, PhiPlacement::Pruned);
    assert!(unpruned.stats().eliminated_phis > 0);
    assert!(unpruned.stats().copy_blocks > 0);
    assert_eq!(pruned.stats().eliminated_phis, 0);
    assert_eq!(pruned.stats().copy_blocks, 0);
    assert!(Arc::ptr_eq(pruned.graph(), pruned.source().graph()));
    let counts = directed(4, es.to_vec(), 0, raw);
    assert_eq!(counts.ordinary_uses, 0);
}
#[test]
fn lowering_owns_its_source_and_repeated_construction_is_deterministic() {
    let raw = RawProgram {
        variables: vec![EntryState::Undefined],
        blocks: vec![
            vec![stmt(&[0], &[])],
            vec![stmt(&[0], &[0])],
            vec![stmt(&[0], &[0])],
            vec![stmt(&[0], &[])],
        ],
    };
    let graph = Arc::new(
        Graph::new(
            4,
            [(0, 2), (2, 3), (0, 1), (1, 3), (3, 0), (0, 1)],
            GraphLimits::default(),
        )
        .unwrap(),
    );
    let ssa = Arc::new(Ssa::construct(graph.clone(), 0, &raw, Limits::default()).unwrap());
    let before_blocks = ssa.blocks().to_vec();
    let before_values = ssa.values().to_vec();
    let source_weak = Arc::downgrade(&ssa);
    let graph_weak = Arc::downgrade(&graph);
    let limits = PhiLoweringLimits::default();
    let lower = PhiLowering::new(ssa.clone(), limits).unwrap();
    let again = PhiLowering::new(ssa.clone(), limits).unwrap();
    assert!(Arc::ptr_eq(lower.source(), &ssa));
    assert_eq!(lower.entry(), again.entry());
    assert_eq!(lower.stats(), again.stats());
    assert_eq!(lower.copy_blocks(), again.copy_blocks());
    assert_eq!(lower.moves(), again.moves());
    assert_eq!(edges(lower.graph()), edges(again.graph()));
    assert_eq!(ssa.blocks(), before_blocks);
    assert_eq!(ssa.values(), before_values);
    let cloned = lower.clone();
    assert!(Arc::ptr_eq(lower.source(), cloned.source()));
    assert!(Arc::ptr_eq(lower.graph(), cloned.graph()));
    drop(raw);
    drop(graph);
    drop(ssa);
    drop(again);
    drop(lower);
    assert!(source_weak.upgrade().is_some());
    assert!(graph_weak.upgrade().is_some());
    assert_eq!(cloned.source().values(), before_values);
    assert_eq!(cloned.source().blocks(), before_blocks);
    assert_eq!(cloned.limits(), limits);
    drop(cloned);
    assert!(source_weak.upgrade().is_none());
    assert!(graph_weak.upgrade().is_none());
}
#[test]
fn deterministic_generated_programs_match_raw_execution_on_lowered_paths() {
    let mut random = Random(0x0eaf_6ace_0055_4319);
    let mut counts = Counts::default();
    for case in 0..750 {
        let (n, es, entry, raw) = random_case(&mut random, case);
        run_case(
            n,
            es,
            entry,
            raw,
            &mut random,
            false,
            case < 8 || case % 97 == 0,
            &mut counts,
        );
    }
    assert_eq!(counts.cases, 1_500);
    assert_eq!(counts.paths, 24_000);
    assert!(counts.ordinary_uses > 1_000_000);
    assert!(counts.undefined_uses > 100_000);
    assert!(counts.entry_prologues > 500);
    assert!(counts.identity_copies > 1_000);
    assert!(counts.critical_splits > 5_000);
    assert!(counts.unreachable_to_reachable_edges > 500);
    assert!(counts.cap_suites >= 30);
    println!("generated lowering oracle: {counts:?}");
}
#[test]
fn hundred_thousand_nodes_with_many_sparse_copy_batches() {
    // Each diamond defines one variable on both arms. There are 100,000
    // original nodes and ValueIds, but only one copy per split incoming edge.
    // Allocating a ValueId-sized table per batch would do billions of entries.
    let started = std::time::Instant::now();
    let diamonds = 33_333;
    let nodes = 3 * diamonds + 1;
    let mut raw = RawProgram {
        variables: vec![EntryState::Undefined],
        blocks: vec![Vec::new(); nodes],
    };
    let mut es = Vec::with_capacity(4 * diamonds);
    let mut path = vec![0];
    for d in 0..diamonds {
        let head = 3 * d;
        let left = head + 1;
        let right = head + 2;
        let join = head + 3;
        es.extend([(head, left), (head, right), (left, join), (right, join)]);
        raw.blocks[left].push(stmt(&[], &[0]));
        raw.blocks[right].push(stmt(&[], &[0]));
        raw.blocks[join].push(stmt(&[0], &[]));
        path.extend([if d % 2 == 0 { left } else { right }, join]);
    }
    let graph = Arc::new(Graph::new(nodes, es, GraphLimits::default()).unwrap());
    let ssa = Arc::new(Ssa::construct(graph, 0, &raw, Limits::default()).unwrap());
    assert_eq!(ssa.values().len(), 100_000);
    assert_eq!(ssa.phi_count(), diamonds);
    let before_lowering = std::time::Instant::now();
    let lower = PhiLowering::new(ssa, PhiLoweringLimits::default()).unwrap();
    let lowering_elapsed = before_lowering.elapsed();
    assert_eq!(lower.stats().copy_blocks, 2 * diamonds);
    assert_eq!(lower.stats().moves, 2 * diamonds);
    assert_eq!(lower.stats().temporaries, 0);
    assert_eq!(lower.stats().identity_copies, 0);
    assert_eq!(lower.graph().node_count(), nodes + 2 * diamonds);
    assert_eq!(lower.graph().edge_count(), 6 * diamonds);
    for d in 0..diamonds {
        let join = 3 * d + 3;
        for side in 0..2 {
            let pred = 3 * d + side + 1;
            let via = nodes + 2 * d + side;
            let copy = &lower.copy_blocks()[2 * d + side];
            assert_eq!(
                (copy.node, copy.predecessor, copy.target),
                (via, Predecessor::Node(pred), join)
            );
            assert_eq!(
                lower.copy_block_for(Predecessor::Node(pred), join),
                Some(via)
            );
            assert_eq!(lower.block_moves(via).unwrap().len(), 1);
            assert_eq!(lower.graph().successors(pred).unwrap(), &[via]);
            assert_eq!(lower.graph().successors(via).unwrap(), &[join]);
        }
    }
    let mut counts = Counts::default();
    execute(&lower, &raw, &path, &mut counts);
    assert_eq!(counts.ordinary_uses, diamonds);
    assert_eq!(counts.executed_moves, diamonds);
    assert_eq!(counts.undefined_uses, 0);
    println!(
        "sparse lowering stress: nodes={nodes}, values={}, blocks={}, moves={}, work={}, lowering={lowering_elapsed:?}, total={:?}",
        lower.stats().values,
        lower.stats().copy_blocks,
        lower.stats().moves,
        lower.stats().work,
        started.elapsed()
    );
}
