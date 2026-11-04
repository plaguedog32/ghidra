//! Liveness-pruned placement: hand-checked phis and operands, limits, work
//! exhaustion, and scaling. Every constructed result is also verified.

use std::collections::BTreeSet;
use std::sync::Arc;

use ghidra_graph::{Graph, Limits as GraphLimits};
use ghidra_ssa::{
    Block, DefinitionSite, EntryState, Error, Limits, OperandSite, PhiId, PhiPlacement,
    Predecessor, RawProgram, RawStatement, RenamedBlock, Resource, Ssa, StatementId, UseSite,
    ValueId, ValueOrigin, VariableId,
};

const IN: EntryState = EntryState::Input;
const UNDEF: EntryState = EntryState::Undefined;

fn v(index: usize) -> VariableId {
    VariableId(index)
}

fn stmt(uses: &[usize], defs: &[usize]) -> RawStatement {
    RawStatement::new(uses.iter().map(|&x| v(x)), defs.iter().map(|&x| v(x)))
}

fn graph(nodes: usize, edges: &[(usize, usize)]) -> Arc<Graph> {
    Arc::new(Graph::new(nodes, edges.iter().copied(), GraphLimits::default()).unwrap())
}

/// Unpruned and pruned forms of the same input, both verified.
fn both(nodes: usize, edges: &[(usize, usize)], program: &RawProgram) -> (Ssa, Ssa) {
    let g = graph(nodes, edges);
    let unpruned = Ssa::construct(Arc::clone(&g), 0, program, Limits::default()).unwrap();
    unpruned.verify(program).unwrap();
    let pruned = Ssa::construct_pruned(g, 0, program, Limits::default()).unwrap();
    pruned.verify(program).unwrap();
    assert_eq!(unpruned.placement(), PhiPlacement::Unpruned);
    assert_eq!(pruned.placement(), PhiPlacement::Pruned);
    (unpruned, pruned)
}

fn block(ssa: &Ssa, node: usize) -> &RenamedBlock {
    ssa.block(node).unwrap().renamed().expect("reachable block")
}

/// Every (node, variable) phi, in node and phi order.
fn phis(ssa: &Ssa) -> BTreeSet<(usize, usize)> {
    (0..ssa.node_count())
        .filter_map(|node| ssa.block(node).unwrap().renamed().map(|b| (node, b)))
        .flat_map(|(node, b)| b.phis().iter().map(move |phi| (node, phi.variable().0)))
        .collect()
}

fn def(ssa: &Ssa, node: usize, index: usize, slot: usize) -> ValueId {
    ssa.definition(DefinitionSite {
        statement: StatementId { node, index },
        slot,
    })
    .unwrap()
}

fn use_of(ssa: &Ssa, node: usize, index: usize, slot: usize) -> ValueId {
    ssa.use_value(UseSite {
        statement: StatementId { node, index },
        slot,
    })
    .unwrap()
}

fn phi_operands(ssa: &Ssa, node: usize, variable: usize) -> Vec<(Predecessor, ValueId)> {
    let block = block(ssa, node);
    let (_, phi) = block.phi_for(v(variable)).expect("phi");
    block
        .incoming()
        .iter()
        .copied()
        .zip(phi.operands().iter().copied())
        .collect()
}

fn phi_value(ssa: &Ssa, node: usize, variable: usize) -> ValueId {
    block(ssa, node)
        .phi_for(v(variable))
        .expect("phi")
        .1
        .value()
}

fn entry(ssa: &Ssa, variable: usize) -> ValueId {
    ssa.entry_value(v(variable)).unwrap()
}

const DIAMOND: [(usize, usize); 4] = [(0, 1), (0, 2), (1, 3), (2, 3)];

/// Diamond: x is read and rewritten on one arm and read at the join; y is
/// written on that arm and never read; z (undefined on entry) is written on
/// that arm and read at the join.
fn diamond() -> RawProgram {
    RawProgram {
        variables: vec![IN, IN, UNDEF],
        blocks: vec![
            vec![stmt(&[], &[0])],
            vec![stmt(&[0], &[0, 1, 2])],
            vec![],
            vec![stmt(&[0, 2], &[])],
        ],
    }
}

#[test]
fn diamond_keeps_live_join_phis_and_drops_dead_ones() {
    let program = diamond();
    let (unpruned, pruned) = both(4, &DIAMOND, &program);
    assert_eq!(phis(&unpruned), BTreeSet::from([(3, 0), (3, 1), (3, 2)]));
    assert_eq!(phis(&pruned), BTreeSet::from([(3, 0), (3, 2)]));
    assert_eq!(pruned.phi_count(), 2);
    assert_eq!(pruned.phi_operand_count(), 4);
    assert_eq!(pruned.values().len(), 3 + 2 + 4);
    assert_eq!(
        phi_operands(&pruned, 3, 0),
        [
            (Predecessor::Node(1), def(&pruned, 1, 0, 0)),
            (Predecessor::Node(2), def(&pruned, 0, 0, 0)),
        ]
    );
    // The undefined entry value stays an explicit operand of the live join.
    assert_eq!(
        phi_operands(&pruned, 3, 2),
        [
            (Predecessor::Node(1), def(&pruned, 1, 0, 2)),
            (Predecessor::Node(2), entry(&pruned, 2)),
        ]
    );
    assert_eq!(
        pruned.value(entry(&pruned, 2)).unwrap().origin,
        ValueOrigin::Entry(UNDEF)
    );
    assert_eq!(use_of(&pruned, 1, 0, 0), def(&pruned, 0, 0, 0));
    assert_eq!(use_of(&pruned, 3, 0, 0), phi_value(&pruned, 3, 0));
    assert_eq!(use_of(&pruned, 3, 0, 1), phi_value(&pruned, 3, 2));
    // Layout is unchanged: entry values, phis in node and phi order, defs.
    assert_eq!(
        pruned.value(phi_value(&pruned, 3, 2)).unwrap().origin,
        ValueOrigin::Phi(PhiId { node: 3, index: 1 })
    );
    assert_eq!(phi_value(&pruned, 3, 0), ValueId(3));
    assert_eq!(def(&pruned, 0, 0, 0), ValueId(5));
}

#[test]
fn entry_backedges_keep_the_virtual_entry_operand_only_when_live() {
    // Entry self-loop: x is loop-carried; t is written before it is read.
    let program = RawProgram {
        variables: vec![IN, UNDEF],
        blocks: vec![vec![stmt(&[0], &[0]), stmt(&[], &[1]), stmt(&[1], &[])]],
    };
    let (unpruned, pruned) = both(1, &[(0, 0)], &program);
    assert_eq!(phis(&unpruned), BTreeSet::from([(0, 0), (0, 1)]));
    assert_eq!(phis(&pruned), BTreeSet::from([(0, 0)]));
    assert_eq!(
        phi_operands(&pruned, 0, 0),
        [
            (Predecessor::Entry, entry(&pruned, 0)),
            (Predecessor::Node(0), def(&pruned, 0, 0, 0)),
        ]
    );
    assert_eq!(use_of(&pruned, 0, 0, 0), phi_value(&pruned, 0, 0));
    assert_eq!(use_of(&pruned, 0, 2, 0), def(&pruned, 0, 1, 0));

    // Longer backedge 0 -> 1 -> 2 -> 0 with exit 2 -> 3. The entry reads x
    // before the loop writes it; t is written in 1 before 2 reads it.
    let program = RawProgram {
        variables: vec![IN, IN],
        blocks: vec![
            vec![stmt(&[0], &[])],
            vec![stmt(&[], &[0]), stmt(&[], &[1])],
            vec![stmt(&[1], &[])],
            vec![stmt(&[0], &[])],
        ],
    };
    let (unpruned, pruned) = both(4, &[(0, 1), (1, 2), (2, 0), (2, 3)], &program);
    assert_eq!(phis(&unpruned), BTreeSet::from([(0, 0), (0, 1)]));
    assert_eq!(phis(&pruned), BTreeSet::from([(0, 0)]));
    assert_eq!(
        phi_operands(&pruned, 0, 0),
        [
            (Predecessor::Entry, entry(&pruned, 0)),
            (Predecessor::Node(2), def(&pruned, 1, 0, 0)),
        ]
    );
    assert_eq!(use_of(&pruned, 0, 0, 0), phi_value(&pruned, 0, 0));
    assert_eq!(use_of(&pruned, 3, 0, 0), def(&pruned, 1, 0, 0));
    assert_eq!(use_of(&pruned, 2, 0, 0), def(&pruned, 1, 1, 0));
}

#[test]
fn irreducible_cycle_and_critical_edges_place_only_live_phis() {
    // 1 <-> 2 is entered from 0 at both nodes; every edge into 1, 2, and 3
    // is critical. x is read in 1 and written in 1 and 2; y is written in 1
    // and read in 2 and 3.
    let edges = [(0, 1), (0, 2), (1, 2), (2, 1), (1, 3), (2, 3)];
    let program = RawProgram {
        variables: vec![IN, IN],
        blocks: vec![
            vec![],
            vec![stmt(&[0], &[0]), stmt(&[], &[1])],
            vec![stmt(&[1], &[0])],
            vec![stmt(&[1], &[])],
        ],
    };
    let (unpruned, pruned) = both(4, &edges, &program);
    let all: BTreeSet<_> = [1, 2, 3]
        .into_iter()
        .flat_map(|node| [(node, 0), (node, 1)])
        .collect();
    assert_eq!(phis(&unpruned), all);
    assert_eq!(phis(&pruned), BTreeSet::from([(1, 0), (2, 1), (3, 1)]));
    assert_eq!(
        phi_operands(&pruned, 1, 0),
        [
            (Predecessor::Node(0), entry(&pruned, 0)),
            (Predecessor::Node(2), def(&pruned, 2, 0, 0)),
        ]
    );
    assert_eq!(
        phi_operands(&pruned, 2, 1),
        [
            (Predecessor::Node(0), entry(&pruned, 1)),
            (Predecessor::Node(1), def(&pruned, 1, 1, 0)),
        ]
    );
    // 2 has no write of y, so its end value is its own phi.
    assert_eq!(
        phi_operands(&pruned, 3, 1),
        [
            (Predecessor::Node(1), def(&pruned, 1, 1, 0)),
            (Predecessor::Node(2), phi_value(&pruned, 2, 1)),
        ]
    );
    assert_eq!(use_of(&pruned, 1, 0, 0), phi_value(&pruned, 1, 0));
    assert_eq!(use_of(&pruned, 2, 0, 0), phi_value(&pruned, 2, 1));
    assert_eq!(use_of(&pruned, 3, 0, 0), phi_value(&pruned, 3, 1));
}

#[test]
fn simultaneous_definitions_read_before_write() {
    // Self-loop at 1 swaps a and b; t is written before each read of it.
    let program = RawProgram {
        variables: vec![IN, IN, UNDEF],
        blocks: vec![
            vec![stmt(&[], &[0, 1])],
            vec![stmt(&[0, 1], &[1, 0]), stmt(&[], &[2]), stmt(&[2, 2], &[2])],
            vec![stmt(&[0], &[])],
        ],
    };
    let (unpruned, pruned) = both(3, &[(0, 1), (1, 1), (1, 2)], &program);
    assert_eq!(phis(&unpruned), BTreeSet::from([(1, 0), (1, 1), (1, 2)]));
    assert_eq!(phis(&pruned), BTreeSet::from([(1, 0), (1, 1)]));
    assert_eq!(
        phi_operands(&pruned, 1, 0),
        [
            (Predecessor::Node(0), def(&pruned, 0, 0, 0)),
            (Predecessor::Node(1), def(&pruned, 1, 0, 1)),
        ]
    );
    assert_eq!(
        phi_operands(&pruned, 1, 1),
        [
            (Predecessor::Node(0), def(&pruned, 0, 0, 1)),
            (Predecessor::Node(1), def(&pruned, 1, 0, 0)),
        ]
    );
    assert_eq!(
        block(&pruned, 1).statements()[0].uses(),
        [phi_value(&pruned, 1, 0), phi_value(&pruned, 1, 1)]
    );
    assert_eq!(
        block(&pruned, 1).statements()[2].uses(),
        [def(&pruned, 1, 1, 0); 2]
    );
    assert_eq!(use_of(&pruned, 2, 0, 0), def(&pruned, 1, 0, 1));
}

#[test]
fn dead_variables_and_unreachable_predecessors_add_nothing() {
    // 4 is unreachable and reads both variables before 3.
    let edges = [(0, 1), (0, 2), (1, 3), (2, 3), (4, 3)];
    let program = RawProgram {
        variables: vec![IN, IN],
        blocks: vec![
            vec![],
            vec![stmt(&[], &[0, 1])],
            vec![],
            vec![stmt(&[0], &[])],
            vec![stmt(&[0, 1], &[0])],
        ],
    };
    let (unpruned, pruned) = both(5, &edges, &program);
    assert_eq!(phis(&unpruned), BTreeSet::from([(3, 0), (3, 1)]));
    assert_eq!(phis(&pruned), BTreeSet::from([(3, 0)]));
    assert_eq!(
        phi_operands(&pruned, 3, 0),
        [
            (Predecessor::Node(1), def(&pruned, 1, 0, 0)),
            (Predecessor::Node(2), entry(&pruned, 0)),
        ]
    );
    assert_eq!(
        pruned.block(4).unwrap(),
        &Block::Unreachable { statement_count: 1 }
    );
    // A variable that is only ever written needs no phi anywhere.
    let mut writes_only = program.clone();
    writes_only.blocks[3].clear();
    let (_, pruned) = both(5, &edges, &writes_only);
    assert_eq!(pruned.phi_count(), 0);
    // Unreachable statements are still validated in pruned mode.
    let mut bad = program;
    bad.blocks[4][0].uses[1] = v(7);
    assert_eq!(
        Ssa::construct_pruned(graph(5, &edges), 0, &bad, Limits::default()).unwrap_err(),
        Error::InvalidOperand {
            site: OperandSite::Use(UseSite {
                statement: StatementId { node: 4, index: 0 },
                slot: 1
            }),
            variable: v(7),
            variable_count: 2
        }
    );
}

#[test]
fn construct_selects_unpruned_and_pruned_matches_it_when_every_phi_is_live() {
    // 0 -> 1 -> 2 -> 1, 1 -> 3: x is read at the header and the exit.
    let edges = [(0, 1), (1, 2), (2, 1), (1, 3)];
    let program = RawProgram {
        variables: vec![IN],
        blocks: vec![
            vec![stmt(&[], &[0])],
            vec![stmt(&[0], &[])],
            vec![stmt(&[0], &[0])],
            vec![stmt(&[0], &[])],
        ],
    };
    let g = graph(4, &edges);
    let plain = Ssa::construct(Arc::clone(&g), 0, &program, Limits::default()).unwrap();
    let explicit = Ssa::construct_with(
        Arc::clone(&g),
        0,
        &program,
        Limits::default(),
        PhiPlacement::Unpruned,
    )
    .unwrap();
    let pruned = Ssa::construct_with(
        Arc::clone(&g),
        0,
        &program,
        Limits::default(),
        PhiPlacement::Pruned,
    )
    .unwrap();
    pruned.verify(&program).unwrap();
    assert_eq!(PhiPlacement::default(), PhiPlacement::Unpruned);
    assert_eq!(plain.placement(), PhiPlacement::Unpruned);
    assert_eq!(pruned.placement(), PhiPlacement::Pruned);
    assert_eq!(plain.blocks(), explicit.blocks());
    assert_eq!(plain.values(), explicit.values());
    assert_eq!(plain.work(), explicit.work());
    assert_eq!(pruned.blocks(), plain.blocks());
    assert_eq!(pruned.values(), plain.values());
    assert_eq!(pruned.phi_count(), 1);
    // Liveness costs work, but only for the one variable with a frontier.
    assert!(pruned.work() > plain.work());
    assert!(Arc::ptr_eq(pruned.graph(), &g));
}

fn limited(limits: Limits) -> Result<Ssa, Error> {
    // Pruned diamond: 3 variables, 3 statements, 7 operands, 2 phis with 4
    // operands, 3 entry + 2 phi + 4 definition values, and 6 live-in pairs:
    // x in {1, 2, 3}, z in {0, 2, 3}, none for y.
    let program = diamond();
    let ssa = Ssa::construct_pruned(graph(4, &DIAMOND), 0, &program, limits)?;
    ssa.verify(&program)?;
    Ok(ssa)
}

type LimitField = fn(&mut Limits) -> &mut usize;

#[test]
fn every_pruned_limit_is_exact() {
    let ssa = limited(Limits::default()).unwrap();
    assert_eq!(ssa.values().len(), 9);
    let cases: [(LimitField, usize, Resource); 7] = [
        (|l| &mut l.max_variables, 3, Resource::Variables),
        (|l| &mut l.max_statements, 3, Resource::Statements),
        (|l| &mut l.max_operands, 7, Resource::Operands),
        (|l| &mut l.max_values, 9, Resource::Values),
        (|l| &mut l.max_phis, 2, Resource::Phis),
        (|l| &mut l.max_phi_operands, 4, Resource::PhiOperands),
        (|l| &mut l.max_live_ins, 6, Resource::LiveIns),
    ];
    for (field, exact, resource) in cases {
        let mut limits = Limits::default();
        *field(&mut limits) = exact;
        assert!(limited(limits).is_ok(), "{resource:?} at its exact size");
        *field(&mut limits) = exact - 1;
        assert_eq!(
            limited(limits).unwrap_err(),
            Error::LimitExceeded { resource },
            "{resource:?} one below"
        );
    }
    // The pruned phi limit is too small for the unpruned form, which never
    // computes liveness and so ignores the live-in limit.
    let limits = Limits {
        max_phis: 2,
        max_live_ins: 0,
        ..Limits::default()
    };
    assert_eq!(
        Ssa::construct(graph(4, &DIAMOND), 0, &diamond(), limits).unwrap_err(),
        Error::LimitExceeded {
            resource: Resource::Phis
        }
    );
    let limits = Limits {
        max_live_ins: 0,
        ..Limits::default()
    };
    let unpruned = Ssa::construct(graph(4, &DIAMOND), 0, &diamond(), limits).unwrap();
    unpruned.verify(&diamond()).unwrap();
}

#[test]
fn pruned_work_exhaustion_is_an_explicit_error_at_every_budget() {
    let mut first_success = None;
    for max_work in 0..10_000 {
        let limits = Limits {
            max_work,
            ..Limits::default()
        };
        match limited(limits) {
            Ok(ssa) => {
                assert!(ssa.work() <= max_work);
                first_success = Some(max_work);
                break;
            }
            Err(error) => assert_eq!(
                error,
                Error::LimitExceeded {
                    resource: Resource::Work
                }
            ),
        }
    }
    assert!(first_success.is_some(), "construction and verification fit");
    // The two graph analyses keep their own budgets in pruned mode too.
    let tight = Arc::new(
        Graph::new(
            4,
            DIAMOND,
            GraphLimits {
                max_work: 30,
                ..GraphLimits::default()
            },
        )
        .unwrap(),
    );
    assert!(matches!(
        Ssa::construct_pruned(tight, 0, &diamond(), Limits::default()),
        Err(Error::Graph(ghidra_graph::Error::LimitExceeded {
            resource: ghidra_graph::Resource::Work
        }))
    ));
}

/// A `n`-node loop 0 -> 1 -> ... -> n-1 -> 1 shaped like adapted machine
/// code: every node writes and then reads its own temporary `t_k`
/// (variable `2 + k`). `i` (variable 0) is read and written at the header,
/// and `acc` (variable 1) is read and written halfway around the loop.
fn temporaries_loop(n: usize) -> (Arc<Graph>, RawProgram) {
    let mut edges: Vec<_> = (1..n).map(|node| (node - 1, node)).collect();
    edges.push((n - 1, 1));
    let mut blocks: Vec<Vec<RawStatement>> = (0..n)
        .map(|node| vec![stmt(&[], &[2 + node]), stmt(&[2 + node], &[])])
        .collect();
    blocks[0].insert(0, stmt(&[], &[0, 1]));
    blocks[1].insert(0, stmt(&[0], &[0]));
    blocks[n / 2].insert(0, stmt(&[1], &[1]));
    let mut variables = vec![IN; n + 2];
    variables[1] = UNDEF;
    (graph(n, &edges), RawProgram { variables, blocks })
}

#[test]
fn hundred_thousand_node_loop_has_only_its_live_phis_and_linear_work() {
    let n = 100_000;
    let (g, program) = temporaries_loop(n);
    let capped = Limits {
        max_phis: 100,
        ..Limits::default()
    };
    // Unpruned placement gives every temporary a dead header phi.
    assert_eq!(
        Ssa::construct(Arc::clone(&g), 0, &program, capped).unwrap_err(),
        Error::LimitExceeded {
            resource: Resource::Phis
        }
    );
    let ssa = Ssa::construct_pruned(Arc::clone(&g), 0, &program, capped).unwrap();
    ssa.verify(&program).unwrap();
    assert_eq!(phis(&ssa), BTreeSet::from([(1, 0), (1, 1)]));
    assert_eq!(
        phi_operands(&ssa, 1, 0),
        [
            (Predecessor::Node(0), def(&ssa, 0, 0, 0)),
            (Predecessor::Node(n - 1), def(&ssa, 1, 0, 0)),
        ]
    );
    assert_eq!(
        phi_operands(&ssa, 1, 1),
        [
            (Predecessor::Node(0), def(&ssa, 0, 0, 1)),
            (Predecessor::Node(n - 1), def(&ssa, n / 2, 0, 0)),
        ]
    );
    assert_eq!(use_of(&ssa, 1, 0, 0), phi_value(&ssa, 1, 0));
    assert_eq!(use_of(&ssa, n / 2, 0, 0), phi_value(&ssa, 1, 1));
    assert_eq!(use_of(&ssa, n - 1, 1, 0), def(&ssa, n - 1, 0, 0));
    assert_eq!(use_of(&ssa, 1, 2, 0), def(&ssa, 1, 1, 0));
    // Work is linear in this input: a fixed cost per node, and doubling the
    // loop at most doubles it. A per-temporary walk of the loop (quadratic)
    // would need about 10^10 units.
    assert!(ssa.work() < 80 * n as u64, "work {}", ssa.work());
    let (half_graph, half_program) = temporaries_loop(n / 2);
    let half = Ssa::construct_pruned(half_graph, 0, &half_program, capped).unwrap();
    assert!(
        ssa.work() <= 2 * half.work() + 1_000,
        "work {} for {n} nodes, {} for half",
        ssa.work(),
        half.work()
    );
    // i and acc are each live on entry to nodes 1..n; temporaries never are.
    let live_ins = 2 * (n - 1);
    let exact = Limits {
        max_live_ins: live_ins,
        ..capped
    };
    let ssa = Ssa::construct_pruned(Arc::clone(&g), 0, &program, exact).unwrap();
    ssa.verify(&program).unwrap();
    let below = Limits {
        max_live_ins: live_ins - 1,
        ..capped
    };
    assert_eq!(
        Ssa::construct_pruned(g, 0, &program, below).unwrap_err(),
        Error::LimitExceeded {
            resource: Resource::LiveIns
        }
    );
}

#[test]
fn adapter_shaped_ten_thousand_instruction_loop_fits_a_small_phi_cap() {
    let (g, program) = temporaries_loop(10_000);
    let limits = Limits {
        max_phis: 100,
        ..Limits::default()
    };
    assert!(matches!(
        Ssa::construct(Arc::clone(&g), 0, &program, limits),
        Err(Error::LimitExceeded {
            resource: Resource::Phis
        })
    ));
    let ssa = Ssa::construct_pruned(g, 0, &program, limits).unwrap();
    ssa.verify(&program).unwrap();
    assert_eq!(ssa.phi_count(), 2);
}
