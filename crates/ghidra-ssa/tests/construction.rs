use std::sync::Arc;

use ghidra_graph::{Graph, Limits as GraphLimits};
use ghidra_ssa::{
    Block, DefinitionSite, EntryState, Error, ImmediateDominator, Limits, OperandSite, PhiId,
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

fn build(nodes: usize, edges: &[(usize, usize)], program: &RawProgram) -> Ssa {
    let ssa = Ssa::construct(graph(nodes, edges), 0, program, Limits::default()).unwrap();
    ssa.verify(program).unwrap();
    ssa
}

fn block(ssa: &Ssa, node: usize) -> &RenamedBlock {
    ssa.block(node).unwrap().renamed().expect("reachable block")
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

#[test]
fn diamond_places_one_phi_and_keeps_entry_values_explicit() {
    let program = RawProgram {
        variables: vec![IN, UNDEF],
        blocks: vec![
            vec![stmt(&[], &[0])],
            vec![stmt(&[0], &[0])],
            vec![],
            vec![stmt(&[0, 1], &[])],
        ],
    };
    let ssa = build(4, &[(0, 1), (0, 2), (1, 3), (2, 3)], &program);
    assert_eq!(ssa.phi_count(), 1);
    assert_eq!(ssa.phi_operand_count(), 2);
    assert_eq!(ssa.values().len(), 2 + 1 + 2);
    assert_eq!(
        phi_operands(&ssa, 3, 0),
        [
            (Predecessor::Node(1), def(&ssa, 1, 0, 0)),
            (Predecessor::Node(2), def(&ssa, 0, 0, 0)),
        ]
    );
    assert_eq!(use_of(&ssa, 1, 0, 0), def(&ssa, 0, 0, 0));
    assert_eq!(use_of(&ssa, 3, 0, 0), phi_value(&ssa, 3, 0));
    // y is never written: no phi, and the use reads the explicit undefined entry.
    assert_eq!(use_of(&ssa, 3, 0, 1), entry(&ssa, 1));
    assert_eq!(
        ssa.value(entry(&ssa, 1)).unwrap().origin,
        ValueOrigin::Entry(UNDEF)
    );
    assert_eq!(ssa.entry_state(v(0)).unwrap(), IN);
    assert_eq!(
        ssa.value(phi_value(&ssa, 3, 0)).unwrap().origin,
        ValueOrigin::Phi(PhiId { node: 3, index: 0 })
    );
    assert_eq!(block(&ssa, 0).incoming(), [Predecessor::Entry]);
    assert_eq!(
        ssa.immediate_dominator(3).unwrap(),
        ImmediateDominator::Parent(0)
    );
    assert_eq!(ssa.entry(), 0);
    assert_eq!(ssa.graph().node_count(), 4);
}

#[test]
fn undefined_value_survives_a_join_with_a_definition() {
    let program = RawProgram {
        variables: vec![UNDEF],
        blocks: vec![vec![], vec![stmt(&[], &[0])], vec![], vec![stmt(&[0], &[])]],
    };
    let ssa = build(4, &[(0, 1), (0, 2), (1, 3), (2, 3)], &program);
    let operands = phi_operands(&ssa, 3, 0);
    assert_eq!(operands[1], (Predecessor::Node(2), entry(&ssa, 0)));
    assert_eq!(
        ssa.value(operands[1].1).unwrap().origin,
        ValueOrigin::Entry(UNDEF)
    );
}

#[test]
fn simple_loop_header_merges_preheader_and_latch() {
    // 0 -> 1 -> 2 -> 1, 1 -> 3
    let program = RawProgram {
        variables: vec![IN],
        blocks: vec![
            vec![stmt(&[], &[0])],
            vec![stmt(&[0], &[])],
            vec![stmt(&[0], &[0])],
            vec![stmt(&[0], &[])],
        ],
    };
    let ssa = build(4, &[(0, 1), (1, 2), (2, 1), (1, 3)], &program);
    let header = phi_value(&ssa, 1, 0);
    assert_eq!(
        phi_operands(&ssa, 1, 0),
        [
            (Predecessor::Node(0), def(&ssa, 0, 0, 0)),
            (Predecessor::Node(2), def(&ssa, 2, 0, 0)),
        ]
    );
    assert_eq!(use_of(&ssa, 1, 0, 0), header);
    assert_eq!(use_of(&ssa, 2, 0, 0), header);
    assert_eq!(use_of(&ssa, 3, 0, 0), header);
    assert_eq!(ssa.phi_count(), 1);
}

#[test]
fn nested_loops_with_multiple_latches_and_an_unreachable_predecessor() {
    // Outer header 1 (latches 3, 4), inner header 2 (latch 3). Node 6 is
    // unreachable and points into the loop; it must add no phi operand.
    let edges = [
        (0, 1),
        (1, 2),
        (2, 3),
        (3, 2),
        (2, 4),
        (4, 1),
        (3, 1),
        (1, 5),
        (6, 3),
    ];
    let program = RawProgram {
        variables: vec![IN],
        blocks: vec![
            vec![],
            vec![],
            vec![stmt(&[0], &[])],
            vec![stmt(&[0], &[0])],
            vec![],
            vec![stmt(&[0], &[])],
            vec![stmt(&[0], &[0]), stmt(&[], &[0])],
        ],
    };
    let ssa = build(7, &edges, &program);
    let outer = phi_value(&ssa, 1, 0);
    let inner = phi_value(&ssa, 2, 0);
    let latch = def(&ssa, 3, 0, 0);
    assert_eq!(
        phi_operands(&ssa, 1, 0),
        [
            (Predecessor::Node(0), entry(&ssa, 0)),
            (Predecessor::Node(3), latch),
            (Predecessor::Node(4), inner),
        ]
    );
    assert_eq!(
        phi_operands(&ssa, 2, 0),
        [(Predecessor::Node(1), outer), (Predecessor::Node(3), latch),]
    );
    assert_eq!(block(&ssa, 3).incoming(), [Predecessor::Node(2)]);
    assert!(block(&ssa, 3).phis().is_empty());
    assert_eq!(use_of(&ssa, 5, 0, 0), outer);
    assert_eq!(
        ssa.block(6).unwrap(),
        &Block::Unreachable { statement_count: 2 }
    );
    assert!(!ssa.is_reachable(6).unwrap());
    assert!(ssa.values().iter().all(|value| match value.origin {
        ValueOrigin::Definition(site) => site.statement.node != 6,
        ValueOrigin::Phi(phi) => phi.node != 6,
        ValueOrigin::Entry(_) => true,
    }));
    assert!(matches!(
        ssa.statement(StatementId { node: 6, index: 0 }),
        Err(Error::InvalidStatement { .. })
    ));
}

#[test]
fn entry_self_loop_has_a_virtual_entry_operand_for_the_first_iteration() {
    // 0 -> 0, 0 -> 1. The first visit of 0 must read the entry value.
    let program = RawProgram {
        variables: vec![IN, UNDEF],
        blocks: vec![vec![stmt(&[0, 1], &[0])], vec![stmt(&[0, 1], &[])]],
    };
    let ssa = build(2, &[(0, 0), (0, 1)], &program);
    assert_eq!(
        block(&ssa, 0).incoming(),
        [Predecessor::Entry, Predecessor::Node(0)]
    );
    assert_eq!(
        phi_operands(&ssa, 0, 0),
        [
            (Predecessor::Entry, entry(&ssa, 0)),
            (Predecessor::Node(0), def(&ssa, 0, 0, 0)),
        ]
    );
    // y is never written, so the loop needs no phi for it.
    assert!(block(&ssa, 0).phi_for(v(1)).is_none());
    assert_eq!(use_of(&ssa, 0, 0, 0), phi_value(&ssa, 0, 0));
    assert_eq!(use_of(&ssa, 0, 0, 1), entry(&ssa, 1));
    assert_eq!(use_of(&ssa, 1, 0, 0), def(&ssa, 0, 0, 0));
}

#[test]
fn entry_with_a_longer_backedge_gets_entry_phis() {
    // 0 -> 1 -> 0, 1 -> 2. Both blocks write x.
    let program = RawProgram {
        variables: vec![UNDEF],
        blocks: vec![
            vec![stmt(&[0], &[0])],
            vec![stmt(&[0], &[0])],
            vec![stmt(&[0], &[])],
        ],
    };
    let ssa = build(3, &[(0, 1), (1, 0), (1, 2)], &program);
    assert_eq!(
        phi_operands(&ssa, 0, 0),
        [
            (Predecessor::Entry, entry(&ssa, 0)),
            (Predecessor::Node(1), def(&ssa, 1, 0, 0)),
        ]
    );
    assert_eq!(use_of(&ssa, 0, 0, 0), phi_value(&ssa, 0, 0));
    assert_eq!(use_of(&ssa, 2, 0, 0), def(&ssa, 1, 0, 0));
}

#[test]
fn irreducible_cycle_and_critical_edges_keep_canonical_order() {
    // Irreducible 1 <-> 2, both entered from 0; 0 -> 3 is a critical edge.
    let edges = [(0, 1), (0, 2), (1, 2), (2, 1), (1, 3), (2, 3), (0, 3)];
    let program = RawProgram {
        variables: vec![IN],
        blocks: vec![
            vec![],
            vec![stmt(&[0], &[0])],
            vec![stmt(&[0], &[0])],
            vec![stmt(&[0], &[])],
        ],
    };
    let ssa = build(4, &edges, &program);
    let (d1, d2) = (def(&ssa, 1, 0, 0), def(&ssa, 2, 0, 0));
    assert_eq!(
        phi_operands(&ssa, 1, 0),
        [
            (Predecessor::Node(0), entry(&ssa, 0)),
            (Predecessor::Node(2), d2),
        ]
    );
    assert_eq!(
        phi_operands(&ssa, 2, 0),
        [
            (Predecessor::Node(0), entry(&ssa, 0)),
            (Predecessor::Node(1), d1),
        ]
    );
    assert_eq!(
        phi_operands(&ssa, 3, 0),
        [
            (Predecessor::Node(0), entry(&ssa, 0)),
            (Predecessor::Node(1), d1),
            (Predecessor::Node(2), d2),
        ]
    );
    assert_eq!(use_of(&ssa, 1, 0, 0), phi_value(&ssa, 1, 0));
    assert_eq!(use_of(&ssa, 2, 0, 0), phi_value(&ssa, 2, 0));
}

#[test]
fn critical_edge_uses_the_source_block_end_value() {
    // 0 -> 1 -> 2 and critical edge 0 -> 2. 0 writes x after an earlier use.
    let program = RawProgram {
        variables: vec![IN],
        blocks: vec![
            vec![stmt(&[0], &[0]), stmt(&[], &[0])],
            vec![stmt(&[], &[0])],
            vec![stmt(&[0], &[])],
        ],
    };
    let ssa = build(3, &[(0, 1), (0, 2), (1, 2)], &program);
    assert_eq!(
        phi_operands(&ssa, 2, 0),
        [
            (Predecessor::Node(0), def(&ssa, 0, 1, 0)),
            (Predecessor::Node(1), def(&ssa, 1, 0, 0)),
        ]
    );
}

#[test]
fn simultaneous_defs_read_before_write_and_repeated_uses() {
    // Swap a and b in one statement, read both twice, and also read c.
    let program = RawProgram {
        variables: vec![IN, IN, UNDEF],
        blocks: vec![vec![
            stmt(&[0, 1, 0, 2, 1], &[1, 0]),
            stmt(&[0, 1, 0], &[2]),
            stmt(&[2, 2], &[]),
        ]],
    };
    let ssa = build(1, &[], &program);
    let first = ssa.statement(StatementId { node: 0, index: 0 }).unwrap();
    assert_eq!(
        first.uses(),
        [
            entry(&ssa, 0),
            entry(&ssa, 1),
            entry(&ssa, 0),
            entry(&ssa, 2),
            entry(&ssa, 1)
        ]
    );
    let (new_b, new_a) = (first.defs()[0], first.defs()[1]);
    assert_eq!(ssa.value(new_b).unwrap().variable, v(1));
    assert_eq!(ssa.value(new_a).unwrap().variable, v(0));
    assert_eq!(
        ssa.value(new_a).unwrap().origin,
        ValueOrigin::Definition(DefinitionSite {
            statement: StatementId { node: 0, index: 0 },
            slot: 1
        })
    );
    let second = ssa.statement(StatementId { node: 0, index: 1 }).unwrap();
    assert_eq!(second.uses(), [new_a, new_b, new_a]);
    let third = ssa.statement(StatementId { node: 0, index: 2 }).unwrap();
    assert_eq!(third.uses(), [second.defs()[0], second.defs()[0]]);
    assert_eq!(ssa.values().len(), 3 + 3);
}

#[test]
fn empty_nodes_statements_and_isolated_entry() {
    let program = RawProgram {
        variables: vec![],
        blocks: vec![vec![RawStatement::default()], vec![]],
    };
    let ssa = build(2, &[], &program);
    assert_eq!(block(&ssa, 0).statements().len(), 1);
    assert!(block(&ssa, 0).statements()[0].uses().is_empty());
    assert_eq!(
        ssa.block(1).unwrap(),
        &Block::Unreachable { statement_count: 0 }
    );
    assert_eq!(
        ssa.immediate_dominator(1).unwrap(),
        ImmediateDominator::Unreachable
    );
    assert!(ssa.values().is_empty());
}

#[test]
fn result_owns_its_data_and_retains_the_graph() {
    let shared = graph(2, &[(0, 1)]);
    let ssa = {
        let program = RawProgram {
            variables: vec![IN],
            blocks: vec![vec![stmt(&[], &[0])], vec![stmt(&[0], &[])]],
        };
        Ssa::construct(Arc::clone(&shared), 0, &program, Limits::default()).unwrap()
    };
    // The raw program is gone; the result still answers every query.
    assert!(Arc::ptr_eq(ssa.graph(), &shared));
    assert_eq!(Arc::strong_count(&shared), 2);
    assert_eq!(use_of(&ssa, 1, 0, 0), def(&ssa, 0, 0, 0));
    fn assert_send_sync<T: Send + Sync + 'static>(_: &T) {}
    assert_send_sync(&ssa);
}

#[test]
fn malformed_ids_and_shapes_are_rejected_before_analysis() {
    let g = graph(2, &[(0, 1)]);
    let program = |blocks: Vec<Vec<RawStatement>>| RawProgram {
        variables: vec![IN, IN],
        blocks,
    };
    let ok = program(vec![vec![], vec![]]);
    assert_eq!(
        Ssa::construct(Arc::clone(&g), 2, &ok, Limits::default()).unwrap_err(),
        Error::InvalidNode {
            node: 2,
            node_count: 2
        }
    );
    assert_eq!(
        Ssa::construct(Arc::clone(&g), 0, &program(vec![vec![]]), Limits::default()).unwrap_err(),
        Error::BlockCount {
            node_count: 2,
            blocks: 1
        }
    );
    // An unreachable node is still validated.
    let bad_use = program(vec![vec![], vec![stmt(&[0, 2], &[])]]);
    let g2 = graph(2, &[]);
    assert_eq!(
        Ssa::construct(Arc::clone(&g2), 0, &bad_use, Limits::default()).unwrap_err(),
        Error::InvalidOperand {
            site: OperandSite::Use(UseSite {
                statement: StatementId { node: 1, index: 0 },
                slot: 1
            }),
            variable: v(2),
            variable_count: 2
        }
    );
    let bad_def = program(vec![vec![stmt(&[], &[usize::MAX])], vec![]]);
    assert!(matches!(
        Ssa::construct(Arc::clone(&g), 0, &bad_def, Limits::default()),
        Err(Error::InvalidOperand {
            site: OperandSite::Definition(_),
            ..
        })
    ));
    let duplicate = program(vec![vec![stmt(&[0, 0], &[1, 0, 1])], vec![]]);
    assert_eq!(
        Ssa::construct(Arc::clone(&g), 0, &duplicate, Limits::default()).unwrap_err(),
        Error::DuplicateDefinition {
            statement: StatementId { node: 0, index: 0 },
            variable: v(1)
        }
    );
    // The same variable in separate statements is fine.
    let separate = program(vec![vec![stmt(&[], &[1]), stmt(&[], &[1])], vec![]]);
    assert!(Ssa::construct(Arc::clone(&g), 0, &separate, Limits::default()).is_ok());
    let empty = Arc::new(Graph::new(0, [], GraphLimits::default()).unwrap());
    assert!(matches!(
        Ssa::construct(empty, 0, &RawProgram::default(), Limits::default()),
        Err(Error::InvalidNode { node: 0, .. })
    ));
    // Accessors reject foreign IDs.
    let ssa = Ssa::construct(Arc::clone(&g), 0, &ok, Limits::default()).unwrap();
    assert!(matches!(ssa.block(2), Err(Error::InvalidNode { .. })));
    assert!(matches!(
        ssa.immediate_dominator(9),
        Err(Error::InvalidNode { .. })
    ));
    assert!(matches!(
        ssa.entry_value(v(2)),
        Err(Error::InvalidVariable { .. })
    ));
    assert!(matches!(
        ssa.entry_state(v(2)),
        Err(Error::InvalidVariable { .. })
    ));
    assert!(matches!(
        ssa.value(ValueId(2)),
        Err(Error::InvalidValue { .. })
    ));
    assert!(matches!(
        ssa.phi(PhiId { node: 1, index: 0 }),
        Err(Error::InvalidPhi { .. })
    ));
    assert!(matches!(
        ssa.statement(StatementId { node: 0, index: 0 }),
        Err(Error::InvalidStatement { .. })
    ));
    // Verification also validates the raw program it is given.
    assert_eq!(
        ssa.verify(&program(vec![vec![]])).unwrap_err(),
        Error::BlockCount {
            node_count: 2,
            blocks: 1
        }
    );
}

fn limited(limits: Limits) -> Result<Ssa, Error> {
    // Diamond: 2 variables, 4 statements, 6 operands, 2 phis with 4 operands,
    // 2 entry + 2 phi + 3 definition values.
    let program = RawProgram {
        variables: vec![IN, UNDEF],
        blocks: vec![
            vec![stmt(&[], &[0])],
            vec![stmt(&[0], &[0, 1])],
            vec![],
            vec![stmt(&[0], &[]), stmt(&[1], &[])],
        ],
    };
    let ssa = Ssa::construct(
        graph(4, &[(0, 1), (0, 2), (1, 3), (2, 3)]),
        0,
        &program,
        limits,
    )?;
    ssa.verify(&program)?;
    Ok(ssa)
}

type LimitField = fn(&mut Limits) -> &mut usize;

#[test]
fn every_resource_limit_is_exact() {
    let ssa = limited(Limits::default()).unwrap();
    assert_eq!(ssa.values().len(), 7);
    assert_eq!(ssa.phi_count(), 2);
    assert_eq!(ssa.phi_operand_count(), 4);
    let cases: [(LimitField, usize, Resource); 6] = [
        (|l| &mut l.max_variables, 2, Resource::Variables),
        (|l| &mut l.max_statements, 4, Resource::Statements),
        (|l| &mut l.max_operands, 6, Resource::Operands),
        (|l| &mut l.max_values, 7, Resource::Values),
        (|l| &mut l.max_phis, 2, Resource::Phis),
        (|l| &mut l.max_phi_operands, 4, Resource::PhiOperands),
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
}

#[test]
fn work_exhaustion_is_an_explicit_error_at_every_budget() {
    let mut first_success = None;
    for max_work in 0..10_000 {
        let limits = Limits {
            max_work,
            ..Limits::default()
        };
        match limited(limits) {
            Ok(ssa) => {
                assert!(ssa.work() <= max_work);
                first_success = Some((max_work, ssa.work()));
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
    let (budget, used) = first_success.expect("construction eventually fits");
    // Construction alone may fit before verification does; both are bounded.
    assert!(used <= budget);
    // Graph-analysis budgets are separate and surface as graph errors.
    let tight = Arc::new(
        Graph::new(
            4,
            [(0, 1), (0, 2), (1, 3), (2, 3)],
            GraphLimits {
                max_work: 30,
                ..GraphLimits::default()
            },
        )
        .unwrap(),
    );
    let program = RawProgram {
        variables: vec![IN],
        blocks: vec![vec![]; 4],
    };
    assert!(matches!(
        Ssa::construct(tight, 0, &program, Limits::default()),
        Err(Error::Graph(ghidra_graph::Error::LimitExceeded {
            resource: ghidra_graph::Resource::Work
        }))
    ));
}

#[test]
fn long_chain_and_long_loop_are_stack_safe() {
    let n = 100_000;
    // Chain: every node reads then writes x.
    let edges: Vec<_> = (1..n).map(|node| (node - 1, node)).collect();
    let program = RawProgram {
        variables: vec![IN],
        blocks: vec![vec![stmt(&[0], &[0])]; n],
    };
    let ssa = build(n, &edges, &program);
    assert_eq!(ssa.phi_count(), 0);
    assert_eq!(use_of(&ssa, n - 1, 0, 0), def(&ssa, n - 2, 0, 0));
    assert_eq!(use_of(&ssa, 0, 0, 0), entry(&ssa, 0));
    // A single 100k-node loop back to node 1: exactly one phi.
    let mut looped = edges.clone();
    looped.push((n - 1, 1));
    let ssa = build(n, &looped, &program);
    assert_eq!(ssa.phi_count(), 1);
    assert_eq!(
        phi_operands(&ssa, 1, 0),
        [
            (Predecessor::Node(0), def(&ssa, 0, 0, 0)),
            (Predecessor::Node(n - 1), def(&ssa, n - 1, 0, 0)),
        ]
    );
    // Self-loop at the entry of a long chain.
    let mut entry_loop = edges;
    entry_loop.push((n - 1, 0));
    let ssa = build(n, &entry_loop, &program);
    assert_eq!(
        phi_operands(&ssa, 0, 0),
        [
            (Predecessor::Entry, entry(&ssa, 0)),
            (Predecessor::Node(n - 1), def(&ssa, n - 1, 0, 0)),
        ]
    );
}

/// `count` diamonds in sequence; each writes x on one arm and reads it at the join.
fn diamond_ladder(count: usize) -> (Arc<Graph>, RawProgram) {
    let n = 3 * count + 1;
    let mut edges = Vec::new();
    let mut blocks = vec![Vec::new(); n];
    for k in 0..count {
        let (top, left, right, join) = (3 * k, 3 * k + 1, 3 * k + 2, 3 * k + 3);
        edges.extend([(top, left), (top, right), (left, join), (right, join)]);
        blocks[left].push(stmt(&[], &[0]));
        blocks[join].push(stmt(&[0], &[]));
    }
    (
        graph(n, &edges),
        RawProgram {
            variables: vec![UNDEF],
            blocks,
        },
    )
}

#[test]
fn many_phis_are_bounded_and_exhaustion_is_explicit() {
    let count = 33_000;
    let (g, program) = diamond_ladder(count);
    let ssa = Ssa::construct(Arc::clone(&g), 0, &program, Limits::default()).unwrap();
    ssa.verify(&program).unwrap();
    assert_eq!(ssa.phi_count(), count);
    assert_eq!(ssa.phi_operand_count(), 2 * count);
    for (limits, resource) in [
        (
            Limits {
                max_phis: count - 1,
                ..Limits::default()
            },
            Resource::Phis,
        ),
        (
            Limits {
                max_phi_operands: 2 * count - 1,
                ..Limits::default()
            },
            Resource::PhiOperands,
        ),
        (
            Limits {
                max_values: ssa.values().len() - 1,
                ..Limits::default()
            },
            Resource::Values,
        ),
        (
            Limits {
                max_work: ssa.work() - 1,
                ..Limits::default()
            },
            Resource::Work,
        ),
    ] {
        assert_eq!(
            Ssa::construct(Arc::clone(&g), 0, &program, limits).unwrap_err(),
            Error::LimitExceeded { resource }
        );
    }
    // Work is linear in this input, not quadratic in its 33k phis.
    assert!(
        ssa.work() < 64 * (3 * count as u64 + 1),
        "work {}",
        ssa.work()
    );
}

#[test]
fn values_have_a_fixed_documented_layout() {
    let (g, program) = diamond_ladder(3);
    let ssa = Ssa::construct(g, 0, &program, Limits::default()).unwrap();
    let origins: Vec<_> = ssa.values().iter().map(|value| value.origin).collect();
    assert_eq!(origins[0], ValueOrigin::Entry(UNDEF));
    for (k, origin) in origins[1..4].iter().enumerate() {
        assert_eq!(
            *origin,
            ValueOrigin::Phi(PhiId {
                node: 3 * k + 3,
                index: 0
            })
        );
    }
    for (k, origin) in origins[4..].iter().enumerate() {
        assert_eq!(
            *origin,
            ValueOrigin::Definition(DefinitionSite {
                statement: StatementId {
                    node: 3 * k + 1,
                    index: 0
                },
                slot: 0
            })
        );
    }
}
