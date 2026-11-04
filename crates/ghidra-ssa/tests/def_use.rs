//! Def-use index: hand-checked sites, phi edge identities, unreachable code,
//! both placement modes, limits, work, scaling, and a generated reference.

use std::collections::BTreeSet;
use std::sync::Arc;

use ghidra_graph::{Graph, Limits as GraphLimits};
use ghidra_ssa::{
    DefUseError, DefUseIndex, DefUseLimits, DefUseResource, EntryState, PhiId, PhiOperandSite,
    PhiPlacement, Predecessor, RawProgram, RawStatement, RenamedBlock, Ssa, StatementId, UseSite,
    ValueId, ValueOrigin, VariableId,
};

const IN: EntryState = EntryState::Input;
const UNDEF: EntryState = EntryState::Undefined;
const MODES: [PhiPlacement; 2] = [PhiPlacement::Unpruned, PhiPlacement::Pruned];

fn v(index: usize) -> VariableId {
    VariableId(index)
}

fn stmt(uses: &[usize], defs: &[usize]) -> RawStatement {
    RawStatement::new(uses.iter().map(|&x| v(x)), defs.iter().map(|&x| v(x)))
}

fn build(
    nodes: usize,
    edges: &[(usize, usize)],
    entry: usize,
    program: &RawProgram,
    placement: PhiPlacement,
) -> Ssa {
    let graph = Arc::new(Graph::new(nodes, edges.iter().copied(), GraphLimits::default()).unwrap());
    let ssa = Ssa::construct_with(
        graph,
        entry,
        program,
        ghidra_ssa::Limits::default(),
        placement,
    )
    .unwrap();
    ssa.verify(program).unwrap();
    ssa
}

fn checked_index(ssa: &Ssa) -> DefUseIndex {
    let index = DefUseIndex::new(ssa, DefUseLimits::default()).unwrap();
    check_against_reference(ssa, &index);
    index
}

fn block(ssa: &Ssa, node: usize) -> &RenamedBlock {
    ssa.block(node).unwrap().renamed().expect("reachable block")
}

fn use_site(node: usize, index: usize, slot: usize) -> UseSite {
    UseSite {
        statement: StatementId { node, index },
        slot,
    }
}

fn phi_site(node: usize, index: usize, operand: usize) -> PhiOperandSite {
    PhiOperandSite {
        phi: PhiId { node, index },
        operand,
    }
}

fn def(ssa: &Ssa, node: usize, index: usize, slot: usize) -> ValueId {
    ssa.statement(StatementId { node, index }).unwrap().defs()[slot]
}

fn phi_value(ssa: &Ssa, node: usize, variable: usize) -> (usize, ValueId) {
    let (index, phi) = block(ssa, node).phi_for(v(variable)).expect("phi");
    (index, phi.value())
}

/// The edge a phi operand site belongs to.
fn edge(ssa: &Ssa, site: PhiOperandSite) -> Predecessor {
    block(ssa, site.phi.node).incoming()[site.operand]
}

/// Reference built only from public `Ssa` accessors: one sorted set of sites
/// per value. The index must match it exactly, with strictly ascending rows.
fn check_against_reference(ssa: &Ssa, index: &DefUseIndex) {
    let count = ssa.values().len();
    let mut uses = vec![BTreeSet::new(); count];
    let mut phis = vec![BTreeSet::new(); count];
    for node in 0..ssa.node_count() {
        let Some(renamed) = ssa.block(node).unwrap().renamed() else {
            continue;
        };
        for (i, phi) in renamed.phis().iter().enumerate() {
            for (operand, value) in phi.operands().iter().enumerate() {
                assert!(phis[value.0].insert(phi_site(node, i, operand)));
            }
        }
        for (i, statement) in renamed.statements().iter().enumerate() {
            for (slot, value) in statement.uses().iter().enumerate() {
                assert!(uses[value.0].insert(use_site(node, i, slot)));
            }
        }
    }
    assert_eq!(index.value_count(), count);
    assert_eq!(index.node_count(), ssa.node_count());
    assert_eq!(index.placement(), ssa.placement());
    assert_eq!(index.total_phi_uses(), ssa.phi_operand_count());
    let mut total = 0;
    for value in 0..count {
        let id = ValueId(value);
        let actual_uses = index.statement_uses(id).unwrap();
        let actual_phis = index.phi_uses(id).unwrap();
        assert!(actual_uses.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(actual_phis.windows(2).all(|pair| pair[0] < pair[1]));
        assert!(actual_uses.iter().eq(uses[value].iter()), "value {value}");
        assert!(actual_phis.iter().eq(phis[value].iter()), "value {value}");
        assert_eq!(
            index.use_count(id).unwrap(),
            uses[value].len() + phis[value].len()
        );
        total += uses[value].len() + phis[value].len();
    }
    assert_eq!(index.total_uses(), total);
    assert_eq!(
        index.total_uses(),
        index.total_statement_uses() + index.total_phi_uses()
    );
    assert_eq!(index.work(), expected_work(ssa));
}

/// The documented exact work: `2 + 4V + 2N + 2P + 2S + 3U + 3A`.
fn expected_work(ssa: &Ssa) -> u64 {
    let (mut statements, mut uses) = (0, 0);
    for b in ssa.blocks().iter().filter_map(|b| b.renamed()) {
        statements += b.statements().len();
        uses += b.statements().iter().map(|s| s.uses().len()).sum::<usize>();
    }
    (2 + 4 * ssa.values().len()
        + 2 * ssa.node_count()
        + 2 * ssa.phi_count()
        + 2 * statements
        + 3 * uses
        + 3 * ssa.phi_operand_count()) as u64
}

#[test]
fn repeated_uses_and_repeated_phi_operands_get_distinct_sites() {
    // 0 -> {1, 4}, 1 -> {2, 3} -> 4. x is written in 1 and read twice at 4;
    // y is never written, so its reads see the undefined entry value.
    let edges = [(0, 1), (0, 4), (1, 2), (1, 3), (2, 4), (3, 4)];
    let program = RawProgram {
        variables: vec![IN, UNDEF],
        blocks: vec![
            vec![],
            vec![stmt(&[], &[0])],
            vec![],
            vec![],
            vec![stmt(&[0, 1, 0], &[])],
        ],
    };
    for mode in MODES {
        let ssa = build(5, &edges, 0, &program, mode);
        let index = checked_index(&ssa);
        let written = def(&ssa, 1, 0, 0);
        let (phi_index, joined) = phi_value(&ssa, 4, 0);
        let entry_x = ssa.entry_value(v(0)).unwrap();
        let entry_y = ssa.entry_value(v(1)).unwrap();

        // One value on two edges of the same phi: two distinct operand sites.
        let sites = index.phi_uses(written).unwrap();
        assert_eq!(
            sites,
            [phi_site(4, phi_index, 1), phi_site(4, phi_index, 2)]
        );
        assert_eq!(edge(&ssa, sites[0]), Predecessor::Node(2));
        assert_eq!(edge(&ssa, sites[1]), Predecessor::Node(3));
        assert!(index.statement_uses(written).unwrap().is_empty());
        assert_eq!(index.use_count(written).unwrap(), 2);

        let sites = index.phi_uses(entry_x).unwrap();
        assert_eq!(sites, [phi_site(4, phi_index, 0)]);
        assert_eq!(edge(&ssa, sites[0]), Predecessor::Node(0));

        // One statement reading the same value twice: slots 0 and 2.
        assert_eq!(
            index.statement_uses(joined).unwrap(),
            [use_site(4, 0, 0), use_site(4, 0, 2)]
        );
        assert!(index.phi_uses(joined).unwrap().is_empty());

        assert_eq!(
            ssa.value(entry_y).unwrap().origin,
            ValueOrigin::Entry(UNDEF)
        );
        assert_eq!(index.statement_uses(entry_y).unwrap(), [use_site(4, 0, 1)]);
        assert_eq!(index.total_uses(), 6);
    }
}

#[test]
fn entry_self_loop_lists_the_virtual_entry_operand() {
    let program = RawProgram {
        variables: vec![UNDEF],
        blocks: vec![vec![stmt(&[0], &[0])]],
    };
    for mode in MODES {
        let ssa = build(1, &[(0, 0)], 0, &program, mode);
        let index = checked_index(&ssa);
        let entry = ssa.entry_value(v(0)).unwrap();
        let (phi_index, header) = phi_value(&ssa, 0, 0);
        let latch = def(&ssa, 0, 0, 0);

        let sites = index.phi_uses(entry).unwrap();
        assert_eq!(sites, [phi_site(0, phi_index, 0)]);
        assert_eq!(edge(&ssa, sites[0]), Predecessor::Entry);
        assert!(index.statement_uses(entry).unwrap().is_empty());

        let sites = index.phi_uses(latch).unwrap();
        assert_eq!(sites, [phi_site(0, phi_index, 1)]);
        assert_eq!(edge(&ssa, sites[0]), Predecessor::Node(0));

        // The phi feeds the statement that redefines it.
        assert_eq!(index.statement_uses(header).unwrap(), [use_site(0, 0, 0)]);
        assert_eq!(index.phi_uses(header).unwrap(), []);
    }
}

#[test]
fn entry_backedge_and_irreducible_cycle_match_their_edges() {
    // Entry backedge: 0 -> 1 -> 0, with x carried around and read in 0.
    let program = RawProgram {
        variables: vec![IN],
        blocks: vec![vec![stmt(&[0], &[])], vec![stmt(&[0], &[0])]],
    };
    for mode in MODES {
        let ssa = build(2, &[(0, 1), (1, 0)], 0, &program, mode);
        let index = checked_index(&ssa);
        let (phi_index, header) = phi_value(&ssa, 0, 0);
        let entry = ssa.entry_value(v(0)).unwrap();
        let back = def(&ssa, 1, 0, 0);
        assert_eq!(index.phi_uses(entry).unwrap(), [phi_site(0, phi_index, 0)]);
        assert_eq!(index.phi_uses(back).unwrap(), [phi_site(0, phi_index, 1)]);
        assert_eq!(
            edge(&ssa, index.phi_uses(back).unwrap()[0]),
            Predecessor::Node(1)
        );
        assert_eq!(
            index.statement_uses(header).unwrap(),
            [use_site(0, 0, 0), use_site(1, 0, 0)]
        );
    }

    // Irreducible cycle 1 <-> 2 entered from 0 at both nodes, exit 3.
    let edges = [(0, 1), (0, 2), (1, 2), (2, 1), (1, 3), (2, 3)];
    let program = RawProgram {
        variables: vec![IN],
        blocks: vec![
            vec![],
            vec![stmt(&[0], &[0])],
            vec![stmt(&[0], &[0])],
            vec![stmt(&[0], &[])],
        ],
    };
    for mode in MODES {
        let ssa = build(4, &edges, 0, &program, mode);
        let index = checked_index(&ssa);
        let entry = ssa.entry_value(v(0)).unwrap();
        let from_1 = def(&ssa, 1, 0, 0);
        let from_2 = def(&ssa, 2, 0, 0);
        // The entry value enters both cycle heads and nothing else.
        let sites = index.phi_uses(entry).unwrap();
        assert_eq!(sites.len(), 2);
        assert!(sites.iter().all(|&s| edge(&ssa, s) == Predecessor::Node(0)));
        assert_eq!(sites.iter().map(|s| s.phi.node).collect::<Vec<_>>(), [1, 2]);
        // Each definition flows to the other head and to the exit join.
        for (value, own, other) in [(from_1, 1, 2), (from_2, 2, 1)] {
            let sites = index.phi_uses(value).unwrap();
            let targets: Vec<_> = sites.iter().map(|&s| (s.phi.node, edge(&ssa, s))).collect();
            assert_eq!(
                targets,
                [
                    (other.min(3), Predecessor::Node(own)),
                    (other.max(3), Predecessor::Node(own))
                ]
            );
            assert!(index.statement_uses(value).unwrap().is_empty());
        }
    }
}

#[test]
fn unreachable_statements_and_predecessors_contribute_no_uses() {
    // 0 -> 1 is reachable; 2 -> 1 comes from unreachable 2; 3 is isolated.
    let program = RawProgram {
        variables: vec![IN],
        blocks: vec![
            vec![stmt(&[], &[0])],
            vec![stmt(&[0], &[])],
            vec![stmt(&[0, 0], &[0])],
            vec![stmt(&[0, 0, 0], &[])],
        ],
    };
    for mode in MODES {
        let ssa = build(4, &[(0, 1), (2, 1)], 0, &program, mode);
        let index = checked_index(&ssa);
        assert_eq!(ssa.phi_count(), 0);
        let written = def(&ssa, 0, 0, 0);
        assert_eq!(index.statement_uses(written).unwrap(), [use_site(1, 0, 0)]);
        assert_eq!(index.use_count(ssa.entry_value(v(0)).unwrap()).unwrap(), 0);
        assert_eq!(index.total_uses(), 1);
    }
}

#[test]
fn unpruned_dead_phis_are_unused_and_pruned_phis_are_not() {
    // Loop 0 -> 1 -> 1: i is carried; t is written before it is read.
    let program = RawProgram {
        variables: vec![IN, UNDEF],
        blocks: vec![
            vec![stmt(&[], &[0])],
            vec![stmt(&[0], &[0]), stmt(&[], &[1]), stmt(&[1], &[])],
        ],
    };
    let unpruned = build(2, &[(0, 1), (1, 1)], 0, &program, PhiPlacement::Unpruned);
    let pruned = build(2, &[(0, 1), (1, 1)], 0, &program, PhiPlacement::Pruned);
    let (u, p) = (checked_index(&unpruned), checked_index(&pruned));
    let entry_t = unpruned.entry_value(v(1)).unwrap();

    let (dead_index, dead) = phi_value(&unpruned, 1, 1);
    assert_eq!(u.use_count(dead).unwrap(), 0);
    // The dead phi still reads the undefined entry value and the latch def.
    assert_eq!(u.phi_uses(entry_t).unwrap(), [phi_site(1, dead_index, 0)]);
    assert_eq!(u.total_phi_uses(), 4);

    assert!(block(&pruned, 1).phi_for(v(1)).is_none());
    assert_eq!(p.use_count(entry_t).unwrap(), 0);
    assert_eq!(p.total_phi_uses(), 2);
    let (_, live) = phi_value(&pruned, 1, 0);
    assert_eq!(p.statement_uses(live).unwrap(), [use_site(1, 0, 0)]);
    assert_eq!(u.total_statement_uses(), p.total_statement_uses());
}

#[test]
fn invalid_lookups_are_errors_and_the_index_is_owned() {
    fn assert_owned<T: Send + Sync + Clone + 'static>(_: &T) {}

    let program = RawProgram {
        variables: vec![IN, IN],
        blocks: vec![vec![stmt(&[0, 1], &[1])]],
    };
    let ssa = build(1, &[], 0, &program, PhiPlacement::Pruned);
    let index = checked_index(&ssa);
    let count = ssa.values().len();
    drop(ssa);
    assert_owned(&index);
    assert_eq!(index.value_count(), 3);
    for bad in [ValueId(count), ValueId(usize::MAX)] {
        let error = DefUseError::InvalidValue {
            value: bad,
            value_count: count,
        };
        assert_eq!(index.statement_uses(bad), Err(error));
        assert_eq!(index.phi_uses(bad), Err(error));
        assert_eq!(index.use_count(bad), Err(error));
    }
    assert_eq!(
        index.statement_uses(ValueId(1)).unwrap(),
        [use_site(0, 0, 1)]
    );
    assert_eq!(index.use_count(ValueId(2)).unwrap(), 0);

    // No variables at all: no values, and every lookup is invalid.
    let empty = build(
        2,
        &[(0, 1)],
        0,
        &RawProgram {
            variables: vec![],
            blocks: vec![vec![RawStatement::default()], vec![]],
        },
        PhiPlacement::Unpruned,
    );
    let index = checked_index(&empty);
    assert_eq!((index.value_count(), index.total_uses()), (0, 0));
    assert!(index.statement_uses(ValueId(0)).is_err());
}

/// The diamond-with-two-latches case above, in a compact form for limits.
fn limits_case() -> Ssa {
    let edges = [(0, 1), (0, 4), (1, 2), (1, 3), (2, 4), (3, 4), (4, 0)];
    let program = RawProgram {
        variables: vec![IN, UNDEF],
        blocks: vec![
            vec![stmt(&[1], &[])],
            vec![stmt(&[], &[0])],
            vec![],
            vec![stmt(&[0], &[1])],
            vec![stmt(&[0, 1, 0], &[])],
        ],
    };
    build(5, &edges, 0, &program, PhiPlacement::Unpruned)
}

#[test]
fn every_limit_is_exact_and_failure_leaves_no_index() {
    let ssa = limits_case();
    let full = checked_index(&ssa);
    let exact = DefUseLimits {
        max_values: full.value_count(),
        max_uses: full.total_uses(),
        max_work: full.work(),
    };
    let at_limit = DefUseIndex::new(&ssa, exact).unwrap();
    assert_eq!(at_limit.limits(), exact);
    assert_eq!(
        (at_limit.work(), at_limit.total_uses()),
        (full.work(), full.total_uses())
    );
    let failure = |resource| Err(DefUseError::LimitExceeded { resource });
    let roomy = DefUseLimits {
        max_work: u64::MAX,
        ..exact
    };
    assert_eq!(
        DefUseIndex::new(
            &ssa,
            DefUseLimits {
                max_values: exact.max_values - 1,
                ..roomy
            }
        ),
        failure(DefUseResource::Values)
    );
    assert_eq!(
        DefUseIndex::new(
            &ssa,
            DefUseLimits {
                max_uses: exact.max_uses - 1,
                ..roomy
            }
        ),
        failure(DefUseResource::Uses)
    );
    assert_eq!(
        DefUseIndex::new(
            &ssa,
            DefUseLimits {
                max_work: exact.max_work - 1,
                ..exact
            }
        ),
        failure(DefUseResource::Work)
    );
    // Every smaller budget fails with the work error, never a partial index.
    for budget in 0..full.work() {
        let limits = DefUseLimits {
            max_work: budget,
            ..exact
        };
        assert_eq!(
            DefUseIndex::new(&ssa, limits),
            failure(DefUseResource::Work)
        );
    }
    // The value cap is checked before any work is charged.
    assert_eq!(
        DefUseIndex::new(
            &ssa,
            DefUseLimits {
                max_values: 0,
                max_uses: 0,
                max_work: 0
            }
        ),
        failure(DefUseResource::Values)
    );
}

/// `n`-node loop 0 -> 1 -> ... -> n-1 -> 1. Each node reads x twice into its
/// own temporary and writes x from it; variable 2 is a never-read input.
fn sparse_loop(n: usize) -> Ssa {
    let mut edges: Vec<_> = (0..n - 1).map(|i| (i, i + 1)).collect();
    edges.push((n - 1, 1));
    let program = RawProgram {
        variables: vec![IN, UNDEF, IN],
        blocks: (0..n)
            .map(|_| vec![stmt(&[0, 0], &[1]), stmt(&[1], &[0])])
            .collect(),
    };
    let graph = Arc::new(Graph::new(n, edges, GraphLimits::default()).unwrap());
    Ssa::construct_pruned(graph, 0, &program, ghidra_ssa::Limits::default()).unwrap()
}

#[test]
fn large_sparse_loop_indexes_in_linear_work() {
    let small = sparse_loop(50_000);
    let large = sparse_loop(100_000);
    let (a, b) = (checked_index(&small), checked_index(&large));
    assert_eq!(large.phi_count(), 1);
    assert_eq!(b.total_uses(), 3 * 100_000 + 2);
    // `V = 3 + 1 + 2N`, `S = 2N`, `U = 3N`, `P = 1`, `A = 2`.
    assert_eq!(
        b.work(),
        2 + 4 * (4 + 200_000) + 2 * 100_000 + 2 + 4 * 100_000 + 9 * 100_000 + 6
    );
    assert!(b.work() <= 2 * a.work());

    // Spot-check the far end: node k's temp is read once, at node k.
    let k = 99_999;
    let temp = def(&large, k, 0, 0);
    assert_eq!(b.statement_uses(temp).unwrap(), [use_site(k, 1, 0)]);
    let x = def(&large, k, 1, 0);
    let (phi_index, header) = phi_value(&large, 1, 0);
    let sites = b.phi_uses(x).unwrap();
    assert_eq!(sites, [phi_site(1, phi_index, 1)]);
    assert_eq!(edge(&large, sites[0]), Predecessor::Node(k));
    assert_eq!(
        b.statement_uses(header).unwrap(),
        [use_site(1, 0, 0), use_site(1, 0, 1)]
    );
    assert_eq!(b.use_count(large.entry_value(v(2)).unwrap()).unwrap(), 0);
}

struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 ^ (self.0 >> 29)
    }

    fn below(&mut self, bound: usize) -> usize {
        (self.next() % bound as u64) as usize
    }
}

/// Phi values reaching a statement read through phis, by a worklist over the
/// SSA operand lists (not the index).
fn useful_phis_by_operands(ssa: &Ssa) -> BTreeSet<usize> {
    let mut phi_of = vec![None; ssa.values().len()];
    let mut work = Vec::new();
    let mut useful = vec![false; ssa.values().len()];
    for node in 0..ssa.node_count() {
        let Some(b) = ssa.block(node).unwrap().renamed() else {
            continue;
        };
        for phi in b.phis() {
            phi_of[phi.value().0] = Some(phi.operands().to_vec());
        }
        for value in b.statements().iter().flat_map(|s| s.uses()) {
            if !useful[value.0] {
                useful[value.0] = true;
                work.push(value.0);
            }
        }
    }
    while let Some(value) = work.pop() {
        for operand in phi_of[value].iter().flatten() {
            if !useful[operand.0] {
                useful[operand.0] = true;
                work.push(operand.0);
            }
        }
    }
    (0..useful.len())
        .filter(|&x| useful[x] && phi_of[x].is_some())
        .collect()
}

/// The same set by round-robin over the index only: a value is useful if a
/// statement reads it or a useful phi has it as an operand.
fn useful_phis_by_index(ssa: &Ssa, index: &DefUseIndex) -> BTreeSet<usize> {
    let phi_value = |site: PhiOperandSite| ssa.phi(site.phi).unwrap().value().0;
    let count = index.value_count();
    let mut useful: Vec<bool> = (0..count)
        .map(|x| !index.statement_uses(ValueId(x)).unwrap().is_empty())
        .collect();
    let mut changed = true;
    while changed {
        changed = false;
        for x in 0..count {
            if !useful[x]
                && index
                    .phi_uses(ValueId(x))
                    .unwrap()
                    .iter()
                    .any(|&site| useful[phi_value(site)])
            {
                useful[x] = true;
                changed = true;
            }
        }
    }
    (0..count)
        .filter(|&x| useful[x] && matches!(ssa.values()[x].origin, ValueOrigin::Phi(_)))
        .collect()
}

#[test]
fn generated_programs_match_the_reference_in_both_modes() {
    let mut random = Random(0x5eed_d3f0);
    let (mut sites, mut dead_unpruned, mut entry_operands) = (0, 0, 0);
    for case in 0..1_500 {
        let n = 1 + random.below(8);
        let density = 1 + (case % 4) as u64;
        let mut edges = Vec::new();
        for a in 0..n {
            for b in 0..n {
                if random.next() % 8 < density {
                    edges.push((a, b));
                }
            }
        }
        let entry = random.below(n);
        let variable_count = 1 + random.below(4);
        let variables = (0..variable_count)
            .map(|_| {
                if random.next().is_multiple_of(2) {
                    IN
                } else {
                    UNDEF
                }
            })
            .collect();
        let blocks = (0..n)
            .map(|_| {
                (0..random.below(4))
                    .map(|_| {
                        let uses = (0..random.below(4))
                            .map(|_| v(random.below(variable_count)))
                            .collect();
                        let defs = (0..variable_count)
                            .filter(|_| random.next().is_multiple_of(3))
                            .map(v)
                            .collect();
                        RawStatement { uses, defs }
                    })
                    .collect()
            })
            .collect();
        let program = RawProgram { variables, blocks };
        for mode in MODES {
            let ssa = build(n, &edges, entry, &program, mode);
            let index = checked_index(&ssa);
            sites += index.total_uses();
            let useful = useful_phis_by_operands(&ssa);
            assert_eq!(useful, useful_phis_by_index(&ssa, &index));
            let phis = ssa.phi_count();
            if mode == PhiPlacement::Pruned {
                // A pruned phi is live, so some read observes it through phis.
                assert_eq!(useful.len(), phis, "case {case}");
            } else {
                dead_unpruned += phis - useful.len();
            }
            if let Some(b) = ssa.block(entry).unwrap().renamed() {
                entry_operands += b.phis().len();
            }
        }
    }
    // The corpus exercises dead phis and virtual entry operands.
    assert!(sites > 40_000, "{sites}");
    assert!(dead_unpruned > 1_000, "{dead_unpruned}");
    assert!(entry_operands > 1_500, "{entry_operands}");
}
