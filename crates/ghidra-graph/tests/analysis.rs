use ghidra_graph::{
    Error, Graph, ImmediateDominator as Id, Limits, NaturalLoop, PostDominator as Pd, Resource,
};

fn graph(n: usize, edges: &[(usize, usize)]) -> Graph {
    Graph::new(n, edges.iter().copied(), Limits::default()).unwrap()
}

#[test]
fn diamond_and_disconnected_nodes() {
    let g = graph(6, &[(0, 1), (0, 2), (1, 3), (2, 3), (4, 3), (4, 5), (5, 4)]);
    let traversal = g.traversal(0).unwrap();
    assert_eq!(traversal.preorder, [0, 1, 3, 2]);
    assert_eq!(traversal.postorder, [3, 1, 2, 0]);
    assert_eq!(traversal.reverse_postorder, [0, 2, 1, 3]);
    assert_eq!(traversal.reachable, [true, true, true, true, false, false]);
    let dom = g.dominators(0).unwrap();
    assert_eq!(dom.entry(), 0);
    assert_eq!(dom.immediate_dominator(0).unwrap(), Id::Root);
    for node in 1..4 {
        assert_eq!(dom.immediate_dominator(node).unwrap(), Id::Parent(0));
    }
    for node in 4..6 {
        assert_eq!(dom.immediate_dominator(node).unwrap(), Id::Unreachable);
        assert!(!dom.dominates(node, node).unwrap());
    }
    assert_eq!(
        dom.frontiers().unwrap(),
        [vec![], vec![3], vec![3], vec![], vec![], vec![]]
    );
    assert!(dom.natural_loops().unwrap().is_empty());
    let scc = g.strongly_connected_components().unwrap();
    assert_eq!(
        scc.components,
        [vec![0], vec![1], vec![2], vec![3], vec![4, 5]]
    );
    assert_eq!(scc.component_of, [0, 1, 2, 3, 4, 4]);
}

#[test]
fn nested_loops_and_multiple_latches() {
    // 1 is the outer header; 2 is the inner header. 6 is an unreachable
    // predecessor of a latch and must not leak into either loop body.
    let g = graph(
        7,
        &[
            (0, 1),
            (1, 2),
            (2, 3),
            (3, 2),
            (2, 4),
            (4, 1),
            (3, 1),
            (1, 5),
            (6, 3),
        ],
    );
    let dom = g.dominators(0).unwrap();
    assert_eq!(
        dom.natural_loops().unwrap(),
        [
            NaturalLoop {
                header: 1,
                latches: vec![3, 4],
                body: vec![1, 2, 3, 4]
            },
            NaturalLoop {
                header: 2,
                latches: vec![3],
                body: vec![2, 3]
            },
        ]
    );
    let df = dom.frontiers().unwrap();
    assert_eq!(df[1], [1]);
    assert_eq!(df[2], [1, 2]);
    assert_eq!(df[3], [1, 2]);
    assert_eq!(df[4], [1]);
    assert_eq!(df[6], []);
}

#[test]
fn self_loops_do_not_absorb_header_predecessors() {
    let g = graph(4, &[(0, 0), (0, 1), (1, 2), (2, 2), (2, 3)]);
    let dom = g.dominators(0).unwrap();
    assert_eq!(
        dom.natural_loops().unwrap(),
        [
            NaturalLoop {
                header: 0,
                latches: vec![0],
                body: vec![0]
            },
            NaturalLoop {
                header: 2,
                latches: vec![2],
                body: vec![2]
            },
        ]
    );
    assert_eq!(dom.frontiers().unwrap(), [vec![0], vec![], vec![2], vec![]]);
    let mixed = graph(3, &[(0, 1), (1, 1), (1, 2), (2, 1)]);
    assert_eq!(
        mixed.dominators(0).unwrap().natural_loops().unwrap(),
        [NaturalLoop {
            header: 1,
            latches: vec![1, 2],
            body: vec![1, 2]
        },]
    );
}

#[test]
fn irreducible_cycle_has_scc_but_no_dominated_backedge() {
    let g = graph(4, &[(0, 1), (0, 2), (1, 2), (2, 1), (1, 3), (2, 3)]);
    let dom = g.dominators(0).unwrap();
    for node in 1..4 {
        assert_eq!(dom.immediate_dominator(node).unwrap(), Id::Parent(0));
    }
    assert_eq!(
        g.strongly_connected_components().unwrap().components,
        [vec![0], vec![1, 2], vec![3]]
    );
    assert!(dom.natural_loops().unwrap().is_empty());
    assert_eq!(
        dom.frontiers().unwrap(),
        [vec![], vec![2, 3], vec![1, 3], vec![]]
    );
}

#[test]
fn explicit_exits_nontermination_and_terminalization() {
    // From 0, either terminate at 2/3 or enter the nonterminating SCC 4/5.
    let g = graph(7, &[(0, 1), (1, 2), (1, 3), (0, 4), (4, 5), (5, 4), (2, 6)]);
    let post = g.post_dominators([3, 2, 3]).unwrap();
    assert_eq!(post.exits(), [2, 3]);
    assert_eq!(post.immediate_post_dominator(0).unwrap(), Pd::Node(1));
    for node in [1, 2, 3] {
        assert_eq!(
            post.immediate_post_dominator(node).unwrap(),
            Pd::SyntheticExit
        );
    }
    for node in [4, 5, 6] {
        assert_eq!(
            post.immediate_post_dominator(node).unwrap(),
            Pd::Unreachable
        );
        assert!(!post.can_reach_exit(node).unwrap());
        assert!(!post.post_dominates(node, node).unwrap());
        assert!(!post.post_dominates(1, node).unwrap());
    }
    assert!(post.post_dominates(1, 0).unwrap());
    assert!(!post.post_dominates(2, 0).unwrap());
    let single = g.post_dominators([2]).unwrap();
    assert_eq!(single.immediate_post_dominator(1).unwrap(), Pd::Node(2));
    assert_eq!(
        single.immediate_post_dominator(2).unwrap(),
        Pd::SyntheticExit
    );
    assert!(!single.can_reach_exit(3).unwrap());
    for node in g.nodes() {
        assert_eq!(
            g.post_dominators([])
                .unwrap()
                .immediate_post_dominator(node)
                .unwrap(),
            Pd::Unreachable
        );
    }
    let cycle = graph(2, &[(0, 1), (1, 0)]);
    assert_eq!(
        cycle
            .post_dominators([1])
            .unwrap()
            .immediate_post_dominator(0)
            .unwrap(),
        Pd::Node(1)
    );
    let isolated = Graph::new(
        1,
        [],
        Limits {
            max_edges: 0,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_eq!(
        isolated
            .post_dominators([0])
            .unwrap()
            .immediate_post_dominator(0)
            .unwrap(),
        Pd::SyntheticExit
    );
}

#[test]
fn canonical_duplicate_treatment_and_input_order() {
    let a = graph(4, &[(2, 3), (0, 2), (0, 1), (1, 3), (0, 2), (3, 3)]);
    let b = graph(4, &[(3, 3), (1, 3), (0, 1), (0, 2), (2, 3)]);
    assert_eq!(a.edge_count(), 5);
    assert_eq!(a.successors(0).unwrap(), [1, 2]);
    assert_eq!(a.predecessors(3).unwrap(), [1, 2, 3]);
    assert_eq!(a.traversal(0).unwrap(), b.traversal(0).unwrap());
    assert_eq!(
        a.strongly_connected_components().unwrap(),
        b.strongly_connected_components().unwrap()
    );
    let da = a.dominators(0).unwrap();
    let db = b.dominators(0).unwrap();
    assert_eq!(da.frontiers().unwrap(), db.frontiers().unwrap());
    assert_eq!(da.natural_loops().unwrap(), db.natural_loops().unwrap());
    for node in a.nodes() {
        assert_eq!(
            da.immediate_dominator(node).unwrap(),
            db.immediate_dominator(node).unwrap()
        );
    }
}

fn limit_error<T: std::fmt::Debug>(result: ghidra_graph::Result<T>, resource: Resource) {
    assert_eq!(result.unwrap_err(), Error::LimitExceeded { resource });
}

#[test]
fn malformed_nodes_and_empty_graph() {
    let empty = graph(0, &[]);
    assert!(
        empty
            .strongly_connected_components()
            .unwrap()
            .components
            .is_empty()
    );
    assert_eq!(empty.post_dominators([]).unwrap().exits(), []);
    assert!(matches!(empty.traversal(0), Err(Error::InvalidNode { .. })));
    assert!(matches!(
        Graph::new(2, [(0, 2)], Limits::default()),
        Err(Error::InvalidNode {
            node: 2,
            node_count: 2
        })
    ));
    assert!(matches!(
        Graph::new(2, [(usize::MAX, 0)], Limits::default()),
        Err(Error::InvalidNode { .. })
    ));
    let g = graph(2, &[(0, 1)]);
    assert!(g.successors(2).is_err());
    assert!(g.predecessors(2).is_err());
    assert!(g.dominators(2).is_err());
    assert!(g.post_dominators([2]).is_err());
    let dom = g.dominators(0).unwrap();
    assert!(dom.immediate_dominator(2).is_err());
    assert!(dom.dominates(2, 0).is_err());
    assert!(dom.dominates(0, 2).is_err());
    let post = g.post_dominators([1]).unwrap();
    assert!(post.immediate_post_dominator(2).is_err());
    assert!(post.can_reach_exit(2).is_err());
    assert!(post.post_dominates(2, 0).is_err());
    assert!(post.post_dominates(0, 2).is_err());
}

#[test]
fn node_edge_and_materialization_limits() {
    limit_error(
        Graph::new(
            3,
            [],
            Limits {
                max_nodes: 2,
                ..Limits::default()
            },
        ),
        Resource::Nodes,
    );
    limit_error(
        Graph::new(
            2,
            [(0, 1), (0, 1)],
            Limits {
                max_edges: 1,
                ..Limits::default()
            },
        ),
        Resource::Edges,
    );
    // Even an infinite duplicate iterator is stopped by the input-record limit.
    limit_error(
        Graph::new(
            1,
            std::iter::repeat((0, 0)),
            Limits {
                max_edges: 8,
                ..Limits::default()
            },
        ),
        Resource::Edges,
    );
    let g = graph(1, &[]);
    limit_error(
        g.post_dominators(std::iter::repeat(0)).map(|_| ()),
        Resource::Nodes,
    );
    let edges = [(0, 1), (0, 2), (1, 3), (2, 3)];
    let g = Graph::new(
        4,
        edges,
        Limits {
            max_frontier_entries: 1,
            ..Limits::default()
        },
    )
    .unwrap();
    limit_error(
        g.dominators(0).unwrap().frontiers(),
        Resource::FrontierEntries,
    );
    let g = Graph::new(
        4,
        edges,
        Limits {
            max_frontier_entries: 2,
            ..Limits::default()
        },
    )
    .unwrap();
    assert!(g.dominators(0).unwrap().frontiers().is_ok());
    let g = Graph::new(
        1,
        [(0, 0)],
        Limits {
            max_loop_entries: 1,
            ..Limits::default()
        },
    )
    .unwrap();
    limit_error(
        g.dominators(0).unwrap().natural_loops(),
        Resource::LoopEntries,
    );
    let g = Graph::new(
        1,
        [(0, 0)],
        Limits {
            max_loop_entries: 2,
            ..Limits::default()
        },
    )
    .unwrap();
    assert_eq!(
        g.dominators(0).unwrap().natural_loops().unwrap()[0].body,
        [0]
    );
}

#[test]
fn work_exhaustion_is_an_error_in_every_analysis() {
    limit_error(
        Graph::new(
            1,
            [],
            Limits {
                max_work: 0,
                ..Limits::default()
            },
        ),
        Resource::Work,
    );
    let g = Graph::new(
        1,
        [],
        Limits {
            max_work: 2,
            ..Limits::default()
        },
    )
    .unwrap();
    limit_error(g.traversal(0), Resource::Work);
    limit_error(g.strongly_connected_components(), Resource::Work);
    limit_error(g.dominators(0).map(|_| ()), Resource::Work);
    limit_error(g.post_dominators([0]).map(|_| ()), Resource::Work);
    // Find budgets where dominance succeeds but materialization fails. Do not
    // confuse failure in dominance setup with failure in a dependent analysis.
    let n = 24;
    let mut edges: Vec<_> = (0..n - 1).map(|v| (v, v + 1)).collect();
    edges.extend((0..n).map(|v| (n - 1, v)));
    let mut failed = [false; 2];
    for max_work in 0..10_000 {
        let Ok(g) = Graph::new(
            n,
            edges.iter().copied(),
            Limits {
                max_work,
                ..Limits::default()
            },
        ) else {
            continue;
        };
        let Ok(dom) = g.dominators(0) else {
            continue;
        };
        let results = [dom.frontiers().map(|_| ()), dom.natural_loops().map(|_| ())];
        for (index, result) in results.into_iter().enumerate() {
            if let Err(error) = result {
                assert_eq!(
                    error,
                    Error::LimitExceeded {
                        resource: Resource::Work
                    }
                );
                failed[index] = true;
            }
        }
        if failed.iter().all(|&v| v) {
            break;
        }
    }
    assert!(
        failed.iter().all(|&v| v),
        "materialization failures: {failed:?}"
    );
}

// Independent slow oracle: remove a candidate vertex and test reachability.
// It does not use semidominators, DFS numbering, or dominator tree construction.
fn reachable(n: usize, edges: &[(usize, usize)], root: usize, removed: Option<usize>) -> Vec<bool> {
    let mut reached = vec![false; n];
    if removed == Some(root) {
        return reached;
    }
    reached[root] = true;
    let mut changed = true;
    while changed {
        changed = false;
        for &(from, to) in edges {
            if reached[from] && !reached[to] && removed != Some(to) {
                reached[to] = true;
                changed = true;
            }
        }
    }
    reached
}

fn slow_dominance(n: usize, edges: &[(usize, usize)], root: usize) -> (Vec<bool>, Vec<Vec<bool>>) {
    let base = reachable(n, edges, root, None);
    let mut dominance = vec![vec![false; n]; n];
    for (a, row) in dominance.iter_mut().enumerate() {
        let without = reachable(n, edges, root, Some(a));
        for b in 0..n {
            row[b] = base[b] && !without[b];
        }
    }
    (base, dominance)
}

fn slow_parent(node: usize, root: usize, reached: &[bool], dom: &[Vec<bool>]) -> Id {
    if !reached[node] {
        return Id::Unreachable;
    }
    if node == root {
        return Id::Root;
    }
    let strict: Vec<_> = (0..reached.len())
        .filter(|&a| a != node && dom[a][node])
        .collect();
    let parents: Vec<_> = strict
        .iter()
        .copied()
        .filter(|&a| strict.iter().all(|&b| a == b || dom[b][a]))
        .collect();
    assert_eq!(parents.len(), 1);
    Id::Parent(parents[0])
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
}

#[test]
fn generated_dominance_frontiers_sccs_and_postdominance_match_oracles() {
    let mut random = Random(0x5eeda11);
    for case in 0..1_600 {
        let n = 1 + (random.next() % 9) as usize;
        let mut edges = Vec::new();
        let density = (case % 5) as u64;
        for a in 0..n {
            for b in 0..n {
                if random.next() % 6 < density {
                    edges.push((a, b));
                }
            }
        }
        let entry = (random.next() % n as u64) as usize;
        let g = graph(n, &edges);
        let actual = g.dominators(entry).unwrap();
        let (reached, expected) = slow_dominance(n, &edges, entry);
        assert_eq!(g.traversal(entry).unwrap().reachable, reached);
        let frontiers = actual.frontiers().unwrap();
        for a in 0..n {
            assert_eq!(
                actual.immediate_dominator(a).unwrap(),
                slow_parent(a, entry, &reached, &expected),
                "case {case}, node {a}, edges {edges:?}"
            );
            let mut frontier = Vec::new();
            for b in 0..n {
                assert_eq!(
                    actual.dominates(a, b).unwrap(),
                    expected[a][b],
                    "case {case}, ({a}, {b})"
                );
                if reached[b]
                    && (a == b || !expected[a][b])
                    && edges
                        .iter()
                        .any(|&(p, to)| to == b && reached[p] && expected[a][p])
                {
                    frontier.push(b);
                }
            }
            assert_eq!(
                frontiers[a], frontier,
                "case {case}, frontier {a}, edges {edges:?}"
            );
        }
        // Definition-based loop oracle: a body member can reach a latch without
        // passing through the header. This deliberately does repeated whole-graph
        // reachability, without loop contraction or reverse predecessor walks.
        let mut expected_loops = Vec::new();
        for (header, dominated) in expected.iter().enumerate() {
            let latches: Vec<_> = (0..n)
                .filter(|&tail| dominated[tail] && edges.contains(&(tail, header)))
                .collect();
            if latches.is_empty() {
                continue;
            }
            let body: Vec<_> = (0..n)
                .filter(|&node| {
                    if node == header {
                        return true;
                    }
                    if !reached[node] {
                        return false;
                    }
                    let path = reachable(n, &edges, node, Some(header));
                    latches.iter().any(|&latch| path[latch])
                })
                .collect();
            expected_loops.push(NaturalLoop {
                header,
                latches,
                body,
            });
        }
        assert_eq!(
            actual.natural_loops().unwrap(),
            expected_loops,
            "case {case}, loops, edges {edges:?}"
        );
        let scc = g.strongly_connected_components().unwrap();
        let reach: Vec<_> = (0..n)
            .map(|root| reachable(n, &edges, root, None))
            .collect();
        for (a, from_a) in reach.iter().enumerate() {
            for (b, from_b) in reach.iter().enumerate() {
                assert_eq!(
                    scc.component_of[a] == scc.component_of[b],
                    from_a[b] && from_b[a]
                );
            }
        }
        let exits: Vec<_> = (0..n).filter(|_| random.next().is_multiple_of(3)).collect();
        let post = g.post_dominators(exits.iter().copied()).unwrap();
        let mut reverse: Vec<_> = edges
            .iter()
            .filter(|(a, _)| !exits.contains(a))
            .map(|&(a, b)| (b, a))
            .collect();
        reverse.extend(exits.iter().map(|&exit| (n, exit)));
        let (can_exit, post_expected) = slow_dominance(n + 1, &reverse, n);
        for a in 0..n {
            assert_eq!(post.can_reach_exit(a).unwrap(), can_exit[a]);
            let parent = match slow_parent(a, n, &can_exit, &post_expected) {
                Id::Unreachable => Pd::Unreachable,
                Id::Parent(p) if p == n => Pd::SyntheticExit,
                Id::Parent(p) => Pd::Node(p),
                Id::Root => unreachable!(),
            };
            assert_eq!(post.immediate_post_dominator(a).unwrap(), parent);
            for (b, &expected) in post_expected[a].iter().take(n).enumerate() {
                assert_eq!(post.post_dominates(a, b).unwrap(), expected);
            }
        }
    }
}

#[test]
fn dense_nested_loops_contract_inner_edges_with_bounded_work() {
    let n = 192;
    let mut edges: Vec<_> = (1..n).map(|v| (v - 1, v)).collect();
    for tail in 1..n {
        edges.extend((0..tail).map(|head| (tail, head)));
    }
    let g = Graph::new(
        n,
        edges,
        Limits {
            max_work: 500_000,
            ..Limits::default()
        },
    )
    .unwrap();
    let dom = g.dominators(0).unwrap();
    let loops = dom.natural_loops().unwrap();
    assert_eq!(loops.len(), n - 1);
    for natural_loop in loops {
        assert_eq!(
            natural_loop.body,
            (natural_loop.header..n).collect::<Vec<_>>()
        );
        assert_eq!(
            natural_loop.latches,
            (natural_loop.header + 1..n).collect::<Vec<_>>()
        );
    }
}

#[test]
fn long_chain_is_stack_safe_and_has_linear_size_results() {
    let n = 100_000;
    let g = Graph::new(n, (1..n).map(|v| (v - 1, v)), Limits::default()).unwrap();
    assert_eq!(g.traversal(0).unwrap().preorder.len(), n);
    assert_eq!(
        g.strongly_connected_components().unwrap().components.len(),
        n
    );
    let dom = g.dominators(0).unwrap();
    assert_eq!(dom.immediate_dominator(n - 1).unwrap(), Id::Parent(n - 2));
    assert!(dom.dominates(0, n - 1).unwrap());
    assert!(!dom.dominates(n - 1, 0).unwrap());
    assert!(dom.frontiers().unwrap().iter().all(Vec::is_empty));
    assert!(dom.natural_loops().unwrap().is_empty());
    let post = g.post_dominators([n - 1]).unwrap();
    assert_eq!(post.immediate_post_dominator(0).unwrap(), Pd::Node(1));
    assert!(post.post_dominates(n - 1, 0).unwrap());
}
