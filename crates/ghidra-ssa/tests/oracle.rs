//! Independent behavioral oracle. Random small CFGs and raw programs are
//! executed along bounded entry paths twice: once with raw variable
//! assignments, once with the renamed SSA program, where each block entry
//! first assigns all phis simultaneously from the operand selected by the
//! incoming edge. Every use must observe the same dynamic definition event.
//! The oracle uses no dominance, frontier, or renaming logic.

use std::sync::Arc;

use ghidra_graph::{Graph, Limits as GraphLimits};
use ghidra_ssa::{
    EntryState, Limits, Predecessor, RawProgram, RawStatement, Ssa, ValueOrigin, VariableId,
};

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

/// What a variable holds at runtime: its entry state or one executed def slot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Token {
    Entry(usize),
    Event(u64),
}

fn random_case(
    random: &mut Random,
    case: usize,
) -> (usize, Vec<(usize, usize)>, usize, RawProgram) {
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
                EntryState::Input
            } else {
                EntryState::Undefined
            }
        })
        .collect();
    let blocks = (0..n)
        .map(|_| {
            (0..random.below(4))
                .map(|_| {
                    let uses = (0..random.below(4))
                        .map(|_| VariableId(random.below(variable_count)))
                        .collect();
                    let mut defs = Vec::new();
                    for x in 0..variable_count {
                        if random.next().is_multiple_of(3) {
                            defs.push(VariableId(x));
                        }
                    }
                    // Shuffle so def order differs from variable order.
                    for i in (1..defs.len()).rev() {
                        defs.swap(i, random.below(i + 1));
                    }
                    RawStatement { uses, defs }
                })
                .collect()
        })
        .collect();
    (n, edges, entry, RawProgram { variables, blocks })
}

/// Execute one path from the entry with both semantics; returns uses checked.
fn execute(ssa: &Ssa, program: &RawProgram, path: &[usize]) -> usize {
    let variable_count = program.variables.len();
    let mut raw: Vec<Token> = (0..variable_count).map(Token::Entry).collect();
    let mut env: Vec<Option<Token>> = vec![None; ssa.values().len()];
    for x in 0..variable_count {
        let value = ssa.entry_value(VariableId(x)).unwrap();
        assert_eq!(
            ssa.value(value).unwrap().origin,
            ValueOrigin::Entry(program.variables[x])
        );
        env[value.0] = Some(Token::Entry(x));
    }
    let mut events = 0u64;
    let mut checked = 0;
    let mut previous = None;
    for &node in path {
        let block = ssa
            .block(node)
            .unwrap()
            .renamed()
            .expect("an executed node is reachable");
        let incoming = previous.map_or(Predecessor::Entry, Predecessor::Node);
        let slot = block
            .incoming_index(incoming)
            .unwrap_or_else(|| panic!("edge {incoming:?} -> {node} has no slot"));
        // Read every selected operand before assigning any phi.
        let selected: Vec<_> = block
            .phis()
            .iter()
            .map(|phi| {
                let operand = phi.operands()[slot];
                assert_eq!(ssa.value(operand).unwrap().variable, phi.variable());
                env[operand.0].expect("phi operand defined on this path")
            })
            .collect();
        for (phi, token) in block.phis().iter().zip(selected) {
            env[phi.value().0] = Some(token);
        }
        // A phi must also agree with the raw state at block entry.
        for phi in block.phis() {
            assert_eq!(
                env[phi.value().0],
                Some(raw[phi.variable().0]),
                "stale phi of {:?} in node {node}, path {path:?}",
                phi.variable()
            );
        }
        for (raw_statement, renamed) in program.blocks[node].iter().zip(block.statements()) {
            for (&variable, &value) in raw_statement.uses.iter().zip(renamed.uses()) {
                assert_eq!(ssa.value(value).unwrap().variable, variable);
                assert_eq!(
                    env[value.0],
                    Some(raw[variable.0]),
                    "stale use of {variable:?} in node {node}, path {path:?}"
                );
                checked += 1;
            }
            for (&variable, &value) in raw_statement.defs.iter().zip(renamed.defs()) {
                events += 1;
                raw[variable.0] = Token::Event(events);
                env[value.0] = Some(Token::Event(events));
            }
        }
        previous = Some(node);
    }
    checked
}

#[test]
fn generated_programs_match_raw_execution_on_bounded_paths() {
    let mut random = Random(0x55a_0bac1e);
    let mut checked = 0;
    let mut phis = 0;
    let mut entry_phis = 0;
    for case in 0..3_000 {
        let (n, edges, entry, program) = random_case(&mut random, case);
        let graph = Arc::new(Graph::new(n, edges.iter().copied(), GraphLimits::default()).unwrap());
        let ssa = Ssa::construct(Arc::clone(&graph), entry, &program, Limits::default()).unwrap();
        ssa.verify(&program).unwrap();
        phis += ssa.phi_count();
        entry_phis += ssa.block(entry).unwrap().renamed().unwrap().phis().len();
        // Reachability is independent: flood fill along raw edges.
        let mut reached = vec![false; n];
        reached[entry] = true;
        let mut changed = true;
        while changed {
            changed = false;
            for &(a, b) in &edges {
                if reached[a] && !reached[b] {
                    reached[b] = true;
                    changed = true;
                }
            }
        }
        for (node, &reached) in reached.iter().enumerate() {
            assert_eq!(ssa.is_reachable(node).unwrap(), reached);
            if !reached {
                assert!(ssa.values().iter().all(|value| match value.origin {
                    ValueOrigin::Definition(site) => site.statement.node != node,
                    ValueOrigin::Phi(phi) => phi.node != node,
                    ValueOrigin::Entry(_) => true,
                }));
            }
        }
        for _ in 0..24 {
            let mut path = vec![entry];
            for _ in 0..random.below(16) {
                let last = *path.last().unwrap();
                let successors = graph.successors(last).unwrap();
                if successors.is_empty() {
                    break;
                }
                path.push(successors[random.below(successors.len())]);
            }
            checked += execute(&ssa, &program, &path);
        }
    }
    // The generator must exercise phis, entry phis, and many uses.
    assert!(phis > 5_000, "phis {phis}");
    assert!(entry_phis > 1_000, "entry phis {entry_phis}");
    assert!(checked > 400_000, "checked {checked}");
}

#[test]
fn exhaustive_short_paths_on_an_irreducible_entry_loop() {
    // Entry 0 is a loop header, 1 <-> 2 is irreducible, 3 has a self-loop.
    let edges = [
        (0, 1),
        (0, 2),
        (1, 2),
        (2, 1),
        (1, 0),
        (2, 3),
        (3, 3),
        (3, 0),
        (4, 1),
    ];
    let program = RawProgram {
        variables: vec![
            EntryState::Undefined,
            EntryState::Input,
            EntryState::Undefined,
        ],
        blocks: vec![
            vec![RawStatement::new(
                [VariableId(0), VariableId(1)],
                [VariableId(2)],
            )],
            vec![RawStatement::new(
                [VariableId(2)],
                [VariableId(0), VariableId(1)],
            )],
            vec![RawStatement::new(
                [VariableId(1), VariableId(0)],
                [VariableId(1), VariableId(0)],
            )],
            vec![
                RawStatement::new([VariableId(0), VariableId(2)], []),
                RawStatement::new([], [VariableId(2)]),
            ],
            vec![RawStatement::new([], [VariableId(0)])],
        ],
    };
    let graph = Arc::new(Graph::new(5, edges, GraphLimits::default()).unwrap());
    let ssa = Ssa::construct(Arc::clone(&graph), 0, &program, Limits::default()).unwrap();
    ssa.verify(&program).unwrap();
    // Every path of up to 13 nodes, depth-first without recursion.
    let mut paths = 0;
    let mut stack = vec![vec![0]];
    while let Some(path) = stack.pop() {
        execute(&ssa, &program, &path);
        paths += 1;
        if path.len() < 13 {
            for &next in graph.successors(*path.last().unwrap()).unwrap() {
                let mut longer = path.clone();
                longer.push(next);
                stack.push(longer);
            }
        }
    }
    assert!(paths > 5_000, "paths {paths}");
}

#[test]
#[should_panic(expected = "stale phi")]
fn oracle_is_not_vacuous() {
    // SSA built where only node 1 writes x, then executed against a raw
    // program of the same shape in which node 2 writes x instead of y.
    let x = VariableId(0);
    let y = VariableId(1);
    let built = RawProgram {
        variables: vec![EntryState::Input, EntryState::Input],
        blocks: vec![
            vec![],
            vec![RawStatement::new([], [x])],
            vec![RawStatement::new([], [y])],
            vec![RawStatement::new([x], [])],
        ],
    };
    let mut executed = built.clone();
    executed.blocks[2][0].defs[0] = x;
    let graph =
        Arc::new(Graph::new(4, [(0, 1), (0, 2), (1, 3), (2, 3)], GraphLimits::default()).unwrap());
    let ssa = Ssa::construct(graph, 0, &built, Limits::default()).unwrap();
    execute(&ssa, &built, &[0, 2, 3]);
    execute(&ssa, &executed, &[0, 2, 3]);
}
