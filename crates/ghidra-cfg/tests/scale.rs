mod common;

use common::*;
use ghidra_cfg::{Cfg, CfgError, CfgInput, EdgeRole, ExitKind, Limits, Resource};
use ghidra_graph::{ImmediateDominator, PostDominator};
use ghidra_pcode::{Opcode, PcodeInstruction, SpaceId};

/// Every observable result except the supplied-order instruction slice.
fn fingerprint(cfg: &Cfg) -> String {
    let blocks: Vec<_> = (0..cfg.block_count())
        .map(|node| cfg.block_points(node).unwrap().to_vec())
        .collect();
    let incoming: Vec<_> = (0..cfg.node_count())
        .map(|node| cfg.in_edges(node).unwrap().to_vec())
        .collect();
    let successors: Vec<_> = cfg
        .graph()
        .nodes()
        .map(|node| cfg.graph().successors(node).unwrap().to_vec())
        .collect();
    let canonical: Vec<_> = cfg.canonical_instructions().cloned().collect();
    format!(
        "{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{:?}|{}|{}",
        cfg.points(),
        blocks,
        cfg.edges(),
        incoming,
        cfg.exits(),
        cfg.calls(),
        cfg.userops(),
        cfg.gaps(),
        successors,
        canonical,
        cfg.entry(),
        cfg.build_work(),
    )
}

fn mixed_program() -> Vec<PcodeInstruction> {
    vec![
        ins(0x1000, 2, vec![]),
        ins(
            0x1002,
            2,
            vec![set_flag(0), cbranch(rel(2), flag(0)), set_flag(1)],
        ),
        ins(
            0x1004,
            4,
            vec![
                call(ram(0x1010)),
                op(Opcode::Callother, None, vec![c(3, 4)]),
            ],
        ),
        ins(
            0x1008,
            4,
            vec![cbranch(ram(0x1002), flag(0)), branch(rel(1))],
        ),
        ins(0x100C, 2, vec![op(Opcode::Branchind, None, vec![reg(0)])]),
        ins(0x1010, 4, vec![op(Opcode::Unimplemented, None, vec![])]),
        ins(0x1018, 4, vec![cbranch(ram(0x5000), flag(1)), set_flag(2)]),
        ins(0x101C, 4, vec![ret(reg(0))]),
    ]
}

#[test]
fn results_are_independent_of_input_instruction_order() {
    let program = mixed_program();
    let expected = fingerprint(&build(0x1000, program.clone()));
    let mut reversed = program.clone();
    reversed.reverse();
    let mut rotated = program.clone();
    rotated.rotate_left(3);
    let mut shuffled = program.clone();
    let mut state = 0x9E37_79B9_7F4A_7C15_u64;
    for index in (1..shuffled.len()).rev() {
        state = state
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        shuffled.swap(index, (state >> 33) as usize % (index + 1));
    }
    for order in [reversed, rotated, shuffled] {
        let cfg = build(0x1000, order.clone());
        assert_eq!(fingerprint(&cfg), expected);
        assert_eq!(cfg.instructions(), &order[..], "supplied data is unchanged");
    }
}

#[test]
fn long_branch_chain_is_stack_safe_through_graph_analyses() {
    const COUNT: u64 = 100_000;
    let mut program: Vec<_> = (0..COUNT)
        .map(|index| {
            let address = 0x10_0000 + index * 4;
            ins(address, 4, vec![set_flag(0), branch(ram(address + 4))])
        })
        .collect();
    program.push(ins(0x10_0000 + COUNT * 4, 4, vec![ret(reg(0))]));
    program.reverse();
    let cfg = build(0x10_0000, program);
    assert_eq!(cfg.block_count(), COUNT as usize + 1);
    assert_eq!(cfg.exit_count(), 1);
    assert!(
        cfg.edges()
            .iter()
            .take(COUNT as usize)
            .all(|edge| edge.role == EdgeRole::Branch && edge.to == edge.from + 1)
    );
    let graph = cfg.graph();
    let last = cfg.node_count() - 1;
    let dominators = graph.dominators(cfg.entry()).unwrap();
    assert_eq!(
        dominators.immediate_dominator(last).unwrap(),
        ImmediateDominator::Parent(last - 1)
    );
    assert!(dominators.natural_loops().unwrap().is_empty());
    let post = graph.post_dominators(cfg.exit_nodes()).unwrap();
    assert_eq!(
        post.immediate_post_dominator(0).unwrap(),
        PostDominator::Node(1)
    );
    assert_eq!(
        graph.traversal(cfg.entry()).unwrap().postorder.len(),
        cfg.node_count()
    );
}

#[test]
fn long_straight_line_input_forms_one_block() {
    const COUNT: u64 = 100_000;
    let program: Vec<_> = (0..COUNT)
        .map(|index| ins(index * 2, 2, vec![copy(reg(index % 8), c(index, 8))]))
        .collect();
    let cfg = build(0, program);
    assert_eq!((cfg.block_count(), cfg.exit_count()), (1, 1));
    assert_eq!(cfg.block_points(0).unwrap().len(), COUNT as usize);
    assert_eq!(
        cfg.exits()[0].kind,
        ExitKind::OutsideFallthrough { target: COUNT * 2 }
    );
    let limits = Limits {
        max_operations: COUNT as usize - 1,
        ..Limits::default()
    };
    let input = CfgInput::new(spaces(), SpaceId(RAM), 0, cfg.shared_instructions());
    assert!(matches!(
        Cfg::new(input, limits),
        Err(CfgError::LimitExceeded {
            resource: Resource::Operations
        })
    ));
}
