mod common;

use std::sync::Arc;

use common::*;
use ghidra_cfg::{
    Arrival, CallSite, CallTarget, Cfg, CfgInput, EdgeRole, ExitKind, Gap, Limits, NodeKind,
    Statement, TargetLocation, UseropSite,
};
use ghidra_graph::PostDominator;
use ghidra_pcode::{Opcode, PcodeInstruction, SpaceId, SpaceKind};

use Arrival::{Exit as ToExit, InstructionEntry as Entry, SameInstruction as Same};

fn edge_summary(cfg: &Cfg) -> Vec<(usize, usize, EdgeRole, Arrival)> {
    cfg.edges()
        .iter()
        .map(|edge| (edge.from, edge.to, edge.role, edge.arrival))
        .collect()
}

#[test]
fn signed_relative_branches_forward_backward_zero_and_to_end() {
    let f = flag(0);
    let cfg = build(
        0x1000,
        vec![
            ins(
                0x1000,
                4,
                vec![
                    set_flag(0),
                    cbranch(rel(2), f),  // op1 -> op3 (forward)
                    set_flag(0),         // op2
                    cbranch(rel(-3), f), // op3 -> op0 (backward to operation 0)
                    cbranch(rel(0), f),  // op4 -> op4 (zero displacement)
                    cbranch(rel(2), f),  // op5 -> 7 == ops.len(): instruction end
                    set_flag(0),         // op6
                ],
            ),
            ins(0x1004, 1, vec![ret(c(0, 8))]),
        ],
    );
    let starts: Vec<_> = (0..cfg.block_count())
        .map(|node| cfg.block_points(node).unwrap()[0])
        .collect();
    assert_eq!(
        starts,
        [
            point(0x1000, 0),
            point(0x1000, 2),
            point(0x1000, 3),
            point(0x1000, 4),
            point(0x1000, 5),
            point(0x1000, 6),
            point(0x1004, 0),
        ]
    );
    assert_eq!(cfg.block_points(0).unwrap().len(), 2);
    use EdgeRole::*;
    assert_eq!(
        edge_summary(&cfg),
        [
            (0, 1, ConditionFalse, Same),
            (0, 2, ConditionTrue, Same),
            (1, 2, Fallthrough, Same),
            (2, 3, ConditionFalse, Same),
            (2, 0, ConditionTrue, Same),
            (3, 4, ConditionFalse, Same),
            (3, 3, ConditionTrue, Same),
            (4, 5, ConditionFalse, Same),
            (4, 6, ConditionTrue, Entry),
            (5, 6, Fallthrough, Entry),
            (6, 7, Return, ToExit),
        ]
    );
    assert_eq!(cfg.exits()[0].kind, ExitKind::Return);
    assert_eq!(cfg.entry(), 0);
    let loops = cfg
        .graph()
        .dominators(cfg.entry())
        .unwrap()
        .natural_loops()
        .unwrap();
    assert_eq!(loops.iter().map(|l| l.header).collect::<Vec<_>>(), [0, 3]);
}

#[test]
fn branch_to_instruction_end_leaves_the_domain_or_the_space() {
    let cfg = build(0x1000, vec![ins(0x1000, 3, vec![branch(rel(1))])]);
    assert_eq!(edge_summary(&cfg), [(0, 1, EdgeRole::Branch, ToExit)]);
    assert_eq!(
        cfg.exits()[0].kind,
        ExitKind::OutsideFallthrough { target: 0x1003 }
    );

    let mut small = spaces();
    small[RAM as usize].address_size = 2;
    let cfg = try_build_with(
        small,
        0xFFFC,
        vec![ins(0xFFFC, 4, vec![set_flag(0), branch(rel(1))])],
        Limits::default(),
    )
    .unwrap();
    assert_eq!(
        cfg.exits().iter().map(|exit| exit.kind).collect::<Vec<_>>(),
        [ExitKind::SpaceEndFallthrough]
    );
}

#[test]
fn conditional_with_internal_and_external_outcomes_keeps_both_paths() {
    let cfg = build(
        0x1000,
        vec![
            ins(0x1000, 4, vec![set_flag(0), cbranch(ram(0x5000), flag(0))]),
            ins(0x1004, 4, vec![ret(reg(0))]),
        ],
    );
    use EdgeRole::*;
    assert_eq!(
        edge_summary(&cfg),
        [
            (0, 1, ConditionFalse, Entry),
            (0, 2, ConditionTrue, ToExit),
            (1, 3, Return, ToExit),
        ]
    );
    assert_eq!(
        cfg.exit(2).unwrap().kind,
        ExitKind::ExternalBranch { target: 0x5000 }
    );
    assert_eq!(cfg.exit(2).unwrap().source, point(0x1000, 1));
    assert!(matches!(cfg.node(3), Some(NodeKind::Exit(exit)) if exit.kind == ExitKind::Return));
    assert!(!cfg.is_block(2) && cfg.block_points(2).is_none());
    assert_eq!(cfg.out_edges(2).unwrap(), []);
    assert_eq!(cfg.in_edges(2).unwrap(), [1]);

    // All exits: the branch block reaches two different terminal outcomes.
    let graph = cfg.graph();
    let post = graph.post_dominators(cfg.exit_nodes()).unwrap();
    assert_eq!(
        post.immediate_post_dominator(0).unwrap(),
        PostDominator::SyntheticExit
    );
    assert!(post.can_reach_exit(0).unwrap());
    // Only RETURN designated: the external outcome is no longer a finite exit.
    let returns = cfg
        .exits()
        .iter()
        .filter(|exit| exit.kind == ExitKind::Return)
        .map(|exit| exit.node);
    let post = graph.post_dominators(returns).unwrap();
    assert_eq!(
        post.immediate_post_dominator(0).unwrap(),
        PostDominator::Node(1)
    );
    assert_eq!(
        post.immediate_post_dominator(2).unwrap(),
        PostDominator::Unreachable
    );
}

#[test]
fn direct_targets_inside_instructions_are_reported_not_resolved() {
    let cfg = build(
        0x1000,
        vec![
            ins(0x1000, 4, vec![set_flag(0), cbranch(ram(0x1006), flag(0))]),
            ins(0x1004, 4, vec![branch(ram(0x1001))]),
        ],
    );
    let kinds: Vec<_> = cfg.exits().iter().map(|exit| exit.kind).collect();
    assert_eq!(
        kinds,
        [
            ExitKind::InteriorBranch {
                target: 0x1006,
                instruction: 0x1004
            },
            ExitKind::InteriorBranch {
                target: 0x1001,
                instruction: 0x1000
            },
        ]
    );
    assert_eq!(cfg.block_count(), 2);
}

#[test]
fn native_entry_and_relative_operation_zero_have_distinct_provenance() {
    let cfg = build(
        0x1000,
        vec![
            ins(
                0x1000,
                4,
                vec![
                    set_flag(0),
                    cbranch(rel(-1), flag(0)), // relative to op 0: same frame
                    branch(ram(0x1000)),       // native jump to its own start: new frame
                ],
            ),
            ins(0x2000, 4, vec![set_flag(0), branch(ram(0x2000))]),
            ins(0x3000, 4, vec![set_flag(0), branch(rel(-1))]),
        ],
    );
    let head = block_at(&cfg, 0x1000, 0);
    let tail = block_at(&cfg, 0x1000, 2);
    let incoming: Vec<_> = cfg
        .in_edges(head)
        .unwrap()
        .iter()
        .map(|&id| {
            let edge = cfg.edges()[id];
            (edge.from, edge.role, edge.arrival)
        })
        .collect();
    assert_eq!(
        incoming,
        [
            (head, EdgeRole::ConditionTrue, Same),
            (tail, EdgeRole::Branch, Entry),
        ]
    );
    // Both self-loops are the same graph edge shape, with different arrivals.
    let native = block_at(&cfg, 0x2000, 0);
    let relative = block_at(&cfg, 0x3000, 0);
    let native_edge = out(&cfg, native, EdgeRole::Branch);
    let relative_edge = out(&cfg, relative, EdgeRole::Branch);
    assert_eq!((native_edge.to, native_edge.arrival), (native, Entry));
    assert_eq!((relative_edge.to, relative_edge.arrival), (relative, Same));
    assert_eq!(cfg.graph().successors(native).unwrap(), [native]);
    assert_eq!(cfg.graph().successors(relative).unwrap(), [relative]);
}

#[test]
fn semantic_roles_survive_graph_edge_collapse() {
    let cfg = build(
        0x1000,
        vec![
            ins(
                0x1000,
                4,
                vec![set_flag(0), cbranch(rel(1), flag(0)), set_flag(1)],
            ),
            ins(0x1004, 4, vec![cbranch(rel(1), flag(0))]),
            ins(0x1008, 4, vec![ret(reg(0))]),
        ],
    );
    // Blocks: [0x1000:0-1], [0x1000:2, 0x1004:0] (adjacent fallthrough), [0x1008:0].
    use EdgeRole::*;
    assert_eq!(
        edge_summary(&cfg),
        [
            (0, 1, ConditionFalse, Same),
            (0, 1, ConditionTrue, Same),
            (1, 2, ConditionFalse, Entry),
            (1, 2, ConditionTrue, Entry),
            (2, 3, Return, ToExit),
        ]
    );
    assert_eq!(
        cfg.block_points(1).unwrap(),
        [point(0x1000, 2), point(0x1004, 0)]
    );
    assert_eq!(cfg.out_edges(0).unwrap().len(), 2);
    assert_eq!(cfg.graph().successors(0).unwrap(), [1]);
    assert_eq!(cfg.graph().successors(1).unwrap(), [2]);
    assert_eq!(cfg.graph().edge_count(), 3);
    assert_eq!(cfg.in_edges(2).unwrap(), [2, 3]);
}

#[test]
fn calls_record_callees_separately_with_possible_continuations() {
    let cfg = build(
        0x1000,
        vec![
            ins(0x1000, 4, vec![set_flag(0), call(ram(0x1008)), set_flag(1)]),
            ins(0x1004, 4, vec![op(Opcode::Callind, None, vec![reg(0)])]),
            ins(0x1008, 4, vec![set_flag(2)]),
            ins(0x100C, 4, vec![branch(ram(0x1010))]),
            ins(0x1010, 4, vec![call(ram(0x100C))]),
        ],
    );
    let first = block_at(&cfg, 0x1000, 0);
    let after_call = block_at(&cfg, 0x1000, 2);
    let after_indirect = block_at(&cfg, 0x1008, 0);
    let last = block_at(&cfg, 0x1010, 0);
    assert_eq!(cfg.block_count(), 4, "call targets do not split blocks");
    assert_eq!(
        cfg.block_points(after_indirect).unwrap(),
        [point(0x1008, 0), point(0x100C, 0)]
    );
    let calls = cfg.calls();
    let exit_of = |site: &CallSite| cfg.exit(site.no_return).unwrap().kind;
    assert_eq!(calls.len(), 3);
    assert_eq!(
        calls[0].target,
        CallTarget::Direct {
            address: 0x1008,
            location: TargetLocation::InstructionStart
        }
    );
    assert_eq!(
        (calls[0].point, calls[0].block, calls[0].continuation),
        (point(0x1000, 1), first, after_call)
    );
    assert_eq!(calls[1].target, CallTarget::Indirect);
    assert_eq!(calls[1].continuation, after_indirect);
    assert_eq!(
        calls[2].target,
        CallTarget::Direct {
            address: 0x100C,
            location: TargetLocation::InstructionStart
        }
    );
    assert_eq!(calls[2].block, last);
    assert_eq!(
        cfg.exit(calls[2].continuation).unwrap().kind,
        ExitKind::OutsideFallthrough { target: 0x1014 }
    );
    for site in calls {
        assert_eq!(exit_of(site), ExitKind::CallNoReturn);
        let roles: Vec<_> = cfg
            .out_edges(site.block)
            .unwrap()
            .iter()
            .map(|edge| edge.role)
            .collect();
        assert_eq!(roles, [EdgeRole::CallReturn, EdgeRole::CallNoReturn]);
    }
    // No edge reaches a callee block: the first call's target begins block
    // `after_indirect`, whose only predecessor is the CALLIND continuation.
    assert_eq!(
        cfg.graph().predecessors(after_indirect).unwrap(),
        [calls[1].block]
    );
    assert!(cfg.graph().predecessors(first).unwrap().is_empty());
    assert_eq!(out(&cfg, first, EdgeRole::CallReturn).arrival, Same);
    assert_eq!(out(&cfg, after_call, EdgeRole::CallReturn).arrival, Entry);

    // Conservative post-dominance keeps the no-return outcome; excluding
    // CallNoReturn exits models only completed calls.
    let graph = cfg.graph();
    let all = graph.post_dominators(cfg.exit_nodes()).unwrap();
    assert_eq!(
        all.immediate_post_dominator(first).unwrap(),
        PostDominator::SyntheticExit
    );
    let completed = cfg
        .exits()
        .iter()
        .filter(|exit| exit.kind != ExitKind::CallNoReturn)
        .map(|exit| exit.node);
    let completed = graph.post_dominators(completed).unwrap();
    assert_eq!(
        completed.immediate_post_dominator(first).unwrap(),
        PostDominator::Node(after_call)
    );
}

#[test]
fn call_locations_classify_interior_and_unsupplied_targets() {
    let cfg = build(
        0x1000,
        vec![
            ins(0x1000, 4, vec![call(ram(0x1002))]),
            ins(0x1004, 4, vec![call(ram(0x9000))]),
            ins(0x1008, 4, vec![ret(reg(0))]),
        ],
    );
    let targets: Vec<_> = cfg.calls().iter().map(|site| site.target).collect();
    assert_eq!(
        targets,
        [
            CallTarget::Direct {
                address: 0x1002,
                location: TargetLocation::InstructionInterior {
                    instruction: 0x1000
                }
            },
            CallTarget::Direct {
                address: 0x9000,
                location: TargetLocation::NotSupplied
            },
        ]
    );
}

#[test]
fn returns_indirect_branches_userops_and_unimplemented_are_explicit() {
    let cfg = build(
        0x1000,
        vec![
            ins(
                0x1000,
                4,
                vec![
                    op(Opcode::Callother, None, vec![c(5, 4)]),
                    op(Opcode::Branchind, None, vec![reg(0)]),
                ],
            ),
            ins(
                0x1004,
                4,
                vec![
                    op(Opcode::Callother, Some(reg(1)), vec![c(7, 4), reg(2)]),
                    op(Opcode::Unimplemented, None, vec![]),
                    set_flag(0),
                ],
            ),
            ins(0x1008, 4, vec![ret(reg(0))]),
        ],
    );
    use EdgeRole::*;
    assert_eq!(
        edge_summary(&cfg),
        [
            (0, 3, IndirectBranch, ToExit),
            (1, 4, Unimplemented, ToExit),
            (2, 5, Return, ToExit),
        ]
    );
    assert_eq!(
        cfg.block_points(2).unwrap(),
        [point(0x1004, 2), point(0x1008, 0)]
    );
    let kinds: Vec<_> = cfg.exits().iter().map(|exit| exit.kind).collect();
    assert_eq!(
        kinds,
        [
            ExitKind::UnresolvedIndirectBranch,
            ExitKind::Unimplemented,
            ExitKind::Return
        ]
    );
    assert_eq!(
        cfg.userops(),
        [
            UseropSite {
                point: point(0x1000, 0),
                block: 0,
                userop: 5
            },
            UseropSite {
                point: point(0x1004, 0),
                block: 1,
                userop: 7
            },
        ]
    );
    // An unresolved indirect branch does not make later code reachable.
    let reachable = cfg.graph().traversal(cfg.entry()).unwrap().reachable;
    assert_eq!(reachable, [true, false, false, true, false, false]);
}

#[test]
fn zero_operation_instructions_have_explicit_noop_points() {
    let cfg = build(
        0x1000,
        vec![
            ins(0x1000, 2, vec![]),
            ins(0x1002, 2, vec![]),
            ins(0x1004, 4, vec![branch(ram(0x1002))]),
        ],
    );
    assert_eq!(
        cfg.points(),
        [point(0x1000, 0), point(0x1002, 0), point(0x1004, 0)]
    );
    assert_eq!(cfg.statement(point(0x1000, 0)), Some(Statement::NoOp));
    assert_eq!(cfg.statement(point(0x1000, 1)), None);
    assert_eq!(cfg.statement(point(0x1001, 0)), None);
    assert!(matches!(
        cfg.statement(point(0x1004, 0)),
        Some(Statement::Operation(op)) if op.opcode == Opcode::Branch
    ));
    assert_eq!(cfg.block_points(0).unwrap(), [point(0x1000, 0)]);
    assert_eq!(
        cfg.block_points(1).unwrap(),
        [point(0x1002, 0), point(0x1004, 0)]
    );
    assert_eq!(cfg.block_of(point(0x1004, 0)), Some(1));
    assert_eq!(cfg.block_of(point(0x1004, 1)), None);
    use EdgeRole::*;
    assert_eq!(
        edge_summary(&cfg),
        [(0, 1, Fallthrough, Entry), (1, 1, Branch, Entry)]
    );
    // A cycle with no exit is not reported as a return.
    assert_eq!(cfg.exit_count(), 0);
    let post = cfg.graph().post_dominators(cfg.exit_nodes()).unwrap();
    assert_eq!(
        post.immediate_post_dominator(1).unwrap(),
        PostDominator::Unreachable
    );
}

#[test]
fn operations_after_a_branch_remain_explicit_unreachable_blocks() {
    let cfg = build(
        0x1000,
        vec![ins(
            0x1000,
            4,
            vec![branch(ram(0x2000)), set_flag(0), set_flag(1)],
        )],
    );
    assert_eq!(cfg.points().len(), 3);
    assert_eq!(
        cfg.block_points(1).unwrap(),
        [point(0x1000, 1), point(0x1000, 2)]
    );
    let kinds: Vec<_> = cfg.exits().iter().map(|exit| exit.kind).collect();
    assert_eq!(
        kinds,
        [
            ExitKind::ExternalBranch { target: 0x2000 },
            ExitKind::OutsideFallthrough { target: 0x1004 }
        ]
    );
    let reachable = cfg.graph().traversal(cfg.entry()).unwrap().reachable;
    assert_eq!(reachable, [true, false, true, false]);
}

#[test]
fn delay_bundle_extent_and_gaps_drive_fallthrough() {
    // A branch plus its expanded delay slot: one 8-byte bundle.
    let bundle = ins(
        0x1000,
        8,
        vec![
            set_flag(0),
            copy(reg(1), c(7, 8)),
            cbranch(ram(0x1004), flag(0)),
        ],
    );
    let cfg = build(
        0x1000,
        vec![
            bundle.clone(),
            ins(0x1008, 2, vec![set_flag(1)]),
            ins(0x100C, 4, vec![ret(reg(0))]),
        ],
    );
    assert_eq!(
        cfg.gaps(),
        [Gap {
            start: 0x100A,
            end: 0x100C
        }]
    );
    let after = block_at(&cfg, 0x1008, 0);
    assert_eq!(out(&cfg, 0, EdgeRole::ConditionFalse).to, after);
    let taken = out(&cfg, 0, EdgeRole::ConditionTrue);
    assert_eq!(
        cfg.exit(taken.to).unwrap().kind,
        ExitKind::InteriorBranch {
            target: 0x1004,
            instruction: 0x1000
        }
    );
    let gap = out(&cfg, after, EdgeRole::Fallthrough);
    assert_eq!(
        cfg.exit(gap.to).unwrap().kind,
        ExitKind::OutsideFallthrough { target: 0x100A }
    );
    assert_eq!(block_at(&cfg, 0x100C, 0), 2);
}

#[test]
fn ownership_is_shared_and_supplied_data_is_unchanged() {
    let original = vec![
        ins(0x1004, 4, vec![ret(reg(0))]),
        ins(0x1000, 4, vec![branch(rel(1)), set_flag(0)]),
    ];
    let instructions: Arc<[PcodeInstruction]> = original.clone().into();
    let input = CfgInput::new(spaces(), SpaceId(RAM), 0x1000, Arc::clone(&instructions));
    let cfg = Cfg::new(input, Limits::default()).unwrap();
    assert!(Arc::ptr_eq(&cfg.shared_instructions(), &instructions));
    assert_eq!(cfg.instructions(), &original[..]);
    let canonical: Vec<_> = cfg.canonical_instructions().map(|i| i.address).collect();
    assert_eq!(canonical, [0x1000, 0x1004]);
    assert_eq!(cfg.instruction_at(0x1004), Some(&original[0]));
    assert_eq!(cfg.instruction_at(0x1002), None);
    assert_eq!(cfg.spaces()[RAM as usize].kind, SpaceKind::Ram);
    assert_eq!(
        (cfg.code_space(), cfg.entry_address()),
        (SpaceId(RAM), 0x1000)
    );
    fn shareable<T: Send + Sync>(_: &T) {}
    shareable(&cfg);
    let graph = cfg.shared_graph();
    let node_count = cfg.node_count();
    drop(cfg);
    assert_eq!(graph.node_count(), node_count);
    assert_eq!(graph.successors(0).unwrap(), [1]);
}
