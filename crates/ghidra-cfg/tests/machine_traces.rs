//! Independent semantic check: execute small programs with the native P-code
//! `Machine` and require every observed operation transition, and the final
//! stop, to be explained by the CFG. The machine shares no code with the CFG.

mod common;

use common::*;
use ghidra_cfg::{
    CallTarget, Cfg, CfgInput, EdgeRole, ExitKind, Limits, NodeKind, ProgramPoint, Statement,
    TargetLocation,
};
use ghidra_graph::{NaturalLoop, PostDominator};
use ghidra_pcode::machine::{ExecutionInput, ExecutionReport, Machine, StopReason};
use ghidra_pcode::{Opcode, PcodeInstruction, SpaceId, Varnode};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Next {
    Point(ProgramPoint),
    Exit(ExitKind),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Transition {
    Edge,
    /// Allowed only because the CFG reports an unresolved indirect branch.
    Indirect,
    /// The machine entered a callee; the CFG must not have an edge for it.
    Call,
}

#[derive(Default, Debug)]
struct Counts {
    edge: usize,
    indirect: usize,
    call: usize,
}

fn immediate(cfg: &Cfg, point: ProgramPoint) -> Vec<Next> {
    let block = cfg.block_of(point).unwrap();
    let points = cfg.block_points(block).unwrap();
    let position = points.iter().position(|&p| p == point).unwrap();
    if let Some(&next) = points.get(position + 1) {
        return vec![Next::Point(next)];
    }
    cfg.out_edges(block)
        .unwrap()
        .iter()
        .map(|edge| match cfg.node(edge.to).unwrap() {
            NodeKind::Block(points) => Next::Point(points[0]),
            NodeKind::Exit(exit) => Next::Exit(exit.kind),
        })
        .collect()
}

/// Executed operations or exits that may follow `point`, skipping no-op points
/// (the machine emits no trace event for zero-operation instructions).
fn next_executed(cfg: &Cfg, start: Vec<Next>) -> Vec<Next> {
    let mut result = Vec::new();
    let mut pending = start;
    let mut steps = 0;
    while let Some(next) = pending.pop() {
        steps += 1;
        assert!(steps < 10_000, "no-op flow does not terminate");
        match next {
            Next::Point(point) if cfg.statement(point) == Some(Statement::NoOp) => {
                pending.extend(immediate(cfg, point));
            }
            other => result.push(other),
        }
    }
    result
}

fn transition(cfg: &Cfg, from: ProgramPoint, to: ProgramPoint) -> Transition {
    let options = next_executed(cfg, immediate(cfg, from));
    if options.contains(&Next::Point(to)) {
        return Transition::Edge;
    }
    let instruction_entry = to.operation_index == 0 && cfg.instruction_at(to.address).is_some();
    if instruction_entry && options.contains(&Next::Exit(ExitKind::UnresolvedIndirectBranch)) {
        return Transition::Indirect;
    }
    let site = cfg.calls().iter().find(|site| site.point == from);
    if let Some(site) = site
        && instruction_entry
        && site.target
            == (CallTarget::Direct {
                address: to.address,
                location: TargetLocation::InstructionStart,
            })
    {
        let callee = cfg.block_of(to).unwrap();
        assert_ne!(site.continuation, callee);
        assert!(
            cfg.out_edges(site.block)
                .unwrap()
                .iter()
                .all(|edge| edge.to != callee),
            "a callee must not be an intra-procedural successor"
        );
        return Transition::Call;
    }
    panic!("machine flow {from} -> {to} is not a CFG path; CFG allows {options:?}");
}

fn assert_trace_is_cfg_path(cfg: &Cfg, report: &ExecutionReport) -> Counts {
    assert!(!report.trace_truncated);
    let trace: Vec<_> = report
        .trace
        .iter()
        .map(|event| ProgramPoint::new(event.address, event.operation as u32))
        .collect();
    for (event, point) in report.trace.iter().zip(&trace) {
        match cfg.statement(*point) {
            Some(Statement::Operation(op)) => assert_eq!(op.opcode, event.opcode),
            other => panic!("trace point {point} is {other:?} in the CFG"),
        }
    }
    let entry = cfg.block_points(cfg.entry()).unwrap()[0];
    let first = next_executed(cfg, vec![Next::Point(entry)]);
    assert!(first.contains(&Next::Point(trace[0])));
    let mut counts = Counts::default();
    let mut record = |kind| match kind {
        Transition::Edge => counts.edge += 1,
        Transition::Indirect => counts.indirect += 1,
        Transition::Call => counts.call += 1,
    };
    for pair in trace.windows(2) {
        record(transition(cfg, pair[0], pair[1]));
    }
    let last = *trace.last().unwrap();
    let options = next_executed(cfg, immediate(cfg, last));
    let site = cfg.calls().iter().find(|site| site.point == last);
    match &report.stop {
        StopReason::FallThrough { next_address } => {
            assert!(options.contains(&Next::Exit(ExitKind::OutsideFallthrough {
                target: *next_address
            })))
        }
        StopReason::ExternalTransfer { target, kind } => match kind.as_str() {
            "branch" => assert!(options.iter().any(|next| matches!(
                next,
                Next::Exit(
                    ExitKind::ExternalBranch { target: t }
                    | ExitKind::InteriorBranch { target: t, .. }
                ) if t == target
            ))),
            "return" => assert!(options.contains(&Next::Exit(ExitKind::Return))),
            "indirect-branch" => {
                assert!(options.contains(&Next::Exit(ExitKind::UnresolvedIndirectBranch)))
            }
            "call" => assert_eq!(
                site.unwrap().target,
                CallTarget::Direct {
                    address: *target,
                    location: TargetLocation::NotSupplied
                }
            ),
            "indirect-call" => assert_eq!(site.unwrap().target, CallTarget::Indirect),
            other => panic!("unexpected machine transfer {other}"),
        },
        StopReason::BudgetExhausted { address, operation } => {
            record(transition(
                cfg,
                last,
                ProgramPoint::new(*address, *operation as u32),
            ));
        }
    }
    counts
}

fn execute(
    entry: u64,
    instructions: Vec<PcodeInstruction>,
    budget: u64,
) -> (Cfg, Machine, ExecutionReport, Counts) {
    let cfg = build(entry, instructions.clone());
    let mut machine = Machine::new(spaces(), 16 * 4096).unwrap();
    let report = machine
        .run(&instructions, SpaceId(RAM), entry, budget)
        .unwrap();
    let counts = assert_trace_is_cfg_path(&cfg, &report);
    (cfg, machine, report, counts)
}

fn read(machine: &Machine, varnode: Varnode) -> u64 {
    machine.read_varnode(&varnode).unwrap().to_u64().unwrap()
}

fn binary(
    opcode: Opcode,
    output: Varnode,
    left: Varnode,
    right: Varnode,
) -> ghidra_pcode::PcodeOperation {
    op(opcode, Some(output), vec![left, right])
}

#[test]
fn checked_in_sum_loop_is_a_natural_loop_and_matches_execution() {
    let input: ExecutionInput =
        serde_json::from_str(include_str!("../../../examples/pcode/sum-loop.json")).unwrap();
    let cfg = Cfg::new(
        CfgInput::new(
            input.spaces.clone(),
            input.code_space,
            input.entry,
            input.instructions.clone(),
        ),
        Limits::default(),
    )
    .unwrap();
    assert_eq!((cfg.block_count(), cfg.exit_count()), (2, 1));
    assert_eq!(
        cfg.block_points(1).unwrap(),
        (2..6).map(|index| point(0x1000, index)).collect::<Vec<_>>()
    );
    assert_eq!(
        cfg.exits()[0].kind,
        ExitKind::OutsideFallthrough { target: 0x1004 }
    );
    let graph = cfg.graph();
    let dominators = graph.dominators(cfg.entry()).unwrap();
    assert_eq!(
        dominators.natural_loops().unwrap(),
        [NaturalLoop {
            header: 1,
            latches: vec![1],
            body: vec![1]
        }]
    );
    let post = graph.post_dominators(cfg.exit_nodes()).unwrap();
    assert_eq!(
        post.immediate_post_dominator(0).unwrap(),
        PostDominator::Node(1)
    );
    assert_eq!(
        post.immediate_post_dominator(1).unwrap(),
        PostDominator::Node(2)
    );

    let mut machine = Machine::new(input.spaces, 8 * 4096).unwrap();
    let report = machine
        .run(
            &input.instructions,
            input.code_space,
            input.entry,
            input.max_operations,
        )
        .unwrap();
    assert_eq!(report.operations, 14);
    let counts = assert_trace_is_cfg_path(&cfg, &report);
    assert_eq!((counts.edge, counts.indirect, counts.call), (13, 0, 0));
}

#[test]
fn native_branches_noops_relative_skips_and_branch_to_end_match_execution() {
    let condition = flag(0);
    let program = vec![
        ins(
            0x1000,
            4,
            vec![copy(reg(0), c(3, 8)), copy(reg(1), c(0, 8))],
        ),
        ins(
            0x1004,
            2,
            vec![
                binary(Opcode::IntAdd, reg(1), reg(1), reg(0)),
                binary(Opcode::IntSub, reg(0), reg(0), c(1, 8)),
            ],
        ),
        ins(0x1006, 2, vec![]),
        ins(
            0x1008,
            4,
            vec![
                binary(Opcode::IntNotequal, condition, reg(0), c(0, 8)),
                cbranch(ram(0x1004), condition),
            ],
        ),
        ins(
            0x100C,
            4,
            vec![
                binary(Opcode::IntEqual, flag(1), reg(1), c(6, 8)),
                cbranch(rel(2), flag(1)),
                copy(reg(2), c(0xBAD, 8)),
                copy(reg(2), c(1, 8)),
                branch(rel(2)),
                copy(reg(2), c(0xDEAD, 8)),
            ],
        ),
        ins(0x1010, 1, vec![ret(c(0x9000, 8))]),
    ];
    let (cfg, machine, report, counts) = execute(0x1000, program, 1000);
    assert!(matches!(
        report.stop,
        StopReason::ExternalTransfer { target: 0x9000, ref kind } if kind == "return"
    ));
    assert_eq!((read(&machine, reg(1)), read(&machine, reg(2))), (6, 1));
    assert_eq!(counts.indirect + counts.call, 0);
    // The dead store after the relative branch to the instruction end is an
    // explicit, entry-unreachable block.
    let dead = block_at(&cfg, 0x100C, 5);
    assert!(!cfg.graph().traversal(cfg.entry()).unwrap().reachable[dead]);
    let to_end = out(&cfg, block_at(&cfg, 0x100C, 3), EdgeRole::Branch);
    assert_eq!(to_end.to, block_at(&cfg, 0x1010, 0));
    assert_eq!(to_end.arrival, ghidra_cfg::Arrival::InstructionEntry);
    let header = block_at(&cfg, 0x1004, 0);
    let loops = cfg
        .graph()
        .dominators(cfg.entry())
        .unwrap()
        .natural_loops()
        .unwrap();
    assert_eq!(loops[0].header, header);
}

#[test]
fn calls_match_execution_without_callee_edges() {
    let external = vec![
        ins(
            0x2000,
            4,
            vec![
                copy(reg(0), c(1, 8)),
                call(ram(0x3000)),
                copy(reg(0), c(2, 8)),
            ],
        ),
        ins(0x2004, 4, vec![ret(c(0x9000, 8))]),
    ];
    let (_, machine, report, _) = execute(0x2000, external, 100);
    assert!(matches!(
        report.stop,
        StopReason::ExternalTransfer { target: 0x3000, ref kind } if kind == "call"
    ));
    assert_eq!(read(&machine, reg(0)), 1);

    // The machine follows a call into a supplied callee (itself). The CFG
    // explains each such step only as a recorded call, never as an edge.
    let recursive = vec![
        ins(0x2000, 4, vec![copy(reg(0), c(1, 8)), call(ram(0x2000))]),
        ins(0x2004, 4, vec![ret(c(0x9000, 8))]),
    ];
    let (cfg, _, report, counts) = execute(0x2000, recursive, 9);
    assert!(matches!(report.stop, StopReason::BudgetExhausted { .. }));
    assert_eq!(counts.call, 4);
    assert_eq!(cfg.graph().successors(0).unwrap(), [1, 2]);
}

#[test]
fn indirect_branches_and_returns_match_execution() {
    let program = vec![
        ins(
            0x4000,
            4,
            vec![
                copy(reg(0), c(0x4008, 8)),
                op(Opcode::Branchind, None, vec![reg(0)]),
            ],
        ),
        ins(0x4004, 4, vec![copy(reg(1), c(1, 8))]),
        ins(0x4008, 4, vec![copy(reg(1), c(2, 8)), ret(c(0x9000, 8))]),
    ];
    let (cfg, machine, report, counts) = execute(0x4000, program, 100);
    assert!(matches!(
        report.stop,
        StopReason::ExternalTransfer { target: 0x9000, ref kind } if kind == "return"
    ));
    assert_eq!(read(&machine, reg(1)), 2);
    assert_eq!(counts.indirect, 1);
    // The CFG does not pretend to know the indirect target.
    assert!(!cfg.graph().traversal(cfg.entry()).unwrap().reachable[1]);
}

#[test]
fn zero_displacement_loop_matches_execution_until_the_budget() {
    let program = vec![ins(0x5000, 1, vec![set_flag(0), branch(rel(0))])];
    let (cfg, _, report, counts) = execute(0x5000, program, 10);
    assert!(matches!(
        report.stop,
        StopReason::BudgetExhausted {
            address: 0x5000,
            operation: 1
        }
    ));
    assert_eq!(counts.edge, 10);
    assert_eq!(cfg.exit_count(), 0);
}

#[test]
fn delay_bundles_and_gaps_match_execution() {
    let program = |value| {
        vec![
            ins(0x5FFC, 4, vec![copy(reg(0), c(value, 8))]),
            ins(
                0x6000,
                8,
                vec![
                    binary(Opcode::IntEqual, flag(0), reg(0), c(0, 8)),
                    copy(reg(1), c(7, 8)),
                    cbranch(ram(0x7000), flag(0)),
                ],
            ),
            ins(0x6008, 4, vec![ret(c(0x9000, 8))]),
        ]
    };
    let (_, machine, report, _) = execute(0x5FFC, program(1), 100);
    assert!(matches!(
        report.stop,
        StopReason::ExternalTransfer { target: 0x9000, ref kind } if kind == "return"
    ));
    assert_eq!(read(&machine, reg(1)), 7);
    let (_, _, report, _) = execute(0x5FFC, program(0), 100);
    assert!(matches!(
        report.stop,
        StopReason::ExternalTransfer { target: 0x7000, ref kind } if kind == "branch"
    ));

    let gap = vec![
        ins(0x8000, 2, vec![copy(reg(0), c(1, 8))]),
        ins(0x8004, 4, vec![ret(c(0x9000, 8))]),
    ];
    let (_, _, report, _) = execute(0x8000, gap, 100);
    assert!(matches!(
        report.stop,
        StopReason::FallThrough {
            next_address: 0x8002
        }
    ));
}

#[test]
fn noop_entry_and_noop_branch_targets_match_execution() {
    let program = vec![
        ins(0x9000, 2, vec![]),
        ins(0x9002, 4, vec![copy(reg(0), c(1, 8)), branch(ram(0x9006))]),
        ins(0x9006, 2, vec![]),
        ins(0x9008, 4, vec![ret(c(0x100, 8))]),
    ];
    let (cfg, _, report, counts) = execute(0x9000, program, 100);
    assert_eq!(report.trace.len(), 3);
    assert_eq!(counts.edge, 2);
    assert_eq!(
        cfg.block_points(block_at(&cfg, 0x9006, 0)).unwrap(),
        [point(0x9006, 0), point(0x9008, 0)]
    );
}
