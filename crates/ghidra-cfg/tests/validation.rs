mod common;

use common::*;
use ghidra_cfg::{CfgError, Limits, OperandError, OperandSlot, Resource};
use ghidra_pcode::model::{MAX_INPUTS, MAX_OPS_PER_INSTRUCTION};
use ghidra_pcode::{Opcode, PcodeInstruction, PcodeOperation, SpaceId, SpaceKind};

fn single(ops: Vec<PcodeOperation>) -> Result<ghidra_cfg::Cfg, CfgError> {
    try_build(0x1000, vec![ins(0x1000, 4, ops)])
}

fn operand_error(result: Result<ghidra_cfg::Cfg, CfgError>) -> (OperandSlot, OperandError) {
    match result {
        Err(CfgError::InvalidOperand { slot, problem, .. }) => (slot, problem),
        other => panic!("expected an operand error, got {other:?}"),
    }
}

fn resource(result: Result<ghidra_cfg::Cfg, CfgError>) -> Resource {
    match result {
        Err(CfgError::LimitExceeded { resource }) => resource,
        other => panic!("expected a limit error, got {other:?}"),
    }
}

#[test]
fn relative_targets_must_stay_within_the_instruction() {
    for (ops, displacement, target) in [
        (vec![branch(rel(-1))], -1, -1),
        (vec![branch(rel(2))], 2, 2),
        (
            vec![set_flag(0), cbranch(rel(i32::MIN), flag(0))],
            i32::MIN,
            1 + i64::from(i32::MIN),
        ),
    ] {
        match single(ops) {
            Err(CfgError::InvalidRelativeTarget {
                displacement: d,
                target: t,
                ..
            }) => assert_eq!((d, t), (displacement, target)),
            other => panic!("unexpected {other:?}"),
        }
    }
    // Only the low 32 bits form the displacement, as in PcodeFrame.
    let high_bits = vn(CONST, 0xFFFF_FFFF_0000_0001, 8);
    let cfg = single(vec![branch(high_bits), set_flag(0)]).unwrap();
    assert_eq!(cfg.block_count(), 2);
}

#[test]
fn direct_labels_are_code_addresses_not_value_reads() {
    assert_eq!(
        operand_error(single(vec![branch(reg(0))])),
        (
            OperandSlot::Input(0),
            OperandError::CrossSpaceLabel {
                space: SpaceId(REG)
            }
        )
    );
    assert_eq!(
        operand_error(single(vec![call(rel(1))])),
        (OperandSlot::Input(0), OperandError::RelativeCallLabel)
    );
    assert_eq!(
        operand_error(single(vec![call(vn(UNIQUE, 0, 8))])),
        (
            OperandSlot::Input(0),
            OperandError::CrossSpaceLabel {
                space: SpaceId(UNIQUE)
            }
        )
    );
    let mut small = spaces();
    small[RAM as usize].address_size = 2;
    let result = try_build_with(
        small.clone(),
        0x1000,
        vec![ins(0x1000, 4, vec![branch(vn(RAM, 0x1_0000, 8))])],
        Limits::default(),
    );
    assert_eq!(
        operand_error(result),
        (
            OperandSlot::Input(0),
            OperandError::LabelOutOfSpace { offset: 0x1_0000 }
        )
    );
    // The last code address is a valid label even with a wide label varnode.
    let cfg = try_build_with(
        small,
        0x1000,
        vec![ins(0x1000, 4, vec![branch(vn(RAM, 0xFFFF, 8))])],
        Limits::default(),
    )
    .unwrap();
    assert_eq!(cfg.exit_count(), 1);
}

#[test]
fn operand_roles_spaces_and_widths_are_checked() {
    let load = |selector, pointer| op(Opcode::Load, Some(reg(0)), vec![selector, pointer]);
    let cases = [
        (
            load(reg(1), reg(2)),
            OperandSlot::Input(0),
            OperandError::RequiresConstant,
        ),
        (
            load(c(99, 4), reg(2)),
            OperandSlot::Input(0),
            OperandError::SelectorSpace { offset: 99 },
        ),
        (
            load(c(u64::from(CONST), 4), reg(2)),
            OperandSlot::Input(0),
            OperandError::SelectorSpace { offset: 0 },
        ),
        (
            load(c(u64::from(RAM), 4), vn(REG, 0, 4)),
            OperandSlot::Input(1),
            OperandError::PointerWidth {
                expected: 8,
                actual: 4,
            },
        ),
        (
            op(
                Opcode::Store,
                None,
                vec![c(u64::from(RAM), 4), reg(0), vn(REG, u64::MAX, 2)],
            ),
            OperandSlot::Input(2),
            OperandError::OutOfSpace,
        ),
        (
            op(Opcode::Branchind, None, vec![vn(REG, 0, 4)]),
            OperandSlot::Input(0),
            OperandError::PointerWidth {
                expected: 8,
                actual: 4,
            },
        ),
        (
            op(Opcode::Callind, None, vec![vn(REG, 0, 2)]),
            OperandSlot::Input(0),
            OperandError::PointerWidth {
                expected: 8,
                actual: 2,
            },
        ),
        (
            ret(vn(REG, 0, 4)),
            OperandSlot::Input(0),
            OperandError::PointerWidth {
                expected: 8,
                actual: 4,
            },
        ),
        (
            op(Opcode::Callother, None, vec![reg(0)]),
            OperandSlot::Input(0),
            OperandError::RequiresConstant,
        ),
        (
            op(Opcode::Subpiece, Some(vn(REG, 0, 4)), vec![reg(1), reg(2)]),
            OperandSlot::Input(1),
            OperandError::RequiresConstant,
        ),
        (
            copy(c(0, 8), reg(0)),
            OperandSlot::Output,
            OperandError::ConstantOutput,
        ),
        (
            copy(vn(REG, u64::MAX - 3, 8), reg(0)),
            OperandSlot::Output,
            OperandError::OutOfSpace,
        ),
        (
            copy(reg(0), vn(77, 0, 8)),
            OperandSlot::Input(0),
            OperandError::UnknownSpace(SpaceId(77)),
        ),
        (
            copy(vn(77, 0, 8), reg(0)),
            OperandSlot::Output,
            OperandError::UnknownSpace(SpaceId(77)),
        ),
    ];
    for (operation, slot, problem) in cases {
        let opcode = operation.opcode;
        assert_eq!(
            operand_error(single(vec![operation])),
            (slot, problem),
            "{opcode}"
        );
    }
    // Constant value inputs are literals and do not need to fit a space.
    single(vec![copy(reg(0), c(u64::MAX, 8))]).unwrap();
    // A valid LOAD/STORE pair with explicit selector and pointer widths.
    single(vec![
        load(c(u64::from(RAM), 4), reg(1)),
        op(
            Opcode::Store,
            None,
            vec![c(u64::from(RAM), 4), reg(1), reg(0)],
        ),
    ])
    .unwrap();
}

#[test]
fn literal_return_targets_do_not_require_a_pointer_sized_read() {
    for size in [1, 2, 4, 8, 16, 512] {
        for target in [0, 0x40] {
            let cfg = single(vec![ret(c(target, size))]).unwrap();
            assert_eq!(cfg.exits().len(), 1);
            assert!(matches!(cfg.exits()[0].kind, ghidra_cfg::ExitKind::Return));
        }
    }
    for opcode in [Opcode::Branchind, Opcode::Callind] {
        assert_eq!(
            operand_error(single(vec![op(opcode, None, vec![c(0, 1)])])),
            (
                OperandSlot::Input(0),
                OperandError::PointerWidth {
                    expected: 8,
                    actual: 1
                }
            )
        );
    }
}

#[test]
fn structural_and_analysis_only_operations_are_rejected() {
    assert!(matches!(
        single(vec![op(Opcode::Copy, Some(reg(0)), vec![])]),
        Err(CfgError::InvalidOperation { .. })
    ));
    assert!(matches!(
        single(vec![op(Opcode::Branch, Some(reg(0)), vec![rel(1)])]),
        Err(CfgError::InvalidOperation { .. })
    ));
    for opcode in [Opcode::Multiequal, Opcode::Indirect] {
        let inputs = vec![reg(1), reg(2)];
        assert!(matches!(
            single(vec![op(opcode, Some(reg(0)), inputs)]),
            Err(CfgError::UnsupportedOperation { opcode: o, .. }) if o == opcode
        ));
    }
}

#[test]
fn spaces_and_code_space_are_validated() {
    assert!(matches!(
        try_build_with(
            vec![],
            0x1000,
            vec![ins(0x1000, 1, vec![])],
            Limits::default()
        ),
        Err(CfgError::NoSpaces)
    ));
    let mut duplicate_id = spaces();
    duplicate_id[3].id = SpaceId(REG);
    assert!(matches!(
        try_build_with(
            duplicate_id,
            0x1000,
            vec![ins(0x1000, 1, vec![])],
            Limits::default()
        ),
        Err(CfgError::DuplicateSpaceId(SpaceId(REG)))
    ));
    let mut duplicate_name = spaces();
    duplicate_name[3].name = "ram".into();
    assert!(matches!(
        try_build_with(duplicate_name, 0x1000, vec![ins(0x1000, 1, vec![])], Limits::default()),
        Err(CfgError::DuplicateSpaceName(name)) if name == "ram"
    ));
    let mut invalid = spaces();
    invalid[2].address_size = 9;
    assert!(matches!(
        try_build_with(
            invalid,
            0x1000,
            vec![ins(0x1000, 1, vec![])],
            Limits::default()
        ),
        Err(CfgError::InvalidSpace {
            id: SpaceId(REG),
            ..
        })
    ));
    let mut word = spaces();
    word[RAM as usize].word_size = 2;
    assert!(matches!(
        try_build_with(
            word,
            0x1000,
            vec![ins(0x1000, 1, vec![])],
            Limits::default()
        ),
        Err(CfgError::WordAddressedCode { word_size: 2, .. })
    ));
    for kind in [SpaceKind::Constant, SpaceKind::Register, SpaceKind::Unique] {
        let mut wrong = spaces();
        wrong[RAM as usize].kind = kind;
        assert!(matches!(
            try_build_with(wrong, 0x1000, vec![ins(0x1000, 1, vec![])], Limits::default()),
            Err(CfgError::CodeSpaceKind { kind: k, .. }) if k == kind
        ));
    }
    let mut other = spaces();
    other[RAM as usize].kind = SpaceKind::Other;
    try_build_with(
        other,
        0x1000,
        vec![ins(0x1000, 1, vec![])],
        Limits::default(),
    )
    .unwrap();
    let missing: Vec<_> = spaces()
        .into_iter()
        .filter(|space| space.id != SpaceId(RAM))
        .collect();
    assert!(matches!(
        try_build_with(
            missing,
            0x1000,
            vec![ins(0x1000, 1, vec![])],
            Limits::default()
        ),
        Err(CfgError::UnknownCodeSpace(SpaceId(RAM)))
    ));
}

#[test]
fn instruction_extents_duplicates_overlaps_and_entry_are_explicit() {
    assert!(matches!(
        try_build(0x1000, vec![]),
        Err(CfgError::EntryNotInstruction { entry: 0x1000 })
    ));
    assert!(matches!(
        try_build(0x1000, vec![ins(0x1000, 0, vec![])]),
        Err(CfgError::InstructionExtent { length: 0, .. })
    ));
    assert!(matches!(
        try_build(u64::MAX, vec![ins(u64::MAX, 2, vec![])]),
        Err(CfgError::InstructionExtent { .. })
    ));
    let mut small = spaces();
    small[RAM as usize].address_size = 2;
    assert!(matches!(
        try_build_with(
            small,
            0xFFFE,
            vec![ins(0xFFFE, 4, vec![])],
            Limits::default()
        ),
        Err(CfgError::InstructionExtent {
            address: 0xFFFE,
            length: 4
        })
    ));
    // Duplicates are reported before any operation content is inspected.
    let bad_ops = ins(0x1000, 4, vec![copy(reg(0), vn(77, 0, 8))]);
    for order in [
        vec![ins(0x1000, 4, vec![]), bad_ops.clone()],
        vec![bad_ops.clone(), ins(0x1000, 4, vec![])],
    ] {
        assert!(matches!(
            try_build(0x1000, order),
            Err(CfgError::DuplicateInstruction { address: 0x1000 })
        ));
    }
    assert!(matches!(
        try_build(0x1000, vec![ins(0x1002, 4, vec![]), ins(0x1000, 4, vec![])]),
        Err(CfgError::OverlappingInstructions {
            first: 0x1000,
            second: 0x1002
        })
    ));
    assert!(matches!(
        try_build(0x1001, vec![ins(0x1000, 4, vec![])]),
        Err(CfgError::EntryNotInstruction { entry: 0x1001 })
    ));
    // The top of a 64-bit space is a valid instruction with no next address.
    let cfg = try_build(u64::MAX, vec![ins(u64::MAX, 1, vec![])]).unwrap();
    assert_eq!(
        cfg.exits()[0].kind,
        ghidra_cfg::ExitKind::SpaceEndFallthrough
    );
}

#[test]
fn counts_are_bounded_before_contents_are_processed() {
    let limits = |change: &dyn Fn(&mut Limits)| {
        let mut limits = Limits::default();
        change(&mut limits);
        limits
    };
    let two = vec![
        ins(0x1000, 4, vec![set_flag(0), set_flag(1)]),
        ins(0x1004, 4, vec![ret(reg(0))]),
    ];
    let build = |limits: Limits| try_build_with(spaces(), 0x1000, two.clone(), limits);
    assert_eq!(
        resource(build(limits(&|l| l.max_spaces = 3))),
        Resource::Spaces
    );
    assert_eq!(
        resource(build(limits(&|l| l.max_instructions = 1))),
        Resource::Instructions
    );
    assert_eq!(
        resource(build(limits(&|l| l.max_operations = 2))),
        Resource::Operations
    );
    assert_eq!(
        resource(build(limits(&|l| l.max_operand_refs = 4))),
        Resource::OperandRefs
    );
    assert_eq!(
        resource(build(limits(&|l| l.max_blocks = 0))),
        Resource::Blocks
    );
    assert_eq!(
        resource(build(limits(&|l| l.max_edges = 0))),
        Resource::Edges
    );
    assert_eq!(
        resource(build(limits(&|l| l.max_exits = 0))),
        Resource::Exits
    );
    assert_eq!(
        resource(build(limits(&|l| l.max_work = 10))),
        Resource::Work
    );
    assert!(matches!(
        build(limits(&|l| l.graph.max_nodes = 1)),
        Err(CfgError::Graph(ghidra_graph::Error::LimitExceeded {
            resource: ghidra_graph::Resource::Nodes
        }))
    ));
    assert!(matches!(
        build(limits(&|l| l.graph.max_work = 1)),
        Err(CfgError::Graph(ghidra_graph::Error::LimitExceeded {
            resource: ghidra_graph::Resource::Work
        }))
    ));

    // Huge operand lists are rejected by totals before any operand is checked:
    // every reference below names an undeclared space.
    let undeclared = vn(77, 0, 8);
    let wide = op(Opcode::Callother, None, vec![undeclared; MAX_INPUTS]);
    let result = try_build_with(
        spaces(),
        0x1000,
        vec![ins(0x1000, 4, vec![wide.clone(); 3])],
        limits(&|l| l.max_operand_refs = 2 * MAX_INPUTS),
    );
    assert_eq!(resource(result), Resource::OperandRefs);
    let mut too_wide = wide.clone();
    too_wide.inputs.push(undeclared);
    assert!(matches!(
        single(vec![too_wide]),
        Err(CfgError::OperationInputCount { count, .. }) if count == MAX_INPUTS + 1
    ));
    let too_long = PcodeInstruction {
        address: 0x1000,
        length: 4,
        ops: vec![copy(reg(0), undeclared); MAX_OPS_PER_INSTRUCTION + 1],
    };
    assert!(matches!(
        try_build(0x1000, vec![too_long]),
        Err(CfgError::InstructionOperationCount { .. })
    ));
}

#[test]
fn work_accounting_is_exact_and_deterministic() {
    let program = vec![
        ins(
            0x1000,
            4,
            vec![set_flag(0), cbranch(rel(-1), flag(0)), call(ram(0x9000))],
        ),
        ins(0x1004, 4, vec![op(Opcode::Callother, None, vec![c(1, 4)])]),
        ins(0x1008, 4, vec![ret(reg(0))]),
    ];
    let cfg = try_build(0x1000, program.clone()).unwrap();
    let work = cfg.build_work();
    assert!(work > 0);
    let mut limits = Limits {
        max_work: work,
        ..Limits::default()
    };
    let exact = try_build_with(spaces(), 0x1000, program.clone(), limits).unwrap();
    assert_eq!(exact.build_work(), work);
    limits.max_work = work - 1;
    assert_eq!(
        resource(try_build_with(spaces(), 0x1000, program.clone(), limits)),
        Resource::Work
    );
    let mut reversed = program;
    reversed.reverse();
    assert_eq!(try_build(0x1000, reversed).unwrap().build_work(), work);
}
