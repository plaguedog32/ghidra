use super::*;

fn space(id: u32, kind: SpaceKind, endian: Endianness, word_size: u32) -> AddressSpace {
    AddressSpace {
        id: SpaceId(id),
        name: format!("space{id}"),
        kind,
        address_size: 8,
        word_size,
        endianness: endian,
    }
}
fn machine() -> Machine {
    Machine::new(
        vec![
            space(0, SpaceKind::Constant, Endianness::Little, 1),
            space(1, SpaceKind::Ram, Endianness::Little, 1),
            space(2, SpaceKind::Register, Endianness::Little, 1),
            space(3, SpaceKind::Unique, Endianness::Little, 1),
        ],
        16 * PAGE_SIZE,
    )
    .unwrap()
}
fn node(space: u32, offset: u64, size: u32) -> Varnode {
    Varnode {
        space: SpaceId(space),
        offset,
        size,
    }
}
fn op(opcode: Opcode, output: Option<Varnode>, inputs: Vec<Varnode>) -> PcodeOperation {
    PcodeOperation {
        opcode,
        output,
        inputs,
    }
}

#[test]
fn integer_loop_uses_relative_operation_branches() {
    let mut state = machine();
    let sum = node(2, 0, 4);
    let counter = node(2, 4, 4);
    let condition = node(3, 0, 1);
    let program = [PcodeInstruction {
        address: 0x1000,
        length: 4,
        ops: vec![
            op(Opcode::Copy, Some(sum), vec![node(0, 0, 4)]),
            op(Opcode::Copy, Some(counter), vec![node(0, 3, 4)]),
            op(Opcode::IntAdd, Some(sum), vec![sum, counter]),
            op(Opcode::IntSub, Some(counter), vec![counter, node(0, 1, 4)]),
            op(
                Opcode::IntNotequal,
                Some(condition),
                vec![counter, node(0, 0, 4)],
            ),
            op(
                Opcode::Cbranch,
                None,
                vec![node(0, u32::MAX as u64 - 2, 4), condition],
            ),
        ],
    }];
    let result = state.run(&program, SpaceId(1), 0x1000, 100).unwrap();
    assert!(matches!(
        result.stop,
        StopReason::FallThrough {
            next_address: 0x1004
        }
    ));
    assert_eq!(result.operations, 14);
    assert_eq!(state.read_varnode(&sum).unwrap().to_u64(), Some(6));
}

#[test]
fn endian_word_addressed_load_store_and_register_aliasing() {
    let mut state = Machine::new(
        vec![
            space(0, SpaceKind::Constant, Endianness::Little, 1),
            space(1, SpaceKind::Ram, Endianness::Big, 2),
            space(2, SpaceKind::Register, Endianness::Little, 1),
        ],
        4 * PAGE_SIZE,
    )
    .unwrap();
    state.map_bytes(SpaceId(1), 6, &[0x12, 0x34]).unwrap();
    let register = node(2, 0, 2);
    let program = [PcodeInstruction {
        address: 0x1000,
        length: 4,
        ops: vec![
            op(
                Opcode::Load,
                Some(register),
                vec![node(0, 1, 4), node(0, 3, 8)],
            ),
            op(
                Opcode::Store,
                None,
                vec![node(0, 1, 4), node(0, 4, 8), register],
            ),
        ],
    }];
    state.run(&program, SpaceId(1), 0x1000, 10).unwrap();
    assert_eq!(
        state.read_varnode(&register).unwrap().to_u64(),
        Some(0x1234)
    );
    assert_eq!(
        state.read_varnode(&node(2, 0, 1)).unwrap().to_u64(),
        Some(0x34)
    );
    assert_eq!(state.read_bytes(SpaceId(1), 8, 2).unwrap(), [0x12, 0x34]);
}

#[test]
fn memory_limits_do_not_partially_write_and_unknown_bytes_are_errors() {
    let mut state = Machine::new(
        vec![
            space(0, SpaceKind::Constant, Endianness::Little, 1),
            space(1, SpaceKind::Ram, Endianness::Little, 1),
        ],
        PAGE_SIZE,
    )
    .unwrap();
    state.map_bytes(SpaceId(1), 0, &[7]).unwrap();
    assert!(matches!(
        state.map_bytes(SpaceId(1), 4095, &[1, 2]),
        Err(MachineError::MemoryLimit)
    ));
    assert!(matches!(
        state.read_bytes(SpaceId(1), 4095, 1),
        Err(MachineError::Uninitialized { .. })
    ));
    assert_eq!(state.read_bytes(SpaceId(1), 0, 1).unwrap(), [7]);
    assert!(matches!(
        state.map_bytes(SpaceId(0), 0, &[1]),
        Err(MachineError::ReadOnlySpace)
    ));
    assert!(state.read_varnode(&node(77, 0, 1)).is_err());
}

#[test]
fn pointers_and_direct_varnodes_use_distinct_word_scaling_rules() {
    let mut definition = space(1, SpaceKind::Ram, Endianness::Little, 2);
    definition.address_size = 1;
    let mut state = Machine::new(vec![definition], PAGE_SIZE).unwrap();
    state.map_bytes(SpaceId(1), 511, &[9]).unwrap();
    assert_eq!(
        state.read_varnode(&node(1, 511, 1)).unwrap().to_u64(),
        Some(9)
    );
    assert!(matches!(
        state.map_bytes(SpaceId(1), 512, &[9]),
        Err(MachineError::AddressOverflow)
    ));
}

#[test]
fn infinite_loop_is_bounded_and_trace_is_capped() {
    let mut state = machine();
    let program = [PcodeInstruction {
        address: 0x1000,
        length: 1,
        ops: vec![op(Opcode::Branch, None, vec![node(0, 0, 4)])],
    }];
    let result = state.run(&program, SpaceId(1), 0x1000, 5000).unwrap();
    assert_eq!(result.operations, 5000);
    assert!(matches!(
        result.stop,
        StopReason::BudgetExhausted {
            address: 0x1000,
            operation: 0
        }
    ));
    assert_eq!(result.trace.len(), MAX_TRACE);
    assert!(result.trace_truncated);
}

#[test]
fn calls_and_returns_transfer_without_inventing_native_stack_effects() {
    let mut state = machine();
    let program = [PcodeInstruction {
        address: 0x1000,
        length: 4,
        ops: vec![op(Opcode::Call, None, vec![node(1, 0x2000, 8)])],
    }];
    let result = state.run(&program, SpaceId(1), 0x1000, 10).unwrap();
    assert!(
        matches!(result.stop, StopReason::ExternalTransfer { target: 0x2000, ref kind } if kind == "call")
    );
    assert!(state.snapshot().regions.is_empty());
    let program = [PcodeInstruction {
        address: 0x1000,
        length: 4,
        ops: vec![op(Opcode::Return, None, vec![node(0, 0x3000, 8)])],
    }];
    let result = state.run(&program, SpaceId(1), 0x1000, 10).unwrap();
    assert!(
        matches!(result.stop, StopReason::ExternalTransfer { target: 0x3000, ref kind } if kind == "return")
    );
}

#[test]
fn literal_trap_returns_allow_narrow_targets_without_relaxing_computed_pointers() {
    for (size, raw, target) in [(1, 0, 0), (1, 0x1234, 0x34), (2, 0x1234, 0x1234)] {
        let mut state = machine();
        let program = [PcodeInstruction {
            address: 0x1000,
            length: 1,
            ops: vec![op(Opcode::Return, None, vec![node(0, raw, size)])],
        }];
        let result = state.run(&program, SpaceId(1), 0x1000, 10).unwrap();
        assert!(matches!(result.stop,
            StopReason::ExternalTransfer { target: actual, ref kind }
            if actual == target && kind == "return"));
        assert_eq!(result.operations, 1);
        assert!(state.snapshot().regions.is_empty());
    }
    for (opcode, target) in [
        (Opcode::Return, node(2, 0, 1)),
        (Opcode::Branchind, node(0, 0, 1)),
        (Opcode::Callind, node(0, 0, 1)),
    ] {
        let mut state = machine();
        state.map_bytes(SpaceId(2), 0, &[0]).unwrap();
        let program = [PcodeInstruction {
            address: 0x1000,
            length: 1,
            ops: vec![op(opcode, None, vec![target])],
        }];
        let error = state.run(&program, SpaceId(1), 0x1000, 10).unwrap_err();
        assert!(matches!(error, MachineError::At { source, .. }
            if matches!(*source, MachineError::InvalidProgram(_))));
    }
}

#[test]
fn malformed_programs_and_context_operations_fail_explicitly() {
    let mut state = machine();
    let instruction = PcodeInstruction {
        address: 0x1000,
        length: 4,
        ops: vec![op(Opcode::Copy, Some(node(2, 0, 4)), vec![])],
    };
    assert!(state.run(&[instruction], SpaceId(1), 0x1000, 10).is_err());
    let instruction = PcodeInstruction {
        address: 0x1000,
        length: 4,
        ops: vec![op(Opcode::Callother, None, vec![node(0, 0, 4)])],
    };
    assert!(matches!(
        state.run(&[instruction], SpaceId(1), 0x1000, 10),
        Err(MachineError::At { .. })
    ));
    assert!(state.snapshot().regions.is_empty());
    let instruction = PcodeInstruction {
        address: 0x1000,
        length: 4,
        ops: vec![],
    };
    assert!(
        state
            .run(&[instruction.clone(), instruction], SpaceId(1), 0x1000, 10)
            .is_err()
    );
}

#[test]
fn memory_snapshot_preserves_only_initialized_ranges() {
    let mut state = machine();
    state.map_bytes(SpaceId(1), 4095, &[1, 2, 3]).unwrap();
    state.map_bytes(SpaceId(1), 4100, &[8]).unwrap();
    let snapshot = state.snapshot().regions;
    assert_eq!(snapshot.len(), 2);
    assert_eq!(snapshot[0].offset, 4095);
    assert_eq!(snapshot[0].bytes, [1, 2, 3]);
    assert_eq!(snapshot[1].offset, 4100);
}

#[test]
fn transfer_ranges_and_pointer_widths_are_checked_before_access() {
    let mut narrow = space(1, SpaceKind::Ram, Endianness::Little, 1);
    narrow.address_size = 1;
    let mut state = Machine::new(
        vec![
            space(0, SpaceKind::Constant, Endianness::Little, 1),
            narrow,
            space(2, SpaceKind::Register, Endianness::Little, 1),
        ],
        4 * PAGE_SIZE,
    )
    .unwrap();
    state.map_bytes(SpaceId(1), 10, &[42]).unwrap();
    for operation in [
        op(Opcode::Branch, None, vec![node(1, 256, 1)]),
        op(Opcode::Branchind, None, vec![node(0, 10, 8)]),
        op(
            Opcode::Load,
            Some(node(2, 0, 1)),
            vec![node(0, 1, 4), node(0, 10, 8)],
        ),
    ] {
        let program = [PcodeInstruction {
            address: 0,
            length: 1,
            ops: vec![operation],
        }];
        assert!(state.run(&program, SpaceId(1), 0, 10).is_err());
    }
    assert!(state.read_varnode(&node(2, 0, 1)).is_err());
}

#[test]
fn snapshots_bound_fragmentation_and_total_output_bytes() {
    let mut state = Machine::new(
        vec![space(1, SpaceKind::Ram, Endianness::Little, 1)],
        2 * MAX_SNAPSHOT_BYTES,
    )
    .unwrap();
    for index in 0..=MAX_SNAPSHOT_REGIONS {
        state
            .map_bytes(SpaceId(1), (index * 2) as u64, &[1])
            .unwrap();
    }
    let fragmented = state.snapshot();
    assert!(fragmented.truncated);
    assert_eq!(fragmented.regions.len(), MAX_SNAPSHOT_REGIONS);
    state
        .map_bytes(SpaceId(1), 0, &vec![7; MAX_SNAPSHOT_BYTES + 1])
        .unwrap();
    let contiguous = state.snapshot();
    assert!(contiguous.truncated);
    assert_eq!(contiguous.regions.len(), 1);
    assert_eq!(contiguous.regions[0].bytes.len(), MAX_SNAPSHOT_BYTES);
}

#[test]
fn analysis_context_calls_are_rejected_instead_of_ignoring_return_values() {
    let mut state = machine();
    let program = [PcodeInstruction {
        address: 0x1000,
        length: 4,
        ops: vec![op(
            Opcode::Call,
            Some(node(2, 0, 8)),
            vec![node(1, 0x2000, 8)],
        )],
    }];
    assert!(state.run(&program, SpaceId(1), 0x1000, 10).is_err());
    assert!(state.snapshot().regions.is_empty());
}
