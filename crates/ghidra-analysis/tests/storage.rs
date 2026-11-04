use std::collections::BTreeMap;

use ghidra_analysis::*;
use ghidra_pcode::{
    AddressSpace, Endianness, Opcode, PcodeInstruction, PcodeOperation, SpaceId, SpaceKind, Value,
    Varnode, machine::Machine,
};

fn spaces(endian: Endianness) -> Vec<AddressSpace> {
    [
        (0, "const", SpaceKind::Constant),
        (1, "ram", SpaceKind::Ram),
        (2, "register", SpaceKind::Register),
        (3, "unique", SpaceKind::Unique),
    ]
    .into_iter()
    .map(|(id, name, kind)| AddressSpace {
        id: SpaceId(id),
        name: name.into(),
        kind,
        address_size: 8,
        word_size: 1,
        endianness: endian,
    })
    .collect()
}

fn node(space: u32, offset: u64, size: u32) -> Varnode {
    Varnode {
        space: SpaceId(space),
        offset,
        size,
    }
}
fn reg(offset: u64, size: u32) -> Varnode {
    node(2, offset, size)
}
fn constant(value: u64, size: u32) -> Varnode {
    node(0, value, size)
}
fn copy(output: Varnode, input: Varnode) -> PcodeOperation {
    PcodeOperation {
        opcode: Opcode::Copy,
        output: Some(output),
        inputs: vec![input],
    }
}
fn instruction(address: u64, ops: Vec<PcodeOperation>) -> PcodeInstruction {
    PcodeInstruction {
        address,
        length: 4,
        ops,
    }
}
fn scalar(layout: &StorageLayout, address: u64, node: Varnode) -> ScalarBinding {
    let ValueBinding::Scalar(binding) = layout.bind(address, node).unwrap() else {
        panic!("expected scalar")
    };
    binding
}
fn read(binding: &ScalarBinding, cells: &BTreeMap<StorageId, Value>) -> Value {
    let values: Vec<_> = binding
        .pieces()
        .iter()
        .map(|piece| cells[&piece.variable].clone())
        .collect();
    binding.compose(&values).unwrap()
}
fn write(binding: &ScalarBinding, cells: &mut BTreeMap<StorageId, Value>, value: &Value) {
    cells.extend(binding.split(value).unwrap());
}

#[test]
fn partial_register_writes_preserve_other_cells_without_implicit_zero_extension() {
    let registers = [reg(0, 8), reg(0, 4), reg(0, 2), reg(0, 1), reg(1, 1)];
    let spaces = spaces(Endianness::Little);
    let layout = StorageLayout::build(
        &spaces,
        &[],
        &registers,
        UniqueScope::Program,
        StorageLimits::default(),
    )
    .unwrap();
    let rax = scalar(&layout, 0, registers[0]);
    let eax = scalar(&layout, 0, registers[1]);
    let al = scalar(&layout, 0, registers[3]);
    let ah = scalar(&layout, 0, registers[4]);
    assert_eq!(
        rax.pieces().iter().map(|p| p.size).collect::<Vec<_>>(),
        [1, 1, 2, 4]
    );
    let mut cells = BTreeMap::new();
    write(
        &rax,
        &mut cells,
        &Value::from_u64(8, 0x1122334455667788).unwrap(),
    );
    write(&al, &mut cells, &Value::from_u64(1, 0xaa).unwrap());
    write(&ah, &mut cells, &Value::from_u64(1, 0xbb).unwrap());
    assert_eq!(read(&rax, &cells).to_u64(), Some(0x112233445566bbaa));
    write(&eax, &mut cells, &Value::from_u64(4, 0xdeadbeef).unwrap());
    assert_eq!(read(&rax, &cells).to_u64(), Some(0x11223344deadbeef));
    // Architectural x86 EAX zero-extension belongs to lifted P-code, not storage aliases.
    assert!(rax.compose(&[]).is_err());
    assert!(rax.split(&Value::from_u64(4, 1).unwrap()).is_err());
}

#[test]
fn overlapping_wide_registers_match_the_concrete_machine_in_both_byte_orders() {
    let mut seed = 0x123456789abcdefu64;
    let mut random = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for endian in [Endianness::Little, Endianness::Big] {
        let spaces = spaces(endian);
        let mut aliases = vec![reg(0, 64), reg(64, 64), reg(0, 128)];
        for _ in 0..120 {
            let start = random() % 128;
            let size = (1 + random() % (128 - start).min(32)) as u32;
            aliases.push(reg(start, size));
        }
        let layout = StorageLayout::build(
            &spaces,
            &[],
            &aliases,
            UniqueScope::Program,
            StorageLimits::default(),
        )
        .unwrap();
        let mut cells = BTreeMap::new();
        let mut machine = Machine::new(spaces, 65536).unwrap();
        let initial: Vec<_> = (0..128).map(|_| random() as u8).collect();
        let initial = Value::from_le_bytes(&initial).unwrap();
        write(&scalar(&layout, 0, aliases[2]), &mut cells, &initial);
        machine.write_varnode(&aliases[2], &initial).unwrap();
        for _ in 0..200 {
            let target = aliases[(random() as usize) % aliases.len()];
            let bytes: Vec<_> = (0..target.size).map(|_| random() as u8).collect();
            let value = Value::from_le_bytes(&bytes).unwrap();
            write(&scalar(&layout, 0, target), &mut cells, &value);
            machine.write_varnode(&target, &value).unwrap();
            for alias in &aliases {
                assert_eq!(
                    read(&scalar(&layout, 0, *alias), &cells),
                    machine.read_varnode(alias).unwrap()
                );
            }
        }
    }
}

#[test]
fn temporary_lifetime_is_explicit_and_instruction_scopes_do_not_alias() {
    let spaces = spaces(Endianness::Little);
    let temporary = node(3, 0, 4);
    let instructions = [
        instruction(0x1000, vec![copy(temporary, constant(1, 4))]),
        instruction(0x1004, vec![copy(temporary, constant(2, 4))]),
    ];
    let local = StorageLayout::build(
        &spaces,
        &instructions,
        &[],
        UniqueScope::Instruction,
        StorageLimits::default(),
    )
    .unwrap();
    assert_ne!(
        scalar(&local, 0x1000, temporary).pieces()[0].variable,
        scalar(&local, 0x1004, temporary).pieces()[0].variable
    );
    assert!(local.bind(0x1008, temporary).is_err());
    let global = StorageLayout::build(
        &spaces,
        &instructions,
        &[],
        UniqueScope::Program,
        StorageLimits::default(),
    )
    .unwrap();
    assert_eq!(
        scalar(&global, 0x1000, temporary),
        scalar(&global, 0x1004, temporary)
    );
}

#[test]
fn dynamic_and_direct_memory_accesses_share_one_state_per_space() {
    let mut spaces = spaces(Endianness::Little);
    spaces.push(AddressSpace {
        id: SpaceId(4),
        name: "other_ram".into(),
        kind: SpaceKind::Other,
        address_size: 8,
        word_size: 1,
        endianness: Endianness::Big,
    });
    let pointer = reg(0, 8);
    let value = reg(8, 4);
    let ops = vec![
        PcodeOperation {
            opcode: Opcode::Store,
            output: None,
            inputs: vec![constant(1, 4), pointer, value],
        },
        PcodeOperation {
            opcode: Opcode::Load,
            output: Some(value),
            inputs: vec![constant(1, 4), pointer],
        },
        copy(value, node(1, 0x2000, 4)),
        copy(node(1, 0x2010, 4), value),
        copy(value, node(4, 0x2000, 4)),
    ];
    let input = [instruction(0x1000, ops)];
    let layout = StorageLayout::build(
        &spaces,
        &input,
        &[],
        UniqueScope::Instruction,
        StorageLimits::default(),
    )
    .unwrap();
    let memory = layout.memory_variable(SpaceId(1)).unwrap();
    let other = layout.memory_variable(SpaceId(4)).unwrap();
    assert_ne!(memory, other);
    let store = layout
        .operation(0x1000, &input[0].ops[0])
        .unwrap()
        .def_use()
        .unwrap();
    assert!(store.uses.contains(&memory));
    assert_eq!(store.definitions, [memory]);
    for op in &input[0].ops[1..3] {
        let effects = layout.operation(0x1000, op).unwrap().def_use().unwrap();
        assert!(effects.uses.contains(&memory));
        assert!(!effects.definitions.contains(&memory));
    }
    let direct_write = layout
        .operation(0x1000, &input[0].ops[3])
        .unwrap()
        .def_use()
        .unwrap();
    assert!(direct_write.uses.contains(&memory));
    assert_eq!(direct_write.definitions, [memory]);
    assert!(
        layout
            .operation(0x1000, &input[0].ops[4])
            .unwrap()
            .def_use()
            .unwrap()
            .uses
            .contains(&other)
    );
}

#[test]
fn metadata_and_direct_control_targets_are_not_memory_reads() {
    let spaces = spaces(Endianness::Little);
    let branches = [instruction(
        0x1000,
        vec![
            PcodeOperation {
                opcode: Opcode::Branch,
                output: None,
                inputs: vec![node(1, u64::MAX, 8)],
            },
            PcodeOperation {
                opcode: Opcode::Cbranch,
                output: None,
                inputs: vec![constant(0xffff_fffd, 4), constant(1, 1)],
            },
        ],
    )];
    let layout = StorageLayout::build(
        &spaces,
        &branches,
        &[],
        UniqueScope::Program,
        StorageLimits::default(),
    )
    .unwrap();
    assert!(layout.variables().is_empty());
    assert!(matches!(
        layout
            .operation(0x1000, &branches[0].ops[0])
            .unwrap()
            .inputs[0],
        InputBinding::DirectTarget(_)
    ));
    let relative = layout.operation(0x1000, &branches[0].ops[1]).unwrap();
    assert_eq!(relative.inputs[0], InputBinding::RelativeTarget(-3));
    assert!(relative.def_use().unwrap().uses.is_empty());
    let ValueBinding::Constant(value) = layout.bind(0, constant(0x1ff, 1)).unwrap() else {
        panic!()
    };
    assert_eq!(value.to_u64(), Some(255));
}

#[test]
fn unknown_effects_cannot_silently_become_a_complete_def_use_summary() {
    let mut spaces = spaces(Endianness::Little);
    spaces.push(AddressSpace {
        id: SpaceId(4),
        name: "iop".into(),
        kind: SpaceKind::Other,
        address_size: 1,
        word_size: 1,
        endianness: Endianness::Little,
    });
    let operations = vec![
        PcodeOperation {
            opcode: Opcode::Call,
            output: Some(reg(0, 4)),
            inputs: vec![node(1, 0x2000, 8), reg(0, 4)],
        },
        PcodeOperation {
            opcode: Opcode::Callother,
            output: None,
            inputs: vec![constant(2, 4), reg(0, 4)],
        },
        PcodeOperation {
            opcode: Opcode::New,
            output: Some(reg(0, 8)),
            inputs: vec![constant(1, 8)],
        },
        PcodeOperation {
            opcode: Opcode::Indirect,
            output: Some(reg(0, 4)),
            inputs: vec![reg(0, 4), node(4, u64::MAX, 8)],
        },
        PcodeOperation {
            opcode: Opcode::Unimplemented,
            output: None,
            inputs: vec![],
        },
    ];
    let input = [instruction(0x1000, operations)];
    let layout = StorageLayout::build(
        &spaces,
        &input,
        &[],
        UniqueScope::Program,
        StorageLimits::default(),
    )
    .unwrap();
    assert!(layout.memory_variable(SpaceId(1)).is_none());
    assert!(layout.memory_variable(SpaceId(4)).is_none());
    for op in &input[0].ops {
        assert!(matches!(
            layout.operation(0x1000, op).unwrap().def_use(),
            Err(StorageError::UnknownEffects(_))
        ));
    }
    assert!(matches!(
        layout.operation(0x1000, &input[0].ops[3]).unwrap().inputs[1],
        InputBinding::OperationReference(_)
    ));
}

#[test]
fn partitions_do_not_cover_gaps_or_invent_partial_cell_writes() {
    let spaces = spaces(Endianness::Big);
    let layout = StorageLayout::build(
        &spaces,
        &[],
        &[reg(0, 4), reg(8, 4)],
        UniqueScope::Program,
        StorageLimits::default(),
    )
    .unwrap();
    for query in [reg(0, 1), reg(1, 3), reg(0, 12), reg(4, 4)] {
        assert!(layout.bind(0, query).is_err());
    }
    let refined = StorageLayout::build(
        &spaces,
        &[],
        &[reg(0, 4), reg(0, 1)],
        UniqueScope::Program,
        StorageLimits::default(),
    )
    .unwrap();
    assert_eq!(scalar(&refined, 0, reg(0, 1)).pieces()[0].value_offset, 0);
    assert_eq!(
        scalar(&refined, 0, reg(0, 4))
            .pieces()
            .iter()
            .map(|p| p.value_offset)
            .collect::<Vec<_>>(),
        [0, 3]
    );
}

#[test]
fn last_address_and_word_scaled_spaces_use_checked_byte_ranges() {
    let mut spaces = spaces(Endianness::Big);
    let layout = StorageLayout::build(
        &spaces,
        &[],
        &[reg(u64::MAX, 1)],
        UniqueScope::Program,
        StorageLimits::default(),
    )
    .unwrap();
    assert_eq!(scalar(&layout, 0, reg(u64::MAX, 1)).pieces().len(), 1);
    assert!(
        StorageLayout::build(
            &spaces,
            &[],
            &[reg(u64::MAX, 2)],
            UniqueScope::Program,
            StorageLimits::default()
        )
        .is_err()
    );
    spaces[2].address_size = 1;
    spaces[2].word_size = 4;
    let layout = StorageLayout::build(
        &spaces,
        &[],
        &[reg(1020, 4)],
        UniqueScope::Program,
        StorageLimits::default(),
    )
    .unwrap();
    assert!(layout.bind(0, reg(1020, 4)).is_ok());
    assert!(layout.bind(0, reg(1021, 4)).is_err());
    spaces[1].address_size = 1;
    spaces[1].word_size = 4;
    let load = PcodeOperation {
        opcode: Opcode::Load,
        output: Some(reg(1020, 4)),
        inputs: vec![constant(1, 4), constant(2, 1)],
    };
    let input = [instruction(0x1000, vec![load])];
    let layout = StorageLayout::build(
        &spaces,
        &input,
        &[],
        UniqueScope::Program,
        StorageLimits::default(),
    )
    .unwrap();
    assert_eq!(
        layout
            .operation(0x1000, &input[0].ops[0])
            .unwrap()
            .memory
            .unwrap()
            .space,
        SpaceId(1)
    );
}

#[test]
fn malformed_roles_ranges_and_limits_fail_without_partial_results() {
    let spaces = spaces(Endianness::Little);
    let valid = [instruction(0x1000, vec![copy(reg(0, 4), constant(1, 4))])];
    for limits in [
        StorageLimits {
            max_instructions: 0,
            ..Default::default()
        },
        StorageLimits {
            max_operations: 0,
            ..Default::default()
        },
        StorageLimits {
            max_operand_refs: 1,
            ..Default::default()
        },
        StorageLimits {
            max_events: 1,
            ..Default::default()
        },
        StorageLimits {
            max_variables: 0,
            ..Default::default()
        },
        StorageLimits {
            max_work: 0,
            ..Default::default()
        },
    ] {
        assert!(matches!(
            StorageLayout::build(&spaces, &valid, &[], UniqueScope::Program, limits),
            Err(StorageError::Limit(_))
        ));
    }
    let invalid = [
        copy(constant(1, 4), constant(1, 4)),
        copy(node(99, 0, 4), constant(1, 4)),
        PcodeOperation {
            opcode: Opcode::Load,
            output: Some(reg(0, 4)),
            inputs: vec![reg(8, 4), reg(0, 8)],
        },
        PcodeOperation {
            opcode: Opcode::Load,
            output: Some(reg(0, 4)),
            inputs: vec![constant(1, 4), reg(0, 4)],
        },
        PcodeOperation {
            opcode: Opcode::Subpiece,
            output: Some(reg(0, 1)),
            inputs: vec![reg(4, 4), reg(0, 4)],
        },
        PcodeOperation {
            opcode: Opcode::Load,
            output: Some(reg(0, 4)),
            inputs: vec![constant(2, 4), reg(0, 8)],
        },
        PcodeOperation {
            opcode: Opcode::Copy,
            output: Some(reg(0, 4)),
            inputs: vec![],
        },
    ];
    for op in invalid {
        assert!(
            StorageLayout::build(
                &spaces,
                &[instruction(0x1000, vec![op])],
                &[],
                UniqueScope::Program,
                StorageLimits::default()
            )
            .is_err()
        );
    }
    assert!(
        StorageLayout::build(
            &spaces,
            &[valid[0].clone(), valid[0].clone()],
            &[],
            UniqueScope::Program,
            StorageLimits::default()
        )
        .is_err()
    );
    let mut duplicate = spaces.clone();
    duplicate.push(spaces[0].clone());
    assert!(
        StorageLayout::build(
            &duplicate,
            &valid,
            &[],
            UniqueScope::Program,
            StorageLimits::default()
        )
        .is_err()
    );
}

#[test]
fn variable_identity_is_deterministic_and_large_temporary_domains_are_iterative() {
    let spaces = spaces(Endianness::Little);
    let mut input: Vec<_> = (0..10_000)
        .map(|i| instruction(0x1000 + i * 4, vec![copy(node(3, 0, 4), constant(i, 4))]))
        .collect();
    let first = StorageLayout::build(
        &spaces,
        &input,
        &[reg(8, 4), reg(0, 8)],
        UniqueScope::Instruction,
        StorageLimits::default(),
    )
    .unwrap();
    input.reverse();
    let second = StorageLayout::build(
        &spaces,
        &input,
        &[reg(0, 8), reg(8, 4)],
        UniqueScope::Instruction,
        StorageLimits::default(),
    )
    .unwrap();
    assert_eq!(first.variables(), second.variables());
    assert_eq!(first.variables().len(), 10_002);
    assert_eq!(
        serde_json::to_value(first.variables()).unwrap(),
        serde_json::to_value(second.variables()).unwrap()
    );
}

#[test]
fn overlapping_operation_inputs_remain_reads_before_simultaneous_definitions() {
    let spaces = spaces(Endianness::Little);
    let operation = PcodeOperation {
        opcode: Opcode::IntAdd,
        output: Some(reg(1, 4)),
        inputs: vec![reg(0, 4), reg(2, 4)],
    };
    let input = [instruction(0x1000, vec![operation])];
    let layout = StorageLayout::build(
        &spaces,
        &input,
        &[],
        UniqueScope::Program,
        StorageLimits::default(),
    )
    .unwrap();
    let bindings = layout.operation(0x1000, &input[0].ops[0]).unwrap();
    let def_use = bindings.def_use().unwrap();
    assert_eq!(
        def_use.uses.iter().map(|id| id.0).collect::<Vec<_>>(),
        [0, 1, 2, 2, 3, 4]
    );
    assert_eq!(
        def_use
            .definitions
            .iter()
            .map(|id| id.0)
            .collect::<Vec<_>>(),
        [1, 2, 3]
    );
}

#[test]
fn maximum_width_values_can_be_partitioned_into_all_byte_aliases() {
    let spaces = spaces(Endianness::Big);
    let mut aliases: Vec<_> = (0..512).map(|offset| reg(offset, 1)).collect();
    aliases.push(reg(0, 512));
    let layout = StorageLayout::build(
        &spaces,
        &[],
        &aliases,
        UniqueScope::Program,
        StorageLimits::default(),
    )
    .unwrap();
    assert_eq!(layout.variables().len(), 512);
    let whole = scalar(&layout, 0, reg(0, 512));
    let bytes: Vec<_> = (0..512).map(|i| (i % 251) as u8).collect();
    let value = Value::from_be_bytes(&bytes).unwrap();
    let mut cells = BTreeMap::new();
    write(&whole, &mut cells, &value);
    assert_eq!(read(&whole, &cells), value);
    for (offset, expected) in bytes.iter().copied().enumerate() {
        assert_eq!(
            read(&scalar(&layout, 0, reg(offset as u64, 1)), &cells).to_u64(),
            Some(u64::from(expected))
        );
    }
}

#[test]
fn big_endian_memory_load_does_not_change_little_endian_register_layout() {
    let mut spaces = spaces(Endianness::Little);
    spaces[1].endianness = Endianness::Big;
    let input = [instruction(
        0x1000,
        vec![PcodeOperation {
            opcode: Opcode::Load,
            output: Some(reg(0, 8)),
            inputs: vec![constant(1, 4), constant(0x2000, 8)],
        }],
    )];
    let layout = StorageLayout::build(
        &spaces,
        &input,
        &[reg(0, 4), reg(0, 1)],
        UniqueScope::Program,
        StorageLimits::default(),
    )
    .unwrap();
    let mut machine = Machine::new(spaces, 65536).unwrap();
    machine
        .map_bytes(
            SpaceId(1),
            0x2000,
            &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
        )
        .unwrap();
    machine.run(&input, SpaceId(1), 0x1000, 10).unwrap();
    let mut cells = BTreeMap::new();
    write(
        &scalar(&layout, 0, reg(0, 8)),
        &mut cells,
        &machine.read_varnode(&reg(0, 8)).unwrap(),
    );
    assert_eq!(
        read(&scalar(&layout, 0, reg(0, 4)), &cells).to_u64(),
        Some(0x55667788)
    );
    assert_eq!(
        read(&scalar(&layout, 0, reg(0, 1)), &cells).to_u64(),
        Some(0x88)
    );
}
