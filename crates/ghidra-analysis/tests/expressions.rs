use std::collections::BTreeMap;
use std::sync::Arc;

use ghidra_analysis::*;
use ghidra_cfg::{Cfg, CfgInput, ProgramPoint, Statement};
use ghidra_pcode::{
    AddressSpace, Endianness, Opcode, PcodeInstruction, PcodeOperation, SpaceId, SpaceKind, Value,
    Varnode, evaluate_pure, machine::Machine,
};
use ghidra_ssa::{EntryState, PhiPlacement, StatementId, ValueId, ValueOrigin};

fn var(space: u32, offset: u64, size: u32) -> Varnode {
    Varnode {
        space: SpaceId(space),
        offset,
        size,
    }
}
fn reg(offset: u64, size: u32) -> Varnode {
    var(2, offset, size)
}
fn con(value: u64, size: u32) -> Varnode {
    var(0, value, size)
}
fn op(opcode: Opcode, output: Option<Varnode>, inputs: Vec<Varnode>) -> PcodeOperation {
    PcodeOperation {
        opcode,
        output,
        inputs,
    }
}
fn copy(output: Varnode, input: Varnode) -> PcodeOperation {
    op(Opcode::Copy, Some(output), vec![input])
}
fn ins(address: u64, ops: Vec<PcodeOperation>) -> PcodeInstruction {
    PcodeInstruction {
        address,
        length: 4,
        ops,
    }
}
fn spaces(endian: Endianness, word: u32) -> Vec<AddressSpace> {
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
        word_size: if id == 1 { word } else { 1 },
        endianness: endian,
    })
    .collect()
}
fn analysis(
    instructions: Vec<PcodeInstruction>,
    endian: Endianness,
    options: AnalysisOptions,
) -> Arc<PcodeSsa> {
    analysis_with(spaces(endian, 1), instructions, options, &[])
}
fn analysis_with(
    spaces: Vec<AddressSpace>,
    instructions: Vec<PcodeInstruction>,
    options: AnalysisOptions,
    extra: &[Varnode],
) -> Arc<PcodeSsa> {
    // A separate byte-addressed code space permits word-addressed RAM tests.
    let mut spaces = spaces;
    spaces.push(AddressSpace {
        id: SpaceId(4),
        name: "code".into(),
        kind: SpaceKind::Other,
        address_size: 8,
        word_size: 1,
        endianness: Endianness::Little,
    });
    let cfg = Arc::new(
        Cfg::new(
            CfgInput::new(
                spaces,
                SpaceId(4),
                instructions
                    .iter()
                    .map(|instruction| instruction.address)
                    .min()
                    .unwrap(),
                instructions,
            ),
            Default::default(),
        )
        .unwrap(),
    );
    let analysis = Arc::new(PcodeSsa::new(cfg, extra, options, Default::default()).unwrap());
    analysis.ssa().verify(analysis.raw()).unwrap();
    analysis
}
fn sid(analysis: &PcodeSsa, address: u64, index: u32) -> StatementId {
    analysis
        .statement_id(ProgramPoint::new(address, index))
        .unwrap()
}
fn expressions(analysis: Arc<PcodeSsa>) -> PcodeExpressions {
    PcodeExpressions::new(analysis, Default::default()).unwrap()
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Concrete {
    Bits(Value),
    Memory(BTreeMap<u64, u8>),
}
fn bits(value: Concrete) -> Value {
    match value {
        Concrete::Bits(v) => v,
        _ => panic!("memory is not bits"),
    }
}
fn bytes_type(node: &ExpressionNode) -> usize {
    match node.ty {
        ExpressionType::Bits(n) => n as usize,
        _ => panic!("expected bits"),
    }
}
fn address(
    program: &PcodeExpressions,
    address: &ExpressionAddress,
    values: &[Option<Concrete>],
) -> Option<u64> {
    match address {
        ExpressionAddress::ByteOffset(offset) => Some(*offset),
        ExpressionAddress::Pointer {
            value, word_size, ..
        } => bits(eval(program, *value, values)?)
            .to_u64()?
            .checked_mul(u64::from(*word_size)),
    }
}
// Test interpreter: it evaluates terms, never inlines an SSA definition or
// derives reaching values. Terms have bounded depth independent of program size.
fn eval(
    program: &PcodeExpressions,
    id: ExpressionId,
    values: &[Option<Concrete>],
) -> Option<Concrete> {
    let node = program.node(id).unwrap();
    let value = match &node.kind {
        ExpressionKind::Constant(v) => Concrete::Bits(v.clone()),
        ExpressionKind::SsaValue(value) => return values[value.0].clone(),
        ExpressionKind::Join(parts) => {
            let mut bytes = vec![0; bytes_type(node)];
            let mut covered = vec![false; bytes.len()];
            for part in parts {
                let value = bits(eval(program, part.value, values)?).to_le_bytes();
                assert_eq!(value.len(), part.size as usize);
                let range = part.lsb_byte as usize..part.lsb_byte as usize + value.len();
                assert!(covered[range.clone()].iter().all(|b| !b));
                covered[range.clone()].fill(true);
                bytes[range].copy_from_slice(&value);
            }
            assert!(covered.iter().all(|b| *b));
            Concrete::Bits(Value::from_le_bytes(&bytes).unwrap())
        }
        ExpressionKind::Extract { value, lsb_byte } => {
            let bytes = bits(eval(program, *value, values)?).to_le_bytes();
            Concrete::Bits(
                Value::from_le_bytes(
                    &bytes[*lsb_byte as usize..*lsb_byte as usize + bytes_type(node)],
                )
                .unwrap(),
            )
        }
        ExpressionKind::Pure { opcode, inputs } => {
            let inputs = inputs
                .iter()
                .map(|value| eval(program, *value, values).map(bits))
                .collect::<Option<Vec<_>>>()?;
            Concrete::Bits(evaluate_pure(*opcode, &inputs, bytes_type(node) as u32).ok()?)
        }
        ExpressionKind::ReadMemory {
            version,
            address: pointer,
            endianness,
            ..
        } => {
            let Concrete::Memory(memory) = values[version.0].as_ref()? else {
                panic!()
            };
            let offset = address(program, pointer, values)?;
            let mut bytes = (0..bytes_type(node))
                .map(|i| memory.get(&(offset + i as u64)).copied())
                .collect::<Option<Vec<_>>>()?;
            if *endianness == Endianness::Big {
                bytes.reverse();
            }
            Concrete::Bits(Value::from_le_bytes(&bytes).unwrap())
        }
        ExpressionKind::WriteMemory {
            version,
            address: pointer,
            value,
            endianness,
            ..
        } => {
            let Concrete::Memory(mut memory) = values[version.0].clone()? else {
                panic!()
            };
            let offset = address(program, pointer, values)?;
            let mut bytes = bits(eval(program, *value, values)?).to_le_bytes();
            if *endianness == Endianness::Big {
                bytes.reverse();
            }
            for (index, byte) in bytes.into_iter().enumerate() {
                memory.insert(offset + index as u64, byte);
            }
            Concrete::Memory(memory)
        }
    };
    Some(value)
}

// Run straight-line terms and the real concrete Machine independently, comparing
// every defined scalar cell and complete observed memory state after each op.
fn compare_machine(program: &PcodeExpressions, machine: &mut Machine) -> usize {
    let analysis = program.analysis();
    let snapshot = machine.snapshot();
    let mut values = vec![None; analysis.ssa().values().len()];
    for (index, value) in analysis.ssa().values().iter().enumerate() {
        if value.origin != ValueOrigin::Entry(EntryState::Input) {
            continue;
        }
        values[index] = match &analysis.layout().variables()[value.variable.0].location {
            StorageLocation::Scalar {
                bank, offset, size, ..
            } => machine
                .read_varnode(&Varnode {
                    space: bank.space,
                    offset: *offset,
                    size: *size,
                })
                .ok()
                .map(Concrete::Bits),
            StorageLocation::Memory { space } => Some(Concrete::Memory(
                snapshot
                    .regions
                    .iter()
                    .filter(|r| r.space == *space)
                    .flat_map(|r| {
                        r.bytes
                            .iter()
                            .enumerate()
                            .map(|(i, b)| (r.offset + i as u64, *b))
                    })
                    .collect(),
            )),
        };
    }
    let mut comparisons = 0;
    for node in 0..analysis.ssa().graph().node_count() {
        let Some(block) = analysis.ssa().block(node).unwrap().renamed() else {
            continue;
        };
        assert!(block.phis().is_empty(), "straight-line oracle only");
        for (index, statement) in block.statements().iter().enumerate() {
            let id = StatementId { node, index };
            let next = statement
                .defs()
                .iter()
                .map(|value| match program.definition(*value).unwrap() {
                    ExpressionDefinition::Expression(root) => eval(program, *root, &values),
                    ExpressionDefinition::Undefined { .. } => None,
                    other => panic!("unexpected statement definition {other:?}"),
                })
                .collect::<Vec<_>>();
            if let Some(operation) = program.operation(id) {
                let Statement::Operation(source) =
                    analysis.cfg().statement(operation.point).unwrap()
                else {
                    panic!()
                };
                assert!(!matches!(
                    source.opcode,
                    Opcode::Branch | Opcode::Cbranch | Opcode::Branchind | Opcode::Return
                ));
                machine
                    .run(
                        &[ins(operation.point.address, vec![source.clone()])],
                        SpaceId(4),
                        operation.point.address,
                        10,
                    )
                    .unwrap();
            }
            for (&value, concrete) in statement.defs().iter().zip(next) {
                if let Some(concrete) = &concrete {
                    let variable = analysis.ssa().value(value).unwrap().variable;
                    match (
                        &analysis.layout().variables()[variable.0].location,
                        concrete,
                    ) {
                        (
                            StorageLocation::Scalar {
                                bank, offset, size, ..
                            },
                            Concrete::Bits(expected),
                        ) => {
                            assert_eq!(
                                &machine
                                    .read_varnode(&Varnode {
                                        space: bank.space,
                                        offset: *offset,
                                        size: *size
                                    })
                                    .unwrap(),
                                expected
                            );
                        }
                        (StorageLocation::Memory { space }, Concrete::Memory(expected)) => {
                            let actual: BTreeMap<_, _> = machine
                                .snapshot()
                                .regions
                                .into_iter()
                                .filter(|r| r.space == *space)
                                .flat_map(|r| {
                                    r.bytes
                                        .into_iter()
                                        .enumerate()
                                        .map(move |(i, b)| (r.offset + i as u64, b))
                                })
                                .collect();
                            assert_eq!(&actual, expected);
                        }
                        _ => panic!("sort mismatch"),
                    }
                    comparisons += 1;
                }
                values[value.0] = concrete;
            }
        }
    }
    comparisons
}

#[test]
fn partial_register_writes_reconstruct_joins_and_slices_in_both_orders() {
    for endian in [Endianness::Little, Endianness::Big] {
        let analysis = analysis(
            vec![ins(
                0x1000,
                vec![
                    copy(reg(0, 8), con(0x1122334455667788, 8)),
                    copy(reg(0, 1), con(0xaa, 1)),
                    copy(reg(16, 8), reg(0, 8)),
                ],
            )],
            endian,
            AnalysisOptions::native(),
        );
        let program = expressions(analysis.clone());
        assert!(
            program
                .nodes()
                .iter()
                .any(|n| matches!(n.kind, ExpressionKind::Join(_)))
        );
        assert!(
            program
                .nodes()
                .iter()
                .any(|n| matches!(n.kind, ExpressionKind::Extract { .. }))
        );
        let mut machine = Machine::new(analysis.cfg().spaces().to_vec(), 16_384).unwrap();
        assert_eq!(compare_machine(&program, &mut machine), 4);
        assert_eq!(
            machine.read_varnode(&reg(16, 8)).unwrap().to_u64(),
            Some(if endian == Endianness::Little {
                0x11223344556677aa
            } else {
                0xaa22334455667788
            })
        );
    }
}

#[test]
fn metadata_and_control_labels_keep_their_roles() {
    let analysis = analysis(
        vec![ins(
            0x1000,
            vec![
                op(
                    Opcode::Subpiece,
                    Some(reg(0, 2)),
                    vec![con(0x1122334455667788, 8), con(2, 4)],
                ),
                op(Opcode::Cbranch, None, vec![var(4, 0x2000, 8), reg(8, 1)]),
            ],
        )],
        Endianness::Little,
        AnalysisOptions::native(),
    );
    let program = expressions(analysis.clone());
    let operation = program.operation(sid(&analysis, 0x1000, 0)).unwrap();
    assert!(matches!(
        operation.operands[1],
        ExpressionOperand::ConstantMetadata { .. }
    ));
    assert_eq!(
        bits(
            eval(
                &program,
                operation.output.unwrap(),
                &vec![None; analysis.ssa().values().len()]
            )
            .unwrap()
        )
        .to_u64(),
        Some(0x5566)
    );
    let branch = program.operation(sid(&analysis, 0x1000, 1)).unwrap();
    assert!(
        matches!(branch.operands[0], ExpressionOperand::DirectTarget(target) if target.offset == 0x2000)
    );
    assert!(
        program
            .nodes()
            .iter()
            .all(|n| !matches!(n.kind, ExpressionKind::ReadMemory { .. }))
    );
}

#[test]
fn memory_versions_and_word_pointers_are_distinct_from_fixed_byte_offsets() {
    for endian in [Endianness::Little, Endianness::Big] {
        let analysis = analysis_with(
            spaces(endian, 4),
            vec![ins(
                0x1000,
                vec![
                    copy(var(1, 8, 4), con(0xaabbccdd, 4)),
                    op(
                        Opcode::Store,
                        None,
                        vec![con(1, 4), con(3, 8), con(0x11223344, 4)],
                    ),
                    op(Opcode::Load, Some(reg(0, 4)), vec![con(1, 4), con(3, 8)]),
                    copy(reg(8, 4), var(1, 8, 4)),
                    op(
                        Opcode::Load,
                        Some(var(1, 24, 4)),
                        vec![con(1, 4), con(3, 8)],
                    ),
                ],
            )],
            AnalysisOptions::native(),
            &[],
        );
        let program = expressions(analysis.clone());
        let mut machine = Machine::new(analysis.cfg().spaces().to_vec(), 16_384).unwrap();
        machine.map_bytes(SpaceId(1), 0, &[0x77; 32]).unwrap();
        assert_eq!(compare_machine(&program, &mut machine), 5);
        assert_eq!(
            machine.read_varnode(&reg(0, 4)).unwrap().to_u64(),
            Some(0x11223344)
        );
        assert_eq!(
            machine.read_varnode(&reg(8, 4)).unwrap().to_u64(),
            Some(0xaabbccdd)
        );
        assert!(program.nodes().iter().any(|n| matches!(
            n.kind,
            ExpressionKind::ReadMemory {
                address: ExpressionAddress::Pointer { word_size: 4, .. },
                ..
            }
        )));
        assert!(program.nodes().iter().any(|n| matches!(
            n.kind,
            ExpressionKind::ReadMemory {
                address: ExpressionAddress::ByteOffset(8),
                ..
            }
        )));
    }
}

#[test]
fn mixed_data_and_register_byte_orders_are_resolved_per_space() {
    let mut definitions = spaces(Endianness::Big, 1);
    definitions[2].endianness = Endianness::Little;
    let analysis = analysis_with(
        definitions,
        vec![ins(
            0x1000,
            vec![
                copy(var(1, 0, 8), con(0x1122334455667788, 8)),
                op(Opcode::Load, Some(reg(0, 8)), vec![con(1, 4), con(0, 8)]),
                copy(reg(0, 1), con(0xaa, 1)),
                copy(var(1, 32, 8), reg(0, 8)),
            ],
        )],
        AnalysisOptions::native(),
        &[],
    );
    let program = expressions(analysis.clone());
    let mut machine = Machine::new(analysis.cfg().spaces().to_vec(), 16_384).unwrap();
    assert!(compare_machine(&program, &mut machine) >= 5);
    assert_eq!(
        machine.read_bytes(SpaceId(1), 32, 8).unwrap(),
        [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0xaa]
    );
}

#[test]
fn undefined_temporaries_phi_cycles_and_opaque_outputs_stay_explicit() {
    let mut options = AnalysisOptions::native();
    options.unknown_effects = UnknownEffectPolicy::HavocAll;
    let analysis = analysis_with(
        spaces(Endianness::Little, 1),
        vec![
            ins(0x1000, vec![copy(var(3, 0, 1), con(7, 1))]),
            ins(
                0x1004,
                vec![
                    copy(reg(0, 1), var(3, 0, 1)),
                    op(
                        Opcode::Callother,
                        Some(reg(8, 1)),
                        vec![con(3, 4), reg(0, 1)],
                    ),
                ],
            ),
        ],
        options,
        &[reg(16, 8)],
    );
    let program = expressions(analysis.clone());
    let resets: Vec<_> = analysis
        .ssa()
        .values()
        .iter()
        .enumerate()
        .filter_map(|(i, _)| {
            matches!(
                program.definition(ValueId(i)).unwrap(),
                ExpressionDefinition::Undefined { .. }
            )
            .then_some(ValueId(i))
        })
        .collect();
    assert!(!resets.is_empty());
    let read = program.operation(sid(&analysis, 0x1004, 0)).unwrap();
    let ExpressionKind::SsaValue(value) = program
        .node(read.operands[0].expression().unwrap())
        .unwrap()
        .kind
    else {
        panic!()
    };
    assert!(matches!(
        program.definition(value).unwrap(),
        ExpressionDefinition::Undefined {
            instruction: 0x1004,
            ..
        }
    ));
    let opaque = program.operation(sid(&analysis, 0x1004, 1)).unwrap();
    assert!(matches!(opaque.operands[0], ExpressionOperand::Userop(3)));
    assert!(opaque.output.is_none());
    let renamed = analysis.ssa().statement(opaque.statement).unwrap();
    assert_eq!(renamed.defs().len(), analysis.layout().variables().len());
    for (slot, &value) in renamed.defs().iter().enumerate() {
        assert_eq!(
            program.definition(value).unwrap(),
            &ExpressionDefinition::Opaque {
                statement: opaque.statement,
                definition_slot: slot
            }
        );
    }
    let loop_analysis = analysis_with(
        spaces(Endianness::Little, 1),
        vec![ins(
            0x1000,
            vec![
                op(Opcode::IntAdd, Some(reg(0, 8)), vec![reg(0, 8), con(1, 8)]),
                op(Opcode::Branch, None, vec![var(4, 0x1000, 8)]),
            ],
        )],
        AnalysisOptions::native(),
        &[],
    );
    let program = expressions(loop_analysis.clone());
    assert_eq!(loop_analysis.ssa().phi_count(), 1);
    assert_eq!(
        program
            .nodes()
            .iter()
            .filter(|n| matches!(n.kind, ExpressionKind::SsaValue(_)))
            .count(),
        1
    );
    for (i, value) in loop_analysis.ssa().values().iter().enumerate() {
        if let ValueOrigin::Phi(phi) = value.origin {
            assert_eq!(
                program.definition(ValueId(i)).unwrap(),
                &ExpressionDefinition::Phi(phi)
            );
        }
    }
}

#[test]
fn processor_defined_segment_operations_require_opaque_semantics() {
    let source = vec![ins(
        0x1000,
        vec![op(
            Opcode::Segmentop,
            Some(reg(8, 4)),
            vec![con(1, 4), con(0x1000, 2), reg(0, 2)],
        )],
    )];
    let mut definitions = spaces(Endianness::Little, 1);
    definitions.push(AddressSpace {
        id: SpaceId(4),
        name: "code".into(),
        kind: SpaceKind::Other,
        address_size: 8,
        word_size: 1,
        endianness: Endianness::Little,
    });
    let cfg = Arc::new(
        Cfg::new(
            CfgInput::new(definitions, SpaceId(4), 0x1000, source.clone()),
            Default::default(),
        )
        .unwrap(),
    );
    assert!(matches!(
        PcodeSsa::new(cfg, &[], AnalysisOptions::native(), Default::default()),
        Err(AnalysisError::UnknownEffects {
            effects: EffectClass::AnalysisContext,
            ..
        })
    ));
    let mut options = AnalysisOptions::native();
    options.unknown_effects = UnknownEffectPolicy::HavocAll;
    let analysis = analysis(source, Endianness::Little, options);
    let program = expressions(analysis.clone());
    let operation = program.operation(sid(&analysis, 0x1000, 0)).unwrap();
    assert!(matches!(
        operation.operands[0],
        ExpressionOperand::SpaceSelector(SpaceId(1))
    ));
    assert!(matches!(
        operation.effects,
        AppliedEffects::Conservative(EffectClass::AnalysisContext)
    ));
    assert!(operation.output.is_none());
    assert!(operation.indirect_memory.is_none());
    assert!(
        analysis
            .layout()
            .variables()
            .iter()
            .all(|v| !matches!(v.location, StorageLocation::Memory { .. }))
    );
    assert!(program.nodes().iter().all(|n| !matches!(
        n.kind,
        ExpressionKind::Pure {
            opcode: Opcode::Segmentop,
            ..
        }
    )));
}

#[test]
fn all_opaque_effect_classes_keep_their_complete_ssa_dependencies() {
    let operations = [
        op(
            Opcode::Call,
            Some(var(1, 0x3000, 8)),
            vec![var(4, 0x2000, 8)],
        ),
        op(Opcode::Callind, Some(reg(8, 8)), vec![reg(0, 8)]),
        op(
            Opcode::Callother,
            Some(reg(8, 8)),
            vec![con(7, 4), reg(0, 8)],
        ),
        op(
            Opcode::Cpoolref,
            Some(reg(8, 8)),
            vec![con(0, 8), reg(0, 8)],
        ),
        op(Opcode::New, Some(reg(8, 8)), vec![con(16, 8)]),
        op(Opcode::Unimplemented, None, vec![]),
    ];
    for source in operations {
        let mut options = AnalysisOptions::native();
        options.unknown_effects = UnknownEffectPolicy::HavocAll;
        let analysis = analysis_with(
            spaces(Endianness::Little, 1),
            vec![ins(0x1000, vec![source])],
            options,
            &[reg(0, 8), reg(8, 8)],
        );
        let program = expressions(analysis.clone());
        let id = sid(&analysis, 0x1000, 0);
        let operation = program.operation(id).unwrap();
        assert!(matches!(operation.effects, AppliedEffects::Conservative(_)));
        assert!(operation.output.is_none());
        let statement = analysis.ssa().statement(id).unwrap();
        assert!(statement.uses().len() >= analysis.layout().variables().len());
        assert_eq!(statement.defs().len(), analysis.layout().variables().len());
        for (slot, &value) in statement.defs().iter().enumerate() {
            assert_eq!(
                program.definition(value).unwrap(),
                &ExpressionDefinition::Opaque {
                    statement: id,
                    definition_slot: slot
                }
            );
        }
    }
}

#[test]
fn repeated_operands_remain_separate_edges_and_faulting_operations_are_retained() {
    let analysis = analysis(
        vec![ins(
            0x1000,
            vec![
                copy(reg(0, 8), con(7, 8)),
                op(Opcode::IntAdd, Some(reg(8, 8)), vec![reg(0, 8), reg(0, 8)]),
                op(Opcode::IntDiv, Some(reg(16, 8)), vec![con(1, 8), con(0, 8)]),
            ],
        )],
        Endianness::Little,
        AnalysisOptions::native(),
    );
    let program = expressions(analysis.clone());
    let repeated = program.operation(sid(&analysis, 0x1000, 1)).unwrap();
    assert_eq!(repeated.operands.len(), 2);
    assert_eq!(repeated.operands[0], repeated.operands[1]);
    let ExpressionKind::Pure { opcode, inputs } =
        &program.node(repeated.output.unwrap()).unwrap().kind
    else {
        panic!()
    };
    assert_eq!(*opcode, Opcode::IntAdd);
    assert_eq!(inputs.len(), 2);
    let divide = program.operation(sid(&analysis, 0x1000, 2)).unwrap();
    assert!(matches!(
        program.node(divide.output.unwrap()).unwrap().kind,
        ExpressionKind::Pure {
            opcode: Opcode::IntDiv,
            ..
        }
    ));
    assert_eq!(
        eval(
            &program,
            divide.output.unwrap(),
            &vec![None; analysis.ssa().values().len()]
        ),
        None
    );
}

#[test]
fn maximum_width_joins_do_not_invent_or_drop_bytes() {
    for endian in [Endianness::Little, Endianness::Big] {
        let aliases: Vec<_> = (0..512).map(|offset| reg(offset, 1)).collect();
        let analysis = analysis_with(
            spaces(endian, 1),
            vec![ins(
                0x1000,
                vec![
                    copy(reg(0, 512), con(0x1122334455667788, 512)),
                    copy(reg(512, 512), reg(0, 512)),
                ],
            )],
            AnalysisOptions::native(),
            &aliases,
        );
        let program = expressions(analysis.clone());
        assert!(
            program.nodes().iter().any(
                |node| matches!(&node.kind, ExpressionKind::Join(pieces) if pieces.len() == 512)
            )
        );
        let mut machine = Machine::new(analysis.cfg().spaces().to_vec(), 16_384).unwrap();
        assert_eq!(compare_machine(&program, &mut machine), 513);
        assert_eq!(
            machine.read_varnode(&reg(512, 512)).unwrap(),
            Value::from_u64(512, 0x1122334455667788).unwrap()
        );
    }
}

#[test]
fn unreachable_operations_and_noops_add_no_expressions() {
    let analysis = analysis(
        vec![
            ins(
                0x1000,
                vec![op(Opcode::Branch, None, vec![var(4, 0x1008, 8)])],
            ),
            ins(0x1004, vec![copy(reg(0, 8), con(0x1234, 8))]),
            ins(0x1008, vec![]),
        ],
        Endianness::Little,
        AnalysisOptions::native(),
    );
    let program = expressions(analysis.clone());
    assert!(program.operation(sid(&analysis, 0x1004, 0)).is_none());
    assert!(program.operation(sid(&analysis, 0x1008, 0)).is_none());
    assert!(program.nodes().is_empty());
    assert_eq!(program.operations().count(), 1);
    let empty = analysis_with(
        spaces(Endianness::Little, 1),
        vec![ins(0x1000, vec![])],
        AnalysisOptions::native(),
        &[],
    );
    let limits = ExpressionLimits {
        max_values: 0,
        max_expression_nodes: 0,
        max_constant_bytes: 0,
        max_references: 0,
        ..Default::default()
    };
    let program = PcodeExpressions::new(empty, limits).unwrap();
    assert!(program.nodes().is_empty());
    assert_eq!(program.operations().count(), 0);
}

#[test]
fn input_order_does_not_change_ids_or_expression_work_in_either_ssa_mode() {
    let instructions = vec![
        ins(0x1000, vec![copy(reg(0, 8), con(8, 8))]),
        ins(
            0x1004,
            vec![copy(reg(16, 1), reg(0, 1)), copy(reg(24, 8), reg(0, 8))],
        ),
    ];
    for placement in [PhiPlacement::Unpruned, PhiPlacement::Pruned] {
        let mut options = AnalysisOptions::native();
        options.phi_placement = placement;
        let left = expressions(analysis(instructions.clone(), Endianness::Big, options));
        let right = expressions(analysis(
            instructions.iter().rev().cloned().collect(),
            Endianness::Big,
            options,
        ));
        assert_eq!(left.nodes(), right.nodes());
        assert_eq!(
            left.operations().collect::<Vec<_>>(),
            right.operations().collect::<Vec<_>>()
        );
        assert_eq!(left.build_work(), right.build_work());
        for index in 0..left.analysis().ssa().values().len() {
            assert_eq!(
                left.definition(ValueId(index)).unwrap(),
                right.definition(ValueId(index)).unwrap()
            );
        }
    }
}

fn next(seed: &mut u64) -> u64 {
    *seed = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *seed >> 16
}

#[test]
fn generated_alias_and_memory_programs_match_the_concrete_machine() {
    let mut seed = 0x24ae_734b_9876;
    let mut compared = 0;
    for case in 0..400 {
        let endian = if case % 2 == 0 {
            Endianness::Little
        } else {
            Endianness::Big
        };
        let word = [1, 2, 4, 8][(case / 2) % 4];
        let mut options = AnalysisOptions::native();
        if case % 3 == 0 {
            options.phi_placement = PhiPlacement::Unpruned;
        }
        let mut instructions = Vec::new();
        for index in 0..24 {
            let width = [1, 2, 4, 8, 16, 32][next(&mut seed) as usize % 6];
            let output = reg(next(&mut seed) % 64, width);
            let left = reg(next(&mut seed) % 64, width);
            let right = if next(&mut seed) & 1 == 0 {
                con(next(&mut seed), width)
            } else {
                reg(next(&mut seed) % 64, width)
            };
            let operation = match next(&mut seed) % 10 {
                0 => copy(output, right),
                1 => op(Opcode::IntAdd, Some(output), vec![left, right]),
                2 => op(Opcode::IntSub, Some(output), vec![left, right]),
                3 => op(Opcode::IntXor, Some(output), vec![left, right]),
                4 => op(Opcode::IntAnd, Some(output), vec![left, right]),
                5 => op(Opcode::IntMult, Some(output), vec![left, right]),
                6 => copy(var(1, next(&mut seed) % 96, width), left),
                7 => copy(output, var(1, next(&mut seed) % 96, width)),
                8 => op(
                    Opcode::Store,
                    None,
                    vec![con(1, 4), con(next(&mut seed) % 16, 8), right],
                ),
                _ => op(
                    Opcode::Load,
                    Some(output),
                    vec![con(1, 4), con(next(&mut seed) % 16, 8)],
                ),
            };
            instructions.push(ins(0x1000 + index * 4, vec![operation]));
        }
        let analysis = analysis_with(spaces(endian, word), instructions, options, &[]);
        let program = expressions(analysis.clone());
        let mut machine = Machine::new(analysis.cfg().spaces().to_vec(), 16_384).unwrap();
        let initial: Vec<_> = (0..160).map(|_| next(&mut seed) as u8).collect();
        machine.map_bytes(SpaceId(2), 0, &initial).unwrap();
        machine.map_bytes(SpaceId(1), 0, &initial).unwrap();
        compared += compare_machine(&program, &mut machine);
    }
    assert!(
        compared > 20_000,
        "{compared} disjoint scalar and memory definitions"
    );
}

#[test]
fn long_programs_keep_linear_terms_and_work_without_expanding_ssa() {
    fn build(count: usize) -> (usize, u64) {
        let instructions = (0..count)
            .map(|i| {
                ins(
                    0x1000 + i as u64 * 4,
                    vec![copy(reg(0, 8), con(i as u64, 8))],
                )
            })
            .collect();
        let program = expressions(analysis(
            instructions,
            Endianness::Little,
            AnalysisOptions::native(),
        ));
        assert_eq!(program.nodes().len(), 2 * count);
        assert_eq!(program.operations().count(), count);
        (program.nodes().len(), program.build_work())
    }
    let (small_nodes, small) = build(25_000);
    let (large_nodes, large) = build(50_000);
    assert_eq!(large_nodes, 2 * small_nodes);
    assert!(large <= 2 * small + 128, "work {small} -> {large}");
    fn send_sync<T: Send + Sync>() {}
    send_sync::<PcodeExpressions>();
}

#[test]
fn all_expression_limits_are_exact_and_invalid_lookups_are_errors() {
    let analysis = analysis(
        vec![ins(
            0x1000,
            vec![
                copy(reg(0, 8), con(1, 8)),
                op(Opcode::IntAdd, Some(reg(0, 8)), vec![reg(0, 8), con(2, 8)]),
            ],
        )],
        Endianness::Little,
        AnalysisOptions::native(),
    );
    let program = expressions(analysis.clone());
    let exact = ExpressionLimits {
        max_graph_nodes: analysis.ssa().graph().node_count(),
        max_values: analysis.ssa().values().len(),
        max_statements: 2,
        max_expression_nodes: program.nodes().len(),
        max_references: program.reference_count(),
        max_constant_bytes: program.constant_bytes(),
        max_work: program.build_work(),
    };
    assert!(PcodeExpressions::new(analysis.clone(), exact).is_ok());
    let mut limits = Vec::new();
    let mut below = exact;
    below.max_graph_nodes -= 1;
    limits.push(below);
    let mut below = exact;
    below.max_values -= 1;
    limits.push(below);
    let mut below = exact;
    below.max_statements -= 1;
    limits.push(below);
    let mut below = exact;
    below.max_expression_nodes -= 1;
    limits.push(below);
    let mut below = exact;
    below.max_references -= 1;
    limits.push(below);
    let mut below = exact;
    below.max_constant_bytes -= 1;
    limits.push(below);
    let mut below = exact;
    below.max_work -= 1;
    limits.push(below);
    for below in limits {
        assert!(matches!(
            PcodeExpressions::new(analysis.clone(), below),
            Err(ExpressionError::Limit(_))
        ));
    }
    for work in 0..exact.max_work {
        assert!(matches!(
            PcodeExpressions::new(
                analysis.clone(),
                ExpressionLimits {
                    max_work: work,
                    ..exact
                }
            ),
            Err(ExpressionError::Limit(_))
        ));
    }
    assert!(matches!(
        program.node(ExpressionId(usize::MAX)),
        Err(ExpressionError::UnknownExpression(_))
    ));
    assert!(matches!(
        program.definition(ValueId(usize::MAX)),
        Err(ExpressionError::UnknownValue(_))
    ));
    assert!(
        program
            .operation(StatementId {
                node: usize::MAX,
                index: usize::MAX
            })
            .is_none()
    );
    assert!(
        program
            .operation(StatementId {
                node: 0,
                index: usize::MAX
            })
            .is_none()
    );
}
