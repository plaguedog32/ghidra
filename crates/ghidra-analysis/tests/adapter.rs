use std::sync::Arc;

use ghidra_analysis::*;
use ghidra_cfg::{Arrival, Cfg, CfgInput, ProgramPoint};
use ghidra_pcode::{
    AddressSpace, Endianness, Opcode, PcodeInstruction, PcodeOperation, SpaceId, SpaceKind, Value,
    Varnode, evaluate_pure, machine::Machine,
};
use ghidra_ssa::{EntryState, Predecessor, StatementId, ValueId, ValueOrigin, VariableId};

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
fn branch(target: Varnode) -> PcodeOperation {
    op(Opcode::Branch, None, vec![target])
}
fn ins(address: u64, ops: Vec<PcodeOperation>) -> PcodeInstruction {
    PcodeInstruction {
        address,
        length: 4,
        ops,
    }
}
fn cfg(instructions: Vec<PcodeInstruction>, endian: Endianness) -> Arc<Cfg> {
    let entry = instructions[0].address;
    Arc::new(
        Cfg::new(
            CfgInput::new(spaces(endian), SpaceId(1), entry, instructions),
            Default::default(),
        )
        .unwrap(),
    )
}
fn build(cfg: Arc<Cfg>, options: AnalysisOptions) -> PcodeSsa {
    let result = PcodeSsa::new(cfg, &[], options, Default::default()).unwrap();
    result.ssa().verify(result.raw()).unwrap();
    result
}
fn id(result: &PcodeSsa, address: u64, index: u32) -> StatementId {
    result
        .statement_id(ProgramPoint::new(address, index))
        .unwrap()
}
fn scalar(result: &PcodeSsa, address: u64, node: Varnode) -> ScalarBinding {
    let ValueBinding::Scalar(binding) = result.layout().bind(address, node).unwrap() else {
        panic!()
    };
    binding
}

#[test]
fn alias_join_places_phis_only_on_modified_cells() {
    for endian in [Endianness::Little, Endianness::Big] {
        let result = build(
            cfg(
                vec![
                    ins(
                        0x1000,
                        vec![
                            copy(reg(0, 8), con(0x1122334455667788, 8)),
                            op(Opcode::Cbranch, None, vec![var(1, 0x1010, 8), reg(16, 1)]),
                        ],
                    ),
                    ins(
                        0x1004,
                        vec![copy(reg(0, 1), con(0xaa, 1)), branch(var(1, 0x1014, 8))],
                    ),
                    ins(0x1010, vec![copy(reg(0, 1), con(0xbb, 1))]),
                    ins(0x1014, vec![copy(reg(8, 8), reg(0, 8))]),
                ],
                endian,
            ),
            AnalysisOptions::native(),
        );
        let low = scalar(&result, 0x1014, reg(0, 1)).pieces()[0].variable;
        let wide = scalar(&result, 0x1014, reg(0, 8));
        assert_eq!(wide.pieces().len(), 2);
        let join = id(&result, 0x1014, 0);
        let block = result.ssa().block(join.node).unwrap().renamed().unwrap();
        assert!(block.phi_for(VariableId(low.0)).is_some());
        let high = wide
            .pieces()
            .iter()
            .find(|p| p.variable != low)
            .unwrap()
            .variable;
        assert!(block.phi_for(VariableId(high.0)).is_none());
        let init = id(&result, 0x1000, 0);
        let use_values = result.ssa().statement(join).unwrap().uses();
        assert!(
            use_values
                .iter()
                .any(|&v| matches!(result.ssa().value(v).unwrap().origin, ValueOrigin::Phi(_)))
        );
        assert!(
            use_values
                .iter()
                .any(|&v| matches!(result.ssa().value(v).unwrap().origin,
            ValueOrigin::Definition(site) if site.statement == init))
        );
    }
}

#[test]
fn direct_and_indirect_memory_reads_observe_the_store_version() {
    let result = build(
        cfg(
            vec![ins(
                0x1000,
                vec![
                    op(
                        Opcode::Store,
                        None,
                        vec![con(1, 4), con(0x3000, 8), con(42, 4)],
                    ),
                    op(
                        Opcode::Load,
                        Some(reg(0, 4)),
                        vec![con(1, 4), con(0x3000, 8)],
                    ),
                    copy(reg(4, 4), var(1, 0x3000, 4)),
                    copy(var(1, 0x3004, 4), reg(0, 4)),
                ],
            )],
            Endianness::Little,
        ),
        AnalysisOptions::native(),
    );
    let store = result.ssa().statement(id(&result, 0x1000, 0)).unwrap();
    let memory = result.layout().memory_variable(SpaceId(1)).unwrap();
    assert_eq!(
        result.ssa().value(store.defs()[0]).unwrap().variable,
        VariableId(memory.0)
    );
    assert_eq!(
        result
            .ssa()
            .statement(id(&result, 0x1000, 1))
            .unwrap()
            .uses(),
        store.defs()
    );
    assert_eq!(
        result
            .ssa()
            .statement(id(&result, 0x1000, 2))
            .unwrap()
            .uses(),
        store.defs()
    );
    let output = result.ssa().statement(id(&result, 0x1000, 3)).unwrap();
    assert!(output.uses().contains(&store.defs()[0]));
    assert_ne!(output.defs(), store.defs());
}

#[test]
fn unknown_effects_require_policy_and_havoc_remains_marked_opaque() {
    for operation in [
        op(Opcode::Call, None, vec![var(1, 0x8000, 8)]),
        op(
            Opcode::Callother,
            Some(reg(8, 8)),
            vec![con(7, 4), reg(0, 8)],
        ),
        op(Opcode::New, Some(reg(8, 8)), vec![con(1, 8)]),
        op(Opcode::Unimplemented, None, vec![]),
    ] {
        let cfg = cfg(
            vec![ins(
                0x1000,
                vec![operation, copy(reg(0, 8), var(1, 0x3000, 8))],
            )],
            Endianness::Little,
        );
        assert!(matches!(
            PcodeSsa::new(
                cfg.clone(),
                &[],
                AnalysisOptions::native(),
                Default::default()
            ),
            Err(AnalysisError::UnknownEffects {
                point: ProgramPoint {
                    address: 0x1000,
                    operation_index: 0
                },
                ..
            })
        ));
        let mut options = AnalysisOptions::native();
        options.unknown_effects = UnknownEffectPolicy::HavocAll;
        let result = PcodeSsa::new(cfg, &[reg(32, 8)], options, Default::default()).unwrap();
        result.ssa().verify(result.raw()).unwrap();
        let first = id(&result, 0x1000, 0);
        let statement = result.ssa().statement(first).unwrap();
        assert_eq!(statement.defs().len(), result.layout().variables().len());
        assert!(statement.uses().len() >= result.layout().variables().len());
        assert!(matches!(
            result.statement(first),
            Some(AdaptedStatement::Operation {
                effects: AppliedEffects::Conservative(_),
                ..
            })
        ));
        let extra = scalar(&result, 0x1000, reg(32, 8)).pieces()[0].variable;
        assert!(
            statement
                .defs()
                .iter()
                .any(|&v| result.ssa().value(v).unwrap().variable == VariableId(extra.0))
        );
    }
}

#[test]
fn native_reentry_resets_uniques_but_relative_backedges_keep_the_frame() {
    let result = build(
        cfg(
            vec![ins(
                0x1000,
                vec![
                    copy(reg(0, 1), var(3, 0, 1)),
                    copy(var(3, 0, 1), con(7, 1)),
                    op(
                        Opcode::Cbranch,
                        None,
                        vec![con((-2i32) as u32 as u64, 4), reg(8, 1)],
                    ),
                    branch(var(1, 0x1000, 8)),
                ],
            )],
            Endianness::Little,
        ),
        AnalysisOptions::native(),
    );
    let unique = scalar(&result, 0x1000, var(3, 0, 1)).pieces()[0].variable;
    let head = id(&result, 0x1000, 0);
    let block = result.ssa().block(head.node).unwrap().renamed().unwrap();
    let (_, phi) = block.phi_for(VariableId(unique.0)).unwrap();
    assert_eq!(block.incoming()[0], Predecessor::Entry);
    assert_eq!(
        result.ssa().value(phi.operands()[0]).unwrap().origin,
        ValueOrigin::Entry(EntryState::Undefined)
    );
    let mut saw_relative = false;
    let mut saw_native = false;
    for (edge_id, edge) in result.cfg().edges().iter().enumerate() {
        if edge.to != head.node {
            continue;
        }
        match edge.arrival {
            Arrival::SameInstruction => {
                saw_relative = true;
                assert_eq!(result.edge_reset(edge_id), None);
                let operand =
                    phi.operands()[block.incoming_index(Predecessor::Node(edge.from)).unwrap()];
                assert!(matches!(result.ssa().value(operand).unwrap().origin,
                    ValueOrigin::Definition(site) if site.statement == id(&result, 0x1000, 1)));
            }
            Arrival::InstructionEntry => {
                saw_native = true;
                let reset = result.edge_reset(edge_id).unwrap();
                assert!(reset >= result.cfg().node_count());
                let operand =
                    phi.operands()[block.incoming_index(Predecessor::Node(reset)).unwrap()];
                let ValueOrigin::Definition(site) = result.ssa().value(operand).unwrap().origin
                else {
                    panic!()
                };
                assert_eq!(site.statement.node, reset);
                assert!(matches!(
                    result.statement(site.statement),
                    Some(AdaptedStatement::UndefinedTemporaries {
                        address: 0x1000,
                        ..
                    })
                ));
            }
            Arrival::Exit => panic!(),
        }
    }
    assert!(saw_native && saw_relative);
}

#[test]
fn merged_blocks_reset_new_instruction_frames_and_noops_keep_source_identity() {
    let result = build(
        cfg(
            vec![
                ins(0x1000, vec![copy(var(3, 0, 1), con(5, 1))]),
                ins(0x1004, vec![]),
                ins(0x1008, vec![copy(reg(0, 1), var(3, 0, 1))]),
            ],
            Endianness::Little,
        ),
        AnalysisOptions::native(),
    );
    assert_eq!(result.cfg().block_count(), 1);
    assert!(matches!(
        result.statement(id(&result, 0x1004, 0)),
        Some(AdaptedStatement::NoOp { .. })
    ));
    let use_id = id(&result, 0x1008, 0);
    let value = result.ssa().statement(use_id).unwrap().uses()[0];
    let ValueOrigin::Definition(site) = result.ssa().value(value).unwrap().origin else {
        panic!()
    };
    assert_eq!(site.statement.node, use_id.node);
    assert!(site.statement.index < use_id.index);
    assert!(matches!(
        result.statement(site.statement),
        Some(AdaptedStatement::UndefinedTemporaries {
            address: 0x1008,
            ..
        })
    ));
    let first = scalar(&result, 0x1000, var(3, 0, 1)).pieces()[0].variable;
    let second = scalar(&result, 0x1008, var(3, 0, 1)).pieces()[0].variable;
    assert_ne!(first, second);
}

#[test]
fn program_scope_preserves_persistent_uniques_and_entry_policy_is_explicit() {
    let cfg = cfg(
        vec![
            ins(0x1000, vec![copy(var(3, 0, 1), con(5, 1))]),
            ins(
                0x1004,
                vec![copy(reg(0, 1), var(3, 0, 1)), branch(var(1, 0x1000, 8))],
            ),
        ],
        Endianness::Little,
    );
    let mut options = AnalysisOptions::pcode_program();
    options.entry.program_uniques = EntryState::Input;
    options.entry.registers = EntryState::Undefined;
    let result = build(cfg, options);
    assert_eq!(result.ssa().graph().node_count(), result.cfg().node_count());
    assert!(
        result
            .cfg()
            .edges()
            .iter()
            .enumerate()
            .all(|(i, _)| result.edge_reset(i).is_none())
    );
    let use_value = result
        .ssa()
        .statement(id(&result, 0x1004, 0))
        .unwrap()
        .uses()[0];
    assert!(matches!(result.ssa().value(use_value).unwrap().origin,
        ValueOrigin::Definition(site) if site.statement == id(&result, 0x1000, 0)));
    for variable in result.layout().variables() {
        let expected = match variable.location {
            StorageLocation::Scalar { bank, .. } if bank.space == SpaceId(3) => EntryState::Input,
            _ => EntryState::Undefined,
        };
        assert_eq!(result.raw().variables[variable.id.0], expected);
    }
}

#[test]
fn unreachable_operations_keep_metadata_without_renamed_values() {
    let result = build(
        cfg(
            vec![ins(
                0x1000,
                vec![branch(var(1, 0x8000, 8)), copy(reg(0, 1), con(5, 1))],
            )],
            Endianness::Little,
        ),
        AnalysisOptions::native(),
    );
    let dead = id(&result, 0x1000, 1);
    assert!(!result.ssa().block(dead.node).unwrap().is_reachable());
    assert!(result.ssa().statement(dead).is_err());
    assert!(matches!(
        result.statement(dead),
        Some(AdaptedStatement::Operation { .. })
    ));
    assert!(result.statement_id(ProgramPoint::new(0x2000, 0)).is_none());
    assert!(
        result
            .statement(StatementId {
                node: usize::MAX,
                index: 0
            })
            .is_none()
    );
}

#[test]
fn adapter_limits_and_work_fail_before_returning_a_partial_analysis() {
    let cfg = cfg(
        vec![ins(
            0x1000,
            vec![copy(reg(0, 8), var(3, 0, 8)), branch(var(1, 0x1000, 8))],
        )],
        Endianness::Little,
    );
    let make = |limits| PcodeSsa::new(cfg.clone(), &[], AnalysisOptions::native(), limits);
    let result = make(AnalysisLimits::default()).unwrap();
    let nodes = result.ssa().graph().node_count();
    let edges: usize = result
        .cfg()
        .edges()
        .iter()
        .enumerate()
        .map(|(i, _)| 1 + usize::from(result.edge_reset(i).is_some()))
        .sum();
    let statements: usize = result.raw().blocks.iter().map(Vec::len).sum();
    let refs: usize = result
        .raw()
        .blocks
        .iter()
        .flatten()
        .map(|s| s.uses.len() + s.defs.len())
        .sum();
    for (name, exact) in [
        ("nodes", nodes),
        ("edges", edges),
        ("statements", statements),
        ("operand references", refs),
    ] {
        let configure = |limit: &mut AnalysisLimits, value| match name {
            "nodes" => limit.max_nodes = value,
            "edges" => limit.max_edges = value,
            "statements" => limit.max_statements = value,
            _ => limit.max_operand_refs = value,
        };
        let mut limit = AnalysisLimits::default();
        configure(&mut limit, exact);
        assert!(make(limit).is_ok(), "exact {name}");
        configure(&mut limit, exact - 1);
        assert!(
            matches!(make(limit), Err(AnalysisError::Limit(actual)) if actual == name),
            "below {name}"
        );
    }
    assert!(
        make(AnalysisLimits {
            max_work: result.build_work(),
            ..Default::default()
        })
        .is_ok()
    );
    assert!(matches!(
        make(AnalysisLimits {
            max_work: result.build_work() - 1,
            ..Default::default()
        }),
        Err(AnalysisError::Limit("work"))
    ));
    assert!(matches!(
        make(AnalysisLimits {
            max_binding_parts: 0,
            ..Default::default()
        }),
        Err(AnalysisError::Limit("binding parts"))
    ));
    let mut options = AnalysisOptions::native();
    options.unknown_effects = UnknownEffectPolicy::HavocAll;
    let opaque = cfg::opaque_cfg();
    assert!(matches!(
        PcodeSsa::new(
            opaque,
            &[reg(16, 8)],
            options,
            AnalysisLimits {
                max_operand_refs: 1,
                ..Default::default()
            }
        ),
        Err(AnalysisError::Limit("operand references"))
    ));
}

mod cfg {
    use super::*;
    pub fn opaque_cfg() -> Arc<Cfg> {
        super::cfg(
            vec![ins(
                0x1000,
                vec![op(Opcode::Callother, None, vec![con(0, 4)])],
            )],
            Endianness::Little,
        )
    }
}

// Execute renamed values using the independently obtained concrete Machine
// trace. Phi assignment is simultaneous. Every SSA operand is compared to raw
// byte-addressed state before evaluating it; a stale-but-dominating value fails.
fn check_machine_trace(instructions: Vec<PcodeInstruction>, endian: Endianness, seed: u8) -> usize {
    let cfg = cfg(instructions, endian);
    let result = build(cfg.clone(), AnalysisOptions::pcode_program());
    let initial: Vec<_> = (0..64).map(|n| seed.wrapping_add(n)).collect();
    let mut reference = Machine::new(spaces(endian), 65536).unwrap();
    reference.map_bytes(SpaceId(2), 0, &initial).unwrap();
    let report = reference
        .run(cfg.instructions(), SpaceId(1), 0x1000, 3000)
        .unwrap();
    assert!(!report.trace_truncated);
    let mut concrete = Machine::new(spaces(endian), 65536).unwrap();
    concrete.map_bytes(SpaceId(2), 0, &initial).unwrap();
    let mut values: Vec<Option<Value>> = vec![None; result.ssa().values().len()];
    for variable in result.layout().variables() {
        if let StorageLocation::Scalar {
            bank, offset, size, ..
        } = variable.location
            && bank.space == SpaceId(2)
        {
            values[variable.id.0] = Some(concrete.read_varnode(&var(2, offset, size)).unwrap());
        }
    }
    let mut previous: Option<StatementId> = None;
    let mut comparisons = 0;
    for event in &report.trace {
        let point = ProgramPoint::new(event.address, event.operation as u32);
        let statement_id = result.statement_id(point).unwrap();
        let entering = previous
            .is_none_or(|last| last.node != statement_id.node || last.index >= statement_id.index);
        if entering {
            let block = result
                .ssa()
                .block(statement_id.node)
                .unwrap()
                .renamed()
                .unwrap();
            let predecessor =
                previous.map_or(Predecessor::Entry, |last| Predecessor::Node(last.node));
            let index = block.incoming_index(predecessor).unwrap();
            let assignments: Vec<_> = block
                .phis()
                .iter()
                .map(|phi| (phi.value(), values[phi.operands()[index].0].clone()))
                .collect();
            for (target, value) in assignments {
                values[target.0] = value;
            }
        }
        let AdaptedStatement::Operation {
            bindings,
            effects: AppliedEffects::Explicit,
            ..
        } = result.statement(statement_id).unwrap()
        else {
            panic!()
        };
        let renamed = result.ssa().statement(statement_id).unwrap();
        let mut use_slot = 0;
        let operation =
            &cfg.instruction_at(point.address).unwrap().ops[point.operation_index as usize];
        let mut inputs = Vec::new();
        for (index, binding) in bindings.inputs.iter().enumerate() {
            if let InputBinding::Value(binding) = binding {
                let value = match binding {
                    ValueBinding::Constant(value) => value.clone(),
                    ValueBinding::Scalar(binding) => {
                        let parts: Vec<_> = binding
                            .pieces()
                            .iter()
                            .map(|_| {
                                let value = values[renamed.uses()[use_slot].0]
                                    .clone()
                                    .expect("defined use");
                                use_slot += 1;
                                value
                            })
                            .collect();
                        binding.compose(&parts).unwrap()
                    }
                    _ => panic!("oracle only uses scalars"),
                };
                assert_eq!(
                    value,
                    concrete.read_varnode(&operation.inputs[index]).unwrap(),
                    "at {point}"
                );
                comparisons += 1;
                inputs.push(value);
            }
        }
        assert_eq!(use_slot, renamed.uses().len());
        if let Some(ValueBinding::Scalar(binding)) = &bindings.output {
            let value = evaluate_pure(operation.opcode, &inputs, binding.size()).unwrap();
            let parts = binding.split(&value).unwrap();
            assert_eq!(parts.len(), renamed.defs().len());
            for ((_, value), &target) in parts.into_iter().zip(renamed.defs()) {
                values[target.0] = Some(value);
            }
            concrete
                .run(
                    &[ins(point.address, vec![operation.clone()])],
                    SpaceId(1),
                    point.address,
                    1,
                )
                .unwrap();
            assert_eq!(
                value,
                concrete.read_varnode(&operation.output.unwrap()).unwrap()
            );
        } else {
            assert!(renamed.defs().is_empty());
        }
        previous = Some(statement_id);
    }
    assert_eq!(
        concrete.read_bytes(SpaceId(2), 0, 64).unwrap(),
        reference.read_bytes(SpaceId(2), 0, 64).unwrap()
    );
    comparisons
}

#[test]
fn renamed_aliases_and_loop_phis_match_concrete_machine_traces() {
    let mut comparisons = 0;
    for endian in [Endianness::Little, Endianness::Big] {
        for seed in 1..=24 {
            comparisons += check_machine_trace(
                vec![ins(
                    0x1000,
                    vec![
                        copy(reg(0, 8), con(u64::MAX - seed as u64, 8)),
                        copy(reg(8, 4), con(seed as u64, 4)),
                        op(Opcode::IntAdd, Some(reg(0, 2)), vec![reg(0, 2), con(1, 2)]),
                        copy(reg(16, 8), reg(0, 8)),
                        op(Opcode::IntSub, Some(reg(8, 4)), vec![reg(8, 4), con(1, 4)]),
                        op(
                            Opcode::IntNotequal,
                            Some(var(3, 0, 1)),
                            vec![reg(8, 4), con(0, 4)],
                        ),
                        op(
                            Opcode::Cbranch,
                            None,
                            vec![con((-4i32) as u32 as u64, 4), var(3, 0, 1)],
                        ),
                    ],
                )],
                endian,
                seed,
            );
        }
    }
    assert!(comparisons > 4000);
}

#[test]
fn long_native_loop_scopes_remain_iterative_and_bounded() {
    let count = 10_000;
    let instructions = (0..count)
        .map(|i| {
            ins(
                0x1000 + i * 4,
                vec![
                    copy(var(3, 0, 1), con(1, 1)),
                    branch(var(
                        1,
                        if i + 1 == count {
                            0x1000
                        } else {
                            0x1004 + i * 4
                        },
                        8,
                    )),
                ],
            )
        })
        .collect();
    let cfg = cfg(instructions, Endianness::Little);
    // Every lexical temp has a definition. Unpruned phi placement across this
    // huge loop is intentionally bounded rather than allowed quadratic output.
    let result = PcodeSsa::new(
        cfg,
        &[],
        AnalysisOptions::native(),
        AnalysisLimits {
            ssa: ghidra_ssa::Limits {
                max_phis: 100,
                ..Default::default()
            },
            ..Default::default()
        },
    );
    assert!(matches!(
        result,
        Err(AnalysisError::Ssa(ghidra_ssa::Error::LimitExceeded { .. }))
    ));
}

#[test]
fn ownership_and_statement_ids_remain_valid_after_input_is_dropped() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<PcodeSsa>();
    let result = build(
        cfg(
            vec![ins(0x1000, vec![copy(reg(0, 8), con(42, 8))])],
            Endianness::Little,
        ),
        AnalysisOptions::native(),
    );
    assert_eq!(result.cfg().instructions().len(), 1);
    assert_eq!(
        result
            .ssa()
            .statement(id(&result, 0x1000, 0))
            .unwrap()
            .defs(),
        &[ValueId(1)]
    );
}
