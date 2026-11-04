//! Headless access to native dataflow. This is an analysis schema, not a
//! decompiler-output or concrete-execution schema.
use std::{ffi::OsString, io::Write, path::Path, sync::Arc};

use ghidra_analysis::{
    AdaptedStatement, AnalysisLimits, AnalysisOptions, AppliedEffects, EffectClass,
    OperationBindings, PcodeSsa, StorageId, StorageVariable, UniqueScope, UnknownEffectPolicy,
};
use ghidra_cfg::{
    Arrival, CallTarget, Cfg, CfgInput, EdgeRole, Exit, ExitKind, NodeKind, ProgramPoint,
    TargetLocation,
};
use ghidra_graph::{ImmediateDominator, NaturalLoop, PostDominator};
use ghidra_pcode::{AddressSpace, PcodeInstruction, machine::ExecutionInput};
use ghidra_ssa::{EntryState, Predecessor, StatementId, ValueOrigin};
use serde::Serialize;

const MAX_OUTPUT: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CommandOptions {
    instruction_uniques: bool,
    havoc_unknown: bool,
}

impl CommandOptions {
    pub(crate) fn parse(args: impl IntoIterator<Item = OsString>) -> Result<Self, String> {
        let mut result = Self::default();
        for argument in args {
            match argument.to_str() {
                Some("--instruction-uniques") if !result.instruction_uniques => {
                    result.instruction_uniques = true;
                }
                Some("--havoc-unknown") if !result.havoc_unknown => result.havoc_unknown = true,
                _ => {
                    return Err(format!(
                        "Unknown or duplicate P-code analysis option: {}",
                        argument.to_string_lossy()
                    ));
                }
            }
        }
        Ok(result)
    }

    fn analysis(self) -> AnalysisOptions {
        let mut options = if self.instruction_uniques {
            AnalysisOptions::native()
        } else {
            AnalysisOptions::pcode_program()
        };
        if self.havoc_unknown {
            options.unknown_effects = UnknownEffectPolicy::HavocAll;
        }
        options
    }
}

pub(crate) fn execute(path: &Path, options: CommandOptions) -> Result<(), String> {
    let input = crate::pcode_cli::read_program(path)?;
    let json = analyze(input, options)?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&json).map_err(|e| e.to_string())?;
    writeln!(stdout).map_err(|e| e.to_string())
}

fn limits() -> AnalysisLimits {
    AnalysisLimits {
        max_nodes: 500_000,
        max_edges: 1_000_000,
        max_statements: 500_000,
        max_operand_refs: 4_000_000,
        graph: ghidra_graph::Limits {
            max_nodes: 500_000,
            max_edges: 1_000_000,
            max_frontier_entries: 1_000_000,
            max_loop_entries: 1_000_000,
            ..Default::default()
        },
        ssa: ghidra_ssa::Limits {
            max_variables: 250_000,
            max_statements: 500_000,
            max_operands: 4_000_000,
            max_values: 2_000_000,
            max_phis: 250_000,
            max_phi_operands: 2_000_000,
            ..Default::default()
        },
        ..Default::default()
    }
}

fn analyze(input: ExecutionInput, options: CommandOptions) -> Result<Vec<u8>, String> {
    let initializers = Initializers {
        regions: input.memory.len(),
        bytes: input.memory.iter().map(|region| region.bytes.len()).sum(),
        applied: false,
    };
    let limits = limits();
    let cfg = Arc::new(
        Cfg::new(
            CfgInput::new(
                input.spaces,
                input.code_space,
                input.entry,
                input.instructions,
            ),
            ghidra_cfg::Limits {
                max_instructions: limits.storage.max_instructions,
                max_operations: limits.storage.max_operations,
                max_operand_refs: limits.storage.max_operand_refs,
                max_blocks: limits.max_nodes,
                max_edges: limits.max_edges,
                max_exits: limits.max_nodes,
                graph: limits.graph,
                ..Default::default()
            },
        )
        .map_err(|e| e.to_string())?,
    );
    let analysis =
        PcodeSsa::new(cfg, &[], options.analysis(), limits).map_err(|e| e.to_string())?;
    analysis
        .ssa()
        .verify(analysis.raw())
        .map_err(|e| e.to_string())?;
    write_report(&analysis, initializers)
}

#[derive(Serialize)]
struct Point {
    address: u64,
    operation_index: u32,
}
impl From<ProgramPoint> for Point {
    fn from(point: ProgramPoint) -> Self {
        Self {
            address: point.address,
            operation_index: point.operation_index,
        }
    }
}

#[derive(Serialize)]
struct Initializers {
    regions: usize,
    bytes: usize,
    applied: bool,
}

#[derive(Serialize)]
struct Policies {
    unique_scope: &'static str,
    unknown_effects: &'static str,
    ssa_form: &'static str,
    ssa_verified: bool,
    memory_model: &'static str,
    initial_state: &'static str,
    concrete_initializers: Initializers,
    post_dominance: &'static str,
    userop_control_flow: &'static str,
}

#[derive(Serialize)]
struct Report<'a> {
    schema: &'static str,
    schema_version: u32,
    policies: Policies,
    entry: usize,
    spaces: &'a [AddressSpace],
    instructions: &'a [PcodeInstruction],
    variables: &'a [StorageVariable],
    cfg: CfgReport,
    nodes: Vec<NodeReport<'a>>,
    values: Vec<ValueReport>,
    natural_loops: Vec<LoopReport>,
}

#[derive(Serialize)]
struct CfgReport {
    entry: usize,
    block_count: usize,
    node_count: usize,
    edges: Vec<EdgeReport>,
    calls: Vec<CallReport>,
    userops: Vec<UseropReport>,
    gaps: Vec<(u64, u64)>,
}
#[derive(Serialize)]
struct EdgeReport {
    from: usize,
    to: usize,
    source: Point,
    role: &'static str,
    arrival: &'static str,
    reset_node: Option<usize>,
}
#[derive(Serialize)]
struct CallReport {
    point: Point,
    block: usize,
    target: CallTargetReport,
    continuation: usize,
    no_return: usize,
}
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum CallTargetReport {
    Direct {
        address: u64,
        location: &'static str,
        containing_instruction: Option<u64>,
    },
    Indirect,
}
#[derive(Serialize)]
struct UseropReport {
    point: Point,
    block: usize,
    userop: u64,
}
#[derive(Serialize)]
struct NodeReport<'a> {
    id: usize,
    source: NodeSource,
    successors: &'a [usize],
    reachable: bool,
    immediate_dominator: Parent,
    immediate_post_dominator: Parent,
    incoming: Vec<Incoming>,
    phis: Vec<PhiReport>,
    statements: Vec<StatementReport<'a>>,
}
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum NodeSource {
    Block { points: Vec<Point> },
    Exit { outcome: ExitReport },
    TemporaryReset { cfg_edge: usize },
}
#[derive(Serialize)]
struct ExitReport {
    from: usize,
    source: Point,
    role: &'static str,
    kind: &'static str,
    target: Option<u64>,
    containing_instruction: Option<u64>,
}
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Parent {
    Unreachable,
    Root,
    Node { node: usize },
    SyntheticExit,
}
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Incoming {
    Entry,
    Node { node: usize },
}
#[derive(Serialize)]
struct PhiReport {
    variable: usize,
    value: usize,
    operands: Vec<usize>,
}
#[derive(Serialize)]
struct StatementReport<'a> {
    index: usize,
    source: StatementSource<'a>,
    uses: Vec<usize>,
    definitions: Vec<usize>,
    renamed: Option<RenamedReport>,
}
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum StatementSource<'a> {
    Operation {
        point: Point,
        bindings: &'a OperationBindings,
        conservative_effects: Option<EffectClass>,
    },
    NoOp {
        point: Point,
    },
    UndefinedTemporaries {
        address: u64,
        variables: &'a [StorageId],
    },
}
#[derive(Serialize)]
struct RenamedReport {
    uses: Vec<usize>,
    definitions: Vec<usize>,
}
#[derive(Serialize)]
struct ValueReport {
    id: usize,
    variable: usize,
    origin: Origin,
}
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Origin {
    Entry {
        state: &'static str,
    },
    Phi {
        node: usize,
        index: usize,
    },
    Definition {
        node: usize,
        statement: usize,
        slot: usize,
    },
}
#[derive(Serialize)]
struct LoopReport {
    header: usize,
    latches: Vec<usize>,
    body: Vec<usize>,
}
impl From<NaturalLoop> for LoopReport {
    fn from(value: NaturalLoop) -> Self {
        Self {
            header: value.header,
            latches: value.latches,
            body: value.body,
        }
    }
}

fn write_report(analysis: &PcodeSsa, initializers: Initializers) -> Result<Vec<u8>, String> {
    let cfg = analysis.cfg();
    let ssa = analysis.ssa();
    let graph = ssa.graph();
    let dominators = graph.dominators(ssa.entry()).map_err(|e| e.to_string())?;
    let natural_loops = dominators
        .natural_loops()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(Into::into)
        .collect();
    let post = graph
        .post_dominators(cfg.exit_nodes())
        .map_err(|e| e.to_string())?;
    let mut reset_edges = vec![None; graph.node_count()];
    let edges = cfg
        .edges()
        .iter()
        .enumerate()
        .map(|(id, edge)| {
            let reset_node = analysis.edge_reset(id);
            if let Some(node) = reset_node {
                reset_edges[node] = Some(id);
            }
            EdgeReport {
                from: edge.from,
                to: edge.to,
                source: edge.source.into(),
                role: role(edge.role),
                arrival: match edge.arrival {
                    Arrival::SameInstruction => "same_instruction",
                    Arrival::InstructionEntry => "instruction_entry",
                    Arrival::Exit => "exit",
                },
                reset_node,
            }
        })
        .collect();
    let mut nodes = Vec::with_capacity(graph.node_count());
    for node in graph.nodes() {
        let block = ssa.block(node).map_err(|e| e.to_string())?;
        let renamed = block.renamed();
        let source = match cfg.node(node) {
            Some(NodeKind::Block(points)) => NodeSource::Block {
                points: points.iter().copied().map(Into::into).collect(),
            },
            Some(NodeKind::Exit(exit)) => NodeSource::Exit {
                outcome: exit_report(exit),
            },
            None => NodeSource::TemporaryReset {
                cfg_edge: reset_edges[node].expect("adapter reset node"),
            },
        };
        let mut statements = Vec::new();
        for (index, raw) in analysis.raw().blocks[node].iter().enumerate() {
            let id = StatementId { node, index };
            let source = match analysis.statement(id).expect("adapter statement") {
                AdaptedStatement::Operation {
                    point,
                    bindings,
                    effects,
                } => StatementSource::Operation {
                    point: (*point).into(),
                    bindings,
                    conservative_effects: match effects {
                        AppliedEffects::Explicit => None,
                        AppliedEffects::Conservative(class) => Some(*class),
                    },
                },
                AdaptedStatement::NoOp { point } => StatementSource::NoOp {
                    point: (*point).into(),
                },
                AdaptedStatement::UndefinedTemporaries { address, variables } => {
                    StatementSource::UndefinedTemporaries {
                        address: *address,
                        variables,
                    }
                }
            };
            let renamed = if renamed.is_some() {
                let renamed = ssa.statement(id).map_err(|e| e.to_string())?;
                Some(RenamedReport {
                    uses: renamed.uses().iter().map(|v| v.0).collect(),
                    definitions: renamed.defs().iter().map(|v| v.0).collect(),
                })
            } else {
                None
            };
            statements.push(StatementReport {
                index,
                source,
                uses: raw.uses.iter().map(|v| v.0).collect(),
                definitions: raw.defs.iter().map(|v| v.0).collect(),
                renamed,
            });
        }
        nodes.push(NodeReport {
            id: node,
            source,
            successors: graph.successors(node).map_err(|e| e.to_string())?,
            reachable: block.is_reachable(),
            immediate_dominator: match ssa.immediate_dominator(node).map_err(|e| e.to_string())? {
                ImmediateDominator::Unreachable => Parent::Unreachable,
                ImmediateDominator::Root => Parent::Root,
                ImmediateDominator::Parent(node) => Parent::Node { node },
            },
            immediate_post_dominator: match post
                .immediate_post_dominator(node)
                .map_err(|e| e.to_string())?
            {
                PostDominator::Unreachable => Parent::Unreachable,
                PostDominator::SyntheticExit => Parent::SyntheticExit,
                PostDominator::Node(node) => Parent::Node { node },
            },
            incoming: renamed.map_or_else(Vec::new, |b| {
                b.incoming()
                    .iter()
                    .map(|p| match p {
                        Predecessor::Entry => Incoming::Entry,
                        Predecessor::Node(node) => Incoming::Node { node: *node },
                    })
                    .collect()
            }),
            phis: renamed.map_or_else(Vec::new, |b| {
                b.phis()
                    .iter()
                    .map(|p| PhiReport {
                        variable: p.variable().0,
                        value: p.value().0,
                        operands: p.operands().iter().map(|v| v.0).collect(),
                    })
                    .collect()
            }),
            statements,
        });
    }
    let report = Report {
        schema: "ghidra-rs.pcode-analysis",
        schema_version: 1,
        policies: Policies {
            unique_scope: match analysis.options().unique_scope {
                UniqueScope::Program => "program",
                UniqueScope::Instruction => "instruction",
            },
            unknown_effects: match analysis.options().unknown_effects {
                UnknownEffectPolicy::Reject => "reject",
                UnknownEffectPolicy::HavocAll => "havoc_all_observed_storage",
            },
            ssa_form: "unpruned",
            ssa_verified: true,
            memory_model: "whole_address_space",
            initial_state: "symbolic_entry_declarations",
            concrete_initializers: initializers,
            post_dominance: "finite_paths_to_all_cfg_exits_including_call_no_return",
            userop_control_flow: "continuation_only_unmodeled_traps_or_nonreturn",
        },
        entry: ssa.entry(),
        spaces: cfg.spaces(),
        instructions: cfg.instructions(),
        variables: analysis.layout().variables(),
        cfg: CfgReport {
            entry: cfg.entry(),
            block_count: cfg.block_count(),
            node_count: cfg.node_count(),
            edges,
            calls: cfg
                .calls()
                .iter()
                .map(|call| CallReport {
                    point: call.point.into(),
                    block: call.block,
                    continuation: call.continuation,
                    no_return: call.no_return,
                    target: match call.target {
                        CallTarget::Indirect => CallTargetReport::Indirect,
                        CallTarget::Direct { address, location } => {
                            let (location, containing_instruction) = match location {
                                TargetLocation::InstructionStart => ("instruction_start", None),
                                TargetLocation::InstructionInterior { instruction } => {
                                    ("instruction_interior", Some(instruction))
                                }
                                TargetLocation::NotSupplied => ("not_supplied", None),
                            };
                            CallTargetReport::Direct {
                                address,
                                location,
                                containing_instruction,
                            }
                        }
                    },
                })
                .collect(),
            userops: cfg
                .userops()
                .iter()
                .map(|u| UseropReport {
                    point: u.point.into(),
                    block: u.block,
                    userop: u.userop,
                })
                .collect(),
            gaps: cfg.gaps().iter().map(|g| (g.start, g.end)).collect(),
        },
        nodes,
        values: ssa
            .values()
            .iter()
            .enumerate()
            .map(|(id, value)| ValueReport {
                id,
                variable: value.variable.0,
                origin: match value.origin {
                    ValueOrigin::Entry(state) => Origin::Entry {
                        state: match state {
                            EntryState::Input => "input",
                            EntryState::Undefined => "undefined",
                        },
                    },
                    ValueOrigin::Phi(phi) => Origin::Phi {
                        node: phi.node,
                        index: phi.index,
                    },
                    ValueOrigin::Definition(site) => Origin::Definition {
                        node: site.statement.node,
                        statement: site.statement.index,
                        slot: site.slot,
                    },
                },
            })
            .collect(),
        natural_loops,
    };
    let mut output = LimitedOutput {
        bytes: Vec::new(),
        maximum: MAX_OUTPUT,
    };
    serde_json::to_writer_pretty(&mut output, &report).map_err(|e| e.to_string())?;
    Ok(output.bytes)
}

fn role(role: EdgeRole) -> &'static str {
    match role {
        EdgeRole::Fallthrough => "fallthrough",
        EdgeRole::Branch => "branch",
        EdgeRole::ConditionFalse => "condition_false",
        EdgeRole::ConditionTrue => "condition_true",
        EdgeRole::IndirectBranch => "indirect_branch",
        EdgeRole::CallReturn => "call_return",
        EdgeRole::CallNoReturn => "call_no_return",
        EdgeRole::Return => "return",
        EdgeRole::Unimplemented => "unimplemented",
    }
}

fn exit_report(exit: &Exit) -> ExitReport {
    let (kind, target, containing_instruction) = match exit.kind {
        ExitKind::Return => ("return", None, None),
        ExitKind::OutsideFallthrough { target } => ("outside_fallthrough", Some(target), None),
        ExitKind::SpaceEndFallthrough => ("space_end_fallthrough", None, None),
        ExitKind::ExternalBranch { target } => ("external_branch", Some(target), None),
        ExitKind::InteriorBranch {
            target,
            instruction,
        } => ("interior_branch", Some(target), Some(instruction)),
        ExitKind::UnresolvedIndirectBranch => ("unresolved_indirect_branch", None, None),
        ExitKind::CallNoReturn => ("call_no_return", None, None),
        ExitKind::Unimplemented => ("unimplemented", None, None),
    };
    ExitReport {
        from: exit.from,
        source: exit.source.into(),
        role: role(exit.role),
        kind,
        target,
        containing_instruction,
    }
}

struct LimitedOutput {
    bytes: Vec<u8>,
    maximum: usize,
}
impl Write for LimitedOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other("P-code analysis JSON exceeds 64 MiB"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ghidra_pcode::{Opcode, PcodeOperation, SpaceId, Varnode};
    use serde_json::Value;

    fn input() -> ExecutionInput {
        serde_json::from_str(include_str!("../../../examples/pcode/sum-loop.json")).unwrap()
    }
    fn report(input: ExecutionInput, options: CommandOptions) -> Value {
        serde_json::from_slice(&analyze(input, options).unwrap()).unwrap()
    }
    fn var(space: u32, offset: u64, size: u32) -> Varnode {
        Varnode {
            space: SpaceId(space),
            offset,
            size,
        }
    }
    fn branch(opcode: Opcode, target: Varnode) -> PcodeOperation {
        PcodeOperation {
            opcode,
            output: None,
            inputs: vec![target],
        }
    }
    fn validate_references(report: &Value) {
        let nodes = report["nodes"].as_array().unwrap();
        let values = report["values"].as_array().unwrap();
        let vars = report["variables"].as_array().unwrap();
        for (index, node) in nodes.iter().enumerate() {
            assert_eq!(node["id"], index);
            for successor in node["successors"].as_array().unwrap() {
                assert!(successor.as_u64().unwrap() < nodes.len() as u64);
            }
            let incoming = node["incoming"].as_array().unwrap();
            for phi in node["phis"].as_array().unwrap() {
                assert_eq!(phi["operands"].as_array().unwrap().len(), incoming.len());
                assert!(phi["variable"].as_u64().unwrap() < vars.len() as u64);
                assert!(phi["value"].as_u64().unwrap() < values.len() as u64);
                for operand in phi["operands"].as_array().unwrap() {
                    assert!(operand.as_u64().unwrap() < values.len() as u64);
                }
            }
            for statement in node["statements"].as_array().unwrap() {
                for field in ["uses", "definitions"] {
                    for var in statement[field].as_array().unwrap() {
                        assert!(var.as_u64().unwrap() < vars.len() as u64);
                    }
                    if !statement["renamed"].is_null() {
                        assert_eq!(
                            statement[field].as_array().unwrap().len(),
                            statement["renamed"][field].as_array().unwrap().len()
                        );
                        for value in statement["renamed"][field].as_array().unwrap() {
                            assert!(value.as_u64().unwrap() < values.len() as u64);
                        }
                    }
                }
            }
        }
        for (index, value) in values.iter().enumerate() {
            assert_eq!(value["id"], index);
            assert!(value["variable"].as_u64().unwrap() < vars.len() as u64);
            let origin = &value["origin"];
            match origin["kind"].as_str().unwrap() {
                "entry" => assert!(matches!(
                    origin["state"].as_str(),
                    Some("input" | "undefined")
                )),
                "phi" => {
                    let phi = &nodes[origin["node"].as_u64().unwrap() as usize]["phis"]
                        [origin["index"].as_u64().unwrap() as usize];
                    assert_eq!(phi["value"], index);
                }
                "definition" => {
                    let statement = &nodes[origin["node"].as_u64().unwrap() as usize]["statements"]
                        [origin["statement"].as_u64().unwrap() as usize];
                    assert_eq!(
                        statement["renamed"]["definitions"]
                            [origin["slot"].as_u64().unwrap() as usize],
                        index
                    );
                }
                other => panic!("unknown origin {other}"),
            }
        }
    }

    #[test]
    fn sum_loop_schema_links_points_phi_values_and_terminal_outcomes() {
        let report = report(input(), CommandOptions::default());
        assert_eq!(report["schema"], "ghidra-rs.pcode-analysis");
        assert_eq!(report["schema_version"], 1);
        assert_eq!(report["policies"]["unique_scope"], "program");
        assert_eq!(report["policies"]["ssa_form"], "unpruned");
        assert_eq!(report["policies"]["ssa_verified"], true);
        assert_eq!(report["natural_loops"].as_array().unwrap().len(), 1);
        let header = report["natural_loops"][0]["header"].as_u64().unwrap() as usize;
        assert!(
            !report["nodes"][header]["phis"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert!(
            report["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|n| n["source"]["kind"] == "exit"
                    && n["source"]["outcome"]["kind"] == "outside_fallthrough")
        );
        validate_references(&report);
    }

    #[test]
    fn alias_branch_retains_both_symbolic_paths_and_concrete_initializers_are_not_applied() {
        let input: ExecutionInput =
            serde_json::from_str(include_str!("../../../examples/pcode/alias-branch.json"))
                .unwrap();
        let mut machine = ghidra_pcode::machine::Machine::new(input.spaces.clone(), 65536).unwrap();
        for memory in &input.memory {
            machine
                .map_bytes(memory.space, memory.offset, &memory.bytes)
                .unwrap();
        }
        machine
            .run(
                &input.instructions,
                input.code_space,
                input.entry,
                input.max_operations,
            )
            .unwrap();
        assert_eq!(
            machine.read_varnode(&var(2, 8, 8)).unwrap().to_u64(),
            Some(0x11223344556677bb)
        );
        let report = report(input, CommandOptions::default());
        let initial = &report["policies"]["concrete_initializers"];
        assert_eq!(initial["regions"], 1);
        assert_eq!(initial["bytes"], 1);
        assert_eq!(initial["applied"], false);
        let nodes = report["nodes"].as_array().unwrap();
        let join = nodes
            .iter()
            .find(|n| {
                n["source"]["points"]
                    .as_array()
                    .is_some_and(|ps| ps.iter().any(|p| p["address"] == 4112))
            })
            .unwrap();
        assert_eq!(join["phis"].as_array().unwrap().len(), 1);
        assert_eq!(join["phis"][0]["operands"].as_array().unwrap().len(), 2);
        assert_eq!(
            join["statements"][0]["renamed"]["uses"]
                .as_array()
                .unwrap()
                .len(),
            2
        );
        assert!(nodes.iter().all(|n| n["reachable"] == true));
        validate_references(&report);
    }

    #[test]
    fn instruction_scope_exports_reset_nodes_and_infinite_loops_have_no_postdominator() {
        let mut input = input();
        input.instructions[0]
            .ops
            .push(branch(Opcode::Branch, var(1, 0x1000, 8)));
        let report = report(
            input,
            CommandOptions {
                instruction_uniques: true,
                ..Default::default()
            },
        );
        assert_eq!(report["policies"]["unique_scope"], "instruction");
        let nodes = report["nodes"].as_array().unwrap();
        assert!(
            nodes
                .iter()
                .any(|n| n["source"]["kind"] == "temporary_reset")
        );
        assert!(
            nodes
                .iter()
                .all(|n| n["immediate_post_dominator"]["kind"] == "unreachable")
        );
        for edge in report["cfg"]["edges"].as_array().unwrap() {
            if edge["arrival"] == "same_instruction" {
                assert!(edge["reset_node"].is_null());
            }
            if let Some(reset) = edge["reset_node"].as_u64() {
                assert_eq!(nodes[reset as usize]["source"]["kind"], "temporary_reset");
                assert_eq!(
                    nodes[reset as usize]["statements"][0]["source"]["kind"],
                    "undefined_temporaries"
                );
            }
        }
        validate_references(&report);
    }

    #[test]
    fn opaque_calls_are_rejected_or_exported_with_explicit_conservative_effects() {
        let mut input = input();
        input.instructions[0]
            .ops
            .insert(0, branch(Opcode::Call, var(1, 0x8000, 8)));
        // Remove relative branches so that prepending the call doesn't change
        // the intentionally tiny function's control labels.
        input.instructions[0].ops.pop();
        assert!(
            analyze(input.clone(), CommandOptions::default())
                .unwrap_err()
                .contains("Call")
        );
        let report = report(
            input,
            CommandOptions {
                havoc_unknown: true,
                ..Default::default()
            },
        );
        assert_eq!(
            report["policies"]["unknown_effects"],
            "havoc_all_observed_storage"
        );
        assert_eq!(report["cfg"]["calls"].as_array().unwrap().len(), 1);
        assert_eq!(report["cfg"]["calls"][0]["target"]["address"], 0x8000);
        let first = &report["nodes"][0]["statements"][0];
        assert_eq!(first["source"]["conservative_effects"], "Call");
        assert_eq!(
            first["definitions"].as_array().unwrap().len(),
            report["variables"].as_array().unwrap().len()
        );
        assert!(
            report["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .any(|n| n["source"]["outcome"]["kind"] == "call_no_return")
        );
        validate_references(&report);
    }

    #[test]
    fn noops_unreachable_operations_and_indirect_exits_remain_distinct() {
        let mut input = input();
        input.instructions = vec![
            PcodeInstruction {
                address: 0x1000,
                length: 4,
                ops: vec![],
            },
            PcodeInstruction {
                address: 0x1004,
                length: 4,
                ops: vec![
                    branch(Opcode::Branchind, var(2, 16, 8)),
                    PcodeOperation {
                        opcode: Opcode::Copy,
                        output: Some(var(2, 0, 1)),
                        inputs: vec![var(0, 5, 1)],
                    },
                ],
            },
        ];
        let report = report(input, CommandOptions::default());
        let nodes = report["nodes"].as_array().unwrap();
        assert!(nodes.iter().any(|n| {
            n["statements"]
                .as_array()
                .unwrap()
                .iter()
                .any(|s| s["source"]["kind"] == "no_op")
        }));
        let dead = nodes.iter().find(|n| n["reachable"] == false).unwrap();
        assert_eq!(dead["source"]["kind"], "block");
        assert_eq!(dead["statements"][0]["source"]["kind"], "operation");
        assert!(dead["statements"][0]["renamed"].is_null());
        assert!(
            nodes
                .iter()
                .any(|n| n["source"]["outcome"]["kind"] == "unresolved_indirect_branch")
        );
        validate_references(&report);
    }

    #[test]
    fn graph_and_ssa_ids_are_independent_of_instruction_input_order() {
        let mut input: ExecutionInput =
            serde_json::from_str(include_str!("../../../examples/pcode/alias-branch.json"))
                .unwrap();
        let first = report(input.clone(), CommandOptions::default());
        input.instructions.reverse();
        let second = report(input, CommandOptions::default());
        for field in ["cfg", "nodes", "variables", "values", "natural_loops"] {
            assert_eq!(first[field], second[field], "{field}");
        }
        assert_ne!(first["instructions"], second["instructions"]);
    }

    #[test]
    fn malformed_programs_do_not_produce_reports_and_options_reject_duplicates() {
        let mut input = input();
        input.entry = 0x8000;
        assert!(analyze(input, CommandOptions::default()).is_err());
        let parse = |args: &[&str]| CommandOptions::parse(args.iter().map(OsString::from));
        assert!(parse(&["--instruction-uniques", "--havoc-unknown"]).is_ok());
        assert!(parse(&["--instruction-uniques", "--instruction-uniques"]).is_err());
        assert!(parse(&["--havoc-unknown", "--havoc-unknown"]).is_err());
        assert!(parse(&["--unknown"]).is_err());
    }

    #[test]
    fn bounded_output_never_appends_beyond_its_limit() {
        let mut output = LimitedOutput {
            bytes: vec![],
            maximum: 5,
        };
        output.write_all(b"12345").unwrap();
        assert!(output.write_all(b"6").is_err());
        assert_eq!(output.bytes, b"12345");
        let mut output = LimitedOutput {
            bytes: vec![],
            maximum: 4,
        };
        assert!(serde_json::to_writer_pretty(&mut output, &[1, 2, 3]).is_err());
        assert!(output.bytes.len() <= 4);
    }

    #[test]
    fn shared_input_reader_rejects_oversized_and_nonprogram_files() {
        let file = tempfile::NamedTempFile::new().unwrap();
        file.as_file().set_len(16 * 1024 * 1024 + 1).unwrap();
        assert!(
            crate::pcode_cli::read_program(file.path())
                .unwrap_err()
                .contains("16 MiB")
        );
        let mut file = tempfile::NamedTempFile::new().unwrap();
        file.write_all(br#"{"schema":"ghidra-rs.lifted-instruction","program":{}}"#)
            .unwrap();
        assert!(crate::pcode_cli::read_program(file.path()).is_err());
    }
}
