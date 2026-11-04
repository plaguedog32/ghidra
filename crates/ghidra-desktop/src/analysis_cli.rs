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
use ghidra_ssa::{EntryState, PhiPlacement, Predecessor, StatementId, ValueOrigin};
use serde::Serialize;

const MAX_OUTPUT: usize = 64 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CommandOptions {
    instruction_uniques: bool,
    havoc_unknown: bool,
    expressions: bool,
    constants: bool,
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
                Some("--expressions") if !result.expressions => result.expressions = true,
                Some("--constants") if !result.constants => result.constants = true,
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

/// Writes the complete buffered document, including its final newline, only
/// after analysis and serialization have both succeeded.
pub(crate) fn execute(path: &Path, options: CommandOptions) -> Result<(), String> {
    let input = crate::pcode_cli::read_program(path)?;
    let json = analyze(input, options)?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&json).map_err(|e| e.to_string())?;
    stdout.flush().map_err(|e| e.to_string())
}

pub(crate) fn limits() -> AnalysisLimits {
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
    analyze_within(input, options, MAX_OUTPUT)
}

/// The complete stdout document, newline included, within `maximum` bytes.
fn analyze_within(
    input: ExecutionInput,
    options: CommandOptions,
    maximum: usize,
) -> Result<Vec<u8>, String> {
    let (analysis, initializers) = verified_snapshot(input, options)?;
    // Terms are reconstructed from the verified snapshot only on request, so
    // the default report keeps its existing shape and cost. Constants imply
    // terms, because their facts are indexed by term IDs.
    let expressions = if options.expressions || options.constants {
        Some(Arc::new(crate::expression_report::build(analysis.clone())?))
    } else {
        None
    };
    let constants = match (&expressions, options.constants) {
        (Some(expressions), true) => Some(crate::constant_report::build(expressions.clone())?),
        _ => None,
    };
    let mut output = LimitedOutput::new(maximum, OUTPUT_TOO_LARGE);
    write_report(
        &analysis,
        initializers,
        expressions.as_deref(),
        constants.as_ref(),
        &mut output,
    )?;
    output
        .write_all(
            b"
",
        )
        .map_err(|e| e.to_string())?;
    Ok(output.into_bytes())
}

const OUTPUT_TOO_LARGE: &str = "P-code analysis JSON exceeds 64 MiB";

/// Expressions for a supplied program, built by the command's own path.
#[cfg(test)]
pub(crate) fn expressions_for(
    input: ExecutionInput,
    instruction_uniques: bool,
    havoc_unknown: bool,
) -> ghidra_analysis::PcodeExpressions {
    let options = CommandOptions {
        instruction_uniques,
        havoc_unknown,
        expressions: true,
        constants: false,
    };
    let (analysis, _) = verified_snapshot(input, options).unwrap();
    crate::expression_report::build(analysis).unwrap()
}

fn verified_snapshot(
    input: ExecutionInput,
    options: CommandOptions,
) -> Result<(Arc<PcodeSsa>, Initializers), String> {
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
        Arc::new(PcodeSsa::new(cfg, &[], options.analysis(), limits).map_err(|e| e.to_string())?);
    analysis
        .ssa()
        .verify(analysis.raw())
        .map_err(|e| e.to_string())?;
    Ok((analysis, initializers))
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
    /// Additive `--expressions` field using `ghidra-rs.expressions` v1.
    #[serde(skip_serializing_if = "Option::is_none")]
    expressions: Option<crate::expression_report::Report<'a>>,
    /// Additive `--constants` field using `ghidra-rs.constants` v1.
    #[serde(skip_serializing_if = "Option::is_none")]
    constants: Option<crate::constant_report::Report<'a>>,
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

fn write_report(
    analysis: &PcodeSsa,
    initializers: Initializers,
    expressions: Option<&ghidra_analysis::PcodeExpressions>,
    constants: Option<&ghidra_analysis::PcodeConstants>,
    output: &mut LimitedOutput,
) -> Result<(), String> {
    if let Some(expressions) = expressions
        && !std::ptr::eq(expressions.analysis().as_ref(), analysis)
    {
        return Err("Expressions belong to a different SSA snapshot".into());
    }
    // Constant facts index the accompanying terms and SSA values, so both
    // must be the exact allocations the facts were computed from.
    if let Some(constants) = constants
        && !expressions.is_some_and(|e| std::ptr::eq(constants.expressions().as_ref(), e))
    {
        return Err("Constant facts belong to a different expression snapshot".into());
    }
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
            ssa_form: match ssa.placement() {
                PhiPlacement::Unpruned => "unpruned",
                PhiPlacement::Pruned => "pruned",
            },
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
        expressions: expressions.map(crate::expression_report::Report),
        constants: constants.map(crate::constant_report::Report),
    };
    serde_json::to_writer_pretty(output, &report).map_err(|e| e.to_string())
}

pub(crate) fn symbolic_json(analysis: &PcodeSsa) -> Result<Vec<u8>, String> {
    let mut output = LimitedOutput::new(MAX_OUTPUT, OUTPUT_TOO_LARGE);
    write_report(
        analysis,
        Initializers {
            regions: 0,
            bytes: 0,
            applied: false,
        },
        None,
        None,
        &mut output,
    )?;
    Ok(output.into_bytes())
}

pub(crate) fn role(role: EdgeRole) -> &'static str {
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

/// Buffers serializer output and fails before appending beyond `maximum`, so
/// callers never write a partial document to stdout.
pub(crate) struct LimitedOutput {
    bytes: Vec<u8>,
    maximum: usize,
    message: &'static str,
}
impl LimitedOutput {
    pub(crate) fn new(maximum: usize, message: &'static str) -> Self {
        Self {
            bytes: Vec::new(),
            maximum,
            message,
        }
    }
    pub(crate) fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}
impl Write for LimitedOutput {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > self.maximum.saturating_sub(self.bytes.len()) {
            return Err(std::io::Error::other(self.message));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use ghidra_pcode::{Opcode, PcodeOperation, SpaceId, Varnode};
    use serde_json::Value;

    fn input() -> ExecutionInput {
        serde_json::from_str(include_str!("../../../examples/pcode/sum-loop.json")).unwrap()
    }
    fn report(input: ExecutionInput, options: CommandOptions) -> Value {
        serde_json::from_slice(&analyze(input, options).unwrap()).unwrap()
    }
    const EXPRESSIONS: CommandOptions = CommandOptions {
        instruction_uniques: false,
        havoc_unknown: false,
        expressions: true,
        constants: false,
    };
    /// A report with `--expressions`, checked against its own SSA IDs.
    fn expression_report(input: ExecutionInput, options: CommandOptions) -> Value {
        let report = report(
            input,
            CommandOptions {
                expressions: true,
                ..options
            },
        );
        validate_references(&report);
        crate::expression_report::tests::validate(&report, &report["expressions"]);
        report
    }
    fn definitions<'a>(report: &'a Value, kind: &str) -> Vec<&'a Value> {
        report["expressions"]["values"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["definition"]["kind"] == kind)
            .collect()
    }
    fn terms<'a>(report: &'a Value, kind: &str) -> Vec<&'a Value> {
        report["expressions"]["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|n| n["term"]["kind"] == kind)
            .collect()
    }
    fn operation<'a>(report: &'a Value, opcode: &str) -> &'a Value {
        report["expressions"]["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["opcode"] == opcode)
            .unwrap()
    }
    fn node<'a>(report: &'a Value, id: &Value) -> &'a Value {
        &report["expressions"]["nodes"][id.as_u64().unwrap() as usize]["term"]
    }
    fn root<'a>(report: &'a Value, value: &Value) -> &'a Value {
        let value = &report["expressions"]["values"][value.as_u64().unwrap() as usize];
        assert_eq!(value["definition"]["kind"], "expression");
        node(report, &value["definition"]["root"])
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
    fn symbolic_export_reports_the_constructed_phi_placement() {
        let program = input();
        let cfg = Arc::new(
            Cfg::new(
                CfgInput::new(
                    program.spaces,
                    program.code_space,
                    program.entry,
                    program.instructions,
                ),
                Default::default(),
            )
            .unwrap(),
        );
        for (placement, expected) in [
            (PhiPlacement::Unpruned, "unpruned"),
            (PhiPlacement::Pruned, "pruned"),
        ] {
            let mut options = AnalysisOptions::pcode_program();
            options.phi_placement = placement;
            let analysis = PcodeSsa::new(cfg.clone(), &[], options, limits()).unwrap();
            analysis.ssa().verify(analysis.raw()).unwrap();
            let json: serde_json::Value =
                serde_json::from_slice(&symbolic_json(&analysis).unwrap()).unwrap();
            assert_eq!(json["policies"]["ssa_form"], expected);
        }
    }

    #[test]
    fn sum_loop_schema_links_points_phi_values_and_terminal_outcomes() {
        let report = report(input(), CommandOptions::default());
        assert_eq!(report["schema"], "ghidra-rs.pcode-analysis");
        assert_eq!(report["schema_version"], 1);
        assert_eq!(report["policies"]["unique_scope"], "program");
        assert_eq!(report["policies"]["ssa_form"], "pruned");
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
    fn expressions_are_opt_in_and_reference_the_same_ssa_ids() {
        let plain = report(input(), CommandOptions::default());
        assert!(plain.get("expressions").is_none());
        let mut with = expression_report(input(), CommandOptions::default());
        assert_eq!(with["expressions"]["schema"], "ghidra-rs.expressions");
        assert_eq!(with["expressions"]["schema_version"], 1);
        // Loop-carried values remain phi definitions referenced as SSA leaves.
        let phis = definitions(&with, "phi");
        assert!(!phis.is_empty());
        let leaves: Vec<_> = terms(&with, "ssa_value")
            .iter()
            .map(|n| n["term"]["value"].clone())
            .collect();
        assert!(phis.iter().any(|phi| leaves.contains(&phi["id"])));
        with.as_object_mut().unwrap().remove("expressions");
        assert_eq!(plain, with);
    }

    #[test]
    fn alias_joins_slices_and_phis_keep_exact_widths() {
        let input: ExecutionInput =
            serde_json::from_str(include_str!("../../../examples/pcode/alias-branch.json"))
                .unwrap();
        let report = expression_report(input, CommandOptions::default());
        // The 8-byte read after the join composes the merged low byte with
        // the untouched upper seven bytes.
        let joins = terms(&report, "join");
        assert!(joins.iter().any(|join| {
            let pieces = join["term"]["pieces"].as_array().unwrap();
            pieces.len() == 2 && pieces[0]["bytes"] == 1 && pieces[1]["bytes"] == 7
        }));
        // The initial 8-byte write is split into the same two aliased cells.
        let slices = terms(&report, "extract");
        assert!(
            slices
                .iter()
                .any(|s| s["type"]["bytes"] == 1 && s["term"]["lsb_byte"] == 0)
        );
        assert!(
            slices
                .iter()
                .any(|s| s["type"]["bytes"] == 7 && s["term"]["lsb_byte"] == 1)
        );
        assert_eq!(definitions(&report, "phi").len(), 1);
        // The RETURN target is a value operand, never an ABI return value.
        let ret = operation(&report, "RETURN");
        assert_eq!(ret["operands"][0]["role"], "value");
        assert_eq!(ret["result"], "none");
        let cbranch = operation(&report, "CBRANCH");
        assert_eq!(cbranch["operands"][0]["role"], "direct_target");
        assert_eq!(cbranch["operands"][1]["role"], "value");
    }

    #[test]
    fn word_pointers_fixed_offsets_and_memory_versions_stay_explicit() {
        let space = |id: u32, name: &str, kind: &str, word: u32, endian: &str| {
            serde_json::json!({"id": id, "name": name, "kind": kind, "address_size": 8,
                "word_size": word, "endianness": endian})
        };
        let vn = |space: u32, offset: u64, size: u32| serde_json::json!({"space": space, "offset": offset, "size": size});
        let program = serde_json::json!({
            "spaces": [
                space(0, "const", "Constant", 1, "Little"),
                space(1, "ram", "Ram", 2, "Big"),
                space(2, "register", "Register", 1, "Little"),
                space(3, "unique", "Unique", 1, "Little"),
                space(4, "code", "Other", 1, "Little"),
            ],
            "code_space": 4,
            "entry": 4096,
            "instructions": [{"address": 4096, "length": 4, "ops": [
                {"opcode": "STORE", "output": null,
                 "inputs": [vn(0, 1, 4), vn(2, 8, 8), vn(2, 16, 4)]},
                {"opcode": "LOAD", "output": vn(2, 24, 4), "inputs": [vn(0, 1, 4), vn(2, 8, 8)]},
                {"opcode": "COPY", "output": vn(1, 16, 4), "inputs": [vn(0, 0x55667788, 4)]},
                {"opcode": "COPY", "output": vn(2, 32, 2), "inputs": [vn(1, 16, 2)]},
            ]}]
        });
        let report = expression_report(
            serde_json::from_value(program).unwrap(),
            CommandOptions::default(),
        );
        let store = operation(&report, "STORE");
        assert_eq!(store["operands"][0]["role"], "space_selector");
        assert_eq!(store["indirect_memory"]["access"], "write");
        assert_eq!(store["result"], "none");
        let stored = &store["definitions"][0];
        let write = root(&report, stored);
        assert_eq!(write["kind"], "write_memory");
        assert_eq!(write["endianness"], "big");
        assert_eq!(write["address"]["kind"], "word_pointer");
        assert_eq!(write["address"]["word_size"], 2);
        assert_eq!(write["address"]["address_bytes"], 8);
        assert_eq!(write["version"], store["indirect_memory"]["version"]);
        // The LOAD reads the version the STORE defined, not the entry state.
        let load = operation(&report, "LOAD");
        assert_eq!(load["indirect_memory"]["access"], "read");
        assert_eq!(&load["indirect_memory"]["version"], stored);
        let read = node(&report, &load["output"]);
        assert_eq!(read["kind"], "read_memory");
        assert_eq!(read["address"]["kind"], "word_pointer");
        assert_eq!(&read["version"], stored);
        // Fixed varnodes keep byte offsets, even in a word-addressed space.
        let copies: Vec<_> = report["expressions"]["operations"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["opcode"] == "COPY")
            .collect();
        let fixed = &copies[0]["definitions"][0];
        let fixed_write = root(&report, fixed);
        assert_eq!(
            fixed_write["address"],
            serde_json::json!({"kind": "byte_offset", "offset": 16})
        );
        assert_eq!(&fixed_write["version"], stored);
        let fixed_read = node(&report, &copies[1]["operands"][0]["node"]);
        assert_eq!(fixed_read["kind"], "read_memory");
        assert_eq!(&fixed_read["version"], fixed);
        assert_eq!(fixed_read["endianness"], "big");
    }

    #[test]
    fn instruction_resets_and_havoc_definitions_remain_undefined_or_opaque() {
        let mut looped = input();
        looped.instructions[0]
            .ops
            .push(branch(Opcode::Branch, var(1, 0x1000, 8)));
        let report = expression_report(
            looped,
            CommandOptions {
                instruction_uniques: true,
                ..Default::default()
            },
        );
        assert!(!definitions(&report, "undefined_reset").is_empty());
        assert!(definitions(&report, "opaque").is_empty());
        let mut called = input();
        called.instructions[0]
            .ops
            .insert(0, branch(Opcode::Call, var(1, 0x8000, 8)));
        called.instructions[0].ops.pop();
        let report = expression_report(
            called,
            CommandOptions {
                havoc_unknown: true,
                ..Default::default()
            },
        );
        let call = operation(&report, "CALL");
        assert_eq!(
            call["effects"],
            serde_json::json!({"kind": "conservative", "class": "Call"})
        );
        assert_eq!(call["result"], "opaque");
        assert!(call["output"].is_null());
        assert_eq!(call["operands"][0]["role"], "direct_target");
        let opaque = definitions(&report, "opaque");
        assert_eq!(opaque.len(), report["variables"].as_array().unwrap().len());
        assert!(
            opaque
                .iter()
                .all(|v| v["definition"]["statement"] == call["statement"])
        );
    }

    #[test]
    fn expression_flag_parsing_and_exact_output_bounds() {
        let parse = |args: &[&str]| CommandOptions::parse(args.iter().map(OsString::from));
        assert!(parse(&["--expressions"]).unwrap().expressions);
        assert!(parse(&["--havoc-unknown", "--expressions", "--instruction-uniques"]).is_ok());
        assert!(parse(&["--expressions", "--expressions"]).is_err());
        assert!(parse(&["--expression"]).is_err());
        assert!(!parse(&[]).unwrap().expressions);
        let exact = analyze(input(), EXPRESSIONS).unwrap().len();
        assert_eq!(
            analyze_within(input(), EXPRESSIONS, exact).unwrap().len(),
            exact
        );
        assert!(
            analyze_within(input(), EXPRESSIONS, exact - 1)
                .unwrap_err()
                .contains("64 MiB")
        );
        let plain = analyze(input(), CommandOptions::default()).unwrap().len();
        assert!(plain < exact);
        assert!(analyze_within(input(), CommandOptions::default(), plain).is_ok());
    }

    const CONSTANTS: CommandOptions = CommandOptions {
        instruction_uniques: false,
        havoc_unknown: false,
        expressions: false,
        constants: true,
    };
    /// A report with `--constants`, checked against its own SSA and term IDs.
    fn constant_report(input: ExecutionInput, options: CommandOptions) -> Value {
        let report = report(
            input,
            CommandOptions {
                constants: true,
                ..options
            },
        );
        validate_references(&report);
        crate::expression_report::tests::validate(&report, &report["expressions"]);
        crate::constant_report::tests::validate(
            &report,
            &report["expressions"],
            &report["constants"],
        );
        report
    }
    fn op(opcode: Opcode, output: Option<Varnode>, inputs: Vec<Varnode>) -> PcodeOperation {
        PcodeOperation {
            opcode,
            output,
            inputs,
        }
    }
    fn instruction(address: u64, ops: Vec<PcodeOperation>) -> PcodeInstruction {
        PcodeInstruction {
            address,
            length: 4,
            ops,
        }
    }
    /// 0x1000 decides a known-constant CBRANCH, so 0x1004 is unreached and the
    /// join's phi folds over its one feasible input. 0x1010 divides by zero,
    /// loads through a constant pointer and branches on an entry input.
    pub(crate) fn constant_program() -> ExecutionInput {
        let mut program = input();
        let reg = |offset, size| var(2, offset, size);
        let con = |value, size| var(0, value, size);
        let label = |address| var(1, address, 8);
        program.instructions = vec![
            instruction(
                0x1000,
                vec![
                    op(Opcode::Copy, Some(reg(0, 4)), vec![con(5, 4)]),
                    op(Opcode::Copy, Some(reg(8, 4)), vec![con(9, 4)]),
                    op(
                        Opcode::IntEqual,
                        Some(reg(64, 1)),
                        vec![reg(0, 4), con(5, 4)],
                    ),
                    op(Opcode::Cbranch, None, vec![label(0x1010), reg(64, 1)]),
                ],
            ),
            instruction(
                0x1004,
                vec![
                    op(Opcode::Copy, Some(reg(8, 4)), vec![con(7, 4)]),
                    op(Opcode::Branch, None, vec![label(0x1010)]),
                ],
            ),
            instruction(
                0x1010,
                vec![
                    op(Opcode::IntAdd, Some(reg(48, 4)), vec![reg(8, 4), con(1, 4)]),
                    op(Opcode::IntDiv, Some(reg(16, 4)), vec![reg(0, 4), con(0, 4)]),
                    op(Opcode::Copy, Some(reg(32, 8)), vec![con(0x2000, 8)]),
                    op(Opcode::Load, Some(reg(24, 4)), vec![con(1, 4), reg(32, 8)]),
                    op(
                        Opcode::IntEqual,
                        Some(reg(65, 1)),
                        vec![reg(40, 4), con(0, 4)],
                    ),
                    op(Opcode::Cbranch, None, vec![label(0x1020), reg(65, 1)]),
                ],
            ),
            instruction(0x1014, vec![op(Opcode::Return, None, vec![con(0x9000, 8)])]),
            instruction(0x1020, vec![op(Opcode::Return, None, vec![reg(0, 8)])]),
        ];
        program
    }
    /// The fact of the single value defined by `opcode` at `address`.
    fn output_fact<'a>(report: &'a Value, address: u64, opcode: &str) -> &'a Value {
        let operation = report["expressions"]["operations"]
            .as_array()
            .unwrap()
            .iter()
            .find(|o| o["point"]["address"] == address && o["opcode"] == opcode)
            .unwrap_or_else(|| panic!("{opcode} at {address:x}"));
        let definitions = operation["definitions"].as_array().unwrap();
        assert_eq!(definitions.len(), 1, "{operation}");
        &report["constants"]["values"][definitions[0].as_u64().unwrap() as usize]
    }
    fn edges_from(report: &Value, address: u64) -> Vec<(String, bool)> {
        let mut edges: Vec<_> = report["cfg"]["edges"]
            .as_array()
            .unwrap()
            .iter()
            .enumerate()
            .filter(|(_, e)| e["source"]["address"] == address)
            .map(|(id, e)| {
                (
                    e["role"].as_str().unwrap().to_string(),
                    report["constants"]["cfg_edge_feasible"][id]
                        .as_bool()
                        .unwrap(),
                )
            })
            .collect();
        edges.sort();
        edges
    }
    fn pair(role: &str, feasible: bool) -> (String, bool) {
        (role.to_string(), feasible)
    }

    #[test]
    fn known_conditions_prune_only_their_outcome_and_unknowns_never_become_zero() {
        let report = constant_report(constant_program(), CommandOptions::default());
        let constants = &report["constants"];
        assert_eq!(constants["schema"], "ghidra-rs.constants");
        assert_eq!(constants["schema_version"], 1);
        assert_eq!(constants["policies"]["analysis"]["unique_scope"], "program");
        assert_eq!(
            constants["policies"]["analysis"]["entry"]["registers"],
            "input"
        );
        // The known condition keeps only its taken outcome.
        assert_eq!(
            edges_from(&report, 0x1000),
            [pair("condition_false", false), pair("condition_true", true)]
        );
        // The skipped block and its definition are unreached, not zero.
        let skipped = output_fact(&report, 0x1004, "COPY");
        assert_eq!(skipped["fact"], "unreached");
        assert!(skipped.get("hex").is_none());
        assert_eq!(edges_from(&report, 0x1004), [pair("branch", false)]);
        // The join's phi folds over its single feasible input.
        assert!(
            report["expressions"]["values"]
                .as_array()
                .unwrap()
                .iter()
                .filter(|v| v["definition"]["kind"] == "phi")
                .map(|v| &constants["values"][v["id"].as_u64().unwrap() as usize])
                .any(|v| v["fact"] == "constant" && v["hex"] == "0x9")
        );
        let sum = output_fact(&report, 0x1010, "INT_ADD");
        assert_eq!(sum["fact"], "constant");
        assert_eq!(sum["hex"], "0xa");
        assert_eq!(sum["bytes"], 4);
        // Division by zero is a reported fault; its result stays unknown and
        // later operations and both outcomes of the next CBRANCH stay feasible.
        let faults = constants["faults"].as_array().unwrap();
        assert_eq!(faults.len(), 1);
        assert_eq!(faults[0]["opcode"], "INT_DIV");
        assert_eq!(faults[0]["point"]["address"], 0x1010);
        assert_eq!(faults[0]["point"]["operation_index"], 1);
        assert!(
            faults[0]["error"]
                .as_str()
                .unwrap()
                .contains("division by zero")
        );
        assert_eq!(output_fact(&report, 0x1010, "INT_DIV")["fact"], "unknown");
        // Memory is not modeled: a constant pointer still loads an unknown.
        assert_eq!(output_fact(&report, 0x1010, "COPY")["hex"], "0x2000");
        assert_eq!(output_fact(&report, 0x1010, "LOAD")["fact"], "unknown");
        // An entry-input condition is unknown and keeps both outcomes.
        assert_eq!(output_fact(&report, 0x1010, "INT_EQUAL")["fact"], "unknown");
        assert_eq!(
            edges_from(&report, 0x1010),
            [pair("condition_false", true), pair("condition_true", true)]
        );
        // RETURN outcomes are control transfers, not ABI return values.
        for address in [0x1014, 0x1020] {
            assert_eq!(edges_from(&report, address), [pair("return", true)]);
        }
        assert_eq!(constants["policies"]["abi_return_values"], false);
        let counts = &constants["counts"];
        assert_eq!(counts["faults"], 1);
        assert!(counts["work"].as_u64().unwrap() > 0);
        assert!(counts["def_use_work"].as_u64().unwrap() > 0);
    }

    #[test]
    fn constants_are_opt_in_include_their_expressions_and_leave_other_fields_unchanged() {
        let plain = report(constant_program(), CommandOptions::default());
        assert!(plain.get("expressions").is_none() && plain.get("constants").is_none());
        let terms = report(constant_program(), EXPRESSIONS);
        assert!(terms.get("constants").is_none());
        let mut with = constant_report(constant_program(), CommandOptions::default());
        let both = constant_report(
            constant_program(),
            CommandOptions {
                expressions: true,
                ..CONSTANTS
            },
        );
        assert_eq!(with, both);
        with.as_object_mut().unwrap().remove("constants");
        assert_eq!(with, terms);
    }

    #[test]
    fn instruction_resets_and_opaque_calls_stay_unknown_and_call_outcomes_stay_feasible() {
        let mut looped = input();
        looped.instructions[0]
            .ops
            .push(branch(Opcode::Branch, var(1, 0x1000, 8)));
        let report = constant_report(
            looped,
            CommandOptions {
                instruction_uniques: true,
                ..Default::default()
            },
        );
        let fact = |report: &Value, value: &Value| {
            report["constants"]["values"][value["id"].as_u64().unwrap() as usize]["fact"].clone()
        };
        let resets: Vec<_> = report["expressions"]["values"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["definition"]["kind"] == "undefined_reset")
            .collect();
        assert!(!resets.is_empty());
        assert!(resets.iter().all(|v| fact(&report, v) == "unknown"));
        let mut called = input();
        called.instructions[0]
            .ops
            .insert(0, branch(Opcode::Call, var(1, 0x8000, 8)));
        called.instructions[0].ops.pop();
        let report = constant_report(
            called,
            CommandOptions {
                havoc_unknown: true,
                ..Default::default()
            },
        );
        let opaque: Vec<_> = report["expressions"]["values"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|v| v["definition"]["kind"] == "opaque")
            .collect();
        assert!(!opaque.is_empty());
        assert!(opaque.iter().all(|v| fact(&report, v) == "unknown"));
        let calls = edges_from(&report, 0x1000);
        assert!(calls.contains(&pair("call_return", true)));
        assert!(calls.contains(&pair("call_no_return", true)));
        assert_eq!(report["constants"]["policies"]["summarizes_calls"], false);
        assert_eq!(
            report["constants"]["policies"]["analysis"]["unknown_effects"],
            "havoc_all_observed_storage"
        );
    }

    #[test]
    fn constant_flag_parsing_exact_bounds_and_snapshot_identity() {
        let parse = |args: &[&str]| CommandOptions::parse(args.iter().map(OsString::from));
        let parsed = parse(&["--constants"]).unwrap();
        assert!(parsed.constants && !parsed.expressions);
        assert!(parse(&["--constants", "--expressions"]).is_ok());
        assert!(parse(&["--expressions", "--constants", "--havoc-unknown"]).is_ok());
        assert!(parse(&["--constants", "--constants"]).is_err());
        assert!(parse(&["--constants", "--expressions", "--expressions"]).is_err());
        assert!(parse(&["--constant"]).is_err());
        assert!(!parse(&[]).unwrap().constants);
        // The cap covers the whole stdout document, including its newline.
        let exact = analyze(constant_program(), CONSTANTS).unwrap();
        assert!(exact.ends_with(b"}\n"));
        assert_eq!(
            analyze_within(constant_program(), CONSTANTS, exact.len()).unwrap(),
            exact
        );
        assert!(
            analyze_within(constant_program(), CONSTANTS, exact.len() - 1)
                .unwrap_err()
                .contains("64 MiB")
        );
        let terms = analyze(constant_program(), EXPRESSIONS).unwrap().len();
        assert!(terms < exact.len());
        // Facts must belong to the exact expression snapshot being reported.
        let (first, _) = verified_snapshot(constant_program(), CONSTANTS).unwrap();
        let (second, _) = verified_snapshot(constant_program(), CONSTANTS).unwrap();
        let first_terms = Arc::new(crate::expression_report::build(first.clone()).unwrap());
        let second_terms = Arc::new(crate::expression_report::build(second.clone()).unwrap());
        let facts = crate::constant_report::build(first_terms.clone()).unwrap();
        assert!(Arc::ptr_eq(facts.expressions(), &first_terms));
        assert!(Arc::ptr_eq(facts.analysis(), &first));
        let initializers = || Initializers {
            regions: 0,
            bytes: 0,
            applied: false,
        };
        let mut output = LimitedOutput::new(MAX_OUTPUT, OUTPUT_TOO_LARGE);
        assert!(
            write_report(
                &second,
                initializers(),
                Some(&second_terms),
                Some(&facts),
                &mut output
            )
            .unwrap_err()
            .contains("different expression snapshot")
        );
        assert!(write_report(&first, initializers(), None, Some(&facts), &mut output).is_err());
        assert!(output.into_bytes().is_empty());
        let mut output = LimitedOutput::new(MAX_OUTPUT, OUTPUT_TOO_LARGE);
        write_report(
            &first,
            initializers(),
            Some(&first_terms),
            Some(&facts),
            &mut output,
        )
        .unwrap();
    }

    #[test]
    fn bounded_output_never_appends_beyond_its_limit() {
        let mut output = LimitedOutput::new(5, "limit");
        output.write_all(b"12345").unwrap();
        assert!(output.write_all(b"6").is_err());
        assert_eq!(output.bytes, b"12345");
        let mut output = LimitedOutput::new(4, "limit");
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
