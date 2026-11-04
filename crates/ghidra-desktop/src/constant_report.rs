//! Shared `ghidra-rs.constants` report semantics for the desktop and both
//! headless commands. Facts are borrowed from one `PcodeConstants` result and
//! streamed through serde; no per-fact JSON value tree is built. IDs index the
//! accompanying `ghidra-rs.pcode-analysis` and `ghidra-rs.expressions` reports
//! built from the same snapshot. Feasibility is conservative static analysis
//! over the supplied CFG, not proof of runtime execution, and nothing here
//! rewrites terms, recovers types or ABI return values, or emits C.
use std::sync::Arc;

use ghidra_analysis::{
    ConstantError, ConstantFact, ConstantLimits, ConstantPolicy, PcodeConstants, PcodeExpressions,
    UniqueScope, UnknownEffectPolicy,
};
use ghidra_ssa::{EntryState, PhiPlacement, ValueId};
use serde::{Serialize, Serializer, ser::Error as _};

use crate::expression_report::Hex;

pub(crate) const SCHEMA: &str = "ghidra-rs.constants";
pub(crate) const SCHEMA_VERSION: u32 = 1;

/// Desktop budgets. Engine defaults already exceed the native analysis and
/// expression limits; evaluated constant bytes match the expression literal
/// budget so their hexadecimal form stays well below the 64 MiB output cap.
pub(crate) fn limits() -> ConstantLimits {
    ConstantLimits {
        max_constant_bytes: 16 * 1024 * 1024,
        ..ConstantLimits::default()
    }
}

/// Propagates over an already built expression snapshot. The result shares
/// that allocation (and through it the SSA snapshot) rather than copying it.
pub(crate) fn build(expressions: Arc<PcodeExpressions>) -> Result<PcodeConstants, String> {
    PcodeConstants::new(expressions, limits())
        .map_err(|e| format!("Constant propagation failed: {e}"))
}

/// Streams a compact report through the caller's capped writer budget.
/// `too_large` is reported when the report would exceed `maximum` bytes.
pub(crate) fn json(
    constants: &PcodeConstants,
    maximum: usize,
    too_large: &'static str,
) -> Result<Vec<u8>, String> {
    let mut output = crate::analysis_cli::LimitedOutput::new(maximum, too_large);
    serde_json::to_writer(&mut output, &Report(constants)).map_err(|e| e.to_string())?;
    Ok(output.into_bytes())
}

/// The complete constants report.
pub(crate) struct Report<'a>(pub &'a PcodeConstants);

#[derive(Serialize)]
struct Entry {
    registers: &'static str,
    program_uniques: &'static str,
    memory: &'static str,
}

#[derive(Serialize)]
struct Analysis {
    unique_scope: &'static str,
    unknown_effects: &'static str,
    entry: Entry,
    phi_placement: &'static str,
}

fn entry_state(state: EntryState) -> &'static str {
    match state {
        EntryState::Input => "input",
        EntryState::Undefined => "undefined",
    }
}

#[derive(Serialize)]
struct Policies {
    ssa_schema: &'static str,
    ssa_schema_version: u32,
    expressions_schema: &'static str,
    expressions_schema_version: u32,
    /// The analyzed snapshot's options, which decide entry and reset values.
    analysis: Analysis,
    lattice: &'static str,
    entry_values: &'static str,
    undefined_resets: &'static str,
    models_memory: bool,
    models_opaque_effects: bool,
    prunes_constant_branches: bool,
    resolves_indirect_targets: bool,
    summarizes_calls: bool,
    faults_cut_control: bool,
    feasibility: &'static str,
    reported_faults: &'static str,
    rewrites_terms: bool,
    type_recovery: bool,
    abi_return_values: bool,
    decompiled_output: bool,
}

impl Policies {
    fn new(policy: ConstantPolicy) -> Self {
        let options = policy.analysis;
        Self {
            ssa_schema: "ghidra-rs.pcode-analysis",
            ssa_schema_version: 1,
            expressions_schema: crate::expression_report::SCHEMA,
            expressions_schema_version: crate::expression_report::SCHEMA_VERSION,
            analysis: Analysis {
                unique_scope: match options.unique_scope {
                    UniqueScope::Program => "program",
                    UniqueScope::Instruction => "instruction",
                },
                unknown_effects: match options.unknown_effects {
                    UnknownEffectPolicy::Reject => "reject",
                    UnknownEffectPolicy::HavocAll => "havoc_all_observed_storage",
                },
                entry: Entry {
                    registers: entry_state(options.entry.registers),
                    program_uniques: entry_state(options.entry.program_uniques),
                    memory: entry_state(options.entry.memory),
                },
                phi_placement: match options.phi_placement {
                    PhiPlacement::Unpruned => "unpruned",
                    PhiPlacement::Pruned => "pruned",
                },
            },
            lattice: "whole_value_unreached_constant_unknown",
            entry_values: "unknown_never_zero",
            undefined_resets: "unknown_never_zero",
            models_memory: policy.models_memory,
            models_opaque_effects: policy.models_opaque_effects,
            prunes_constant_branches: policy.prunes_constant_branches,
            resolves_indirect_targets: policy.resolves_indirect_targets,
            summarizes_calls: policy.summarizes_calls,
            faults_cut_control: policy.faults_cut_control,
            feasibility: "conservative_static_over_supplied_cfg_not_runtime_reachability",
            reported_faults: "final_fixpoint_only",
            rewrites_terms: false,
            type_recovery: false,
            abi_return_values: false,
            decompiled_output: false,
        }
    }
}

#[derive(Serialize)]
struct DefUseLimitsOut {
    max_values: usize,
    max_uses: usize,
    max_work: u64,
}

#[derive(Serialize)]
struct LimitsOut {
    max_graph_nodes: usize,
    max_graph_edges: usize,
    max_cfg_edges: usize,
    max_values: usize,
    max_statements: usize,
    max_expression_nodes: usize,
    max_plan_records: usize,
    max_queue: usize,
    max_constant_bytes: usize,
    max_work: u64,
    def_use: DefUseLimitsOut,
}

impl From<ConstantLimits> for LimitsOut {
    fn from(l: ConstantLimits) -> Self {
        Self {
            max_graph_nodes: l.max_graph_nodes,
            max_graph_edges: l.max_graph_edges,
            max_cfg_edges: l.max_cfg_edges,
            max_values: l.max_values,
            max_statements: l.max_statements,
            max_expression_nodes: l.max_expression_nodes,
            max_plan_records: l.max_plan_records,
            max_queue: l.max_queue,
            max_constant_bytes: l.max_constant_bytes,
            max_work: l.max_work,
            def_use: DefUseLimitsOut {
                max_values: l.def_use.max_values,
                max_uses: l.def_use.max_uses,
                max_work: l.def_use.max_work,
            },
        }
    }
}

#[derive(Serialize)]
struct Counts {
    values: usize,
    constant_values: usize,
    unknown_values: usize,
    unreached_values: usize,
    terms: usize,
    graph_nodes: usize,
    executable_nodes: usize,
    executable_graph_edges: usize,
    cfg_edges: usize,
    feasible_cfg_edges: usize,
    executed_statements: usize,
    faults: usize,
    constant_bytes: usize,
    evaluations: usize,
    value_changes: usize,
    phi_folds: usize,
    notifications: usize,
    plan_records: usize,
    queue_peak: usize,
    /// Propagation work, excluding the nested def-use build.
    work: u64,
    /// The nested def-use index build, with its own budget.
    def_use_work: u64,
}

impl Serialize for Report<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let c = self.0;
        let stats = c.stats();
        let analysis = c.analysis();
        let mut report = serializer.serialize_struct("Constants", 10)?;
        report.serialize_field("schema", SCHEMA)?;
        report.serialize_field("schema_version", &SCHEMA_VERSION)?;
        report.serialize_field("policies", &Policies::new(c.policy()))?;
        report.serialize_field("limits", &LimitsOut::from(c.limits()))?;
        report.serialize_field(
            "counts",
            &Counts {
                values: analysis.ssa().values().len(),
                constant_values: stats.constant_values,
                unknown_values: stats.unknown_values,
                unreached_values: stats.unreached_values,
                terms: c.expressions().nodes().len(),
                graph_nodes: analysis.ssa().graph().node_count(),
                executable_nodes: stats.executable_nodes,
                executable_graph_edges: stats.executable_edges,
                cfg_edges: analysis.cfg().edges().len(),
                feasible_cfg_edges: stats.feasible_cfg_edges,
                executed_statements: stats.executed_statements,
                faults: c.faults().len(),
                constant_bytes: stats.constant_bytes,
                evaluations: stats.evaluations,
                value_changes: stats.value_changes,
                phi_folds: stats.phi_folds,
                notifications: stats.notifications,
                plan_records: stats.plan_records,
                queue_peak: stats.queue_peak,
                work: stats.work,
                def_use_work: stats.def_use_work,
            },
        )?;
        report.serialize_field("values", &Values(c))?;
        report.serialize_field("terms", &Terms(c))?;
        report.serialize_field("node_executable", &NodeExecutable(c))?;
        report.serialize_field("cfg_edge_feasible", &EdgeFeasible(c))?;
        report.serialize_field("faults", &Faults(c))?;
        report.end()
    }
}

/// `{id, fact}` plus `bytes` and `hex` for a constant. Unreached and unknown
/// facts are explicit records, never omitted and never shown as zero.
struct Fact<'a> {
    id: usize,
    fact: ConstantFact<'a>,
}
impl Serialize for Fact<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut out = serializer.serialize_struct("Fact", 4)?;
        out.serialize_field("id", &self.id)?;
        match self.fact {
            ConstantFact::Unreached => out.serialize_field("fact", "unreached")?,
            ConstantFact::Unknown => out.serialize_field("fact", "unknown")?,
            ConstantFact::Constant(value) => {
                out.serialize_field("fact", "constant")?;
                out.serialize_field("bytes", &value.size())?;
                out.serialize_field("hex", &Hex(value))?;
            }
        }
        out.end()
    }
}

/// Reports an inconsistent result as a serialization error rather than
/// emitting a partial or guessed record.
struct Fallible<T>(Result<T, ConstantError>);
impl<T: Serialize> Serialize for Fallible<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            Ok(value) => value.serialize(serializer),
            Err(error) => Err(S::Error::custom(error)),
        }
    }
}

struct Values<'a>(&'a PcodeConstants);
impl Serialize for Values<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let c = self.0;
        let count = c.analysis().ssa().values().len();
        serializer.collect_seq(
            (0..count).map(|id| Fallible(c.value(ValueId(id)).map(|fact| Fact { id, fact }))),
        )
    }
}

struct Terms<'a>(&'a PcodeConstants);
impl Serialize for Terms<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let c = self.0;
        let count = c.expressions().nodes().len();
        serializer.collect_seq((0..count).map(|id| {
            Fallible(
                c.expression(ghidra_analysis::ExpressionId(id))
                    .map(|fact| Fact { id, fact }),
            )
        }))
    }
}

struct NodeExecutable<'a>(&'a PcodeConstants);
impl Serialize for NodeExecutable<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let c = self.0;
        let count = c.analysis().ssa().graph().node_count();
        serializer.collect_seq((0..count).map(|node| Fallible(c.is_node_executable(node))))
    }
}

struct EdgeFeasible<'a>(&'a PcodeConstants);
impl Serialize for EdgeFeasible<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let c = self.0;
        let count = c.analysis().cfg().edges().len();
        serializer.collect_seq((0..count).map(|edge| Fallible(c.is_cfg_edge_feasible(edge))))
    }
}

#[derive(Serialize)]
struct Statement {
    node: usize,
    index: usize,
}

#[derive(Serialize)]
struct Point {
    address: u64,
    operation_index: u32,
}

struct Message<'a>(&'a ghidra_pcode::Error);
impl Serialize for Message<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self.0)
    }
}

#[derive(Serialize)]
struct FaultOut<'a> {
    statement: Statement,
    point: Point,
    term: usize,
    opcode: &'static str,
    error: Message<'a>,
}

struct Faults<'a>(&'a PcodeConstants);
impl Serialize for Faults<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let c = self.0;
        serializer.collect_seq(c.faults().iter().map(|fault| {
            Fallible(
                c.expressions()
                    .operation(fault.statement)
                    .ok_or(ConstantError::UnknownStatement(fault.statement))
                    .map(|operation| FaultOut {
                        statement: Statement {
                            node: fault.statement.node,
                            index: fault.statement.index,
                        },
                        point: Point {
                            address: operation.point.address,
                            operation_index: operation.point.operation_index,
                        },
                        term: fault.expression.0,
                        opcode: fault.opcode.mnemonic(),
                        error: Message(&fault.error),
                    }),
            )
        }))
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::Value as Json;

    fn id(value: &Json) -> usize {
        value.as_u64().expect("unsigned ID") as usize
    }

    fn check_fact(fact: &Json, ty: &Json) {
        match fact["fact"].as_str().unwrap() {
            "constant" => {
                assert_eq!(ty["kind"], "bits", "{fact} {ty}");
                assert_eq!(fact["bytes"], ty["bytes"], "{fact} {ty}");
                let hex = fact["hex"].as_str().unwrap();
                assert!(hex.starts_with("0x"));
                assert!(hex.len() - 2 <= 2 * id(&fact["bytes"]));
            }
            "unknown" | "unreached" => {
                assert!(fact.get("hex").is_none() && fact.get("bytes").is_none());
            }
            other => panic!("fact kind {other}"),
        }
    }

    /// Checks a constants report against the SSA and expression reports of the
    /// same snapshot: IDs, widths, counts, feasibility and fault provenance.
    pub(crate) fn validate(ssa: &Json, expressions: &Json, report: &Json) {
        assert_eq!(report["schema"], SCHEMA);
        assert_eq!(report["schema_version"], SCHEMA_VERSION);
        let policies = &report["policies"];
        assert_eq!(policies["ssa_schema"], ssa["schema"]);
        assert_eq!(policies["expressions_schema"], expressions["schema"]);
        assert_eq!(
            policies["analysis"]["unique_scope"],
            ssa["policies"]["unique_scope"]
        );
        assert_eq!(
            policies["analysis"]["unknown_effects"],
            ssa["policies"]["unknown_effects"]
        );
        assert_eq!(
            policies["analysis"]["phi_placement"],
            ssa["policies"]["ssa_form"]
        );
        for (field, expected) in [
            ("models_memory", false),
            ("models_opaque_effects", false),
            ("prunes_constant_branches", true),
            ("resolves_indirect_targets", false),
            ("summarizes_calls", false),
            ("faults_cut_control", false),
            ("rewrites_terms", false),
            ("type_recovery", false),
            ("abi_return_values", false),
            ("decompiled_output", false),
        ] {
            assert_eq!(policies[field], expected, "{field}");
        }
        let values = report["values"].as_array().unwrap();
        let terms = report["terms"].as_array().unwrap();
        let nodes = report["node_executable"].as_array().unwrap();
        let edges = report["cfg_edge_feasible"].as_array().unwrap();
        let ssa_values = ssa["values"].as_array().unwrap();
        let ssa_nodes = ssa["nodes"].as_array().unwrap();
        let cfg_edges = ssa["cfg"]["edges"].as_array().unwrap();
        let expr_values = expressions["values"].as_array().unwrap();
        let expr_nodes = expressions["nodes"].as_array().unwrap();
        assert_eq!(values.len(), ssa_values.len());
        assert_eq!(terms.len(), expr_nodes.len());
        assert_eq!(nodes.len(), ssa_nodes.len());
        assert_eq!(edges.len(), cfg_edges.len());
        let counts = &report["counts"];
        let count = |kind: &str| values.iter().filter(|v| v["fact"] == kind).count();
        assert_eq!(id(&counts["values"]), values.len());
        assert_eq!(id(&counts["constant_values"]), count("constant"));
        assert_eq!(id(&counts["unknown_values"]), count("unknown"));
        assert_eq!(id(&counts["unreached_values"]), count("unreached"));
        assert_eq!(id(&counts["terms"]), terms.len());
        assert_eq!(id(&counts["graph_nodes"]), nodes.len());
        assert_eq!(id(&counts["cfg_edges"]), edges.len());
        let executable = |node: usize| nodes[node].as_bool().unwrap();
        assert_eq!(
            id(&counts["executable_nodes"]),
            (0..nodes.len()).filter(|&n| executable(n)).count()
        );
        assert_eq!(
            id(&counts["feasible_cfg_edges"]),
            edges.iter().filter(|e| e.as_bool().unwrap()).count()
        );
        // The SSA entry node always runs; an SSA-unreachable node never does.
        assert!(executable(id(&ssa["entry"])));
        for (node, record) in ssa_nodes.iter().enumerate() {
            if record["reachable"] == false {
                assert!(!executable(node));
            }
        }
        // A feasible edge leaves an executable node.
        for (edge, record) in edges.iter().zip(cfg_edges) {
            if edge.as_bool().unwrap() {
                assert!(executable(id(&record["from"])));
            }
        }
        for (current, value) in values.iter().enumerate() {
            assert_eq!(id(&value["id"]), current);
            check_fact(value, &expr_values[current]["type"]);
            let origin = &ssa_values[current]["origin"];
            match origin["kind"].as_str().unwrap() {
                // Entry state is never assumed to be a constant, or zero.
                "entry" => assert_eq!(value["fact"], "unknown"),
                "definition" => {
                    let definition = &expr_values[current]["definition"];
                    if matches!(
                        definition["kind"].as_str(),
                        Some("undefined_reset" | "opaque")
                    ) {
                        assert_ne!(value["fact"], "constant", "{definition}");
                    }
                    if value["fact"] != "unreached" {
                        assert!(executable(id(&origin["node"])));
                    } else {
                        assert!(!executable(id(&origin["node"])));
                    }
                }
                _ => {}
            }
        }
        for (current, term) in terms.iter().enumerate() {
            assert_eq!(id(&term["id"]), current);
            let node = &expr_nodes[current];
            check_fact(term, &node["type"]);
            match node["term"]["kind"].as_str().unwrap() {
                // An SSA leaf has exactly its value's fact.
                "ssa_value" => {
                    let value = &values[id(&node["term"]["value"])];
                    assert_eq!(term["fact"], value["fact"]);
                    assert_eq!(term.get("hex"), value.get("hex"));
                }
                // Memory and loads are not modeled.
                "read_memory" | "write_memory" => assert_ne!(term["fact"], "constant"),
                "constant" if term["fact"] == "constant" => {
                    assert_eq!(term["hex"], node["term"]["hex"]);
                }
                _ => {}
            }
        }
        let operations = expressions["operations"].as_array().unwrap();
        let faults = report["faults"].as_array().unwrap();
        assert_eq!(id(&counts["faults"]), faults.len());
        for fault in faults {
            let operation = operations
                .iter()
                .find(|o| o["statement"] == fault["statement"])
                .expect("fault statement has an operation");
            assert_eq!(operation["point"], fault["point"]);
            assert!(executable(id(&fault["statement"]["node"])));
            let term = id(&fault["term"]);
            // A faulting term remains unknown and keeps its opcode.
            assert_eq!(terms[term]["fact"], "unknown");
            assert_eq!(expr_nodes[term]["term"]["opcode"], fault["opcode"]);
            assert!(!fault["error"].as_str().unwrap().is_empty());
        }
    }
}
