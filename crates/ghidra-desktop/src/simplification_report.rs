//! Shared `ghidra-rs.simplification` report semantics for both headless
//! commands. Terms are borrowed from one `PcodeSimplification` and streamed
//! through serde; no per-term JSON value tree is built. Term IDs are their own
//! namespace; `node` fields index the accompanying `ghidra-rs.expressions`
//! report, `value`/`version` fields its SSA values and `statement` fields the
//! `ghidra-rs.pcode-analysis` nodes, all built from the same snapshot. The
//! canonical terms are a value projection: the original operations remain the
//! required evaluation stream, and nothing here is decompiled C, recovered
//! types, ABI return values or a `--run-pcode` input.
use std::sync::Arc;

use ghidra_analysis::{
    ExpressionDefinition, ExpressionId, ExpressionType, PcodeConstants, PcodeSimplification, Rule,
    SimplifyError, SimplifyLimits, SimplifyPolicy, Term, TermAddress, TermFault, TermIdentity,
    TermKind, TermOrigin,
};
use ghidra_pcode::Endianness;
use ghidra_ssa::{StatementId, ValueId};
use serde::{Serialize, Serializer, ser::Error as _};

use crate::expression_report::Hex;

pub(crate) const SCHEMA: &str = "ghidra-rs.simplification";
pub(crate) const SCHEMA_VERSION: u32 = 1;

/// Desktop budgets: engine defaults, except that owned literal bytes match
/// the expression and constant literal budgets so their hexadecimal form
/// stays well below the 64 MiB output cap.
pub(crate) fn limits() -> SimplifyLimits {
    SimplifyLimits {
        max_literal_bytes: 16 * 1024 * 1024,
        ..SimplifyLimits::default()
    }
}

/// Simplifies over already computed constant facts. The result shares that
/// allocation (and through it the expression and SSA snapshots).
pub(crate) fn build(constants: Arc<PcodeConstants>) -> Result<PcodeSimplification, String> {
    PcodeSimplification::new(constants, limits()).map_err(|e| format!("Simplification failed: {e}"))
}

/// Streams a compact report through the caller's capped writer budget.
pub(crate) fn json(
    simplification: &PcodeSimplification,
    maximum: usize,
    too_large: &'static str,
) -> Result<Vec<u8>, String> {
    let mut output = crate::analysis_cli::LimitedOutput::new(maximum, too_large);
    serde_json::to_writer(&mut output, &Report(simplification)).map_err(|e| e.to_string())?;
    Ok(output.into_bytes())
}

/// The complete simplification report.
pub(crate) struct Report<'a>(pub &'a PcodeSimplification);

#[derive(Serialize)]
struct ConstantsPolicy {
    prunes_constant_branches: bool,
    faults_cut_control: bool,
    resolves_indirect_targets: bool,
    summarizes_calls: bool,
    models_memory: bool,
    models_opaque_effects: bool,
    feasibility: &'static str,
}

#[derive(Serialize)]
struct Policies {
    ssa_schema: &'static str,
    ssa_schema_version: u32,
    expressions_schema: &'static str,
    expressions_schema_version: u32,
    constants_schema: &'static str,
    constants_schema_version: u32,
    /// The original constant-propagation feasibility policy, unchanged.
    constants: ConstantsPolicy,
    scope: &'static str,
    canonical_terms: &'static str,
    evaluation: &'static str,
    term_identity: &'static str,
    faulting_terms: &'static str,
    memory: &'static str,
    leaves: &'static str,
    folding: &'static str,
    executable_statements_only: bool,
    prunes_control: bool,
    rewrites_operations: bool,
    eliminates_dead_code: bool,
    forwards_memory: bool,
    shares_memory_terms: bool,
    shares_faulting_terms: bool,
    propagates_faulting_definitions: bool,
    discards_faulting_subterms: bool,
    annihilators: bool,
    float_identities: bool,
    normalized_boolean_rewrites: bool,
    reorders_pointer_or_metadata: bool,
    resolves_indirect_targets: bool,
    type_recovery: bool,
    abi_return_values: bool,
    decompiled_output: bool,
}

impl Policies {
    fn new(policy: SimplifyPolicy) -> Self {
        let constants = policy.constants;
        Self {
            ssa_schema: "ghidra-rs.pcode-analysis",
            ssa_schema_version: 1,
            expressions_schema: crate::expression_report::SCHEMA,
            expressions_schema_version: crate::expression_report::SCHEMA_VERSION,
            constants_schema: crate::constant_report::SCHEMA,
            constants_schema_version: crate::constant_report::SCHEMA_VERSION,
            constants: ConstantsPolicy {
                prunes_constant_branches: constants.prunes_constant_branches,
                faults_cut_control: constants.faults_cut_control,
                resolves_indirect_targets: constants.resolves_indirect_targets,
                summarizes_calls: constants.summarizes_calls,
                models_memory: constants.models_memory,
                models_opaque_effects: constants.models_opaque_effects,
                feasibility: "conservative_static_over_supplied_cfg_not_runtime_reachability",
            },
            scope: "statements_executed_by_constant_propagation_unreached_not_simplified",
            canonical_terms: "value_projection_not_an_executable_replacement",
            evaluation: "original_operation_stream_required_all_declared_reads_effects_faults",
            term_identity: "hash_consed_type_operator_operands_literal_width_and_bytes",
            faulting_terms: "distinct_never_shared_propagated_or_discarded",
            memory: "reads_and_writes_distinct_no_forwarding_versions_retained",
            leaves: "phi_entry_undefined_reset_opaque_and_memory_state_identities_never_zero",
            folding: "evaluate_pure_exact_refused_folds_are_not_runtime_faults",
            executable_statements_only: policy.executable_statements_only,
            prunes_control: policy.prunes_control,
            rewrites_operations: policy.rewrites_operations,
            eliminates_dead_code: policy.eliminates_dead_code,
            forwards_memory: policy.forwards_memory,
            shares_memory_terms: policy.shares_memory_terms,
            shares_faulting_terms: policy.shares_faulting_terms,
            propagates_faulting_definitions: policy.propagates_faulting_definitions,
            discards_faulting_subterms: policy.discards_faulting_subterms,
            annihilators: policy.annihilators,
            float_identities: policy.float_identities,
            normalized_boolean_rewrites: policy.normalized_boolean_rewrites,
            reorders_pointer_or_metadata: policy.reorders_pointer_or_metadata,
            resolves_indirect_targets: policy.resolves_indirect_targets,
            type_recovery: policy.type_recovery,
            abi_return_values: policy.abi_return_values,
            decompiled_output: policy.decompiled_output,
        }
    }
}

#[derive(Serialize)]
struct LimitsOut {
    max_values: usize,
    max_expression_nodes: usize,
    max_statements: usize,
    max_terms: usize,
    max_term_inputs: usize,
    max_literal_bytes: usize,
    max_live: usize,
    max_work: u64,
}

impl From<SimplifyLimits> for LimitsOut {
    fn from(l: SimplifyLimits) -> Self {
        Self {
            max_values: l.max_values,
            max_expression_nodes: l.max_expression_nodes,
            max_statements: l.max_statements,
            max_terms: l.max_terms,
            max_term_inputs: l.max_term_inputs,
            max_literal_bytes: l.max_literal_bytes,
            max_live: l.max_live,
            max_work: l.max_work,
        }
    }
}

#[derive(Serialize)]
struct Counts {
    expression_nodes: usize,
    values: usize,
    terms: usize,
    literal_terms: usize,
    leaf_terms: usize,
    distinct_terms: usize,
    term_inputs: usize,
    literal_bytes: usize,
    executed_statements: usize,
    executed_operations: usize,
    skipped_operations: usize,
    canonical_nodes: usize,
    unmapped_nodes: usize,
    shared_terms: usize,
    literal_nodes: usize,
    literals_beyond_constants: usize,
    literal_values: usize,
    propagated_values: usize,
    leaf_values: usize,
    literal_outputs: usize,
    forwarded_outputs: usize,
    new_literal_conditions: usize,
    evaluations: usize,
    refused_folds: usize,
    faults: usize,
    live_peak: usize,
    /// Simplification work only; the source snapshots had their own budgets.
    work: u64,
}

struct Rules<'a>(&'a PcodeSimplification);
impl Serialize for Rules<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let stats = self.0.stats();
        let mut map = serializer.serialize_map(Some(Rule::ALL.len()))?;
        for &rule in Rule::ALL {
            map.serialize_entry(rule.name(), &stats.rule(rule))?;
        }
        map.end()
    }
}

impl Serialize for Report<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let s = self.0;
        let stats = s.stats();
        let mut report = serializer.serialize_struct("Simplification", 12)?;
        report.serialize_field("schema", SCHEMA)?;
        report.serialize_field("schema_version", &SCHEMA_VERSION)?;
        report.serialize_field("policies", &Policies::new(s.policy()))?;
        report.serialize_field("limits", &LimitsOut::from(s.limits()))?;
        report.serialize_field(
            "counts",
            &Counts {
                expression_nodes: s.expressions().nodes().len(),
                values: s.analysis().ssa().values().len(),
                terms: stats.terms,
                literal_terms: stats.literal_terms,
                leaf_terms: stats.leaf_terms,
                distinct_terms: stats.distinct_terms,
                term_inputs: stats.term_inputs,
                literal_bytes: stats.literal_bytes,
                executed_statements: stats.executed_statements,
                executed_operations: stats.executed_operations,
                skipped_operations: stats.skipped_operations,
                canonical_nodes: stats.canonical_nodes,
                unmapped_nodes: stats.unmapped_nodes,
                shared_terms: stats.shared_terms,
                literal_nodes: stats.literal_nodes,
                literals_beyond_constants: stats.literals_beyond_constants,
                literal_values: stats.literal_values,
                propagated_values: stats.propagated_values,
                leaf_values: stats.leaf_values,
                literal_outputs: stats.literal_outputs,
                forwarded_outputs: stats.forwarded_outputs,
                new_literal_conditions: stats.new_literal_conditions,
                evaluations: stats.evaluations,
                refused_folds: stats.refused_folds,
                faults: s.faults().len(),
                live_peak: stats.live_peak,
                work: stats.work,
            },
        )?;
        report.serialize_field("rules", &Rules(s))?;
        report.serialize_field("terms", &Terms(s))?;
        report.serialize_field("node_terms", &NodeTerms(s))?;
        report.serialize_field("values", &Values(s))?;
        report.serialize_field("operations", &Operations(s))?;
        report.serialize_field("faults", &Faults(s))?;
        report.serialize_field("refused_folds", &RefusedFolds(s))?;
        report.end()
    }
}

/// Reports an inconsistent snapshot as a serialization error rather than
/// emitting a partial or guessed record.
struct Fallible<T>(Result<T, SimplifyError>);
impl<T: Serialize> Serialize for Fallible<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            Ok(value) => value.serialize(serializer),
            Err(error) => Err(S::Error::custom(error)),
        }
    }
}

struct Type(ExpressionType);
impl Serialize for Type {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        enum Out {
            Bits { bytes: u32 },
            Memory { space: u32 },
        }
        match self.0 {
            ExpressionType::Bits(bytes) => Out::Bits { bytes },
            ExpressionType::Memory(space) => Out::Memory { space: space.0 },
        }
        .serialize(serializer)
    }
}

fn endian(endianness: Endianness) -> &'static str {
    match endianness {
        Endianness::Little => "little",
        Endianness::Big => "big",
    }
}

struct Address(TermAddress);
impl Serialize for Address {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        enum Out {
            ByteOffset {
                offset: u64,
            },
            WordPointer {
                term: usize,
                word_size: u32,
                address_bytes: u8,
            },
        }
        match self.0 {
            TermAddress::ByteOffset(offset) => Out::ByteOffset { offset },
            TermAddress::Pointer {
                term,
                word_size,
                address_size,
            } => Out::WordPointer {
                term: term.0,
                word_size,
                address_bytes: address_size,
            },
        }
        .serialize(serializer)
    }
}

struct TermIds<'a>(&'a [ghidra_analysis::TermId]);
impl Serialize for TermIds<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(|id| id.0))
    }
}

struct Pieces<'a>(&'a [ghidra_analysis::TermPiece]);
impl Serialize for Pieces<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Piece {
            term: usize,
            lsb_byte: u32,
            bytes: u32,
        }
        serializer.collect_seq(self.0.iter().map(|p| Piece {
            term: p.term.0,
            lsb_byte: p.lsb_byte,
            bytes: p.size,
        }))
    }
}

struct Kind<'a>(&'a TermKind);
impl Serialize for Kind<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        enum Out<'a> {
            Literal {
                bytes: u32,
                hex: Hex<'a>,
            },
            Leaf {
                value: usize,
            },
            Join {
                pieces: Pieces<'a>,
            },
            Extract {
                term: usize,
                lsb_byte: u32,
            },
            Apply {
                opcode: &'static str,
                inputs: TermIds<'a>,
            },
            ReadMemory {
                node: usize,
                space: u32,
                version: usize,
                address: Address,
                endianness: &'static str,
            },
            WriteMemory {
                node: usize,
                space: u32,
                version: usize,
                address: Address,
                term: usize,
                endianness: &'static str,
            },
        }
        match self.0 {
            TermKind::Literal(value) => Out::Literal {
                bytes: value.size(),
                hex: Hex(value),
            },
            TermKind::Leaf(value) => Out::Leaf { value: value.0 },
            TermKind::Join(pieces) => Out::Join {
                pieces: Pieces(pieces),
            },
            TermKind::Extract { term, lsb_byte } => Out::Extract {
                term: term.0,
                lsb_byte: *lsb_byte,
            },
            TermKind::Apply { opcode, inputs } => Out::Apply {
                opcode: opcode.mnemonic(),
                inputs: TermIds(inputs),
            },
            TermKind::ReadMemory {
                node,
                space,
                version,
                address,
                endianness,
            } => Out::ReadMemory {
                node: node.0,
                space: space.0,
                version: version.0,
                address: Address(*address),
                endianness: endian(*endianness),
            },
            TermKind::WriteMemory {
                node,
                space,
                version,
                address,
                value,
                endianness,
            } => Out::WriteMemory {
                node: node.0,
                space: space.0,
                version: version.0,
                address: Address(*address),
                term: value.0,
                endianness: endian(*endianness),
            },
        }
        .serialize(serializer)
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Origin {
    Node { node: usize },
    Value { value: usize },
}

#[derive(Serialize)]
struct TermOut<'a> {
    id: usize,
    #[serde(rename = "type")]
    ty: Type,
    term: Kind<'a>,
    fault: &'static str,
    identity: &'static str,
    reads_memory: bool,
    boolean: bool,
    origin: Origin,
    rule: Option<&'static str>,
}

fn term_out(id: usize, term: &Term) -> TermOut<'_> {
    TermOut {
        id,
        ty: Type(term.ty),
        term: Kind(&term.kind),
        fault: match term.fault {
            TermFault::None => "none",
            TermFault::Subterm => "subterm",
            TermFault::Here => "here",
        },
        identity: match term.identity() {
            TermIdentity::Structural => "structural",
            TermIdentity::Distinct => "distinct",
            TermIdentity::Value => "value",
        },
        reads_memory: term.reads_memory,
        boolean: term.boolean,
        origin: match term.origin {
            TermOrigin::Node(node) => Origin::Node { node: node.0 },
            TermOrigin::Value(value) => Origin::Value { value: value.0 },
        },
        rule: term.rule.map(Rule::name),
    }
}

struct Terms<'a>(&'a PcodeSimplification);
impl Serialize for Terms<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(
            self.0
                .terms()
                .iter()
                .enumerate()
                .map(|(id, term)| term_out(id, term)),
        )
    }
}

struct NodeTerms<'a>(&'a PcodeSimplification);
impl Serialize for NodeTerms<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let s = self.0;
        serializer.collect_seq((0..s.expressions().nodes().len()).map(|node| {
            Fallible(
                s.node_term(ExpressionId(node))
                    .map(|term| term.map(|t| t.0)),
            )
        }))
    }
}

#[derive(Serialize)]
struct ValueOut {
    id: usize,
    term: usize,
    /// The definition's term, for an expression-defined value whose
    /// statement was executed.
    definition_term: Option<usize>,
    propagated: bool,
}

struct Values<'a>(&'a PcodeSimplification);
impl Serialize for Values<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let s = self.0;
        serializer.collect_seq((0..s.analysis().ssa().values().len()).map(|id| {
            let value = ValueId(id);
            Fallible((|| {
                let definition_term = match s.expressions().definition(value)? {
                    ExpressionDefinition::Expression(root) => s.node_term(*root)?.map(|t| t.0),
                    _ => None,
                };
                Ok(ValueOut {
                    id,
                    term: s.value_term(value)?.0,
                    definition_term,
                    propagated: s.is_propagated(value)?,
                })
            })())
        }))
    }
}

#[derive(Serialize)]
struct Statement {
    node: usize,
    index: usize,
}
impl From<StatementId> for Statement {
    fn from(id: StatementId) -> Self {
        Self {
            node: id.node,
            index: id.index,
        }
    }
}

#[derive(Serialize)]
struct Point {
    address: u64,
    operation_index: u32,
}
impl From<ghidra_cfg::ProgramPoint> for Point {
    fn from(point: ghidra_cfg::ProgramPoint) -> Self {
        Self {
            address: point.address,
            operation_index: point.operation_index,
        }
    }
}

struct OperandTerms<'a>(ghidra_analysis::SimplifiedOperation<'a>);
impl Serialize for OperandTerms<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let operation = self.0;
        serializer.collect_seq(
            (0..operation.source.operands.len()).map(|slot| operation.operand(slot).map(|t| t.0)),
        )
    }
}

#[derive(Serialize)]
struct OperationOut<'a> {
    statement: Statement,
    point: Point,
    opcode: &'static str,
    executable: bool,
    /// One entry per source operand slot; `null` for non-value roles.
    /// The whole list is `null` for an operation that was not executed.
    operands: Option<OperandTerms<'a>>,
    output: Option<usize>,
}

struct Operations<'a>(&'a PcodeSimplification);
impl Serialize for Operations<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.operations().map(|operation| {
            Fallible(operation.map(|operation| OperationOut {
                statement: operation.source.statement.into(),
                point: operation.source.point.into(),
                opcode: operation.source.opcode.mnemonic(),
                executable: operation.executable,
                operands: operation.executable.then_some(OperandTerms(operation)),
                output: operation.output().map(|t| t.0),
            }))
        }))
    }
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
    node: usize,
    term: usize,
    opcode: &'static str,
    error: Message<'a>,
}

fn point(s: &PcodeSimplification, statement: StatementId) -> Result<Point, SimplifyError> {
    s.expressions()
        .operation(statement)
        .map(|operation| operation.point.into())
        .ok_or(SimplifyError::Inconsistent(
            "fault statement has no operation",
        ))
}

struct Faults<'a>(&'a PcodeSimplification);
impl Serialize for Faults<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let s = self.0;
        serializer.collect_seq(s.faults().iter().zip(s.constants().faults()).map(
            |(fault, original)| {
                Fallible(point(s, fault.statement).map(|point| FaultOut {
                    statement: fault.statement.into(),
                    point,
                    node: fault.node.0,
                    term: fault.term.0,
                    opcode: fault.opcode.mnemonic(),
                    error: Message(&original.error),
                }))
            },
        ))
    }
}

struct RefusedFolds<'a>(&'a PcodeSimplification);
impl Serialize for RefusedFolds<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let s = self.0;
        serializer.collect_seq(s.refused_folds().iter().map(|refused| {
            Fallible(point(s, refused.statement).map(|point| FaultOut {
                statement: refused.statement.into(),
                point,
                node: refused.node.0,
                term: refused.term.0,
                opcode: refused.opcode.mnemonic(),
                error: Message(&refused.error),
            }))
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

    /// Checks a simplification report against the SSA, expression and
    /// constant reports of the same snapshot: every ID resolves in its own
    /// namespace, types agree, constant facts are literals, unexecuted
    /// operations carry no terms and faults keep their provenance.
    pub(crate) fn validate(ssa: &Json, expressions: &Json, constants: &Json, report: &Json) {
        assert_eq!(report["schema"], SCHEMA);
        assert_eq!(report["schema_version"], SCHEMA_VERSION);
        let policies = &report["policies"];
        assert_eq!(policies["ssa_schema"], ssa["schema"]);
        assert_eq!(policies["expressions_schema"], expressions["schema"]);
        assert_eq!(
            policies["expressions_schema_version"],
            expressions["schema_version"]
        );
        assert_eq!(policies["constants_schema"], constants["schema"]);
        assert_eq!(
            policies["constants_schema_version"],
            constants["schema_version"]
        );
        for field in [
            "prunes_constant_branches",
            "faults_cut_control",
            "resolves_indirect_targets",
            "summarizes_calls",
            "models_memory",
            "models_opaque_effects",
        ] {
            assert_eq!(
                policies["constants"][field], constants["policies"][field],
                "{field}"
            );
        }
        for (field, expected) in [
            ("executable_statements_only", true),
            ("prunes_control", false),
            ("rewrites_operations", false),
            ("eliminates_dead_code", false),
            ("forwards_memory", false),
            ("shares_memory_terms", false),
            ("shares_faulting_terms", false),
            ("propagates_faulting_definitions", false),
            ("discards_faulting_subterms", false),
            ("annihilators", false),
            ("float_identities", false),
            ("normalized_boolean_rewrites", true),
            ("reorders_pointer_or_metadata", false),
            ("type_recovery", false),
            ("abi_return_values", false),
            ("decompiled_output", false),
        ] {
            assert_eq!(policies[field], expected, "{field}");
        }
        let terms = report["terms"].as_array().unwrap();
        let node_terms = report["node_terms"].as_array().unwrap();
        let values = report["values"].as_array().unwrap();
        let operations = report["operations"].as_array().unwrap();
        let expr_nodes = expressions["nodes"].as_array().unwrap();
        let expr_values = expressions["values"].as_array().unwrap();
        let expr_operations = expressions["operations"].as_array().unwrap();
        let ssa_values = ssa["values"].as_array().unwrap();
        let ssa_nodes = ssa["nodes"].as_array().unwrap();
        let counts = &report["counts"];
        assert_eq!(id(&counts["terms"]), terms.len());
        assert_eq!(id(&counts["expression_nodes"]), expr_nodes.len());
        assert_eq!(id(&counts["values"]), ssa_values.len());
        assert_eq!(node_terms.len(), expr_nodes.len());
        assert_eq!(values.len(), ssa_values.len());
        assert_eq!(operations.len(), expr_operations.len());
        let value_type = |value: &Json| &expr_values[id(value)]["type"];
        for (current, term) in terms.iter().enumerate() {
            assert_eq!(id(&term["id"]), current);
            let earlier = |reference: &Json| {
                let child = id(reference);
                assert!(child < current, "term {current} references {child}");
                &terms[child]["type"]
            };
            let body = &term["term"];
            match body["kind"].as_str().unwrap() {
                "literal" => {
                    assert_eq!(term["type"]["bytes"], body["bytes"]);
                    assert_eq!(term["identity"], "structural");
                    assert_eq!(term["fault"], "none");
                }
                "leaf" => {
                    assert_eq!(&term["type"], value_type(&body["value"]));
                    assert_eq!(term["identity"], "value");
                    assert_eq!(values[id(&body["value"])]["term"], current);
                }
                "join" => {
                    let mut next = 0;
                    for piece in body["pieces"].as_array().unwrap() {
                        assert_eq!(piece["lsb_byte"], next);
                        assert_eq!(earlier(&piece["term"])["bytes"], piece["bytes"]);
                        next += piece["bytes"].as_u64().unwrap();
                    }
                    assert_eq!(term["type"]["bytes"], next);
                }
                "extract" => {
                    let source = earlier(&body["term"]);
                    let end = body["lsb_byte"].as_u64().unwrap()
                        + term["type"]["bytes"].as_u64().unwrap();
                    assert!(end < source["bytes"].as_u64().unwrap() + 1);
                }
                "apply" => {
                    for input in body["inputs"].as_array().unwrap() {
                        assert_eq!(earlier(input)["kind"], "bits");
                    }
                }
                kind @ ("read_memory" | "write_memory") => {
                    assert_eq!(term["identity"], "distinct");
                    assert_eq!(term["fault"], "here");
                    let node = id(&body["node"]);
                    assert_eq!(expr_nodes[node]["term"]["kind"], kind);
                    assert_eq!(node_terms[node], current);
                    let version = value_type(&body["version"]);
                    assert_eq!(version["kind"], "memory");
                    assert_eq!(version["space"], body["space"]);
                    assert_eq!(body["version"], expr_nodes[node]["term"]["version"]);
                    if body["address"]["kind"] == "word_pointer" {
                        assert_eq!(
                            earlier(&body["address"]["term"])["bytes"],
                            body["address"]["address_bytes"]
                        );
                    }
                    if kind == "write_memory" {
                        earlier(&body["term"]);
                    }
                }
                other => panic!("term kind {other}"),
            }
            match term["origin"]["kind"].as_str().unwrap() {
                "node" => assert!(id(&term["origin"]["node"]) < expr_nodes.len()),
                "value" => assert!(id(&term["origin"]["value"]) < ssa_values.len()),
                other => panic!("origin {other}"),
            }
        }
        let constant_terms = constants["terms"].as_array().unwrap();
        for (node, mapped) in node_terms.iter().enumerate() {
            let Some(term) = mapped.as_u64() else {
                continue;
            };
            let term = &terms[term as usize];
            assert_eq!(term["type"], expr_nodes[node]["type"], "node {node}");
            if constant_terms[node]["fact"] == "constant" {
                assert_eq!(term["term"]["kind"], "literal");
                assert_eq!(term["term"]["hex"], constant_terms[node]["hex"]);
            }
        }
        let constant_values = constants["values"].as_array().unwrap();
        for (current, value) in values.iter().enumerate() {
            assert_eq!(id(&value["id"]), current);
            let term = &terms[id(&value["term"])];
            assert_eq!(&term["type"], &expr_values[current]["type"]);
            match constant_values[current]["fact"].as_str().unwrap() {
                "constant" => assert_eq!(term["term"]["hex"], constant_values[current]["hex"]),
                // Unreached values are never presented as results.
                "unreached" => assert_eq!(term["term"]["value"], current),
                _ => {}
            }
            let definition = &expr_values[current]["definition"];
            if value["propagated"] == true {
                assert_eq!(definition["kind"], "expression");
                assert_eq!(value["definition_term"], value["term"]);
                assert_eq!(node_terms[id(&definition["root"])], value["term"]);
                assert_eq!(term["fault"], "none");
                assert_eq!(term["reads_memory"], false);
            }
            if definition["kind"] != "expression" && constant_values[current]["fact"] != "constant"
            {
                assert_eq!(term["term"]["kind"], "leaf");
                assert_eq!(term["term"]["value"], current);
            }
        }
        let executable = constants["node_executable"].as_array().unwrap();
        let mut executed = 0;
        for (operation, source) in operations.iter().zip(expr_operations) {
            assert_eq!(operation["statement"], source["statement"]);
            assert_eq!(operation["point"], source["point"]);
            assert_eq!(operation["opcode"], source["opcode"]);
            let node = id(&operation["statement"]["node"]);
            assert!(node < ssa_nodes.len());
            assert_eq!(operation["executable"], executable[node]);
            if operation["executable"] == false {
                assert!(operation["operands"].is_null() && operation["output"].is_null());
                continue;
            }
            executed += 1;
            let operands = operation["operands"].as_array().unwrap();
            let source_operands = source["operands"].as_array().unwrap();
            assert_eq!(operands.len(), source_operands.len());
            for (term, original) in operands.iter().zip(source_operands) {
                match original["node"].as_u64() {
                    Some(node) => assert_eq!(term, &node_terms[node as usize]),
                    None => assert!(term.is_null()),
                }
            }
            match source["output"].as_u64() {
                Some(node) => assert_eq!(operation["output"], node_terms[node as usize]),
                None => assert!(operation["output"].is_null()),
            }
        }
        assert_eq!(id(&counts["executed_operations"]), executed);
        let faults = report["faults"].as_array().unwrap();
        let original_faults = constants["faults"].as_array().unwrap();
        assert_eq!(faults.len(), original_faults.len());
        assert_eq!(id(&counts["faults"]), faults.len());
        for (fault, original) in faults.iter().zip(original_faults) {
            for field in ["statement", "point", "opcode", "error"] {
                assert_eq!(fault[field], original[field], "{field}");
            }
            assert_eq!(fault["node"], original["term"]);
            assert_eq!(node_terms[id(&fault["node"])], fault["term"]);
            assert_eq!(terms[id(&fault["term"])]["fault"], "here");
        }
        let refused = report["refused_folds"].as_array().unwrap();
        assert_eq!(id(&counts["refused_folds"]), refused.len());
        for fold in refused {
            let term = &terms[id(&fold["term"])];
            assert_eq!(term["term"]["kind"], "apply");
            assert_eq!(term["term"]["opcode"], fold["opcode"]);
            assert_eq!(term["identity"], "distinct");
            assert_eq!(node_terms[id(&fold["node"])], fold["term"]);
            assert!(!fold["error"].as_str().unwrap().is_empty());
        }
        let rules = report["rules"].as_object().unwrap();
        assert_eq!(rules.len(), Rule::ALL.len());
    }
}
