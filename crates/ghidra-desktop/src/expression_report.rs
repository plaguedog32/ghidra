//! Shared `ghidra-rs.expressions` report semantics for the desktop and both
//! headless commands. Reports borrow the reconstructed terms and stream them
//! through serde; no per-node JSON value tree is built. This is an inspection
//! schema for typed P-code terms, not decompiled C or recovered types.
use std::sync::Arc;

use ghidra_analysis::{
    AppliedEffects, ExpressionAddress, ExpressionDefinition, ExpressionId, ExpressionKind,
    ExpressionLimits, ExpressionMemoryUse, ExpressionOperand, ExpressionOperation, ExpressionPiece,
    ExpressionType, MemoryAccessKind, PcodeExpressions, PcodeSsa,
};
use ghidra_pcode::{Endianness, Value, Varnode};
use ghidra_ssa::{EntryState, StatementId, ValueId};
use serde::{Serialize, Serializer, ser::Error as _};

pub(crate) const SCHEMA: &str = "ghidra-rs.expressions";
pub(crate) const SCHEMA_VERSION: u32 = 1;

/// Desktop budgets sized to the native analysis limits in `analysis_cli`.
/// Literal bytes stay well below the 64 MiB output cap.
pub(crate) fn limits() -> ExpressionLimits {
    ExpressionLimits {
        max_graph_nodes: 500_000,
        max_values: 2_000_000,
        max_statements: 500_000,
        max_expression_nodes: 4_000_000,
        max_references: 8_000_000,
        max_constant_bytes: 16 * 1024 * 1024,
        max_work: 100_000_000,
    }
}

/// Reconstructs terms from an already verified SSA snapshot. The returned
/// value shares that snapshot's allocation rather than rebuilding it.
pub(crate) fn build(analysis: Arc<PcodeSsa>) -> Result<PcodeExpressions, String> {
    PcodeExpressions::new(analysis, limits())
        .map_err(|e| format!("Expression reconstruction failed: {e}"))
}

/// Streams a compact report through the caller's capped writer budget.
/// `too_large` is reported when the report would exceed `maximum` bytes.
pub(crate) fn json(
    expressions: &PcodeExpressions,
    maximum: usize,
    too_large: &'static str,
) -> Result<Vec<u8>, String> {
    let mut output = crate::analysis_cli::LimitedOutput::new(maximum, too_large);
    serde_json::to_writer(&mut output, &Report(expressions)).map_err(|e| e.to_string())?;
    Ok(output.into_bytes())
}

/// The complete expression report. IDs in `values`, `version`, `statement`
/// and phi definitions are those of the accompanying SSA report.
pub(crate) struct Report<'a>(pub &'a PcodeExpressions);

#[derive(Serialize)]
struct Policies {
    ssa_schema: &'static str,
    ssa_schema_version: u32,
    terms: &'static str,
    evaluation: &'static str,
    fixed_memory_addresses: &'static str,
    pointer_addresses: &'static str,
    memory_model: &'static str,
    undefined_values: &'static str,
    unknown_effects: &'static str,
    type_recovery: bool,
    decompiled_output: bool,
}

const POLICIES: Policies = Policies {
    ssa_schema: "ghidra-rs.pcode-analysis",
    ssa_schema_version: 1,
    terms: "acyclic_nodes_reference_earlier_nodes_ssa_leaves_not_expanded",
    evaluation: "none_opcodes_retained_including_potential_traps",
    fixed_memory_addresses: "byte_offsets",
    pointer_addresses: "addressable_words_scaled_by_word_size",
    memory_model: "versioned_whole_address_space_states",
    undefined_values: "explicit_never_zero",
    unknown_effects: "opaque_definitions_full_domain_uses_in_ssa",
    type_recovery: false,
    decompiled_output: false,
};

#[derive(Serialize)]
struct Counts {
    nodes: usize,
    values: usize,
    operations: usize,
    references: usize,
    constant_bytes: usize,
    build_work: u64,
}

impl Serialize for Report<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let e = self.0;
        let mut report = serializer.serialize_struct("Expressions", 7)?;
        report.serialize_field("schema", SCHEMA)?;
        report.serialize_field("schema_version", &SCHEMA_VERSION)?;
        report.serialize_field("policies", &POLICIES)?;
        report.serialize_field(
            "counts",
            &Counts {
                nodes: e.nodes().len(),
                values: e.analysis().ssa().values().len(),
                operations: e.operations().count(),
                references: e.reference_count(),
                constant_bytes: e.constant_bytes(),
                build_work: e.build_work(),
            },
        )?;
        report.serialize_field("nodes", &Nodes(e))?;
        report.serialize_field("values", &Values(e))?;
        report.serialize_field("operations", &Operations(e))?;
        report.end()
    }
}

struct Nodes<'a>(&'a PcodeExpressions);
impl Serialize for Nodes<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.nodes().iter().enumerate().map(|(id, node)| Node {
            id,
            ty: Type(node.ty),
            term: Term(&node.kind),
        }))
    }
}

#[derive(Serialize)]
struct Node<'a> {
    id: usize,
    #[serde(rename = "type")]
    ty: Type,
    term: Term<'a>,
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

/// Literal bit pattern as unsigned hexadecimal; `bytes` carries the width.
pub(crate) struct Hex<'a>(pub &'a Value);
impl Serialize for Hex<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("0x{:x}", self.0.bits()))
    }
}

struct Ids<'a>(&'a [ExpressionId]);
impl Serialize for Ids<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(|id| id.0))
    }
}

struct ValueIds<'a>(&'a [ValueId]);
impl Serialize for ValueIds<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_seq(self.0.iter().map(|id| id.0))
    }
}

struct Pieces<'a>(&'a [ExpressionPiece]);
impl Serialize for Pieces<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        struct Piece {
            node: usize,
            lsb_byte: u32,
            bytes: u32,
        }
        serializer.collect_seq(self.0.iter().map(|p| Piece {
            node: p.value.0,
            lsb_byte: p.lsb_byte,
            bytes: p.size,
        }))
    }
}

struct Address<'a>(&'a ExpressionAddress);
impl Serialize for Address<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        enum Out {
            ByteOffset {
                offset: u64,
            },
            WordPointer {
                node: usize,
                word_size: u32,
                address_bytes: u8,
            },
        }
        match *self.0 {
            ExpressionAddress::ByteOffset(offset) => Out::ByteOffset { offset },
            ExpressionAddress::Pointer {
                value,
                word_size,
                address_size,
            } => Out::WordPointer {
                node: value.0,
                word_size,
                address_bytes: address_size,
            },
        }
        .serialize(serializer)
    }
}

struct Term<'a>(&'a ExpressionKind);
impl Serialize for Term<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        enum Out<'a> {
            Constant {
                bytes: u32,
                hex: Hex<'a>,
            },
            SsaValue {
                value: usize,
            },
            Join {
                pieces: Pieces<'a>,
            },
            Extract {
                node: usize,
                lsb_byte: u32,
            },
            Apply {
                opcode: &'static str,
                inputs: Ids<'a>,
            },
            ReadMemory {
                space: u32,
                version: usize,
                address: Address<'a>,
                endianness: &'static str,
            },
            WriteMemory {
                space: u32,
                version: usize,
                address: Address<'a>,
                node: usize,
                endianness: &'static str,
            },
        }
        match self.0 {
            ExpressionKind::Constant(value) => Out::Constant {
                bytes: value.size(),
                hex: Hex(value),
            },
            ExpressionKind::SsaValue(value) => Out::SsaValue { value: value.0 },
            ExpressionKind::Join(pieces) => Out::Join {
                pieces: Pieces(pieces),
            },
            ExpressionKind::Extract { value, lsb_byte } => Out::Extract {
                node: value.0,
                lsb_byte: *lsb_byte,
            },
            ExpressionKind::Pure { opcode, inputs } => Out::Apply {
                opcode: opcode.mnemonic(),
                inputs: Ids(inputs),
            },
            ExpressionKind::ReadMemory {
                space,
                version,
                address,
                endianness,
            } => Out::ReadMemory {
                space: space.0,
                version: version.0,
                address: Address(address),
                endianness: endian(*endianness),
            },
            ExpressionKind::WriteMemory {
                space,
                version,
                address,
                value,
                endianness,
            } => Out::WriteMemory {
                space: space.0,
                version: version.0,
                address: Address(address),
                node: value.0,
                endianness: endian(*endianness),
            },
        }
        .serialize(serializer)
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

struct Values<'a>(&'a PcodeExpressions);
impl Serialize for Values<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(tag = "kind", rename_all = "snake_case")]
        enum Definition {
            Entry {
                state: &'static str,
            },
            Phi {
                node: usize,
                index: usize,
            },
            Expression {
                root: usize,
            },
            UndefinedReset {
                statement: Statement,
                instruction: u64,
            },
            Opaque {
                statement: Statement,
                definition_slot: usize,
            },
        }
        #[derive(Serialize)]
        struct Out {
            id: usize,
            variable: usize,
            #[serde(rename = "type")]
            ty: Type,
            definition: Definition,
        }
        let e = self.0;
        let ssa = e.analysis().ssa();
        serializer.collect_seq(
            ssa.values()
                .iter()
                .enumerate()
                .map(|(id, value)| {
                    let definition = e.definition(ValueId(id))?;
                    Ok(Out {
                        id,
                        variable: value.variable.0,
                        ty: Type(e.value_type(ValueId(id))?),
                        definition: match *definition {
                            ExpressionDefinition::Entry(state) => Definition::Entry {
                                state: match state {
                                    EntryState::Input => "input",
                                    EntryState::Undefined => "undefined",
                                },
                            },
                            ExpressionDefinition::Phi(phi) => Definition::Phi {
                                node: phi.node,
                                index: phi.index,
                            },
                            ExpressionDefinition::Expression(root) => {
                                Definition::Expression { root: root.0 }
                            }
                            ExpressionDefinition::Undefined {
                                statement,
                                instruction,
                            } => Definition::UndefinedReset {
                                statement: statement.into(),
                                instruction,
                            },
                            ExpressionDefinition::Opaque {
                                statement,
                                definition_slot,
                            } => Definition::Opaque {
                                statement: statement.into(),
                                definition_slot,
                            },
                        },
                    })
                })
                .map(Fallible),
        )
    }
}

/// Reports an inconsistent snapshot as a serialization error rather than
/// emitting a partial or guessed record.
struct Fallible<T>(Result<T, ghidra_analysis::ExpressionError>);
impl<T: Serialize> Serialize for Fallible<T> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match &self.0 {
            Ok(value) => value.serialize(serializer),
            Err(error) => Err(S::Error::custom(error)),
        }
    }
}

struct Operations<'a>(&'a PcodeExpressions);
impl Serialize for Operations<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let e = self.0;
        serializer.collect_seq(
            e.operations()
                .map(|operation| Fallible(operation_out(e, operation))),
        )
    }
}

#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum Effects {
    Explicit,
    Conservative { class: ghidra_analysis::EffectClass },
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum ResultKind {
    /// `output` names the complete bit result.
    Expression,
    /// STORE and control operations; memory writes are value definitions.
    None,
    /// Definitions are opaque; no term is reconstructed.
    Opaque,
}

#[derive(Serialize)]
struct Point {
    address: u64,
    operation_index: u32,
}

#[derive(Serialize)]
struct MemoryUse {
    space: u32,
    version: usize,
    access: &'static str,
}
impl From<&ExpressionMemoryUse> for MemoryUse {
    fn from(memory: &ExpressionMemoryUse) -> Self {
        Self {
            space: memory.space.0,
            version: memory.version.0,
            access: match memory.kind {
                MemoryAccessKind::Read => "read",
                MemoryAccessKind::Write => "write",
            },
        }
    }
}

#[derive(Serialize)]
struct OperationOut<'a> {
    statement: Statement,
    point: Point,
    opcode: &'static str,
    effects: Effects,
    operands: Operands<'a>,
    result: ResultKind,
    output: Option<usize>,
    indirect_memory: Option<MemoryUse>,
    definitions: ValueIds<'a>,
}

fn operation_out<'a>(
    e: &'a PcodeExpressions,
    operation: &'a ExpressionOperation,
) -> Result<OperationOut<'a>, ghidra_analysis::ExpressionError> {
    let definitions = e
        .analysis()
        .ssa()
        .statement(operation.statement)
        .map_err(|_| ghidra_analysis::ExpressionError::Inconsistent("operation statement"))?
        .defs();
    let (effects, result) = match operation.effects {
        AppliedEffects::Explicit => (
            Effects::Explicit,
            if operation.output.is_some() {
                ResultKind::Expression
            } else {
                ResultKind::None
            },
        ),
        AppliedEffects::Conservative(class) => {
            (Effects::Conservative { class }, ResultKind::Opaque)
        }
    };
    Ok(OperationOut {
        statement: operation.statement.into(),
        point: Point {
            address: operation.point.address,
            operation_index: operation.point.operation_index,
        },
        opcode: operation.opcode.mnemonic(),
        effects,
        operands: Operands(&operation.operands),
        result,
        output: operation.output.map(|id| id.0),
        indirect_memory: operation.indirect_memory.as_ref().map(Into::into),
        definitions: ValueIds(definitions),
    })
}

struct Operands<'a>(&'a [ExpressionOperand]);
impl Serialize for Operands<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(tag = "role", rename_all = "snake_case")]
        enum Out {
            Value { node: usize },
            ConstantMetadata { node: usize, source: Varnode },
            RelativeTarget { offset: i32 },
            DirectTarget { target: Varnode },
            SpaceSelector { space: u32 },
            Userop { index: u64 },
            OperationReference { source: Varnode },
        }
        serializer.collect_seq(self.0.iter().map(|operand| match *operand {
            ExpressionOperand::Value(node) => Out::Value { node: node.0 },
            ExpressionOperand::ConstantMetadata { source, value } => Out::ConstantMetadata {
                node: value.0,
                source,
            },
            ExpressionOperand::RelativeTarget(offset) => Out::RelativeTarget { offset },
            ExpressionOperand::DirectTarget(target) => Out::DirectTarget { target },
            ExpressionOperand::SpaceSelector(space) => Out::SpaceSelector { space: space.0 },
            ExpressionOperand::Userop(index) => Out::Userop { index },
            ExpressionOperand::OperationReference(source) => Out::OperationReference { source },
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

    fn bits(ty: &Json) -> u64 {
        assert_eq!(ty["kind"], "bits", "{ty}");
        ty["bytes"].as_u64().unwrap()
    }

    fn statement_of(origin: &Json) -> Json {
        serde_json::json!({"node": origin["node"], "index": origin["statement"]})
    }

    /// Checks every reference in an expression report against the SSA report
    /// it accompanies: IDs, origins, types, memory versions and roles.
    pub(crate) fn validate(ssa: &Json, report: &Json) {
        assert_eq!(report["schema"], SCHEMA);
        assert_eq!(report["schema_version"], SCHEMA_VERSION);
        assert_eq!(report["policies"]["ssa_schema"], ssa["schema"]);
        assert_eq!(report["policies"]["type_recovery"], false);
        assert_eq!(report["policies"]["decompiled_output"], false);
        let nodes = report["nodes"].as_array().unwrap();
        let values = report["values"].as_array().unwrap();
        let operations = report["operations"].as_array().unwrap();
        let ssa_values = ssa["values"].as_array().unwrap();
        let ssa_nodes = ssa["nodes"].as_array().unwrap();
        let counts = &report["counts"];
        assert_eq!(id(&counts["nodes"]), nodes.len());
        assert_eq!(id(&counts["values"]), values.len());
        assert_eq!(id(&counts["operations"]), operations.len());
        assert_eq!(values.len(), ssa_values.len());
        let memory_version = |version: &Json, space: &Json| {
            let ty = &values[id(version)]["type"];
            assert_eq!(ty["kind"], "memory");
            assert_eq!(&ty["space"], space);
        };
        for (current, node) in nodes.iter().enumerate() {
            assert_eq!(id(&node["id"]), current);
            let child = |reference: &Json| {
                let child = id(reference);
                assert!(
                    child < current,
                    "node {current} must reference earlier nodes"
                );
                &nodes[child]["type"]
            };
            let address = |address: &Json| match address["kind"].as_str().unwrap() {
                "byte_offset" => assert!(address["offset"].is_u64()),
                "word_pointer" => {
                    assert_eq!(bits(child(&address["node"])), address["address_bytes"]);
                    assert!(address["word_size"].as_u64().unwrap() >= 1);
                }
                other => panic!("address kind {other}"),
            };
            let ty = &node["type"];
            let term = &node["term"];
            match term["kind"].as_str().unwrap() {
                "constant" => {
                    assert_eq!(bits(ty), term["bytes"]);
                    let hex = term["hex"].as_str().unwrap();
                    assert!(hex.starts_with("0x"));
                    assert!(hex.len() - 2 <= 2 * term["bytes"].as_u64().unwrap() as usize);
                }
                "ssa_value" => assert_eq!(ty, &values[id(&term["value"])]["type"]),
                "join" => {
                    let mut next = 0;
                    for piece in term["pieces"].as_array().unwrap() {
                        assert_eq!(piece["lsb_byte"], next);
                        assert_eq!(bits(child(&piece["node"])), piece["bytes"]);
                        next += piece["bytes"].as_u64().unwrap();
                    }
                    assert_eq!(bits(ty), next);
                }
                "extract" => {
                    let end = term["lsb_byte"].as_u64().unwrap() + bits(ty);
                    assert!(end <= bits(child(&term["node"])));
                }
                "apply" => {
                    assert!(!term["opcode"].as_str().unwrap().is_empty());
                    for input in term["inputs"].as_array().unwrap() {
                        child(input);
                    }
                    bits(ty);
                }
                "read_memory" => {
                    bits(ty);
                    memory_version(&term["version"], &term["space"]);
                    address(&term["address"]);
                    assert!(matches!(
                        term["endianness"].as_str(),
                        Some("little" | "big")
                    ));
                }
                "write_memory" => {
                    assert_eq!(ty["kind"], "memory");
                    assert_eq!(ty["space"], term["space"]);
                    memory_version(&term["version"], &term["space"]);
                    address(&term["address"]);
                    bits(child(&term["node"]));
                }
                other => panic!("term kind {other}"),
            }
        }
        let statement = |s: &Json| &ssa_nodes[id(&s["node"])]["statements"][id(&s["index"])];
        let operation_at = |s: &Json| {
            operations.iter().find(|o| {
                o["statement"]["node"] == s["node"] && o["statement"]["index"] == s["index"]
            })
        };
        for (current, value) in values.iter().enumerate() {
            assert_eq!(id(&value["id"]), current);
            let ssa_value = &ssa_values[current];
            assert_eq!(value["variable"], ssa_value["variable"]);
            let origin = &ssa_value["origin"];
            let definition = &value["definition"];
            match definition["kind"].as_str().unwrap() {
                "entry" => {
                    assert_eq!(origin["kind"], "entry");
                    assert_eq!(origin["state"], definition["state"]);
                }
                "phi" => {
                    assert_eq!(origin["kind"], "phi");
                    assert_eq!(origin["node"], definition["node"]);
                    assert_eq!(origin["index"], definition["index"]);
                    let phi = &ssa_nodes[id(&definition["node"])]["phis"][id(&definition["index"])];
                    assert_eq!(id(&phi["value"]), current);
                }
                kind => {
                    assert_eq!(origin["kind"], "definition");
                    let site = statement_of(origin);
                    let source = statement(&site);
                    let slot = id(&origin["slot"]);
                    assert_eq!(id(&source["renamed"]["definitions"][slot]), current);
                    match kind {
                        "expression" => {
                            assert_eq!(nodes[id(&definition["root"])]["type"], value["type"]);
                            assert_ne!(operation_at(&site).unwrap()["result"], "opaque");
                        }
                        "undefined_reset" => {
                            assert_eq!(definition["statement"], site);
                            assert_eq!(source["source"]["kind"], "undefined_temporaries");
                            assert_eq!(source["source"]["address"], definition["instruction"]);
                            assert!(operation_at(&site).is_none());
                        }
                        "opaque" => {
                            assert_eq!(definition["statement"], site);
                            assert_eq!(definition["definition_slot"], origin["slot"]);
                            let operation = operation_at(&site).unwrap();
                            assert_eq!(operation["result"], "opaque");
                            assert_eq!(operation["effects"]["kind"], "conservative");
                            assert!(operation["output"].is_null());
                        }
                        other => panic!("definition kind {other}"),
                    }
                }
            }
        }
        for operation in operations {
            let source = statement(&operation["statement"]);
            assert_eq!(source["source"]["kind"], "operation");
            assert_eq!(source["source"]["point"], operation["point"]);
            assert_eq!(source["renamed"]["definitions"], operation["definitions"]);
            let opaque = operation["effects"]["kind"] == "conservative";
            assert_eq!(opaque, operation["result"] == "opaque");
            assert_eq!(
                operation["result"] == "expression",
                !operation["output"].is_null()
            );
            if let Some(output) = operation["output"].as_u64() {
                bits(&nodes[output as usize]["type"]);
            }
            for operand in operation["operands"].as_array().unwrap() {
                if let Some(node) = operand["node"].as_u64() {
                    assert!((node as usize) < nodes.len());
                }
                assert!(matches!(
                    operand["role"].as_str().unwrap(),
                    "value"
                        | "constant_metadata"
                        | "relative_target"
                        | "direct_target"
                        | "space_selector"
                        | "userop"
                        | "operation_reference"
                ));
            }
            if !operation["indirect_memory"].is_null() {
                let memory = &operation["indirect_memory"];
                memory_version(&memory["version"], &memory["space"]);
            }
        }
    }
}
