//! Bounded lifting of recovered binary functions. The initial path is x86-only:
//! context-changing instructions and delay bundles require a flow-aware decoder.
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex, mpsc},
};

use ghidra_analysis::{
    AnalysisOptions, PcodeConstants, PcodeExpressions, PcodeSsa, UnknownEffectPolicy,
};
use ghidra_cfg::{Cfg, CfgInput};
use ghidra_core::{
    BinaryImage,
    functions::{Function, FunctionDiscovery},
};
use ghidra_pcode::Endianness;
use ghidra_sleigh::SleighLanguage;
use serde::Serialize;

use crate::lifting::LanguageConfig;

pub(crate) struct CommandArguments {
    entry: u64,
    context: BTreeMap<String, u64>,
    havoc_unknown: bool,
    simplify: bool,
}

impl CommandArguments {
    pub fn parse(entry: &str, arguments: &[String]) -> Result<Self, String> {
        if arguments.len() > ghidra_project::MAX_CONTEXT_FIELDS + 2 {
            return Err("Too many function analysis arguments".into());
        }
        let entry = crate::pcode_cli::hex_address(entry)?;
        let mut havoc_unknown = false;
        let mut simplify = false;
        let mut context = Vec::new();
        for argument in arguments {
            if argument == "--havoc-unknown" && !havoc_unknown {
                havoc_unknown = true;
            } else if argument == "--simplify" && !simplify {
                simplify = true;
            } else if argument.starts_with('-') {
                return Err(format!(
                    "Unknown or duplicate function analysis option: {argument}"
                ));
            } else {
                context.push(argument.clone());
            }
        }
        Ok(Self {
            entry,
            context: crate::pcode_cli::context_overrides(&context)?,
            havoc_unknown,
            simplify,
        })
    }
}

pub(crate) fn execute(
    binary: &std::path::Path,
    root: &std::path::Path,
    language_id: &str,
    arguments: CommandArguments,
) -> Result<(), String> {
    use std::io::Write;
    let loaded = crate::report::load_path(binary)?;
    let catalog = ghidra_languages::Catalog::discover(root).map_err(|e| e.to_string())?;
    let definition = catalog
        .by_id(language_id)
        .ok_or_else(|| format!("Unknown language ID: {language_id}"))?
        .clone();
    let source = definition
        .source
        .available_path()
        .ok_or("Selected language source is unavailable")?
        .to_path_buf();
    let request = FunctionRequest {
        key: RequestKey {
            id: 0,
            generation: 0,
            revision: 0,
            entry: arguments.entry,
        },
        config: LanguageConfig {
            source,
            definition: Some(definition),
            context: arguments.context,
            revision: 0,
        },
        image: loaded.image,
        functions: loaded.functions,
        havoc_unknown: arguments.havoc_unknown,
    };
    let result = Compiler::default().analyze(&request)?;
    // `--simplify` is opt-in: the shared worker result is unchanged, and the
    // field is appended to its exact document.
    let simplified = if arguments.simplify {
        let simplification = crate::simplification_report::build(result.constants.clone())?;
        Some(simplified_json(&result, &simplification, MAX_DOCUMENT)?)
    } else {
        None
    };
    // The document was assembled within `MAX_DOCUMENT`, so the final newline
    // keeps stdout within the 64 MiB cap.
    let mut stdout = std::io::stdout().lock();
    stdout
        .write_all(simplified.as_deref().unwrap_or(result.json.as_bytes()))
        .map_err(|e| e.to_string())?;
    writeln!(stdout).map_err(|e| e.to_string())?;
    stdout.flush().map_err(|e| e.to_string())
}

pub(crate) const MAX_FUNCTION_INSTRUCTIONS: usize = 5_000;
const MAX_FUNCTION_OPERATIONS: usize = 100_000;
const MAX_DISASSEMBLY_BYTES: usize = 4 * 1024 * 1024;
const MAX_JSON: usize = 64 * 1024 * 1024;
/// The document without the command's final newline, so stdout stays within
/// `MAX_JSON` bytes and the desktop copy uses the same limit.
const MAX_DOCUMENT: usize = MAX_JSON - 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RequestKey {
    pub id: u64,
    pub generation: u64,
    pub revision: u64,
    pub entry: u64,
}

#[derive(Clone)]
pub(crate) struct FunctionRequest {
    pub key: RequestKey,
    pub config: LanguageConfig,
    pub image: Arc<BinaryImage>,
    pub functions: Arc<FunctionDiscovery>,
    pub havoc_unknown: bool,
}

pub(crate) struct FunctionResponse {
    pub key: RequestKey,
    pub result: Result<FunctionView, String>,
}

#[derive(Debug)]
pub(crate) struct FunctionView {
    pub entry: u64,
    pub name: String,
    pub complete: bool,
    pub language_id: String,
    pub native: Vec<NativeInstruction>,
    /// The verified SSA snapshot; the same allocation as `expressions.analysis()`.
    pub analysis: Arc<PcodeSsa>,
    /// Typed terms reconstructed on the worker after SSA verification.
    pub expressions: Arc<PcodeExpressions>,
    /// Statements with expression operations, in node/statement order, so the
    /// UI can virtualize operation rows without rescanning every frame.
    pub expression_operations: Vec<ghidra_ssa::StatementId>,
    /// Sparse conditional constant facts built on the worker from the same
    /// `expressions` allocation. Feasibility is conservative and static.
    pub constants: Arc<PcodeConstants>,
    /// Values proven constant, ascending, collected once for virtual rows.
    pub constant_values: Vec<ghidra_ssa::ValueId>,
    pub json: String,
}

#[derive(Debug, Serialize)]
pub(crate) struct NativeInstruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub disassembly: String,
}

pub(crate) struct FunctionWorker {
    latest: Arc<Mutex<Option<FunctionRequest>>>,
    wake: mpsc::SyncSender<()>,
    results: mpsc::Receiver<FunctionResponse>,
}

impl FunctionWorker {
    pub fn spawn() -> Self {
        let latest = Arc::new(Mutex::new(None::<FunctionRequest>));
        let (wake, signal) = mpsc::sync_channel(1);
        let (sender, results) = mpsc::sync_channel(1);
        let work = latest.clone();
        std::thread::spawn(move || {
            let mut cache = Compiler::default();
            while signal.recv().is_ok() {
                let request = match work.lock() {
                    Ok(mut latest) => latest.take(),
                    Err(_) => break,
                };
                let Some(request) = request else {
                    continue;
                };
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    cache.analyze(&request)
                }))
                .unwrap_or_else(|_| {
                    cache = Compiler::default();
                    Err(
                        "Function analysis worker panicked; its compiled state was discarded"
                            .into(),
                    )
                });
                if sender
                    .send(FunctionResponse {
                        key: request.key,
                        result,
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
        Self {
            latest,
            wake,
            results,
        }
    }

    pub fn request(&self, request: FunctionRequest) -> Result<(), String> {
        validate_request(&request)?;
        *self
            .latest
            .lock()
            .map_err(|_| "Function analysis worker state is unavailable")? = Some(request);
        match self.wake.try_send(()) {
            Ok(()) | Err(mpsc::TrySendError::Full(())) => Ok(()),
            Err(mpsc::TrySendError::Disconnected(())) => {
                Err("Function analysis worker stopped".into())
            }
        }
    }

    pub fn try_recv(&self) -> Result<Option<FunctionResponse>, String> {
        match self.results.try_recv() {
            Ok(response) => Ok(Some(response)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err("Function analysis worker stopped".into()),
        }
    }
}

fn validate_request(request: &FunctionRequest) -> Result<&Function, String> {
    if request.config.context.len() > ghidra_project::MAX_CONTEXT_FIELDS
        || request
            .config
            .context
            .keys()
            .any(|name| name.is_empty() || name.len() > ghidra_project::MAX_CONTEXT_NAME_BYTES)
    {
        return Err("Function processor context exceeds its field/name limits".into());
    }
    if !request.image.supports_x86_disassembly() {
        return Err("Recovered function lifting currently requires an x86/x64 binary".into());
    }
    if request.image.sections.len() > 4096 || request.functions.functions.len() > 4096 {
        return Err("Function analysis mapping/function count limit exceeded".into());
    }
    let definition = request.config.definition.as_ref().ok_or(
        "Choose a matching x86 catalog language in the P-code tab before analyzing a function",
    )?;
    if !definition.processor.eq_ignore_ascii_case("x86")
        || definition.size != request.image.bitness
        || definition.endian != Endianness::Little
        || definition.instruction_endian != Endianness::Little
    {
        return Err("Function analysis requires an x86 catalog language matching the binary's bitness and byte order".into());
    }
    let function = request
        .functions
        .functions
        .iter()
        .find(|f| f.entry == request.key.entry)
        .ok_or("The requested recovered function is unavailable")?;
    if function.instructions.is_empty() || function.instructions.len() > MAX_FUNCTION_INSTRUCTIONS {
        return Err(format!(
            "Function analysis requires 1..={MAX_FUNCTION_INSTRUCTIONS} recovered instructions"
        ));
    }
    if function.name.len() > 2048 {
        return Err("Function analysis name exceeds 2048 bytes".into());
    }
    Ok(function)
}

pub(crate) mod reduced;
#[cfg(test)]
pub(crate) mod tests;

#[derive(Default)]
struct Compiler {
    compiled: Option<(LanguageConfig, SleighLanguage)>,
    failed: Option<(LanguageConfig, String)>,
}

impl Compiler {
    fn analyze(&mut self, request: &FunctionRequest) -> Result<FunctionView, String> {
        let function = validate_request(request)?;
        let cache_hit = self
            .compiled
            .as_ref()
            .is_some_and(|(config, _)| config == &request.config);
        if !cache_hit {
            if let Some((config, error)) = &self.failed
                && config == &request.config
            {
                return Err(error.clone());
            }
            let result = SleighLanguage::from_language(
                request
                    .config
                    .definition
                    .as_ref()
                    .expect("catalog validation"),
                &request.config.context,
            )
            .map_err(|e| e.to_string());
            match result {
                Ok(language) => {
                    self.compiled = Some((request.config.clone(), language));
                    self.failed = None;
                }
                Err(error) => {
                    self.failed = Some((request.config.clone(), error.clone()));
                    return Err(error);
                }
            }
        }
        let language = &mut self.compiled.as_mut().expect("compiled language").1;
        let mut poisoned = false;
        let result = lift_function(request, function, language, &mut poisoned);
        // Decode/analysis errors do not invalidate a successfully compiled
        // language. Clear its dynamic context; dependency panics discard it.
        if result.is_err() {
            language.reset_context();
        }
        if poisoned {
            self.compiled = None;
        }
        result
    }
}

fn lift_function(
    request: &FunctionRequest,
    function: &Function,
    language: &mut SleighLanguage,
    poisoned: &mut bool,
) -> Result<FunctionView, String> {
    if !language.spaces().iter().any(|s| {
        s.id == language.code_space()
            && u32::from(s.address_size) * 8 == request.image.bitness
            && s.word_size == 1
    }) {
        return Err("Compiled language code-space width does not match this binary".into());
    }
    let mut order = BTreeMap::new();
    for instruction in &function.instructions {
        if !(1..=15).contains(&instruction.bytes.len())
            || order.insert(instruction.address, instruction).is_some()
        {
            return Err(
                "Recovered function has an invalid instruction size or duplicate address".into(),
            );
        }
    }
    if !order.contains_key(&function.entry) {
        return Err("Recovered function has no entry instruction".into());
    }
    let mut native = Vec::with_capacity(order.len());
    let mut instructions = Vec::with_capacity(order.len());
    let mut operations = 0usize;
    let mut display_bytes = 0usize;
    let mut previous_end = None;
    for instruction in order.values() {
        if previous_end.is_some_and(|end| instruction.address < end) {
            return Err("Recovered function instructions overlap".into());
        }
        let next = instruction
            .address
            .checked_add(instruction.bytes.len() as u64)
            .ok_or("Native instruction address overflow")?;
        previous_end = Some(next);
        let bytes = crate::lifting::instruction_window(&request.image, instruction.address)?;
        if !bytes.starts_with(&instruction.bytes) {
            return Err(format!(
                "Recovered bytes at {:X} differ from the loaded binary",
                instruction.address
            ));
        }
        language.reset_context();
        let lifted = language.decode(instruction.address, &bytes).map_err(|e| {
            *poisoned = matches!(e, ghidra_sleigh::Error::DependencyPanic(_));
            format!("At {:X}: {e}", instruction.address)
        })?;
        display_bytes = display_bytes
            .checked_add(lifted.text.len())
            .filter(|&n| n <= MAX_DISASSEMBLY_BYTES)
            .ok_or("Function disassembly text exceeds 4 MiB")?;
        if lifted.text.len() > 4096 {
            return Err("Instruction disassembly text exceeds 4096 bytes".into());
        }
        if lifted.context_commits != 0 {
            return Err(format!(
                "Instruction at {:X} emits decode context commits; flow-aware function lifting is required",
                instruction.address
            ));
        }
        if !lifted.delay_slots.is_empty() {
            return Err("Function lifting of delay-slot bundles is not implemented".into());
        }
        if lifted.length as usize != instruction.bytes.len()
            || lifted.next_address != next
            || lifted.instruction.length != lifted.length
        {
            return Err(format!(
                "SLEIGH and binary recovery disagree on the instruction boundary at {:X}",
                instruction.address
            ));
        }
        operations = operations
            .checked_add(lifted.instruction.ops.len())
            .ok_or("Function operation count overflow")?;
        if operations > MAX_FUNCTION_OPERATIONS {
            return Err("Function exceeds 100000 lifted P-code operations".into());
        }
        native.push(NativeInstruction {
            address: instruction.address,
            bytes: instruction.bytes.clone(),
            disassembly: lifted.text,
        });
        instructions.push(lifted.instruction);
    }
    let limits = crate::analysis_cli::limits();
    let cfg = Arc::new(
        Cfg::new(
            CfgInput::new(
                language.spaces().to_vec(),
                language.code_space(),
                function.entry,
                instructions,
            ),
            ghidra_cfg::Limits {
                graph: limits.graph,
                ..Default::default()
            },
        )
        .map_err(|e| e.to_string())?,
    );
    let mut options = AnalysisOptions::native();
    if request.havoc_unknown {
        options.unknown_effects = UnknownEffectPolicy::HavocAll;
    }
    let analysis = Arc::new(PcodeSsa::new(cfg, &[], options, limits).map_err(|e| e.to_string())?);
    analysis
        .ssa()
        .verify(analysis.raw())
        .map_err(|e| e.to_string())?;
    let expressions = Arc::new(crate::expression_report::build(analysis.clone())?);
    let constants = Arc::new(crate::constant_report::build(expressions.clone())?);
    let definition = request
        .config
        .definition
        .as_ref()
        .expect("catalog validation");
    #[derive(Serialize)]
    struct Metadata<'a> {
        entry: u64,
        name: &'a str,
        recovery_complete: bool,
        language_id: &'a str,
        language_major: u32,
        language_minor: u32,
        context_overrides: &'a BTreeMap<String, u64>,
        decode_context: &'static str,
        boundary_validation: &'static str,
        native_instructions: &'a [NativeInstruction],
    }
    let metadata = serde_json::to_vec(&Metadata {
        entry: function.entry,
        name: &function.name,
        recovery_complete: function.complete,
        language_id: &definition.id,
        language_major: definition.version.major,
        language_minor: definition.version.minor,
        context_overrides: &request.config.context,
        decode_context: "independent_processor_defaults_no_context_commits",
        boundary_validation: "matches_recovered_lengths_and_loaded_bytes",
        native_instructions: &native,
    })
    .map_err(|e| e.to_string())?;
    let dataflow = crate::analysis_cli::symbolic_json(&analysis)?;
    let json = function_json(
        &metadata,
        &dataflow,
        MAX_DOCUMENT,
        |remaining| crate::expression_report::json(&expressions, remaining, FUNCTION_TOO_LARGE),
        |remaining| crate::constant_report::json(&constants, remaining, FUNCTION_TOO_LARGE),
    )?;
    Ok(FunctionView {
        entry: function.entry,
        name: function.name.clone(),
        complete: function.complete,
        language_id: definition.id.clone(),
        native,
        expression_operations: expressions.operations().map(|o| o.statement).collect(),
        constant_values: constants.constants().map(|(id, _)| id).collect(),
        analysis,
        expressions,
        constants,
        json: String::from_utf8(json).map_err(|e| e.to_string())?,
    })
}

const FUNCTION_TOO_LARGE: &str = "Function analysis JSON exceeds 64 MiB";
const FUNCTION_PREFIX: &[u8] =
    br#"{"schema":"ghidra-rs.function-analysis","schema_version":1,"function":"#;
const ANALYSIS_KEY: &[u8] = br#","analysis":"#;
const EXPRESSIONS_KEY: &[u8] = br#","expressions":"#;
const CONSTANTS_KEY: &[u8] = br#","constants":"#;
const SIMPLIFICATION_KEY: &[u8] = br#","simplification":"#;

/// The `--analyze-function --simplify` document without its final newline:
/// the function's exact document with a final `simplification` field, within
/// `maximum` bytes. The command and the desktop's reduced copy both use it,
/// and it rejects a simplification of any other snapshot.
fn simplified_json(
    result: &FunctionView,
    simplification: &ghidra_analysis::PcodeSimplification,
    maximum: usize,
) -> Result<Vec<u8>, String> {
    if !Arc::ptr_eq(simplification.constants(), &result.constants)
        || !Arc::ptr_eq(simplification.expressions(), &result.expressions)
        || !Arc::ptr_eq(simplification.analysis(), &result.analysis)
    {
        return Err("Simplification belongs to a different function snapshot".into());
    }
    append_field(
        result.json.as_bytes(),
        SIMPLIFICATION_KEY,
        maximum,
        |remaining| {
            crate::simplification_report::json(simplification, remaining, FUNCTION_TOO_LARGE)
        },
    )
}

/// Appends `key` and a report before the closing brace of a complete JSON
/// object, within `maximum` bytes. The report is serialized into exactly the
/// budget left by the document and key, and the result is reserved once.
fn append_field(
    document: &[u8],
    key: &[u8],
    maximum: usize,
    report: impl FnOnce(usize) -> Result<Vec<u8>, String>,
) -> Result<Vec<u8>, String> {
    let Some((b'}', body)) = document.split_last() else {
        return Err("Function JSON is not a complete object".into());
    };
    let fixed = document
        .len()
        .checked_add(key.len())
        .ok_or("Function JSON size overflow")?;
    let remaining = maximum.checked_sub(fixed).ok_or(FUNCTION_TOO_LARGE)?;
    let report = report(remaining)?;
    let size = fixed
        .checked_add(report.len())
        .filter(|&n| n <= maximum)
        .ok_or(FUNCTION_TOO_LARGE)?;
    let mut json = Vec::with_capacity(size);
    json.extend_from_slice(body);
    json.extend_from_slice(key);
    json.extend_from_slice(&report);
    json.push(b'}');
    debug_assert_eq!(json.len(), size);
    Ok(json)
}

/// Assembles `{prefix function, analysis, expressions, constants}` within
/// `maximum` bytes. Each report is serialized into exactly the budget left by
/// the fixed parts and earlier reports, and the final buffer is reserved once
/// at its exact size.
fn function_json(
    metadata: &[u8],
    dataflow: &[u8],
    maximum: usize,
    expressions: impl FnOnce(usize) -> Result<Vec<u8>, String>,
    constants: impl FnOnce(usize) -> Result<Vec<u8>, String>,
) -> Result<Vec<u8>, String> {
    let fixed = [
        FUNCTION_PREFIX.len(),
        metadata.len(),
        ANALYSIS_KEY.len(),
        dataflow.len(),
        EXPRESSIONS_KEY.len(),
        CONSTANTS_KEY.len(),
        1,
    ]
    .into_iter()
    .try_fold(0usize, usize::checked_add)
    .ok_or("Function JSON size overflow")?;
    let remaining = maximum.checked_sub(fixed).ok_or(FUNCTION_TOO_LARGE)?;
    let expressions = expressions(remaining)?;
    let remaining = remaining
        .checked_sub(expressions.len())
        .ok_or(FUNCTION_TOO_LARGE)?;
    let constants = constants(remaining)?;
    let size = [fixed, expressions.len(), constants.len()]
        .into_iter()
        .try_fold(0usize, usize::checked_add)
        .filter(|&n| n <= maximum)
        .ok_or(FUNCTION_TOO_LARGE)?;
    let mut json = Vec::with_capacity(size);
    json.extend_from_slice(FUNCTION_PREFIX);
    json.extend_from_slice(metadata);
    json.extend_from_slice(ANALYSIS_KEY);
    json.extend_from_slice(dataflow);
    json.extend_from_slice(EXPRESSIONS_KEY);
    json.extend_from_slice(&expressions);
    json.extend_from_slice(CONSTANTS_KEY);
    json.extend_from_slice(&constants);
    json.push(b'}');
    debug_assert_eq!(json.len(), size);
    Ok(json)
}
