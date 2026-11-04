//! `sleigh-compile` — compile a SLEIGH specification from source and report on it.
//!
//! Arguments come either from flags or from one JSON object whose keys are
//! the flag names; `--json` switches the output to JSON.
//!
//! ```text
//! sleigh-compile open_sleigh/src/x86/x86-64.slaspec --decode 90
//! sleigh-compile --args '{"spec":"open_sleigh/src/x86/x86-64.slaspec","decode":"4889d8"}' --json
//! sleigh-compile broken.slaspec --no-config --json
//! ```

use clap::Parser;
use serde::{Deserialize, Serialize};
use sleigh::{CompileOptions, CompiledSpec, Compiler, ContextBytes, Decoder, SourceDb};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    process,
    time::Instant,
};

/// Compile a SLEIGH specification from source and report on it.
#[derive(Parser)]
#[command(name = "sleigh-compile", version)]
struct Cli {
    /// All options as one JSON object; keys are the long flag names
    #[arg(long, value_name = "JSON", conflicts_with_all = ["spec", "define", "context", "no_config", "decode", "address", "lint"])]
    args: Option<String>,
    /// Emit JSON instead of text
    #[arg(long)]
    json: bool,
    #[command(flatten)]
    opts: Opts,
}

/// The options proper: one struct for both the flags and the `--args` JSON.
#[derive(clap::Args, Deserialize, Default)]
#[serde(default, deny_unknown_fields)]
struct Opts {
    /// Path to a .slaspec file
    spec: Option<String>,
    /// Preprocessor define as KEY=VALUE (repeatable)
    #[arg(long = "define")]
    define: Vec<String>,
    /// Initial context field as FIELD=VALUE (repeatable)
    #[arg(long = "context")]
    context: Vec<String>,
    /// Skip the build_config.toml lookup for defines/context
    #[arg(long = "no-config")]
    #[serde(rename = "no-config")]
    no_config: bool,
    /// After compiling, decode these bytes once to prove the spec works
    #[arg(long)]
    decode: Option<String>,
    /// Address to decode at (decimal or 0x-prefixed)
    #[arg(long, default_value = "0")]
    #[serde(default = "default_address")]
    address: String,
    /// Run the crate's lint pass and include its diagnostics in the output
    #[arg(long)]
    lint: bool,
}

/// One architecture entry of `build_config.toml`.
#[derive(Deserialize)]
struct Arch {
    path: String,
    defines: Option<HashMap<String, String>>,
    context: Option<HashMap<String, u64>>,
}

#[derive(Serialize)]
struct Output {
    spec: String,
    ok: bool,
    diagnostics: Vec<DiagnosticOut>,
    registers: usize,
    tables: usize,
    spaces: Vec<SpaceOut>,
    context_fields: usize,
    default_space: Option<String>,
    applied_context: HashMap<String, u64>,
    decoded: Option<Decoded>,
    compile_ms: f64,
}

#[derive(Serialize)]
struct DiagnosticOut {
    severity: String,
    message: String,
    location: String,
}

#[derive(Serialize)]
struct SpaceOut {
    name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    size: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    wordsize: Option<usize>,
}

#[derive(Serialize)]
struct Decoded {
    address: String,
    text: String,
}

fn parse_int(what: &str, value: &str) -> Result<u64, String> {
    let value = value.trim();
    match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => value.parse(),
    }
    .map_err(|_| format!("invalid {what} '{value}'"))
}

fn default_address() -> String {
    "0".to_string()
}

fn parse_hex(value: &str) -> Result<Vec<u8>, String> {
    let value: String = value.chars().filter(|c| !c.is_whitespace()).collect();
    if value.is_empty() || value.len() % 2 != 0 {
        return Err("bytes must be a non-empty, even-length hex string".to_string());
    }
    (0..value.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&value[i..i + 2], 16)
                .map_err(|_| format!("invalid hex byte '{}'", &value[i..i + 2]))
        })
        .collect()
}

fn parse_kv(what: &str, entry: &str) -> Result<(String, String), String> {
    entry
        .split_once('=')
        .map(|(k, v)| (k.trim().to_string(), v.trim().to_string()))
        .ok_or_else(|| format!("invalid {what} '{entry}': expected KEY=VALUE"))
}

fn parse_context_value(what: &str, value: &str) -> Result<u64, String> {
    let value = value.trim();
    match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => value.parse(),
    }
    .map_err(|_| format!("invalid {what} value '{value}'"))
}

/// Finds the `build_config.toml` governing `spec_path`, if there is one.
///
/// Walks up from the specification towards the filesystem root, accepting
/// either a sibling `build_config.toml` or one inside a `precompile/`
/// directory, so both a path into the workspace and a path relative to
/// `precompile/` itself resolve.
fn find_config(spec_path: &Path) -> Option<PathBuf> {
    let start = fs::canonicalize(spec_path).ok()?;
    start.ancestors().skip(1).find_map(|dir| {
        let candidates = [
            dir.join("build_config.toml"),
            dir.join("precompile/build_config.toml"),
        ];
        candidates.into_iter().find(|path| path.is_file())
    })
}

/// Reads the architecture entry in `config_path` whose `path` is `spec_path`.
fn arch_for_spec(config_path: &Path, spec_path: &Path) -> Option<(String, Arch)> {
    let config_dir = config_path.parent()?;
    let text = fs::read_to_string(config_path).ok()?;
    let arches: HashMap<String, Arch> = toml::from_str(&text).ok()?;

    let wanted = fs::canonicalize(spec_path).ok()?;
    arches.into_iter().find(|(_, arch)| {
        fs::canonicalize(config_dir.join(&arch.path)).is_ok_and(|path| path == wanted)
    })
}

/// Applies an architecture's initial `context` to the compiled specification.
fn apply_context(
    spec: &mut CompiledSpec,
    context: &mut ContextBytes,
    fields: &[(String, u64)],
) -> Result<HashMap<String, u64>, String> {
    let mut applied = HashMap::new();
    for (field_name, value) in fields {
        let field = spec
            .field(field_name)
            .ok_or_else(|| format!("no context field '{field_name}' in this specification"))?;
        spec.set_context_field(context, field.id, *value)
            .map_err(|e| format!("setting '{field_name}' failed: {e:?}"))?;
        applied.insert(field_name.clone(), *value);
    }
    Ok(applied)
}

fn run(opts: &Opts) -> Result<Output, String> {
    let spec_path_str = opts
        .spec
        .clone()
        .ok_or_else(|| "give a spec path".to_string())?;
    let spec_path = Path::new(&spec_path_str);

    let mut cli_defines = HashMap::new();
    for entry in &opts.define {
        let (k, v) = parse_kv("--define", entry)?;
        cli_defines.insert(k, v);
    }
    let mut cli_context = Vec::new();
    for entry in &opts.context {
        let (k, v) = parse_kv("--context", entry)?;
        cli_context.push((
            k.clone(),
            parse_context_value(&format!("--context {k}"), &v)?,
        ));
    }

    let arch = if opts.no_config {
        None
    } else {
        find_config(spec_path).and_then(|config| arch_for_spec(&config, spec_path))
    };

    let mut defines = arch
        .as_ref()
        .and_then(|(_, arch)| arch.defines.clone())
        .unwrap_or_default();
    defines.extend(cli_defines);

    let mut config_context: Vec<(String, u64)> = arch
        .as_ref()
        .and_then(|(_, arch)| arch.context.clone())
        .unwrap_or_default()
        .into_iter()
        .collect();
    config_context.extend(cli_context);

    let mut sources = SourceDb::new();
    let root = sources
        .add_file_from_path(spec_path)
        .map_err(|e| format!("reading '{}' failed: {e}", spec_path.display()))?;

    let start = Instant::now();
    let compiler = Compiler::new(&mut sources).with_options(CompileOptions { defines });
    let compiled = if opts.lint {
        compiler.compile_with_lints(root)
    } else {
        compiler.compile(root).map(|spec| (spec, Vec::new()))
    };
    let compile_ms = start.elapsed().as_secs_f64() * 1000.0;

    let (mut spec, lint_diagnostics) = match compiled {
        Ok(result) => result,
        Err(error) => {
            let diagnostics = error
                .diagnostics()
                .iter()
                .map(|d| DiagnosticOut {
                    severity: format!("{:?}", d.severity),
                    message: d.message.clone(),
                    location: d.render(&sources),
                })
                .collect();
            return Ok(Output {
                spec: spec_path_str,
                ok: false,
                diagnostics,
                registers: 0,
                tables: 0,
                spaces: Vec::new(),
                context_fields: 0,
                default_space: None,
                applied_context: HashMap::new(),
                decoded: None,
                compile_ms,
            });
        }
    };

    let mut context = spec.new_context();
    let applied_context = apply_context(&mut spec, &mut context, &config_context)?;
    if !applied_context.is_empty() {
        spec.set_context_bytes(context.clone())
            .map_err(|e| format!("setting the initial context failed: {e:?}"))?;
    }

    let registers = spec.registers().count();
    let tables = spec
        .symbols()
        .filter(|s| matches!(s.kind, sleigh::SymbolKind::Table))
        .count();
    let context_fields = spec
        .symbols()
        .filter(|s| matches!(s.kind, sleigh::SymbolKind::Field))
        .count();
    let spaces: Vec<SpaceOut> = spec
        .spaces()
        .map(|s| SpaceOut {
            name: s.name().map(str::to_string),
            size: Some(s.address_size()),
            wordsize: Some(s.word_size()),
        })
        .collect();
    let default_space = spec
        .spaces()
        .find(|s| s.id == spec.default_space())
        .and_then(|s| s.name().map(str::to_string));

    let decoded = match &opts.decode {
        Some(hex) => {
            let bytes = parse_hex(hex)?;
            let address = parse_int("address", &opts.address)?;
            let decoder = Decoder::new(&spec);
            let instruction = decoder
                .decode_one(address, &bytes, &context)
                .map_err(|e| format!("no instruction decodes from '{hex}': {e:?}"))?;
            Some(Decoded {
                address: format!("{address:#x}"),
                text: instruction.to_string(),
            })
        }
        None => None,
    };

    let diagnostics = lint_diagnostics
        .iter()
        .map(|d| DiagnosticOut {
            severity: format!("{:?}", d.severity),
            message: d.message.clone(),
            location: d.render(&sources),
        })
        .collect();

    Ok(Output {
        spec: spec_path_str,
        ok: true,
        diagnostics,
        registers,
        tables,
        spaces,
        context_fields,
        default_space,
        applied_context,
        decoded,
        compile_ms,
    })
}

fn main() {
    let cli = Cli::parse();
    let opts = match &cli.args {
        Some(json) => match serde_json::from_str::<Opts>(json) {
            Ok(opts) => opts,
            Err(e) => fail(cli.json, &format!("invalid --args: {e}")),
        },
        None => cli.opts,
    };
    let output = match run(&opts) {
        Ok(output) => output,
        Err(e) => fail(cli.json, &e),
    };
    if !output.ok {
        if cli.json {
            println!("{}", serde_json::to_string_pretty(&output).unwrap());
        } else {
            println!("spec:  {}", output.spec);
            println!("ok:    false");
            println!("compile_ms: {:.2}", output.compile_ms);
            for d in &output.diagnostics {
                println!("{}", d.location);
            }
        }
        process::exit(1);
    }
    if cli.json {
        println!("{}", serde_json::to_string_pretty(&output).unwrap());
        return;
    }
    println!("spec:           {}", output.spec);
    println!("ok:             true");
    println!("compile_ms:     {:.2}", output.compile_ms);
    println!("registers:      {}", output.registers);
    println!("tables:         {}", output.tables);
    println!("context_fields: {}", output.context_fields);
    println!(
        "default_space:  {}",
        output.default_space.as_deref().unwrap_or("<none>")
    );
    println!("spaces:");
    for space in &output.spaces {
        println!(
            "  {:<12} size={:?} wordsize={:?}",
            space.name.as_deref().unwrap_or("<unnamed>"),
            space.size,
            space.wordsize
        );
    }
    if !output.applied_context.is_empty() {
        println!("applied_context:");
        for (k, v) in &output.applied_context {
            println!("  {k} = {v:#x}");
        }
    }
    if let Some(decoded) = &output.decoded {
        println!("decoded:        [{}] {}", decoded.address, decoded.text);
    }
    if !output.diagnostics.is_empty() {
        println!("lints:");
        for d in &output.diagnostics {
            println!("  {}", d.location);
        }
    }
}

fn fail(json: bool, message: &str) -> ! {
    if json {
        eprintln!("{}", serde_json::json!({ "error": message }));
    } else {
        eprintln!("error: {message}");
    }
    process::exit(1);
}
