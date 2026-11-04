//! `sleigh-decode` – decode raw bytes using a SLEIGH processor specification.
//!
//! # Usage
//!
//! ```text
//! sleigh-decode <spec-file> <hex-bytes>
//!
//! Arguments:
//!   <spec-file>   Path to a .slaspec file
//!   <hex-bytes>   Hex-encoded instruction bytes, e.g. 90 or 4883c045
//! ```
//!
//! Specifications rarely decode correctly from a zero-initialized context:
//! x86-64, for one, reads as 16/32-bit until `longMode` is set. So the spec
//! argument is looked up in the nearest `build_config.toml` — the same file
//! `sleigh-precompile` builds from — and that architecture's `defines` and
//! initial `context` are applied, keeping this tool's answers in step with the
//! embedded specifications everything else decodes with.
//!
//! # Example
//!
//! ```text
//! $ sleigh-decode open_sleigh/src/x86/x86-64.slaspec 90
//! [0x0000] NOP
//! ```

use sleigh::{
    CompileOptions, CompiledSpec, Compiler, ContextBytes, DecodeError, Decoder, SourceDb,
};
use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
    process,
};

/// One architecture entry of `build_config.toml`.
#[derive(serde::Deserialize)]
struct Arch {
    path: String,
    defines: Option<HashMap<String, String>>,
    context: Option<HashMap<String, u64>>,
}

fn usage(prog: &str) -> ! {
    eprintln!("Usage: {prog} <spec-file> <hex-bytes>");
    eprintln!();
    eprintln!("  <spec-file>   path to a .slaspec file");
    eprintln!("  <hex-bytes>   instruction bytes as a hex string (e.g. 90 or 4883c045)");
    process::exit(1);
}

fn parse_hex(s: &str) -> Vec<u8> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if s.len() % 2 != 0 {
        eprintln!("error: hex string must have an even number of digits");
        process::exit(1);
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or_else(|_| {
                eprintln!("error: invalid hex byte '{}'", &s[2 * i..2 * i + 2]);
                process::exit(1);
            })
        })
        .collect()
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
///
/// A specification the configuration does not mention is not an error: the
/// caller falls back to a zero-initialized context, as before.
fn arch_for_spec(config_path: &Path, spec_path: &Path) -> Option<(String, Arch)> {
    let config_dir = config_path.parent()?;
    let text = fs::read_to_string(config_path).ok()?;
    let arches: HashMap<String, Arch> = toml::from_str(&text).unwrap_or_else(|error| {
        eprintln!("error: parsing '{}' failed: {error}", config_path.display());
        process::exit(1);
    });

    let wanted = fs::canonicalize(spec_path).ok()?;
    arches.into_iter().find(|(_, arch)| {
        fs::canonicalize(config_dir.join(&arch.path)).is_ok_and(|path| path == wanted)
    })
}

/// Applies an architecture's initial `context` to the compiled specification.
fn apply_context(name: &str, spec: &mut CompiledSpec, fields: &HashMap<String, u64>) {
    let mut context: ContextBytes = spec.new_context();
    for (field_name, value) in fields {
        let Some(field) = spec.field(field_name) else {
            eprintln!("error: {name}: no context field '{field_name}' in this specification");
            process::exit(1);
        };
        spec.set_context_field(&mut context, field.id, *value)
            .unwrap_or_else(|error| {
                eprintln!("error: {name}: setting '{field_name}' failed: {error:?}");
                process::exit(1);
            });
    }
    spec.set_context_bytes(context).unwrap_or_else(|error| {
        eprintln!("error: {name}: setting the initial context failed: {error:?}");
        process::exit(1);
    });
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let prog = args.first().map(String::as_str).unwrap_or("sleigh-decode");

    if args.len() != 3 {
        usage(prog);
    }

    let spec_path = Path::new(&args[1]);
    let bytes = parse_hex(&args[2]);

    let arch = find_config(spec_path).and_then(|config| arch_for_spec(&config, spec_path));
    let defines = arch
        .as_ref()
        .and_then(|(_, arch)| arch.defines.clone())
        .unwrap_or_default();

    let mut sources = SourceDb::new();
    let root = sources.add_file_from_path(spec_path).unwrap_or_else(|e| {
        eprintln!("error: reading '{}' failed: {e}", spec_path.display());
        process::exit(1);
    });
    let compiled = Compiler::new(&mut sources)
        .with_options(CompileOptions { defines })
        .compile(root);
    let mut spec = match compiled {
        Ok(spec) => spec,
        Err(error) => {
            for diagnostic in error.diagnostics() {
                eprintln!("{}", diagnostic.render(&sources));
            }
            process::exit(1);
        }
    };

    // Report the decoding context on stderr: a silently mode-mismatched
    // decode is exactly the failure this lookup exists to prevent.
    match &arch {
        Some((name, arch)) => {
            if let Some(fields) = &arch.context {
                apply_context(name, &mut spec, fields);
            }
            eprintln!("note: decoding as '{name}' from build_config.toml");
        }
        None => eprintln!("note: spec not in any build_config.toml; decoding with a zero context"),
    }

    let context = spec.new_context();
    let decoder = Decoder::new(&spec);

    match decoder.decode_one(0, &bytes, &context) {
        Ok(inst) => {
            println!("[0x{:04x}] {inst}", 0u64);
        }
        Err(DecodeError::NoMatch) => {
            eprintln!("error: no matching instruction for bytes: {}", args[2]);
            process::exit(1);
        }
        Err(error) => {
            eprintln!("error: failed to decode bytes {}: {error:?}", args[2]);
            process::exit(1);
        }
    }
}
