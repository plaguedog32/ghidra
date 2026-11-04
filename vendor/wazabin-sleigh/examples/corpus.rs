//! Compiles every `.slaspec` in the vendored Ghidra corpus and reports which
//! ones fail.
//!
//! The compatibility figure quoted in the README comes from here, so it can be
//! re-derived rather than trusted:
//!
//! ```text
//! $ cargo run -p wazabin-sleigh --example corpus
//! 142/149 specifications compiled
//! ```
//!
//! Requires the `open_sleigh` submodule (`just setup`). Pass a directory to
//! check a different corpus, such as an overlaid Ghidra installation.

use std::{
    env,
    path::{Path, PathBuf},
    process,
};

use sleigh::{Compiler, SourceDb};

const DEFAULT_CORPUS: &str = "../precompile/open_sleigh/src";

fn main() {
    let root = env::args().nth(1).unwrap_or_else(|| {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(DEFAULT_CORPUS)
            .to_string_lossy()
            .into_owned()
    });

    let root = PathBuf::from(root);
    let mut specs = match collect(&root) {
        Ok(specs) => specs,
        Err(error) => {
            eprintln!("error: reading '{}' failed: {error}", root.display());
            eprintln!("note: the corpus is a submodule; run `just setup` to fetch it");
            process::exit(1);
        }
    };
    specs.sort();

    let mut failures = Vec::new();
    for spec in &specs {
        // Each specification gets its own database: they are independent
        // compilations that happen to share a directory.
        let mut sources = SourceDb::new();
        let outcome = sources
            .add_file_from_path(spec)
            .map_err(|error| error.to_string())
            .and_then(|root| {
                Compiler::new(&mut sources)
                    .compile(root)
                    .map_err(|error| first_message(&error))
            });

        if let Err(reason) = outcome {
            failures.push((spec.clone(), reason));
        }
    }

    let compiled = specs.len() - failures.len();
    println!("{compiled}/{} specifications compiled", specs.len());

    for (spec, reason) in &failures {
        // Report paths relative to the corpus, not the absolute path we built.
        let shown = spec.strip_prefix(&root).unwrap_or(spec);
        println!("  FAIL {}: {reason}", shown.display());
    }
}

/// The first error a failed compilation reported, which is the one that
/// explains why it stopped.
fn first_message(error: &sleigh::CompileError) -> String {
    error
        .diagnostics()
        .first()
        .map(|diagnostic| diagnostic.message.clone())
        .unwrap_or_else(|| "compilation failed without a diagnostic".to_owned())
}

fn collect(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut specs = Vec::new();
    let mut pending = vec![dir.to_path_buf()];

    while let Some(dir) = pending.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "slaspec") {
                specs.push(path);
            }
        }
    }

    Ok(specs)
}
