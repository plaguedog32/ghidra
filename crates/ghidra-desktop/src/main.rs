mod analysis_cli;
mod app;
mod demo;
mod function_analysis;
mod lifting;
mod pcode_cli;
mod report;

use std::path::PathBuf;

fn main() -> eframe::Result {
    let mut args = std::env::args_os().skip(1);
    let first = args.next();
    match first.as_deref().and_then(|s| s.to_str()) {
        Some("--help" | "-h") => {
            println!(
                "Ghidra Rust {} — native analysis workbench\n\nUsage:\n  ghidra-rs [BINARY_OR_PROJECT]\n  ghidra-rs --demo\n  ghidra-rs --analyze BINARY_OR_PROJECT\n  ghidra-rs --create-project SOURCE DESTINATION.ghrs\n  ghidra-rs --run-pcode PROGRAM.json\n  ghidra-rs --analyze-pcode PROGRAM.json [--instruction-uniques] [--havoc-unknown]\n  ghidra-rs --analyze-function BINARY ROOT LANGUAGE_ID HEX_ENTRY [--havoc-unknown] [context=value ...]\n  ghidra-rs --languages ROOT\n  ghidra-rs --compiler-spec ROOT LANGUAGE_ID COMPILER_ID\n  ghidra-rs --lift-language ROOT LANGUAGE_ID HEX_ADDRESS HEX_BYTES [context=value ...]\n  ghidra-rs --lift-pcode SPEC HEX_ADDRESS HEX_BYTES [context=value ...]\n  ghidra-rs --version\n\nPE / ELF / Mach-O; x86 / x64 disassembly, recursive functions, linkage, and portable projects. No Java required.",
                env!("CARGO_PKG_VERSION")
            );
            return Ok(());
        }
        Some("--version" | "-V") => {
            println!("ghidra-rs {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some("--analyze") => {
            let Some(path) = args.next() else {
                eprintln!("--analyze requires a binary path");
                std::process::exit(2);
            };
            if args.next().is_some() {
                eprintln!("--analyze accepts exactly one binary path");
                std::process::exit(2);
            }
            match report::load_path(&PathBuf::from(path)) {
                Ok(loaded) => match report::json(&loaded) {
                    Ok(json) => println!("{json}"),
                    Err(error) => {
                        eprintln!("{error}");
                        std::process::exit(1);
                    }
                },
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(1);
                }
            }
            return Ok(());
        }
        Some("--create-project") => {
            let (Some(source), Some(destination)) = (args.next(), args.next()) else {
                eprintln!("--create-project requires SOURCE and DESTINATION.ghrs");
                std::process::exit(2);
            };
            if args.next().is_some() {
                eprintln!("Too many project arguments");
                std::process::exit(2);
            }
            let result = report::load_path(&PathBuf::from(source)).and_then(|loaded| {
                ghidra_project::Project {
                    metadata: loaded.metadata,
                    image: loaded.image,
                }
                .save(&PathBuf::from(destination))
                .map_err(|e| e.to_string())
            });
            if let Err(error) = result {
                eprintln!("{error}");
                std::process::exit(1);
            }
            println!("Project saved");
            return Ok(());
        }
        Some("--analyze-function") => {
            let (Some(binary), Some(root), Some(language), Some(entry)) =
                (args.next(), args.next(), args.next(), args.next())
            else {
                eprintln!(
                    "--analyze-function requires BINARY ROOT LANGUAGE_ID HEX_ENTRY [--havoc-unknown] [context=value ...]"
                );
                std::process::exit(2);
            };
            let rest: Vec<String> = args.map(|a| a.to_string_lossy().into_owned()).collect();
            let arguments =
                match function_analysis::CommandArguments::parse(&entry.to_string_lossy(), &rest) {
                    Ok(arguments) => arguments,
                    Err(error) => {
                        eprintln!("{error}");
                        std::process::exit(2);
                    }
                };
            if let Err(error) = function_analysis::execute(
                &PathBuf::from(binary),
                &PathBuf::from(root),
                &language.to_string_lossy(),
                arguments,
            ) {
                eprintln!("{error}");
                std::process::exit(1);
            }
            return Ok(());
        }
        Some("--analyze-pcode") => {
            let Some(path) = args.next() else {
                eprintln!("--analyze-pcode requires a JSON program");
                std::process::exit(2);
            };
            let options = match analysis_cli::CommandOptions::parse(args) {
                Ok(options) => options,
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(2);
                }
            };
            if let Err(error) = analysis_cli::execute(&PathBuf::from(path), options) {
                eprintln!("{error}");
                std::process::exit(1);
            }
            return Ok(());
        }
        Some("--run-pcode") => {
            let Some(path) = args.next() else {
                eprintln!("--run-pcode requires a JSON program");
                std::process::exit(2);
            };
            if args.next().is_some() {
                eprintln!("--run-pcode accepts one JSON program");
                std::process::exit(2);
            }
            match pcode_cli::execute(&PathBuf::from(path)) {
                Ok(true) => {}
                Ok(false) => std::process::exit(3),
                Err(error) => {
                    eprintln!("{error}");
                    std::process::exit(1);
                }
            }
            return Ok(());
        }
        Some("--compiler-spec") => {
            let (Some(root), Some(language), Some(compiler)) =
                (args.next(), args.next(), args.next())
            else {
                eprintln!("--compiler-spec requires ROOT LANGUAGE_ID COMPILER_ID");
                std::process::exit(2);
            };
            if args.next().is_some() {
                eprintln!("--compiler-spec accepts exactly three arguments");
                std::process::exit(2);
            }
            if let Err(error) = pcode_cli::compiler_spec(
                &PathBuf::from(root),
                &language.to_string_lossy(),
                &compiler.to_string_lossy(),
            ) {
                eprintln!("{error}");
                std::process::exit(1);
            }
            return Ok(());
        }
        Some("--languages") => {
            let Some(root) = args.next() else {
                eprintln!("--languages requires a language catalog root");
                std::process::exit(2);
            };
            if args.next().is_some() {
                eprintln!("--languages accepts one root directory");
                std::process::exit(2);
            }
            if let Err(error) = pcode_cli::list_languages(&PathBuf::from(root)) {
                eprintln!("{error}");
                std::process::exit(1);
            }
            return Ok(());
        }
        Some("--lift-language") => {
            let (Some(root), Some(id), Some(address), Some(bytes)) =
                (args.next(), args.next(), args.next(), args.next())
            else {
                eprintln!(
                    "--lift-language requires ROOT LANGUAGE_ID HEX_ADDRESS HEX_BYTES [context=value ...]"
                );
                std::process::exit(2);
            };
            let context: Vec<String> = args.map(|a| a.to_string_lossy().into_owned()).collect();
            if let Err(error) = pcode_cli::lift_language(
                &PathBuf::from(root),
                &id.to_string_lossy(),
                &address.to_string_lossy(),
                &bytes.to_string_lossy(),
                &context,
            ) {
                eprintln!("{error}");
                std::process::exit(1);
            }
            return Ok(());
        }
        Some("--lift-pcode") => {
            let (Some(spec), Some(address), Some(bytes)) = (args.next(), args.next(), args.next())
            else {
                eprintln!("--lift-pcode requires SPEC HEX_ADDRESS HEX_BYTES [context=value ...]");
                std::process::exit(2);
            };
            let context: Vec<String> = args.map(|a| a.to_string_lossy().into_owned()).collect();
            if let Err(error) = pcode_cli::lift(
                &PathBuf::from(spec),
                &address.to_string_lossy(),
                &bytes.to_string_lossy(),
                &context,
            ) {
                eprintln!("{error}");
                std::process::exit(1);
            }
            return Ok(());
        }
        Some(flag) if flag.starts_with('-') && flag != "--demo" => {
            eprintln!("Unknown option: {flag}. Use --help.");
            std::process::exit(2);
        }
        _ => {}
    }
    if args.next().is_some() {
        eprintln!("Expected a single path or --demo. Use --help.");
        std::process::exit(2);
    }
    let initial = match first {
        Some(arg) if arg == "--demo" => Some(app::Input::Demo),
        Some(path) => Some(app::Input::Path(PathBuf::from(path))),
        None => None,
    };
    let options = eframe::NativeOptions {
        viewport: eframe::egui::ViewportBuilder::default()
            .with_inner_size([1440.0, 900.0])
            .with_min_inner_size([1000.0, 650.0]),
        renderer: eframe::Renderer::Glow,
        ..Default::default()
    };
    eframe::run_native(
        "Ghidra Rust",
        options,
        Box::new(move |cc| Ok(Box::new(app::Workbench::new(cc, initial)))),
    )
}
