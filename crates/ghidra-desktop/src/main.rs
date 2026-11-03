mod app;
mod demo;
mod report;

use std::path::PathBuf;

fn main() -> eframe::Result {
    let mut args = std::env::args_os().skip(1);
    let first = args.next();
    match first.as_deref().and_then(|s| s.to_str()) {
        Some("--help" | "-h") => {
            println!(
                "Ghidra Rust 0.1.0 — native desktop analysis milestone\n\nUsage:\n  ghidra-rs [BINARY]\n  ghidra-rs --demo\n  ghidra-rs --analyze BINARY\n  ghidra-rs --version\n\nPE / ELF / Mach-O metadata; x86 / x64 disassembly. No Java required."
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
