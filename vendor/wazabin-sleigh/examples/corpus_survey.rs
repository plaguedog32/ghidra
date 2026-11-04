//! Compiles every `.slaspec` in the open_sleigh corpus and reports the tally.
use std::path::Path;

fn main() {
    let root = Path::new("crates/sleigh/precompile/open_sleigh/src");
    let mut specs: Vec<_> = std::fs::read_dir(root)
        .expect("corpus root")
        .filter_map(|e| e.ok())
        .flat_map(|arch| {
            std::fs::read_dir(arch.path())
                .into_iter()
                .flatten()
                .filter_map(|e| e.ok())
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "slaspec"))
                .collect::<Vec<_>>()
        })
        .collect();
    specs.sort();

    let (mut ok, mut failed) = (0, 0);
    let mut reasons: std::collections::BTreeMap<String, usize> = Default::default();
    for path in &specs {
        let Ok(text) = std::fs::read_to_string(path) else {
            continue;
        };
        let mut sources = sleigh::SourceDb::new();
        let root_id = sources.add_file(path.clone(), text);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            sleigh::Compiler::new(&mut sources).compile(root_id)
        }));
        match result {
            Ok(Ok(_)) => ok += 1,
            Ok(Err(e)) => {
                failed += 1;
                let msg = e.to_string();
                // For a parse failure the useful part is what the grammar
                // expected, not the position it gave up at.
                let key = match msg
                    .lines()
                    .find(|l| l.trim_start().starts_with("= expected"))
                {
                    Some(expected) => format!("PARSE {}", expected.trim()),
                    None => msg.lines().next().unwrap_or("?").trim().to_owned(),
                };
                *reasons
                    .entry(key.chars().take(120).collect::<String>())
                    .or_default() += 1;
            }
            Err(_) => {
                failed += 1;
                *reasons.entry("*** PANIC ***".into()).or_default() += 1;
            }
        }
    }
    if let Ok(needle) = std::env::var("SHOW") {
        let mut shown = 0;
        for path in &specs {
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            let mut sources = sleigh::SourceDb::new();
            let root_id = sources.add_file(path.clone(), text);
            if let Err(e) = sleigh::Compiler::new(&mut sources).compile(root_id) {
                let msg = e.to_string();
                if msg.contains(&needle) {
                    println!("### {}\n{msg}\n", path.display());
                    shown += 1;
                    if shown >= 3 {
                        break;
                    }
                }
            }
        }
    }
    if std::env::var("SHOW_ONE").is_ok() {
        for path in &specs {
            let Ok(text) = std::fs::read_to_string(path) else {
                continue;
            };
            let mut sources = sleigh::SourceDb::new();
            let root_id = sources.add_file(path.clone(), text);
            if let Err(e) = sleigh::Compiler::new(&mut sources).compile(root_id) {
                let msg = e.to_string();
                if msg.contains("-->") {
                    println!("### {}\n{msg}\n", path.display());
                    break;
                }
            }
        }
    }
    println!("compiled {ok}/{} ({failed} failed)", specs.len());
    let mut top: Vec<_> = reasons.into_iter().collect();
    top.sort_by_key(|(_, n)| std::cmp::Reverse(*n));
    for (reason, n) in top.iter() {
        println!("  {n:3}  {reason}");
    }
}
