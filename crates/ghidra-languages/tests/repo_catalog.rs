//! Discovery against this checkout's real `.ldefs`/`.pspec` files. Upstream specs are
//! the authority; these tests only read them.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use ghidra_languages::{
    AssetStatus, Catalog, DiagnosticKind, Endianness, LanguageDefinition, ResolvedValue, Severity,
    ValueOrigin,
};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn catalog() -> &'static Catalog {
    static CATALOG: OnceLock<Catalog> = OnceLock::new();
    CATALOG.get_or_init(|| Catalog::discover(&repo_root()).expect("discover repo catalog"))
}

fn lang(id: &str) -> &'static LanguageDefinition {
    catalog()
        .by_id(id)
        .unwrap_or_else(|| panic!("language {id} not in catalog"))
}

fn pairs(values: &[ResolvedValue]) -> Vec<(&str, u128)> {
    values.iter().map(|v| (v.name.as_str(), v.value)).collect()
}

fn rel(path: &Path) -> String {
    let root = std::path::absolute(repo_root()).unwrap();
    let mut out: Vec<String> = Vec::new();
    for c in path.strip_prefix(&root).expect("inside root").components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::Normal(s) => out.push(s.to_string_lossy().into_owned()),
            _ => {}
        }
    }
    out.join("/")
}

#[test]
fn discovers_every_shipped_language_without_errors() {
    let catalog = catalog();
    let errors: Vec<_> = catalog
        .diagnostics
        .iter()
        .filter(|d| d.severity >= Severity::Warning)
        .map(ToString::to_string)
        .collect();
    assert!(errors.is_empty(), "unexpected diagnostics: {errors:#?}");
    // 53 module .ldefs; the emulator test-resource mock.ldefs is excluded by default.
    assert_eq!(catalog.ldefs_files.len(), 53);
    assert!(
        catalog
            .ldefs_files
            .iter()
            .all(|p| !p.to_string_lossy().contains("mock.ldefs"))
    );
    // 202 <language> entries (the Skeleton module's only entry is commented out).
    assert_eq!(catalog.languages.len(), 202);
    assert_eq!(
        catalog.languages.iter().filter(|l| l.deprecated).count(),
        12
    );
    for language in &catalog.languages {
        assert!(
            language.source.is_available(),
            "{}: {:?}",
            language.id,
            language.source
        );
        assert!(language.processor_spec.is_available(), "{}", language.id);
        assert!(!language.compilers.is_empty(), "{}", language.id);
        for compiler in &language.compilers {
            assert!(
                compiler.spec.is_available(),
                "{} {}",
                language.id,
                compiler.id
            );
        }
    }
}

#[test]
fn every_processor_spec_loads_with_no_unsupported_forms() {
    for language in &catalog().languages {
        let spec = language
            .load_processor_spec()
            .unwrap_or_else(|e| panic!("{}: {e}", language.id));
        assert!(
            spec.diagnostics.is_empty(),
            "{}: {:#?}",
            language.id,
            spec.diagnostics
        );
    }
}

#[test]
fn x86_64_definition_and_assets() {
    let x64 = lang("x86:LE:64:default");
    assert_eq!(x64.processor, "x86");
    assert_eq!(x64.endian, Endianness::Little);
    assert_eq!(x64.instruction_endian, Endianness::Little);
    assert_eq!(x64.size, 64);
    assert_eq!(x64.variant, "default");
    assert_eq!(x64.version.to_string(), "4.9");
    assert_eq!(x64.description, "Intel/AMD 64-bit x86");
    assert!(!x64.deprecated);
    assert_eq!(x64.sla_file, "x86-64.sla");
    assert_eq!(x64.source.status, AssetStatus::Present);
    assert_eq!(
        rel(x64.source.path.as_ref().unwrap()),
        "Ghidra/Processors/x86/data/languages/x86-64.slaspec"
    );
    assert_eq!(
        rel(x64.processor_spec.path.as_ref().unwrap()),
        "Ghidra/Processors/x86/data/languages/x86-64.pspec"
    );
    // Legitimate cross-directory reference: ../manuals/x86.idx
    let manual = x64.manual_index.as_ref().unwrap();
    assert_eq!(manual.declared, "../manuals/x86.idx");
    assert_eq!(manual.status, AssetStatus::Present);
    assert_eq!(
        rel(manual.path.as_ref().unwrap()),
        "Ghidra/Processors/x86/data/manuals/x86.idx"
    );
    let ids: Vec<_> = x64.compilers.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids, ["windows", "clangwindows", "gcc", "golang"]);
    assert_eq!(x64.default_compiler().unwrap().name, "Visual Studio");
    let gcc = x64.compiler("gcc").unwrap();
    assert_eq!(gcc.spec.declared, "x86-64-gcc.cspec");
    assert_eq!(
        rel(gcc.spec.path.as_ref().unwrap()),
        "Ghidra/Processors/x86/data/languages/x86-64-gcc.cspec"
    );
    let gnu: Vec<_> = x64.external_names_for("gnu").collect();
    assert_eq!(gnu, ["i386:x86-64:intel", "i386:x86-64"]);
}

#[test]
fn x86_64_processor_context_defaults() {
    let spec = lang("x86:LE:64:default").load_processor_spec().unwrap();
    assert_eq!(spec.program_counter.as_deref(), Some("RIP"));
    assert_eq!(spec.property("useropLibs"), Some("x86"));
    assert_eq!(spec.context_sets.len(), 1);
    assert_eq!(spec.tracked_sets.len(), 1);

    let globals = spec.context_globals("ram");
    assert_eq!(
        pairs(&globals),
        [
            ("addrsize", 2),
            ("opsize", 1),
            ("rexprefix", 0),
            ("longMode", 1)
        ]
    );
    assert!(
        globals
            .iter()
            .all(|v| v.origin == ValueOrigin::SpaceWide { block: 0 })
    );
    // Tracked register state is separate from decode context.
    assert_eq!(pairs(&spec.tracked_globals("ram")), [("DF", 0)]);
    assert!(globals.iter().all(|v| v.name != "DF"));
    assert_eq!(pairs(&spec.context_at("ram", 0x1400_0000)), pairs(&globals));
    // Context is per space; other spaces get nothing.
    assert!(spec.context_globals("register").is_empty());

    // Same SLEIGH source, different variant defaults.
    let compat = lang("x86:LE:64:compat32");
    assert_eq!(compat.source.path, lang("x86:LE:64:default").source.path);
    let compat_spec = compat.load_processor_spec().unwrap();
    assert_eq!(
        pairs(&compat_spec.context_globals("ram")),
        [
            ("addrsize", 1),
            ("opsize", 1),
            ("rexprefix", 0),
            ("longMode", 0)
        ]
    );
}

#[test]
fn x86_variants_map_to_shared_slaspec() {
    let ids = [
        "x86:LE:32:default",
        "x86:LE:32:System Management Mode",
        "x86:LE:16:Real Mode",
        "x86:LE:16:Protected Mode",
    ];
    for id in ids {
        let l = lang(id);
        assert_eq!(l.sla_file, "x86.sla", "{id}");
        assert_eq!(
            rel(l.source.path.as_ref().unwrap()),
            "Ghidra/Processors/x86/data/languages/x86.slaspec"
        );
    }
    assert_eq!(lang("x86:LE:16:Real Mode").size, 16);
    assert_eq!(lang("x86:LE:16:Real Mode").variant, "Real Mode");
    assert_eq!(catalog().by_processor("x86").count(), 6);
}

#[test]
fn arm_v7_definitions() {
    let v7 = lang("ARM:LE:32:v7");
    assert_eq!(v7.processor, "ARM");
    assert_eq!(v7.size, 32);
    assert_eq!(v7.sla_file, "ARM7_le.sla");
    assert_eq!(
        rel(v7.source.path.as_ref().unwrap()),
        "Ghidra/Processors/ARM/data/languages/ARM7_le.slaspec"
    );
    assert_eq!(v7.processor_spec.declared, "ARMt.pspec");
    let ids: Vec<_> = v7.compilers.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids, ["default", "windows", "apcs"]);

    let be = lang("ARM:BE:32:v7");
    assert_eq!(be.endian, Endianness::Big);
    assert_eq!(
        rel(be.source.path.as_ref().unwrap()),
        "Ghidra/Processors/ARM/data/languages/ARM7_be.slaspec"
    );

    // Mixed-endian variant: big data, little instructions.
    let mixed = lang("ARM:LEBE:32:v7LEInstruction");
    assert_eq!(mixed.endian, Endianness::Big);
    assert_eq!(mixed.instruction_endian, Endianness::Little);

    let spec = v7.load_processor_spec().unwrap();
    assert_eq!(spec.program_counter.as_deref(), Some("pc"));
    assert_eq!(
        pairs(&spec.context_globals("ram")),
        [("TMode", 0), ("LRset", 0)]
    );
    assert_eq!(pairs(&spec.tracked_globals("ram")), [("spsr", 0)]);
    assert_eq!(
        spec.context_sets[0].values[0].description.as_deref(),
        Some("0 for ARM 32-bit, 1 for THUMB 16-bit")
    );
}

#[test]
fn mips_definitions() {
    let be = lang("MIPS:BE:32:default");
    assert_eq!(be.endian, Endianness::Big);
    assert_eq!(be.size, 32);
    assert_eq!(be.version.to_string(), "1.9");
    assert_eq!(
        rel(be.source.path.as_ref().unwrap()),
        "Ghidra/Processors/MIPS/data/languages/mips32be.slaspec"
    );
    assert_eq!(be.processor_spec.declared, "mips32.pspec");
    let ids: Vec<_> = be.compilers.iter().map(|c| c.id.as_str()).collect();
    assert_eq!(ids, ["default", "windows", "eabi"]);
    let le = lang("MIPS:LE:32:default");
    assert_eq!(le.endian, Endianness::Little);
    assert_eq!(
        rel(le.source.path.as_ref().unwrap()),
        "Ghidra/Processors/MIPS/data/languages/mips32le.slaspec"
    );
    let spec = be.load_processor_spec().unwrap();
    assert_eq!(
        pairs(&spec.context_globals("ram")),
        [("PAIR_INSTRUCTION_FLAG", 0), ("RELP", 1)]
    );
    assert!(spec.tracked_sets.is_empty());
    assert_eq!(catalog().by_processor("MIPS").count(), 22);
}

#[test]
fn ranged_context_8048_is_not_a_global() {
    let spec = lang("8048:LE:16:default").load_processor_spec().unwrap();
    assert!(spec.context_globals("CODE").is_empty());
    assert_eq!(pairs(&spec.context_at("CODE", 0x100)), [("DBF", 0)]);
    assert_eq!(pairs(&spec.context_at("CODE", 0x7ff)), [("DBF", 0)]);
    assert_eq!(pairs(&spec.context_at("CODE", 0x800)), [("DBF", 1)]);
    assert!(spec.context_at("CODE", 0x1000).is_empty());
    assert!(matches!(
        spec.context_at("CODE", 0x900)[0].origin,
        ValueOrigin::Ranged {
            block: 1,
            first: Some(0x800),
            last: Some(0xfff)
        }
    ));
}

#[test]
fn ranged_tracked_pic16_stays_tracked() {
    let spec = lang("PIC-16:LE:16:PIC-16").load_processor_spec().unwrap();
    assert_eq!(pairs(&spec.context_globals("CODE")), [("doPseudo", 0)]);
    let tracked_globals = spec.tracked_globals("CODE");
    assert!(tracked_globals.iter().any(|v| v.name == "SkipNext"));
    assert!(tracked_globals.iter().all(|v| v.name != "PCLATH"));
    let at = spec.tracked_at("CODE", 0x250);
    assert!(at.iter().any(|v| v.name == "PCLATH" && v.value == 1));
    // Tracked registers never appear as decode context.
    assert!(
        spec.context_at("CODE", 0x250)
            .iter()
            .all(|v| v.name != "PCLATH")
    );
}

#[test]
fn msp430_escaped_description_attribute() {
    let spec = lang("TI_MSP430:LE:16:default")
        .load_processor_spec()
        .unwrap();
    let set = &spec.context_sets[0];
    assert!(set.is_ranged());
    assert_eq!(
        set.values[0].description.as_deref(),
        Some("1 instruction starts > 64K")
    );
    assert!(spec.context_globals("RAM").is_empty());
    assert_eq!(pairs(&spec.context_at("RAM", 0x1234)), [("ctx_isHi", 1)]);
}

#[test]
fn deprecated_riscv_finds_assets_like_ghidra() {
    let old = lang("RISCV:LE:64:RV64I");
    assert!(old.deprecated);
    assert_eq!(old.source.status, AssetStatus::FoundBySearch);
    assert_eq!(
        rel(old.source.path.as_ref().unwrap()),
        "Ghidra/Processors/RISCV/data/languages/riscv.lp64d.slaspec"
    );
    assert!(catalog().diagnostics_for("RISCV:LE:64:RV64I").all(|d| {
        d.severity == Severity::Info && matches!(d.kind, DiagnosticKind::AssetFoundBySearch(_))
    }));
}
