//! Opt-in probes: compile retained SLEIGH sources for their real register
//! files and resolve the retained compiler specs against them. Run with
//! `cargo test -p ghidra-abi --test real_catalog -- --ignored`.
//!
//! Expected offsets come from the retained `.sinc`/`.cspec` text. Record
//! counts are cross-checked against the parsed declarations, not pinned to a
//! previous run. A passing probe resolves storage; it does not execute an ABI.
mod common;

use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

use common::single;
use ghidra_abi::{
    AbiAddress, AbiLimits, AbiSpace, BindingSite, CompilerStorage, JoinKind, RegisterDefinition,
    RegisterFile, ResolvedStorage,
};
use ghidra_languages::{CompilerSpec, MemoryTag, Storage};
use ghidra_pcode::{Endianness, SpaceKind};

struct Language {
    file: Arc<RegisterFile>,
    definition: ghidra_languages::LanguageDefinition,
}

/// Compile one language source once; its compiler variants share the file.
fn compile(id: &str) -> Language {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Ghidra/Processors");
    let catalog = ghidra_languages::Catalog::discover(&root).unwrap();
    let definition = catalog.by_id(id).unwrap().clone();
    let language =
        ghidra_sleigh::SleighLanguage::from_language(&definition, &BTreeMap::new()).unwrap();
    let registers = language
        .registers()
        .unwrap()
        .into_iter()
        .map(|r| RegisterDefinition {
            name: r.name,
            space: r.space,
            offset: r.offset,
            size: r.size,
        })
        .collect();
    let file = RegisterFile::new(
        language.spaces().to_vec(),
        language.code_space(),
        registers,
        AbiLimits::default(),
    )
    .unwrap();
    // Ghidra's RegisterBuilder folds a register with an identical address and
    // bit range into an alias of the first one; this crate keeps distinct IDs.
    // Report how often byte-identical extents occur in the compiled layout.
    let mut extents = BTreeMap::new();
    for r in file.registers() {
        *extents
            .entry((r.space, r.offset, r.size))
            .or_insert(0_usize) += 1;
    }
    let shared: usize = extents.values().filter(|&&n| n > 1).map(|n| n - 1).sum();
    eprintln!("{id}: {shared} registers share an identical byte extent with an earlier one");
    Language {
        file: Arc::new(file),
        definition,
    }
}

impl Language {
    fn resolve(&self, compiler: &str) -> CompilerStorage {
        let spec = self.definition.load_compiler_spec(compiler).unwrap();
        let storage =
            CompilerStorage::new(Arc::new(spec), self.file.clone(), AbiLimits::default()).unwrap();
        check_counts(&storage);
        eprintln!(
            "{} {compiler}: {} registers, {} bindings, {} ranges, {} pieces, {} name bytes, {} work",
            self.definition.id,
            self.file.registers().len(),
            storage.bindings().len(),
            storage.ranges().len(),
            storage.total_pieces(),
            storage.name_bytes(),
            storage.build_work()
        );
        storage
    }

    fn register(&self, name: &str) -> &RegisterDefinition {
        let id = self
            .file
            .register_id(name)
            .unwrap_or_else(|| panic!("{name}"));
        self.file.register(id).unwrap()
    }

    /// (offset, size) in the language's register space.
    fn at(&self, name: &str) -> (u64, u32) {
        let r = self.register(name);
        assert_eq!(self.file.space(r.space).unwrap().kind, SpaceKind::Register);
        (r.offset, r.size)
    }

    fn overlap(&self, a: &str, b: &str) -> bool {
        let id = |n| self.file.register_id(n).unwrap();
        self.file.registers_overlap(id(a), id(b)).unwrap()
    }
}

fn pieces(storage: &Storage) -> usize {
    match storage {
        Storage::Join { pieces, .. } => pieces.len(),
        _ => 1,
    }
}

fn register_tags(tags: &[MemoryTag]) -> usize {
    tags.iter()
        .filter(|t| matches!(t, MemoryTag::Register { .. }))
        .count()
}

/// Output record and piece totals derived from the parsed declarations.
fn check_counts(storage: &CompilerStorage) {
    let spec: &CompilerSpec = storage.source();
    let mut bindings = usize::from(spec.return_address.is_some()) + spec.prefer_split.len();
    let mut ranges = spec.global.len()
        + spec.no_high_ptr.as_ref().map_or(0, Vec::len)
        + spec.read_only.as_ref().map_or(0, Vec::len)
        + spec.infer_pointer_bounds.len();
    let mut total = spec
        .return_address
        .iter()
        .chain(&spec.prefer_split)
        .map(pieces)
        .sum::<usize>()
        + register_tags(&spec.global)
        + spec.no_high_ptr.as_deref().map_or(0, register_tags)
        + spec.read_only.as_deref().map_or(0, register_tags);
    for model in &spec.prototypes {
        let lists = [
            &model.unaffected,
            &model.killed_by_call,
            &model.likely_trash,
            &model.internal_storage,
        ];
        let returns = model.return_address.as_deref().unwrap_or(&[]);
        let entries = model
            .input
            .entries
            .iter()
            .chain(&model.output.entries)
            .map(|e| &e.storage);
        let all: Vec<&Storage> = lists
            .into_iter()
            .flatten()
            .chain(returns)
            .chain(entries)
            .collect();
        bindings += all.len();
        total += all.iter().map(|s| pieces(s)).sum::<usize>();
        for tags in [&model.local_range, &model.param_range]
            .into_iter()
            .flatten()
        {
            ranges += tags.len();
            total += register_tags(tags);
        }
    }
    assert_eq!(storage.bindings().len(), bindings);
    assert_eq!(storage.ranges().len(), ranges);
    assert_eq!(storage.total_pieces(), total);
    assert_eq!(storage.space_bases().len(), spec.space_bases.len());
    assert_eq!(
        storage.dead_code_delays().len(),
        spec.dead_code_delays.len()
    );
    for (index, model) in spec.prototypes.iter().enumerate() {
        let returns = storage.return_addresses(index).unwrap();
        let expected = match &model.return_address {
            Some(list) => list.len(),
            None => usize::from(spec.return_address.is_some()),
        };
        assert_eq!(returns.len(), expected, "{}", model.name);
    }
}

fn model(storage: &CompilerStorage, name: &str) -> usize {
    storage
        .source()
        .prototypes
        .iter()
        .position(|p| p.name == name)
        .unwrap_or_else(|| panic!("{name}"))
}

fn register_of(storage: &CompilerStorage, site: BindingSite) -> String {
    let binding = storage.binding(site).unwrap_or_else(|| panic!("{site:?}"));
    let id = single(&binding.storage).register.unwrap();
    storage.register_file().register(id).unwrap().name.clone()
}

fn stack(offset: i64) -> AbiAddress {
    AbiAddress {
        space: AbiSpace::Stack,
        offset: offset as u64,
    }
}

/// Most-significant-first join pieces as (register name, lsb byte).
fn join_of(storage: &CompilerStorage, site: BindingSite) -> Vec<(String, u32)> {
    let binding = storage.binding(site).unwrap();
    let ResolvedStorage::Join { kind, pieces, .. } = &binding.storage else {
        panic!("{site:?} is not a join")
    };
    assert_eq!(*kind, JoinKind::Concatenation);
    pieces
        .iter()
        .map(|p| {
            let id = p.storage.register.unwrap();
            let name = storage.register_file().register(id).unwrap().name.clone();
            (name, p.lsb_byte.unwrap())
        })
        .collect()
}

#[test]
#[ignore = "compiles the retained x86-64 SLEIGH source and resolves three compiler specs"]
fn x86_64_windows_gcc_and_go_storage_resolve_against_compiled_registers() {
    let x86 = compile("x86:LE:64:default");
    // ia.sinc: 8-byte GPRs from 0, R8.. from 0x80, XMM0_Qa at 0x1200.
    for (name, at) in [
        ("RAX", (0, 8)),
        ("RCX", (8, 8)),
        ("RDX", (0x10, 8)),
        ("RSP", (0x20, 8)),
        ("RBP", (0x28, 8)),
        ("RSI", (0x30, 8)),
        ("RDI", (0x38, 8)),
        ("R8", (0x80, 8)),
        ("R9", (0x88, 8)),
        ("EAX", (0, 4)),
        ("AH", (1, 1)),
        ("XMM0_Qa", (0x1200, 8)),
    ] {
        assert_eq!(x86.at(name), at, "{name}");
    }
    assert!(x86.overlap("RAX", "AH") && x86.overlap("EAX", "AL"));
    assert!(!x86.overlap("AL", "AH") && !x86.overlap("RAX", "RCX"));
    // Case-variant lookup reaches the declared spelling.
    assert_eq!(x86.file.register_id("rax"), x86.file.register_id("RAX"));

    let windows = x86.resolve("windows");
    let stack_props = windows.stack();
    assert_eq!(
        (stack_props.address_size, stack_props.pointer),
        (8, x86.file.register_id("RSP"))
    );
    let spec_return = windows.binding(BindingSite::SpecReturnAddress).unwrap();
    assert_eq!(single(&spec_return.storage).address, stack(0));
    assert_eq!(spec_return.storage.size(), Some(8));
    let fastcall = model(&windows, "__fastcall");
    let inputs: Vec<String> = (0..8)
        .map(|entry| {
            register_of(
                &windows,
                BindingSite::Input {
                    model: fastcall,
                    entry,
                },
            )
        })
        .collect();
    assert_eq!(
        inputs,
        [
            "XMM0_Qa", "RCX", "XMM1_Qa", "RDX", "XMM2_Qa", "R8", "XMM3_Qa", "R9"
        ]
    );
    let groups: Vec<_> = (0..8)
        .map(|entry| {
            let site = BindingSite::Input {
                model: fastcall,
                entry,
            };
            windows
                .binding(site)
                .unwrap()
                .parameter
                .as_ref()
                .unwrap()
                .group
        })
        .collect();
    assert_eq!(
        groups,
        [
            Some(0),
            Some(0),
            Some(1),
            Some(1),
            Some(2),
            Some(2),
            Some(3),
            Some(3)
        ]
    );
    let pool = windows
        .binding(BindingSite::Input {
            model: fastcall,
            entry: 8,
        })
        .unwrap();
    assert_eq!(single(&pool.storage).address, stack(40));
    assert_eq!(pool.storage.size(), None);
    let constraints = pool.parameter.as_ref().unwrap();
    assert_eq!((constraints.max_size, constraints.alignment), (500, 8));
    // localrange: 0xfffffffffff0bdc1..=-1 is -999999..=-1, then 8..=39.
    let local = |index| {
        let range = windows
            .range(BindingSite::LocalRange {
                model: fastcall,
                index,
            })
            .unwrap();
        (range.first, range.last)
    };
    assert_eq!(local(0), (stack(-999_999), stack(-1)));
    assert_eq!(local(1), (stack(8), stack(39)));
    let global = windows.range(BindingSite::Global(0)).unwrap();
    assert_eq!((global.first.offset, global.last.offset), (0, u64::MAX));

    let gcc = x86.resolve("gcc");
    // processEntry's explicit RBP return replaces the stack fallback.
    let entry = model(&gcc, "processEntry");
    let explicit = gcc.return_addresses(entry).unwrap();
    assert_eq!(explicit.len(), 1);
    assert_eq!(
        single(&explicit[0].storage).register,
        x86.file.register_id("RBP")
    );
    let inherited = gcc.return_addresses(model(&gcc, "__stdcall")).unwrap();
    assert_eq!(inherited[0].site, BindingSite::SpecReturnAddress);

    let go = x86.resolve("golang");
    // duffcopy: piece1=RSI piece2=RDI; __stdcall: piece1=RDX piece2=RAX.
    assert_eq!(
        join_of(
            &go,
            BindingSite::Output {
                model: model(&go, "duffcopy"),
                entry: 1
            }
        ),
        [("RSI".to_owned(), 8), ("RDI".to_owned(), 0)]
    );
    assert_eq!(
        join_of(
            &go,
            BindingSite::Output {
                model: model(&go, "__stdcall"),
                entry: 2
            }
        ),
        [("RDX".to_owned(), 8), ("RAX".to_owned(), 0)]
    );
    // The overlays share one compiled register file.
    assert!(Arc::ptr_eq(windows.register_file(), go.register_file()));
}

#[test]
#[ignore = "compiles the retained ARMv7 little-endian SLEIGH source"]
fn armv7_default_storage_resolves_against_compiled_registers() {
    let arm = compile("ARM:LE:32:v7");
    // ARM.sinc: r0..pc are 4 bytes from 0x20.
    assert_eq!(arm.at("r0"), (0x20, 4));
    assert_eq!(arm.at("sp"), (0x20 + 13 * 4, 4));
    assert_eq!(arm.at("lr"), (0x20 + 14 * 4, 4));
    let storage = arm.resolve("default");
    assert_eq!(storage.stack().address_size, 4);
    assert_eq!(storage.stack().pointer, arm.file.register_id("sp"));
    // No spec-level return address: undeclared models have none.
    assert!(storage.binding(BindingSite::SpecReturnAddress).is_none());
    let entry = model(&storage, "processEntry");
    assert!(storage.return_addresses(entry).unwrap().is_empty());
    assert_eq!(
        register_of(
            &storage,
            BindingSite::Input {
                model: entry,
                entry: 0
            }
        ),
        "r0"
    );
    let pool = storage
        .binding(BindingSite::Input {
            model: entry,
            entry: 1,
        })
        .unwrap();
    assert_eq!(single(&pool.storage).address, stack(0));
    let stdcall = model(&storage, "__stdcall");
    assert_eq!(
        register_of(
            &storage,
            BindingSite::Input {
                model: stdcall,
                entry: 0
            }
        ),
        "s0"
    );
}

#[test]
#[ignore = "compiles the retained MIPS32 big-endian SLEIGH source"]
fn mips32_big_endian_default_storage_resolves_against_compiled_registers() {
    let mips = compile("MIPS:BE:32:default");
    let register_space = mips.register("a0").space;
    assert_eq!(
        mips.file.space(register_space).unwrap().endianness,
        Endianness::Big
    );
    // mips.sinc: 4-byte GPRs from 0; big-endian FPU halves swap within pairs.
    assert_eq!(mips.at("a0"), (16, 4));
    assert_eq!(mips.at("sp"), (29 * 4, 4));
    assert_eq!(mips.at("ra"), (31 * 4, 4));
    assert_eq!(mips.at("f12_13"), (0x1030, 8));
    assert_eq!(mips.at("f13"), (0x1030, 4));
    assert_eq!(mips.at("f12"), (0x1034, 4));
    assert!(mips.overlap("f12", "f12_13") && mips.overlap("f13", "f12_13"));
    assert!(!mips.overlap("f12", "f13"));

    let storage = mips.resolve("default");
    assert_eq!(storage.stack().address_size, 4);
    let spec_return = storage.binding(BindingSite::SpecReturnAddress).unwrap();
    assert_eq!(
        single(&spec_return.storage).register,
        mips.file.register_id("ra")
    );
    let stdcall = model(&storage, "__stdcall");
    let inputs: Vec<String> = (0..6)
        .map(|entry| {
            register_of(
                &storage,
                BindingSite::Input {
                    model: stdcall,
                    entry,
                },
            )
        })
        .collect();
    assert_eq!(inputs, ["f12_13", "f14_15", "a0", "a1", "a2", "a3"]);
    let pool = storage
        .binding(BindingSite::Input {
            model: stdcall,
            entry: 6,
        })
        .unwrap();
    assert_eq!(single(&pool.storage).address, stack(16));
    // Global register-space range and signed local ranges.
    let global = storage.range(BindingSite::Global(1)).unwrap();
    assert_eq!(
        (global.first, global.last.offset),
        (
            AbiAddress {
                space: AbiSpace::Language(register_space),
                offset: 0x2000
            },
            0x2fff
        )
    );
    let local = |index| {
        let r = storage
            .range(BindingSite::LocalRange {
                model: stdcall,
                index,
            })
            .unwrap();
        (r.first, r.last)
    };
    assert_eq!(local(0), (stack(-1_000_000), stack(-1)));
    assert_eq!(local(1), (stack(0), stack(15)));
    assert_eq!(
        storage.return_addresses(stdcall).unwrap(),
        std::slice::from_ref(spec_return)
    );
}

#[test]
#[ignore = "compiles the retained AArch64 little-endian SLEIGH source"]
fn aarch64_go_joins_resolve_against_compiled_registers() {
    let aarch64 = compile("AARCH64:LE:64:v8A");
    // AARCH64instructions.sinc: x0..x30 are 8 bytes from 0x4000; sp at 8.
    for index in [0_u64, 1, 8, 20, 21, 30] {
        assert_eq!(aarch64.at(&format!("x{index}")), (0x4000 + 8 * index, 8));
    }
    assert_eq!(aarch64.at("sp"), (8, 8));
    assert_eq!(aarch64.at("wsp"), (8, 4));
    assert!(aarch64.overlap("sp", "wsp"));
    let go = aarch64.resolve("golang");
    assert_eq!(go.stack().address_size, 8);
    let internal = model(&go, "abi-internal");
    assert_eq!(
        register_of(
            &go,
            BindingSite::Output {
                model: internal,
                entry: 0
            }
        ),
        "q0"
    );
    assert_eq!(
        register_of(
            &go,
            BindingSite::Output {
                model: internal,
                entry: 1
            }
        ),
        "x0"
    );
    // Output entry k (2..=9) joins x(k-1)..x0, most significant first.
    for entry in 2..=9_u32 {
        let expected: Vec<(String, u32)> =
            (0..entry).rev().map(|i| (format!("x{i}"), 8 * i)).collect();
        let site = BindingSite::Output {
            model: internal,
            entry: entry as usize,
        };
        assert_eq!(join_of(&go, site), expected, "entry {entry}");
        let binding = go.binding(site).unwrap();
        let constraints = binding.parameter.as_ref().unwrap();
        assert_eq!(binding.storage.size(), Some(8 * entry));
        assert_eq!(constraints.max_size, 8 * entry);
    }
    // duffcopy: piece2="x21" piece1="x20".
    assert_eq!(
        join_of(
            &go,
            BindingSite::Output {
                model: model(&go, "duffcopy"),
                entry: 1
            }
        ),
        [("x20".to_owned(), 8), ("x21".to_owned(), 0)]
    );
}
