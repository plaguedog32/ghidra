//! Opt-in: the native one-value fallback over real compiled register files.
//! Run with `cargo test --release -p ghidra-abi --test native_fallback_real -- --ignored`.
//!
//! The probed lists use `<join_per_primitive storage="float">`, whose members
//! call `assignAddressFallback(float, member, matchExact=true)` without rule
//! dispatch. Requests here are what such members (or the metatype fallback)
//! would pass: explicit aligned widths, alignments and classes. Expected
//! registers come from the retained `.cspec` entry order and compiled SLEIGH
//! register offsets. Each list declares rules: the default policy refuses
//! them, and every probe runs `BypassUnexecuted` and checks the report. This
//! is fallback parity, not a member action or calling convention.
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

use ghidra_abi::*;
use ghidra_languages::StorageClass;

const G: StorageClass = StorageClass::General;
const F: StorageClass = StorageClass::Float;
const INPUT: ParameterDirection = ParameterDirection::Input;
const OUTPUT: ParameterDirection = ParameterDirection::Output;

struct Language {
    file: Arc<RegisterFile>,
    definition: ghidra_languages::LanguageDefinition,
}

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
    Language {
        file: Arc::new(file),
        definition,
    }
}

/// (space, first byte, size).
type Bytes = (AbiSpace, i64, u32);

struct Profile {
    resources: CompilerResources,
    model: usize,
}

impl Language {
    fn profile(&self, compiler: &str, model: &str) -> Profile {
        let spec = self.definition.load_compiler_spec(compiler).unwrap();
        let storage =
            CompilerStorage::new(Arc::new(spec), self.file.clone(), AbiLimits::default()).unwrap();
        let model = storage
            .source()
            .prototypes
            .iter()
            .position(|p| p.name == model)
            .unwrap_or_else(|| panic!("{model}"));
        Profile {
            resources: CompilerResources::new(Arc::new(storage), Default::default()).unwrap(),
            model,
        }
    }

    /// Bytes `skip..skip + size` of a named register.
    fn at(&self, name: &str, skip: u64, size: u32) -> Bytes {
        let id = self
            .file
            .register_id(name)
            .unwrap_or_else(|| panic!("{name}"));
        let r = self.file.register(id).unwrap();
        assert!(u64::from(size) + skip <= u64::from(r.size), "{name}");
        (AbiSpace::Language(r.space), (r.offset + skip) as i64, size)
    }
}

fn bypass(class_match: ClassMatch) -> FallbackPolicy {
    FallbackPolicy {
        class_match,
        declared_rules: DeclaredRules::BypassUnexecuted,
    }
}

impl Profile {
    fn state(&self, direction: ParameterDirection) -> AllocationState {
        AllocationState::new(&self.resources, self.model, direction, Default::default()).unwrap()
    }

    fn run(
        &self,
        state: &mut AllocationState,
        size: u32,
        alignment: u32,
        class: StorageClass,
        class_match: ClassMatch,
    ) -> NativeFallbackAssignment {
        let result = state
            .assign_native_fallback(
                &self.resources,
                NativeFallbackRequest::new(size, alignment, class),
                bypass(class_match),
                Default::default(),
            )
            .unwrap();
        assert!(result.unexecuted.rules > 0);
        result
    }
}

/// (declaration index, placed bytes) of an assignment.
fn placed(result: &NativeFallbackAssignment) -> (usize, Vec<Bytes>) {
    let NativeFallbackOutcome::Assigned(a) = &result.outcome else {
        panic!("expected an assignment: {result:?}")
    };
    let bytes = match &a.value.storage {
        PlacedStorage::Bits { pieces } => pieces
            .iter()
            .map(|p| {
                (
                    p.storage.address.space,
                    p.storage.address.offset as i64,
                    p.storage.size.unwrap(),
                )
            })
            .collect(),
        PlacedStorage::FloatConversion { .. } => panic!("unexpected conversion"),
    };
    (a.entry, bytes)
}

#[test]
#[ignore = "compiles the retained AArch64 SLEIGH source"]
fn aarch64_float_members_take_q_registers_in_exact_class_mode() {
    let aarch64 = compile("AARCH64:LE:64:v8A");
    // __cdecl input: x8 (hiddenret), q0..q7 (float, 1..16), x0..x7, then
    // an 8-aligned 500-byte stack pool; seven declared rules.
    let p = aarch64.profile("default", "__cdecl");
    let mut state = p.state(INPUT);
    let refused = state.assign_native_fallback(
        &p.resources,
        NativeFallbackRequest::new(4, 4, F),
        Default::default(),
        Default::default(),
    );
    assert!(matches!(
        refused,
        Err(NativeFallbackError::RulesNotExecuted {
            rules: 7,
            pointer_max: None,
            ..
        })
    ));
    // Eight float members fill q0..q7 (little endian: low bytes).
    for i in 0..8 {
        let result = p.run(&mut state, 4, 4, F, ClassMatch::Exact);
        assert_eq!(result.unexecuted.rules, 7);
        assert_eq!(
            placed(&result),
            (1 + i, vec![aarch64.at(&format!("q{i}"), 0, 4)])
        );
    }
    // A ninth exact float member has no candidate: the action would fail.
    let ninth = p.run(&mut state.clone(), 4, 4, F, ClassMatch::Exact);
    assert_eq!(ninth.outcome, NativeFallbackOutcome::NoFit);
    assert_eq!(
        (ninth.usage.examined_entries, ninth.usage.candidates),
        (18, 0)
    );
    // The metatype fallback (General accepts any) skips x8's hiddenret class
    // and takes x0.
    let any = p.run(&mut state, 4, 4, F, ClassMatch::GeneralAcceptsAny);
    assert_eq!(placed(&any), (9, vec![aarch64.at("x0", 0, 4)]));
    // A double member uses a whole d-sized prefix of q0 in a fresh state.
    let double = p.run(&mut p.state(INPUT), 8, 8, F, ClassMatch::Exact);
    assert_eq!(placed(&double), (1, vec![aarch64.at("q0", 0, 8)]));

    // General values: x0..x7, then the stack with native alignment waste.
    let mut state = p.state(INPUT);
    for i in 0..8 {
        let result = p.run(&mut state, 8, 8, G, ClassMatch::GeneralAcceptsAny);
        assert_eq!(
            placed(&result),
            (9 + i, vec![aarch64.at(&format!("x{i}"), 0, 8)])
        );
    }
    let spill = p.run(&mut state, 4, 4, G, ClassMatch::GeneralAcceptsAny);
    assert_eq!(placed(&spill), (17, vec![(AbiSpace::Stack, 0, 4)]));
    // Cursor 1 with type alignment 16: 8 % 16 = 8 wastes one slot.
    let wide = p.run(&mut state, 16, 16, G, ClassMatch::GeneralAcceptsAny);
    let NativeFallbackOutcome::Assigned(a) = &wide.outcome else {
        panic!()
    };
    assert_eq!((a.cursor, a.alignment_waste), (1, 1));
    assert_eq!(placed(&wide), (17, vec![(AbiSpace::Stack, 16, 16)]));
    // A bypassed rule changes the result: a 24-byte struct would be passed by
    // pointer (`convert_to_ptr`); the bare primitive rejects x0..x7 by size
    // and uses 24 stack bytes.
    let structure = p.run(&mut p.state(INPUT), 24, 8, G, ClassMatch::GeneralAcceptsAny);
    assert_eq!(structure.rejected.len(), 8);
    assert!(
        structure
            .rejected
            .iter()
            .all(|c| c.rejection == NoFit::AboveCapacity)
    );
    assert_eq!(placed(&structure), (17, vec![(AbiSpace::Stack, 0, 24)]));

    // Output: q0..q3 (float), x0, x1. Four float members, then exact NoFit.
    let mut output = p.state(OUTPUT);
    for i in 0..4 {
        let result = p.run(&mut output, 4, 4, F, ClassMatch::Exact);
        assert_eq!(
            placed(&result),
            (i, vec![aarch64.at(&format!("q{i}"), 0, 4)])
        );
    }
    let fifth = p.run(&mut output, 4, 4, F, ClassMatch::Exact);
    assert_eq!(fifth.outcome, NativeFallbackOutcome::NoFit);
}

#[test]
#[ignore = "compiles the retained MIPS SLEIGH source"]
fn mips64_big_endian_members_are_right_justified_and_share_groups() {
    let mips = compile("MIPS:BE:64:default");
    let p = mips.profile("default", "__stdcall");
    // Output: f0, f2 (float, 4..8), v0, v1 (general, 1..8).
    let mut output = p.state(OUTPUT);
    let first = p.run(&mut output, 4, 4, F, ClassMatch::Exact);
    assert_eq!(placed(&first), (0, vec![mips.at("f0", 4, 4)]));
    let second = p.run(&mut output, 4, 4, F, ClassMatch::Exact);
    assert_eq!(placed(&second), (1, vec![mips.at("f2", 4, 4)]));
    let third = p.run(&mut output.clone(), 4, 4, F, ClassMatch::Exact);
    assert_eq!(third.outcome, NativeFallbackOutcome::NoFit);
    let general = p.run(&mut output, 4, 4, F, ClassMatch::GeneralAcceptsAny);
    assert_eq!(placed(&general), (2, vec![mips.at("v0", 4, 4)]));
    // Below the float minimum both float entries reject before v0.
    let small = p.run(&mut p.state(OUTPUT), 2, 2, F, ClassMatch::GeneralAcceptsAny);
    assert_eq!(
        small
            .rejected
            .iter()
            .map(|c| (c.entry, c.rejection))
            .collect::<Vec<_>>(),
        [(0, NoFit::BelowMinimum), (1, NoFit::BelowMinimum)]
    );
    assert_eq!(placed(&small), (2, vec![mips.at("v0", 6, 2)]));
    let double = p.run(&mut p.state(OUTPUT), 8, 8, F, ClassMatch::Exact);
    assert_eq!(placed(&double), (0, vec![mips.at("f0", 0, 8)]));

    // Input: eight groups {f12+i, a0..t3}, then an 8-aligned stack pool. A
    // float consumes its group, so the paired integer register is skipped.
    let mut input = p.state(INPUT);
    let float = p.run(&mut input, 4, 4, F, ClassMatch::Exact);
    assert_eq!(placed(&float), (0, vec![mips.at("f12", 4, 4)]));
    let integer = p.run(&mut input, 8, 8, G, ClassMatch::GeneralAcceptsAny);
    assert_eq!(placed(&integer), (3, vec![mips.at("a1", 0, 8)]));
    assert_eq!(integer.usage.examined_entries, 4);
    for _ in 0..6 {
        p.run(&mut input, 8, 8, G, ClassMatch::GeneralAcceptsAny);
    }
    // All eight groups are consumed; the stack slot is right-justified.
    let spill = p.run(&mut input, 4, 4, G, ClassMatch::GeneralAcceptsAny);
    assert_eq!(placed(&spill), (16, vec![(AbiSpace::Stack, 4, 4)]));
}
