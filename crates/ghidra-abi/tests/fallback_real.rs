//! Opt-in: the retained fallback primitive over real compiled register files.
//! Run with `cargo test --release -p ghidra-abi --test fallback_real -- --ignored`.
//!
//! Requests are explicit scalar widths and classes. Expected registers come
//! from the retained `.cspec` entry order and SLEIGH register offsets. Where a
//! list declares rules or `pointermax`, the batch must bypass them explicitly,
//! and each probe pins a request whose full prototype assignment would differ.
//! Passing here is fallback parity, not calling-convention completeness.
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

use ghidra_abi::*;
use ghidra_languages::{Extension, StorageClass};

const G: StorageClass = StorageClass::General;
const F: StorageClass = StorageClass::Float;
const P: StorageClass = StorageClass::Ptr;
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

    /// Placed bytes `(space, offset + skip, size)` inside a named register.
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

/// (space, first byte, size).
type Bytes = (AbiSpace, i64, u32);

fn on_stack(offset: i64, size: u32) -> Bytes {
    (AbiSpace::Stack, offset, size)
}

fn req(size: u32, class: StorageClass) -> FallbackRequest {
    FallbackRequest::new(size, size.min(8), class)
}

const BYPASS: FallbackPolicy = FallbackPolicy {
    class_match: ClassMatch::GeneralAcceptsAny,
    declared_rules: DeclaredRules::BypassUnexecuted,
};

impl Profile {
    fn assign(
        &self,
        direction: ParameterDirection,
        requests: &[FallbackRequest],
        policy: FallbackPolicy,
    ) -> Result<FallbackBatch, FallbackError> {
        let mut state =
            AllocationState::new(&self.resources, self.model, direction, Default::default())
                .unwrap();
        let batch = state.assign_fallback(&self.resources, requests, policy, Default::default())?;
        check_disjoint(&batch);
        Ok(batch)
    }
}

fn assigned(batch: &FallbackBatch, index: usize) -> &FallbackAssignment {
    match &batch.outcomes[index] {
        FallbackOutcome::Assigned(a) => a,
        other => panic!("request {index}: {other:?}"),
    }
}

fn placed(a: &FallbackAssignment) -> Vec<Bytes> {
    match &a.value.storage {
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
        PlacedStorage::FloatConversion { container, .. } => vec![(
            container.address.space,
            container.address.offset as i64,
            container.size.unwrap(),
        )],
    }
}

/// Expected `(entry index, placed pieces)` for each request, in order.
fn expect(batch: &FallbackBatch, expected: &[(usize, Vec<Bytes>)]) {
    for (index, (entry, pieces)) in expected.iter().enumerate() {
        let a = assigned(batch, index);
        let actual = match a.site {
            BindingSite::Input { entry, .. } | BindingSite::Output { entry, .. } => entry,
            _ => unreachable!(),
        };
        assert_eq!(
            (actual, placed(a)),
            (*entry, pieces.clone()),
            "request {index}"
        );
    }
}

/// Independent oracle: no two assigned values share a physical byte.
fn check_disjoint(batch: &FallbackBatch) {
    let mut seen = std::collections::BTreeSet::new();
    for outcome in &batch.outcomes {
        let FallbackOutcome::Assigned(a) = outcome else {
            continue;
        };
        for (space, offset, size) in placed(a) {
            for byte in offset..offset + i64::from(size) {
                assert!(seen.insert((space, byte)), "{space:?}:{byte:#x} reused");
            }
        }
    }
}

#[test]
#[ignore = "compiles the retained x86-64 SLEIGH source"]
fn x86_64_windows_gcc_and_go_fallback_over_compiled_registers() {
    let x86 = compile("x86:LE:64:default");

    // Windows __fastcall: groups {XMM0_Qa,RCX} .. {XMM3_Qa,R9}, stack at 40.
    let win = x86.profile("windows", "__fastcall");
    let requests = [
        req(4, G),
        req(8, F),
        req(8, P),
        req(4, F),
        req(8, G),
        req(8, F),
        req(2, G),
    ];
    assert!(matches!(
        win.assign(INPUT, &requests, Default::default()),
        Err(FallbackError::RulesNotExecuted {
            rules: 1,
            pointer_max: Some(8),
            ..
        })
    ));
    let batch = win.assign(INPUT, &requests, BYPASS).unwrap();
    expect(
        &batch,
        &[
            (1, vec![x86.at("RCX", 0, 4)]),
            (2, vec![x86.at("XMM1_Qa", 0, 8)]),
            (5, vec![x86.at("R8", 0, 8)]),
            (6, vec![x86.at("XMM3_Qa", 0, 4)]),
            (8, vec![on_stack(40, 8)]),
            (8, vec![on_stack(48, 8)]),
            (8, vec![on_stack(56, 2)]),
        ],
    );
    assert_eq!(batch.unexecuted.pointer_max, Some(8));
    // pointermax=8 would pass a 16-byte value by reference in RCX, moving
    // the int to RDX. The bare primitive puts the value on the stack and
    // leaves RCX for the int.
    let batch = win.assign(INPUT, &[req(16, G), req(4, G)], BYPASS).unwrap();
    expect(
        &batch,
        &[(8, vec![on_stack(40, 16)]), (1, vec![x86.at("RCX", 0, 4)])],
    );
    let batch = win.assign(OUTPUT, &[req(8, F)], BYPASS).unwrap();
    expect(&batch, &[(0, vec![x86.at("XMM0_Qa", 0, 8)])]);

    // SysV __stdcall: XMM0..7 then RDI, RSI, RDX, RCX, R8, R9, stack at 8.
    let gcc = x86.profile("gcc", "__stdcall");
    let mut requests = vec![req(4, G), req(8, F), req(8, P), req(4, F)];
    requests.extend([req(8, G); 5]);
    requests.extend([req(8, F), req(2, G)]);
    let batch = gcc.assign(INPUT, &requests, BYPASS).unwrap();
    expect(
        &batch,
        &[
            (8, vec![x86.at("RDI", 0, 4)]),
            (0, vec![x86.at("XMM0_Qa", 0, 8)]),
            (9, vec![x86.at("RSI", 0, 8)]),
            (1, vec![x86.at("XMM1_Qa", 0, 4)]),
            (10, vec![x86.at("RDX", 0, 8)]),
            (11, vec![x86.at("RCX", 0, 8)]),
            (12, vec![x86.at("R8", 0, 8)]),
            (13, vec![x86.at("R9", 0, 8)]),
            (14, vec![on_stack(8, 8)]),
            (2, vec![x86.at("XMM2_Qa", 0, 8)]),
            (14, vec![on_stack(16, 2)]),
        ],
    );
    assert_eq!(batch.unexecuted.rules, 2);
    // join_dual_class would bind a 16-byte two-long struct to two general
    // registers; the primitive has no 16-byte register entry.
    let batch = gcc.assign(INPUT, &[req(16, G)], BYPASS).unwrap();
    expect(&batch, &[(14, vec![on_stack(8, 16)])]);

    // Go abi-internal: XMM0..14, RAX, RBX, RCX, RDI, RSI, R8..R11, and a
    // one-byte-aligned stack pool at 8. Type alignment leaves holes.
    let go = x86.profile("golang", "abi-internal");
    let mut requests = vec![req(8, G); 9];
    requests.extend([req(1, G), req(8, G), req(2, G)]);
    let batch = go.assign(INPUT, &requests, BYPASS).unwrap();
    let names = ["RAX", "RBX", "RCX", "RDI", "RSI", "R8", "R9", "R10", "R11"];
    let mut expected: Vec<_> = names
        .iter()
        .enumerate()
        .map(|(i, name)| (15 + i, vec![x86.at(name, 0, 8)]))
        .collect();
    expected.extend([
        (24, vec![on_stack(8, 1)]),
        (24, vec![on_stack(16, 8)]),
        (24, vec![on_stack(24, 2)]),
    ]);
    expect(&batch, &expected);
    assert_eq!(
        assigned(&batch, 10).slots,
        Some(SlotRange { first: 8, next: 16 })
    );
    // The float rules would send a sixteenth double to the stack; the
    // primitive lets the General RAX entry take it.
    let batch = go.assign(INPUT, &[req(8, F); 16], BYPASS).unwrap();
    assert_eq!(placed(assigned(&batch, 14)), [x86.at("XMM14_Qa", 0, 8)]);
    assert_eq!(placed(assigned(&batch, 15)), [x86.at("RAX", 0, 8)]);
}

#[test]
#[ignore = "compiles the retained ARMv7 SLEIGH source"]
fn armv7_default_fallback_over_compiled_registers() {
    let arm = compile("ARM:LE:32:v7");
    let profile = arm.profile("default", "__stdcall");
    // s0..s15 (entries 0..15), r0..r3 (16..19), stack at 0 with 4-byte slots.
    let requests = [req(4, G), req(4, F), req(8, F), req(2, G), req(4, F)];
    let batch = profile.assign(INPUT, &requests, BYPASS).unwrap();
    expect(
        &batch,
        &[
            (16, vec![arm.at("r0", 0, 4)]),
            (0, vec![arm.at("s0", 0, 4)]),
            // The float rule would join s2:s3; the primitive finds no 8-byte
            // register entry and uses two aligned stack slots.
            (20, vec![on_stack(0, 8)]),
            (17, vec![arm.at("r1", 0, 2)]),
            (1, vec![arm.at("s1", 0, 4)]),
        ],
    );
    assert_eq!(assigned(&batch, 0).value.extension, Extension::IntType);
    assert_eq!(batch.unexecuted.rules, 7);
}

#[test]
#[ignore = "compiles the retained MIPS32 big-endian SLEIGH source"]
fn mips32_big_endian_fallback_right_justifies_over_compiled_registers() {
    let mips = compile("MIPS:BE:32:default");
    let profile = mips.profile("default", "__stdcall");
    // f12_13, f14_15 (0, 1), a0..a3 (2..5), stack at 16 with 4-byte slots.
    let requests = [
        req(8, F),
        req(4, G),
        req(2, G),
        req(4, F),
        req(1, G),
        req(4, G),
        req(2, G),
        req(8, G),
    ];
    let batch = profile.assign(INPUT, &requests, BYPASS).unwrap();
    expect(
        &batch,
        &[
            (0, vec![mips.at("f12_13", 0, 8)]),
            // The leading-double rule would also consume a0 (consume_extra);
            // the primitive does not, so the int takes a0.
            (2, vec![mips.at("a0", 0, 4)]),
            (3, vec![mips.at("a1", 2, 2)]),
            (1, vec![mips.at("f14_15", 4, 4)]),
            (4, vec![mips.at("a2", 3, 1)]),
            (5, vec![mips.at("a3", 0, 4)]),
            (6, vec![on_stack(18, 2)]),
            (6, vec![on_stack(24, 8)]),
        ],
    );
}

#[test]
#[ignore = "compiles the retained AArch64 SLEIGH source"]
fn aarch64_go_fallback_needs_no_rule_bypass_for_its_input_list() {
    let aarch64 = compile("AARCH64:LE:64:v8A");
    let profile = aarch64.profile("golang", "abi-internal");
    // q0..q15 (0..15), x0..x15 (16..31), stack at 8 with 16-byte slots. The
    // input list declares no rules, so the default policy runs.
    let mut requests = vec![req(8, G), req(8, F), req(4, F), req(4, G)];
    requests.extend([req(8, G); 14]);
    requests.extend([req(8, G), req(4, G)]);
    let batch = profile
        .assign(INPUT, &requests, Default::default())
        .unwrap();
    let mut expected = vec![
        (16, vec![aarch64.at("x0", 0, 8)]),
        (0, vec![aarch64.at("q0", 0, 8)]),
        (1, vec![aarch64.at("q1", 0, 4)]),
        (17, vec![aarch64.at("x1", 0, 4)]),
    ];
    for i in 2..16 {
        expected.push((16 + i, vec![aarch64.at(&format!("x{i}"), 0, 8)]));
    }
    expected.extend([(32, vec![on_stack(8, 8)]), (32, vec![on_stack(24, 4)])]);
    expect(&batch, &expected);
    assert_eq!(batch.unexecuted.rules, 0);

    // Output joins x1:x0 and x2:x1:x0 keep source order and significance.
    let batch = profile
        .assign(OUTPUT, &[req(16, G)], Default::default())
        .unwrap();
    expect(
        &batch,
        &[(2, vec![aarch64.at("x1", 0, 8), aarch64.at("x0", 0, 8)])],
    );
    let batch = profile
        .assign(OUTPUT, &[req(24, G)], Default::default())
        .unwrap();
    assert_eq!(
        placed(assigned(&batch, 0)),
        [
            aarch64.at("x2", 0, 8),
            aarch64.at("x1", 0, 8),
            aarch64.at("x0", 0, 8)
        ]
    );
    // Go multiple results are not separate fallback requests: every join
    // shares x0's group, so a second 8-byte result does not fit.
    let batch = profile
        .assign(OUTPUT, &[req(8, G), req(8, G)], Default::default())
        .unwrap();
    assert_eq!(batch.first_no_fit, Some(1));
}

#[test]
#[ignore = "compiles the retained SH-2A source with its 40960-byte bank register"]
fn sh2a_big_endian_fallback_over_compiled_registers() {
    let sh = compile("SuperH:BE:32:SH-2A");
    let profile = sh.profile("default", "__stdcall");
    // fr4..fr7 (0..3, exactly 4 bytes), r4..r7 (4..7), stack at 0.
    let requests = [req(2, G), req(4, F), req(8, F), req(1, G), req(2, F)];
    let batch = profile
        .assign(INPUT, &requests, Default::default())
        .unwrap();
    expect(
        &batch,
        &[
            (4, vec![sh.at("r4", 2, 2)]),
            (0, vec![sh.at("fr4", 0, 4)]),
            (8, vec![on_stack(0, 8)]),
            (5, vec![sh.at("r5", 3, 1)]),
            (6, vec![sh.at("r6", 2, 2)]),
        ],
    );
    let batch = profile
        .assign(OUTPUT, &[req(8, G)], Default::default())
        .unwrap();
    expect(&batch, &[(2, vec![sh.at("r1", 0, 4), sh.at("r0", 0, 4)])]);
}
