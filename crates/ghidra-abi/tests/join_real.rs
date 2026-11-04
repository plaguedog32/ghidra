//! Opt-in: the native `<join>` action over real compiled register files.
//! Run with `cargo test --release -p ghidra-abi --test join_real -- --ignored`.
//!
//! Each probe takes the retained `<join>` rules from the parsed `.cspec`,
//! pins their declared attributes against the source text, and runs explicit
//! raw size/alignment requests. Expected registers come from the retained
//! entry order and the compiled SLEIGH register offsets. Rule matching and
//! dispatch are not executed: a request here is what the rule's action would
//! do after its filter matched. Passing is action parity on these lists, not
//! calling-convention completeness.
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

use ghidra_abi::*;
use ghidra_languages::StorageClass;

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

/// (space, signed first byte, size), most significant first.
type Bytes = (AbiSpace, i64, u32);

fn on_stack(offset: i64, size: u32) -> Bytes {
    (AbiSpace::Stack, offset, size)
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

impl Profile {
    /// The declared `<join>` actions of one list, in rule order.
    fn joins(&self, direction: ParameterDirection) -> Vec<JoinAttributes> {
        let prototype = &self.resources.storage().source().prototypes[self.model];
        let list = match direction {
            INPUT => &prototype.input,
            OUTPUT => &prototype.output,
        };
        list.rules
            .iter()
            .filter_map(|rule| JoinAttributes::from_action(&rule.action))
            .collect()
    }

    fn state(&self, direction: ParameterDirection) -> AllocationState {
        AllocationState::new(&self.resources, self.model, direction, Default::default()).unwrap()
    }

    fn join(
        &self,
        s: &mut AllocationState,
        a: JoinAttributes,
        size: u32,
        align: u32,
    ) -> JoinOutcome {
        let result = s
            .assign_join(
                &self.resources,
                &a,
                JoinRequest::new(size, align),
                Default::default(),
            )
            .unwrap_or_else(|e| panic!("{size}/{align}: {e}"));
        result.outcome
    }

    fn bytes(
        &self,
        s: &mut AllocationState,
        a: JoinAttributes,
        size: u32,
        align: u32,
    ) -> Vec<Bytes> {
        match self.join(s, a, size, align) {
            JoinOutcome::Assigned(JoinAllocation {
                storage: JoinStorage::Pieces(pieces),
                ..
            }) => {
                let mut lsb = 0;
                for p in pieces.iter().rev() {
                    assert_eq!(p.piece.lsb_byte, lsb);
                    lsb += p.piece.storage.size.unwrap();
                }
                assert_eq!(lsb, size);
                pieces
                    .iter()
                    .map(|p| {
                        let s = &p.piece.storage;
                        (s.address.space, s.address.offset as i64, s.size.unwrap())
                    })
                    .collect()
            }
            other => panic!("{size}/{align}: {other:?}"),
        }
    }
}

fn attrs(storage: Option<StorageClass>, align: bool) -> JoinAttributes {
    JoinAttributes {
        storage,
        align: align.then_some(true),
        ..Default::default()
    }
}

/// Every occupied byte is held once, and the held set covers all value bytes.
fn check_held(s: &AllocationState) {
    let mut last: Option<(AbiSpace, i128)> = None;
    for e in s.occupied() {
        if let Some((space, end)) = last
            && space == e.space
        {
            assert!(e.first > end, "{e:?} overlaps");
        }
        last = Some((e.space, e.last));
    }
}

#[test]
#[ignore = "compiles the retained x86-64 SLEIGH source"]
fn x86_64_go_int128_join_over_compiled_registers() {
    let x86 = compile("x86:LE:64:default");
    let go = x86.profile("golang", "abi-internal");
    // x86-64-golang.cspec: int/uint 9..16 bytes use a bare <join/>.
    assert_eq!(go.joins(INPUT), [JoinAttributes::default(); 2]);
    assert_eq!(go.joins(OUTPUT), [JoinAttributes::default(); 2]);
    let join = JoinAttributes::default();
    let mut s = go.state(INPUT);
    // Tiles RAX RBX RCX RDI RSI R8 R9 R10 R11; stack at 8 with 1-byte slots.
    assert_eq!(
        go.bytes(&mut s, join, 16, 8),
        [x86.at("RBX", 0, 8), x86.at("RAX", 0, 8)]
    );
    // A 12-byte value keeps the low half of its last register.
    assert_eq!(
        go.bytes(&mut s, join, 12, 4),
        [x86.at("RDI", 0, 4), x86.at("RCX", 0, 8)]
    );
    assert_eq!(
        go.bytes(&mut s, join, 16, 8),
        [x86.at("R8", 0, 8), x86.at("RSI", 0, 8)]
    );
    assert_eq!(
        go.bytes(&mut s, join, 16, 8),
        [x86.at("R10", 0, 8), x86.at("R9", 0, 8)]
    );
    // R11 plus eight bytes spilled at the first stack slot.
    assert_eq!(
        go.bytes(&mut s, join, 16, 8),
        [on_stack(8, 8), x86.at("R11", 0, 8)]
    );
    // Registers exhausted: the whole value on the stack, 8-aligned.
    assert_eq!(go.bytes(&mut s, join, 16, 8), [on_stack(16, 16)]);
    check_held(&s);
    // Output lists do not spill.
    let mut s = go.state(OUTPUT);
    assert_eq!(
        go.bytes(&mut s, join, 16, 8),
        [x86.at("RBX", 0, 8), x86.at("RAX", 0, 8)]
    );
    for _ in 0..3 {
        go.bytes(&mut s, join, 16, 8);
    }
    let before = s.groups().to_vec();
    assert_eq!(
        go.join(&mut s, join, 16, 8),
        JoinOutcome::NoFit(JoinNoFit::StackSpillDisabled { uncovered: 8 })
    );
    assert_eq!(s.groups(), before);
}

fn arm_rules(profile: &Profile) -> (JoinAttributes, JoinAttributes, JoinAttributes) {
    let float = StorageClass::Float;
    let joins = profile.joins(INPUT);
    // ARM.cspec input: float varargs, HFA varargs, HFA, float (backfill), any.
    assert_eq!(
        joins,
        [
            attrs(None, true),
            attrs(None, true),
            JoinAttributes {
                stack_spill: Some(false),
                ..attrs(Some(float), true)
            },
            JoinAttributes {
                stack_spill: Some(false),
                backfill: Some(true),
                ..attrs(Some(float), true)
            },
            attrs(None, true),
        ]
    );
    assert_eq!(
        profile.joins(OUTPUT),
        [
            attrs(Some(float), false),
            attrs(Some(float), false),
            attrs(None, false)
        ]
    );
    (joins[2], joins[3], joins[4])
}

#[test]
#[ignore = "compiles the retained ARMv7 SLEIGH source"]
fn armv7_aapcs_float_backfill_and_core_register_alignment() {
    let arm = compile("ARM:LE:32:v7");
    let p = arm.profile("default", "__stdcall");
    let (hfa, float, any) = arm_rules(&p);
    // f(float, double, float): s0, s3:s2, then backfilled s1.
    let mut s = p.state(INPUT);
    assert_eq!(p.bytes(&mut s, float, 4, 4), [arm.at("s0", 0, 4)]);
    assert_eq!(
        p.bytes(&mut s, float, 8, 8),
        [arm.at("s3", 0, 4), arm.at("s2", 0, 4)]
    );
    assert_eq!(p.bytes(&mut s, float, 4, 4), [arm.at("s1", 0, 4)]);
    // An HFA of four floats takes the next four registers without backfill.
    assert_eq!(
        p.bytes(&mut s, hfa, 16, 4),
        [
            arm.at("s7", 0, 4),
            arm.at("s6", 0, 4),
            arm.at("s5", 0, 4),
            arm.at("s4", 0, 4)
        ]
    );
    check_held(&s);
    // f(int, long long, int): r0, r3:r2 (r1 consumed for alignment), stack.
    let mut s = p.state(INPUT);
    assert_eq!(p.bytes(&mut s, any, 4, 4), [arm.at("r0", 0, 4)]);
    assert_eq!(
        p.bytes(&mut s, any, 8, 8),
        [arm.at("r3", 0, 4), arm.at("r2", 0, 4)]
    );
    assert_eq!(p.bytes(&mut s, any, 4, 4), [on_stack(0, 4)]);
    // A 20-byte structure splits across r0..r3 and the stack.
    let mut s = p.state(INPUT);
    assert_eq!(
        p.bytes(&mut s, any, 20, 4),
        [
            on_stack(0, 4),
            arm.at("r3", 0, 4),
            arm.at("r2", 0, 4),
            arm.at("r1", 0, 4),
            arm.at("r0", 0, 4)
        ]
    );
    // Outputs: double in s1:s0, long long in r1:r0, 12 bytes do not fit.
    let outputs = p.joins(OUTPUT);
    let mut s = p.state(OUTPUT);
    assert_eq!(
        p.bytes(&mut s, outputs[1], 8, 8),
        [arm.at("s1", 0, 4), arm.at("s0", 0, 4)]
    );
    let mut s = p.state(OUTPUT);
    assert_eq!(
        p.bytes(&mut s, outputs[2], 8, 8),
        [arm.at("r1", 0, 4), arm.at("r0", 0, 4)]
    );
    assert_eq!(
        p.join(&mut s, outputs[2], 12, 4),
        JoinOutcome::NoFit(JoinNoFit::StackSpillDisabled { uncovered: 12 })
    );
    // A single float output fills s0 exactly; no conversion is needed.
    let mut s = p.state(OUTPUT);
    assert_eq!(p.bytes(&mut s, outputs[1], 4, 4), [arm.at("s0", 0, 4)]);
}

#[test]
#[ignore = "compiles the retained ARMv7 big-endian SLEIGH source"]
fn armv7_big_endian_consumes_most_significant_first_and_right_justifies() {
    let arm = compile("ARM:BE:32:v7");
    let p = arm.profile("default", "__stdcall");
    let (_, float, any) = arm_rules(&p);
    let mut s = p.state(INPUT);
    let a = s
        .assign_join(
            &p.resources,
            &any,
            JoinRequest::new(3, 1),
            Default::default(),
        )
        .unwrap();
    assert!(a.config.big_endian && a.config.consume_most_significant && a.config.justify_right);
    let JoinOutcome::Assigned(JoinAllocation {
        storage: JoinStorage::Pieces(pieces),
        ..
    }) = a.outcome
    else {
        panic!()
    };
    // Three bytes keep the low (last) bytes of big-endian r0.
    let r0 = arm.at("r0", 1, 3);
    assert_eq!(
        (
            pieces[0].piece.storage.address.offset as i64,
            pieces[0].piece.storage.size
        ),
        (r0.1, Some(3))
    );
    assert_eq!(
        p.bytes(&mut s, any, 8, 8),
        [arm.at("r2", 0, 4), arm.at("r3", 0, 4)]
    );
    // Stack spill right-justifies the remaining two bytes in their slot.
    let mut s = p.state(INPUT);
    assert_eq!(
        p.bytes(&mut s, any, 18, 4),
        [
            arm.at("r0", 0, 4),
            arm.at("r1", 0, 4),
            arm.at("r2", 0, 4),
            arm.at("r3", 0, 4),
            on_stack(2, 2)
        ]
    );
    let mut s = p.state(INPUT);
    p.bytes(&mut s, float, 4, 4);
    assert_eq!(
        p.bytes(&mut s, float, 8, 8),
        [arm.at("s2", 0, 4), arm.at("s3", 0, 4)]
    );
}

#[test]
#[ignore = "compiles the retained MIPS32 big-endian SLEIGH source"]
fn mips32_be_struct_reverse_justification_and_alignment() {
    let mips = compile("MIPS:BE:32:default");
    let p = mips.profile("default", "__stdcall");
    let reversed = JoinAttributes {
        reverse_justify: Some(true),
        ..attrs(None, true)
    };
    let joins = p.joins(INPUT);
    // mips32be.cspec: struct, union (both reversejustify), then any.
    assert_eq!(joins, [reversed, reversed, attrs(None, true)]);
    assert_eq!(p.joins(OUTPUT), [JoinAttributes::default()]);
    let (structure, any) = (joins[0], joins[2]);
    // A 6-byte structure is left-justified: a0, then the high half of a1.
    let mut s = p.state(INPUT);
    assert_eq!(
        p.bytes(&mut s, structure, 6, 2),
        [mips.at("a0", 0, 4), mips.at("a1", 0, 2)]
    );
    // Scalars are right-justified: 3 bytes use the low bytes of a0.
    let mut s = p.state(INPUT);
    assert_eq!(p.bytes(&mut s, any, 3, 1), [mips.at("a0", 1, 3)]);
    // f(int, long long): a0, a2:a3 after consuming a1 for alignment.
    let mut s = p.state(INPUT);
    assert_eq!(p.bytes(&mut s, any, 4, 4), [mips.at("a0", 0, 4)]);
    assert_eq!(
        p.bytes(&mut s, any, 8, 8),
        [mips.at("a2", 0, 4), mips.at("a3", 0, 4)]
    );
    // Spills start at stack offset 16; justification follows the rule.
    let mut s = p.state(INPUT);
    p.bytes(&mut s, any, 8, 4);
    let mut t = s.clone();
    assert_eq!(
        p.bytes(&mut s, structure, 12, 4),
        [mips.at("a2", 0, 4), mips.at("a3", 0, 4), on_stack(16, 4)]
    );
    assert_eq!(
        p.bytes(&mut t, any, 10, 4),
        [mips.at("a2", 0, 4), mips.at("a3", 0, 4), on_stack(18, 2)]
    );
    check_held(&s);
    let mut s = p.state(OUTPUT);
    assert_eq!(
        p.bytes(&mut s, p.joins(OUTPUT)[0], 8, 8),
        [mips.at("v0", 0, 4), mips.at("v1", 0, 4)]
    );
}

#[test]
#[ignore = "compiles the retained AArch64 SLEIGH source"]
fn aarch64_general_joins_in_both_byte_orders() {
    for (id, big) in [("AARCH64:LE:64:v8A", false), ("AARCH64:BE:64:v8A", true)] {
        let aarch64 = compile(id);
        let p = aarch64.profile("default", "__cdecl");
        assert_eq!(p.joins(INPUT), [attrs(None, true)]);
        assert_eq!(p.joins(OUTPUT), [JoinAttributes::default()]);
        let any = p.joins(INPUT)[0];
        let x = |i: u32| aarch64.at(&format!("x{i}"), 0, 8);
        let ordered = |first: Bytes, second: Bytes| {
            if big {
                vec![first, second]
            } else {
                vec![second, first]
            }
        };
        let mut s = p.state(INPUT);
        // An int uses x0's low half: offset 0 (LE) or 4 (BE).
        assert_eq!(
            p.bytes(&mut s, any, 4, 4),
            [aarch64.at("x0", if big { 4 } else { 0 }, 4)]
        );
        // __int128 skips x1 for 16-byte alignment and takes x2/x3.
        assert_eq!(p.bytes(&mut s, any, 16, 16), ordered(x(2), x(3)));
        // Two more pairs, then x7 with eight bytes on the stack.
        assert_eq!(p.bytes(&mut s, any, 16, 8), ordered(x(4), x(5)));
        p.bytes(&mut s, any, 8, 8);
        assert_eq!(p.bytes(&mut s, any, 16, 8), ordered(x(7), on_stack(0, 8)));
        check_held(&s);
        let mut s = p.state(OUTPUT);
        let output = p.joins(OUTPUT)[0];
        assert_eq!(p.bytes(&mut s, output, 16, 8), ordered(x(0), x(1)));
        assert_eq!(
            p.join(&mut s, output, 8, 8),
            JoinOutcome::NoFit(JoinNoFit::StackSpillDisabled { uncovered: 8 })
        );
    }
}
