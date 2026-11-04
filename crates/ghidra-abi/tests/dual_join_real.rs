//! Opt-in: the native `<join_dual_class>` action over real compiled register
//! files and the compiler specs' own data organizations. Run with
//! `cargo test --release -p ghidra-abi --test dual_join_real -- --ignored`.
//!
//! Each probe takes the retained `<join_dual_class>` rule from the parsed
//! `.cspec`, pins its declared attributes against the source text, converts
//! declared C types through the native graph built from that spec's data
//! organization, and runs the action. Expected registers come from retained
//! entry order, `<group>` structure and compiled SLEIGH register offsets.
//! Rule matching and dispatch are not executed: a call here is what the
//! rule's action would do after its filter matched (some values are larger
//! than the rule's `maxsize`). Passing is action parity for the listed
//! pairs and types, not calling-convention completeness.
use std::{collections::BTreeMap, path::PathBuf, sync::Arc};

use ghidra_abi::*;
use ghidra_languages::{RuleAction, StorageClass};
use ghidra_pcode::Endianness;
use ghidra_types::{Builtin, TypeDefinition, TypeId, TypeKind, TypeLayouts};

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

/// Declared C types, converted with one spec's data organization.
struct Types {
    graph: Arc<NativeTypeGraph>,
    names: BTreeMap<&'static str, TypeId>,
}

impl Types {
    fn id(&self, name: &str) -> NativeTypeId {
        self.graph.native(self.names[name]).unwrap()
    }
}

struct Profile {
    resources: CompilerResources,
    model: usize,
    types: Types,
}

impl Language {
    fn order(&self) -> Endianness {
        self.file
            .space(self.file.default_space())
            .unwrap()
            .endianness
    }

    fn profile(&self, compiler: &str, model: &str) -> Profile {
        let spec = self.definition.load_compiler_spec(compiler).unwrap();
        let organization = spec.resolved_data_organization(8);
        let storage =
            CompilerStorage::new(Arc::new(spec), self.file.clone(), AbiLimits::default()).unwrap();
        let model = storage
            .source()
            .prototypes
            .iter()
            .position(|p| p.name == model)
            .unwrap_or_else(|| panic!("{model}"));
        // C declarations: builtins take their widths from the organization.
        let mut definitions = Vec::new();
        let mut names = BTreeMap::new();
        let mut add = |name: &'static str, kind: TypeKind| {
            definitions.push(TypeDefinition::new(name, kind));
            names.insert(name, TypeId(definitions.len() - 1));
            TypeId(definitions.len() - 1)
        };
        let long = add("long", TypeKind::Builtin(Builtin::Long));
        let int = add("int", TypeKind::Builtin(Builtin::Int));
        let float = add("float", TypeKind::Builtin(Builtin::Float));
        let double = add("double", TypeKind::Builtin(Builtin::Double));
        let long_double = add("long double", TypeKind::Builtin(Builtin::LongDouble));
        let structure = |fields: &[TypeId]| {
            TypeKind::Structure(ghidra_types::Composite {
                fields: fields
                    .iter()
                    .enumerate()
                    .map(|(i, ty)| ghidra_types::Field::new(format!("f{i}"), *ty))
                    .collect(),
                packing: ghidra_types::Packing::Default,
                minimum_alignment: ghidra_types::MinimumAlignment::Default,
            })
        };
        add("{double,long}", structure(&[double, long]));
        add("{long,double}", structure(&[long, double]));
        add(
            "{float,float,int,int}",
            structure(&[float, float, int, int]),
        );
        add("{float,int}", structure(&[float, int]));
        add("{float}", structure(&[float]));
        add("{float,float}", structure(&[float, float]));
        add("{int}", structure(&[int]));
        add("{double}", structure(&[double]));
        add("{double,double}", structure(&[double, double]));
        add("{long,long}", structure(&[long, long]));
        add(
            "{double,double,double}",
            structure(&[double, double, double]),
        );
        add("{long double}", structure(&[long_double]));
        add("{double x9}", structure(&[double; 9]));
        add("{long x10}", structure(&[long; 10]));
        add("{double,float,float}", structure(&[double, float, float]));
        let layouts = Arc::new(
            TypeLayouts::new_with_endianness(
                definitions.into(),
                organization,
                self.order(),
                Default::default(),
            )
            .unwrap(),
        );
        let map = NativeAlignmentMap::from_organization(layouts.organization(), Default::default())
            .unwrap();
        let graph = Arc::new(
            NativeTypeGraph::new(layouts, &map, Default::default(), Default::default()).unwrap(),
        );
        Profile {
            resources: CompilerResources::new(Arc::new(storage), Default::default()).unwrap(),
            model,
            types: Types { graph, names },
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
    /// The declared `<join_dual_class>` actions of one list, in rule order.
    fn duals(&self, direction: ParameterDirection) -> Vec<DualJoinAttributes> {
        let prototype = &self.resources.storage().source().prototypes[self.model];
        let list = match direction {
            INPUT => &prototype.input,
            OUTPUT => &prototype.output,
        };
        list.rules
            .iter()
            .filter(|rule| matches!(rule.action, RuleAction::JoinDualClass { .. }))
            .map(|rule| DualJoinAttributes::from_action(&rule.action).unwrap())
            .collect()
    }

    fn state(&self, direction: ParameterDirection) -> AllocationState {
        AllocationState::new(&self.resources, self.model, direction, Default::default()).unwrap()
    }

    fn run(&self, s: &mut AllocationState, a: DualJoinAttributes, ty: &str) -> DualJoinAssignment {
        s.assign_dual_join(
            &self.resources,
            &a,
            self.types.graph.clone(),
            self.types.id(ty),
            Default::default(),
        )
        .unwrap_or_else(|e| panic!("{ty}: {e}"))
    }

    fn bytes(&self, s: &mut AllocationState, a: DualJoinAttributes, ty: &str) -> Vec<Bytes> {
        let result = self.run(s, a, ty);
        match &result.outcome {
            DualJoinOutcome::Assigned(DualJoinAllocation {
                storage: JoinStorage::Pieces(pieces),
                size,
                ..
            }) => {
                let mut lsb = 0;
                for p in pieces.iter().rev() {
                    assert_eq!(p.piece.lsb_byte, lsb);
                    lsb += p.piece.storage.size.unwrap();
                }
                assert_eq!(lsb, *size);
                pieces
                    .iter()
                    .map(|p| {
                        let s = &p.piece.storage;
                        (s.address.space, s.address.offset as i64, s.size.unwrap())
                    })
                    .collect()
            }
            other => panic!("{ty}: {other:?}"),
        }
    }
}

/// Every occupied byte is held once.
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
fn x86_64_gcc_dual_class_over_xmm_and_integer_registers() {
    let x86 = compile("x86:LE:64:default");
    let gcc = x86.profile("gcc", "__stdcall");
    // x86-64-gcc.cspec: input and output declare a bare <join_dual_class/>
    // (general base, float alternate, no spill, no fill).
    assert_eq!(gcc.duals(INPUT), [DualJoinAttributes::default()]);
    assert_eq!(gcc.duals(OUTPUT), [DualJoinAttributes::default()]);
    let dual = DualJoinAttributes::default();
    let mut s = gcc.state(INPUT);
    // Input float tiles XMM0_Qa..XMM7_Qa and general RDI RSI RDX RCX R8 R9,
    // all 8 bytes. {double, long}: XMM0_Qa (bytes 0..8) and RDI (8..16);
    // little endian lists the high half first.
    let a = gcc.run(&mut s.clone(), dual, "{double,long}");
    assert_eq!(a.config.tile_size, 8);
    assert!(!a.config.big_endian && !a.config.consume_from_stack);
    assert_eq!(
        gcc.bytes(&mut s, dual, "{double,long}"),
        [x86.at("RDI", 0, 8), x86.at("XMM0_Qa", 0, 8)]
    );
    // Two floats share the first eightbyte (SSE), two ints the second.
    assert_eq!(
        gcc.bytes(&mut s, dual, "{float,float,int,int}"),
        [x86.at("RSI", 0, 8), x86.at("XMM1_Qa", 0, 8)]
    );
    // A float and an int in one eightbyte: INTEGER.
    assert_eq!(
        gcc.bytes(&mut s, dual, "{float,int}"),
        [x86.at("RDX", 0, 8)]
    );
    // A lone float keeps the low four bytes of XMM2.
    assert_eq!(
        gcc.bytes(&mut s, dual, "{float}"),
        [x86.at("XMM2_Qa", 0, 4)]
    );
    assert_eq!(
        gcc.bytes(&mut s, dual, "{long,double}"),
        [x86.at("XMM3_Qa", 0, 8), x86.at("RCX", 0, 8)]
    );
    check_held(&s);
    // long double (10 bytes) crosses the first eightbyte window: NoFit, so
    // the following <goto_stack/> rule would apply.
    assert_eq!(
        gcc.run(&mut gcc.state(INPUT), dual, "{long double}")
            .outcome,
        DualJoinOutcome::NoFit(DualJoinNoFit::Window {
            offset: 0,
            rejection: DualTileRejection::CrossesWindow { primitive: 0 }
        })
    );
    // Four XMM tiles remain: three doubles fit, then a two-double value
    // exhausts the float class with no spill and changes nothing.
    gcc.bytes(&mut s, dual, "{double,double,double}");
    let before = (s.groups().to_vec(), s.occupied().collect::<Vec<_>>());
    assert_eq!(
        gcc.run(&mut s, dual, "{double,double}").outcome,
        DualJoinOutcome::NoFit(DualJoinNoFit::Exhausted {
            class: DualClass::Alternate,
            offset: 8,
            uncovered: 8
        })
    );
    assert_eq!(
        (s.groups().to_vec(), s.occupied().collect::<Vec<_>>()),
        before
    );
    // Outputs: XMM0_Qa/XMM1_Qa and RAX/RDX.
    let mut s = gcc.state(OUTPUT);
    assert_eq!(
        gcc.bytes(&mut s.clone(), dual, "{double,long}"),
        [x86.at("RAX", 0, 8), x86.at("XMM0_Qa", 0, 8)]
    );
    assert_eq!(
        gcc.bytes(&mut s.clone(), dual, "{long,long}"),
        [x86.at("RDX", 0, 8), x86.at("RAX", 0, 8)]
    );
    assert_eq!(
        gcc.bytes(&mut s, dual, "{double,double}"),
        [x86.at("XMM1_Qa", 0, 8), x86.at("XMM0_Qa", 0, 8)]
    );
    check_held(&s);
}

fn mips64(id: &str, reverse_justify: Option<bool>, big: bool) {
    let mips = compile(id);
    let n64 = mips.profile("default", "__stdcall");
    // mips64be.cspec: <join_dual_class stackspill="true" fillalternate="true"
    // reversejustify="true"/>; mips64le.cspec omits reversejustify.
    let dual = DualJoinAttributes {
        stack_spill: Some(true),
        fill_alternate: Some(true),
        reverse_justify,
        ..Default::default()
    };
    assert_eq!(n64.duals(INPUT), [dual]);
    assert!(n64.duals(OUTPUT).is_empty());
    let a = n64.run(&mut n64.state(INPUT), dual, "{int}");
    assert_eq!(
        (
            a.config.base,
            a.config.alternate,
            a.config.big_endian,
            a.config.consume_most_significant,
            a.config.justify_right,
            a.config.tile_size
        ),
        (
            StorageClass::General,
            StorageClass::Float,
            big,
            big,
            false,
            8
        )
    );
    // f12/a0 .. f19/t3 are eight <group>s: each float shares a group with
    // the general register at the same argument position.
    let order = |mut bytes: Vec<Bytes>| {
        if !big {
            bytes.reverse();
        }
        bytes
    };
    // {double, long}: f12 takes group 0, so the long skips a0 for a1.
    let mut s = n64.state(INPUT);
    assert_eq!(
        n64.bytes(&mut s, dual, "{double,long}"),
        order(vec![mips.at("f12", 0, 8), mips.at("a1", 0, 8)])
    );
    // Two floats in one doubleword are general under fillalternate.
    assert_eq!(
        n64.bytes(&mut s, dual, "{float,float}"),
        order(vec![mips.at("a2", 0, 8)])
    );
    // {double, float, float}: f15 (position 3) then t0 (position 4).
    assert_eq!(
        n64.bytes(&mut s, dual, "{double,float,float}"),
        order(vec![mips.at("f15", 0, 8), mips.at("t0", 0, 8)])
    );
    check_held(&s);
    // A 4-byte {int} uses the first four bytes of a0: the high half on big
    // endian (left justified by reversejustify), the low half on little.
    assert_eq!(
        n64.bytes(&mut n64.state(INPUT), dual, "{int}"),
        [mips.at("a0", 0, 4)]
    );
    // {float} is not a full doubleword: general under fillalternate.
    assert_eq!(
        n64.bytes(&mut n64.state(INPUT), dual, "{float}"),
        [mips.at("a0", 0, 4)]
    );
    // Nine doubles: f12..f19, then the float class is exhausted and the
    // remaining doubleword spills to the 8-aligned stack at offset 0.
    let mut expected: Vec<_> = (12..20).map(|n| mips.at(&format!("f{n}"), 0, 8)).collect();
    expected.push(on_stack(0, 8));
    let mut s = n64.state(INPUT);
    assert_eq!(n64.bytes(&mut s, dual, "{double x9}"), order(expected));
    assert_eq!(
        s.groups().last(),
        Some(&GroupState::Available { used_slots: 1 })
    );
    check_held(&s);
    // Ten longs: a0..t3, then sixteen bytes of stack.
    let mut expected: Vec<_> = ["a0", "a1", "a2", "a3", "t0", "t1", "t2", "t3"]
        .iter()
        .map(|n| mips.at(n, 0, 8))
        .collect();
    expected.push(on_stack(0, 16));
    let mut s = n64.state(INPUT);
    assert_eq!(n64.bytes(&mut s, dual, "{long x10}"), order(expected));
    check_held(&s);
}

#[test]
#[ignore = "compiles the retained MIPS64 SLEIGH source"]
fn mips64_be_dual_class_with_shared_groups_fill_and_spill() {
    mips64("MIPS:BE:64:default", Some(true), true);
}

#[test]
#[ignore = "compiles the retained MIPS64 SLEIGH source"]
fn mips64_le_dual_class_with_shared_groups_fill_and_spill() {
    mips64("MIPS:LE:64:default", None, false);
}
