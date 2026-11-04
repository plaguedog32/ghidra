//! CompilerStorage: every declaration keeps its source position; parameter
//! capacity stays separate from storage width; return-address fallback,
//! ranges, space bases and dead-code delays; and exact construction budgets.
mod common;

use std::sync::Arc;

use common::*;
use ghidra_abi::{
    AbiAddress, AbiError, AbiLimits, AbiSpace, BindingSite, CompilerStorage, JoinKind,
    ParameterConstraints, ResolvedStorage,
};
use ghidra_languages::{
    AddressRange, CompilerSpec, Extension, JoinPiece, MemoryTag, ParamEntry, Storage, StorageClass,
};

const FIXTURE: &str = r#"<compiler_spec>
  <global>
    <range space="ram" first="0x1000" last="0x1fff"/>
    <register name="LR"/>
    <range space="ram"/>
  </global>
  <readonly><range space="ram" first="0x2000" last="0x2fff"/></readonly>
  <nohighptr><range space="ram" first="0x100" last="0x1ff"/></nohighptr>
  <stackpointer register="sp" space="ram"/>
  <spacebase name="gp" register="r3" space="ram"/>
  <spacebase name="tp" register="R2" space="stack"/>
  <deadcodedelay space="register" delay="3"/>
  <deadcodedelay space="OTHER" delay="-1"/>
  <inferptrbounds><range space="ram" first="0x10" last="0x20"/></inferptrbounds>
  <prefersplit style="inhalf"><register name="d0"/><varnode space="ram" offset="0x40" size="8"/></prefersplit>
  <returnaddress><varnode space="stack" offset="0" size="4"/></returnaddress>
  <default_proto>
    <prototype name="std" extrapop="0" stackshift="0">
      <input>
        <group>
          <pentry minsize="1" maxsize="4" metatype="float"><register name="f0"/></pentry>
          <pentry minsize="1" maxsize="4"><register name="r0"/></pentry>
        </group>
        <pentry minsize="1" maxsize="8" extension="sign"><addr space="join" piece1="r2" piece2="r1"/></pentry>
        <pentry minsize="1" maxsize="500" align="4"><addr space="stack" offset="8"/></pentry>
      </input>
      <output>
        <pentry minsize="1" maxsize="4" align="4"><register name="r0"/></pentry>
        <pentry minsize="5" maxsize="8"><addr space="join" piece1="r1" piece2="r0"/></pentry>
      </output>
      <unaffected><register name="sp"/><register name="r3"/></unaffected>
      <killedbycall><register name="r0"/><register name="r1"/><register name="r2"/></killedbycall>
      <likelytrash><register name="r2"/></likelytrash>
      <internal_storage><register name="lr"/></internal_storage>
      <localrange>
        <range space="stack" first="0xfffffff0" last="0xffffffff"/>
        <range space="stack" first="0" last="7"/>
      </localrange>
      <paramrange><range space="stack" first="8" last="0x7fffffff"/><register name="r1"/></paramrange>
    </prototype>
  </default_proto>
  <prototype name="explicit" extrapop="0" stackshift="0">
    <input/><output/>
    <returnaddress><register name="lr"/><varnode space="stack" offset="4" size="4"/></returnaddress>
  </prototype>
  <prototype name="suppressed" extrapop="0" stackshift="0">
    <input/><output/>
    <returnaddress></returnaddress>
  </prototype>
  <prototype name="inherits" extrapop="0" stackshift="0">
    <input/><output/>
  </prototype>
</compiler_spec>"#;

fn fixture() -> CompilerStorage {
    storage(parse(FIXTURE), &small_file(), AbiLimits::default()).unwrap()
}

fn ram(offset: u64) -> AbiAddress {
    AbiAddress {
        space: AbiSpace::Language(RAM),
        offset,
    }
}

fn stack(offset: i64) -> AbiAddress {
    AbiAddress {
        space: AbiSpace::Stack,
        offset: offset as u64,
    }
}

#[test]
fn every_declaration_is_resolved_at_its_source_position() {
    let compiled = fixture();
    let file = compiled.register_file().clone();
    let id = |name| file.register_id(name);
    let register_at = |site| {
        let binding = compiled.binding(site).unwrap_or_else(|| panic!("{site:?}"));
        assert_eq!(binding.site, site);
        single(&binding.storage).register
    };
    use BindingSite::*;
    // Clobber lists keep model/list positions.
    assert_eq!(register_at(Unaffected { model: 0, index: 0 }), id("sp"));
    assert_eq!(register_at(Unaffected { model: 0, index: 1 }), id("r3"));
    for (index, name) in ["r0", "r1", "r2"].into_iter().enumerate() {
        assert_eq!(register_at(KilledByCall { model: 0, index }), id(name));
    }
    assert_eq!(register_at(LikelyTrash { model: 0, index: 0 }), id("r2"));
    assert_eq!(
        register_at(InternalStorage { model: 0, index: 0 }),
        id("lr")
    );
    assert_eq!(register_at(PreferSplit(0)), id("d0"));
    let split = compiled.binding(PreferSplit(1)).unwrap();
    assert_eq!(single(&split.storage).address, ram(0x40));
    assert!(compiled.binding(PreferSplit(2)).is_none());
    assert!(
        compiled
            .binding(KilledByCall { model: 0, index: 3 })
            .is_none()
    );
    assert!(
        compiled
            .binding(KilledByCall { model: 1, index: 0 })
            .is_none()
    );
    // Input entries in declaration order, including a grouped pair.
    assert_eq!(register_at(Input { model: 0, entry: 0 }), id("f0"));
    assert_eq!(register_at(Input { model: 0, entry: 1 }), id("r0"));
    let join = &compiled
        .binding(Input { model: 0, entry: 2 })
        .unwrap()
        .storage;
    let ResolvedStorage::Join { kind, pieces, .. } = join else {
        panic!()
    };
    assert_eq!(*kind, JoinKind::Concatenation);
    assert_eq!(
        (pieces[0].storage.register, pieces[0].lsb_byte),
        (id("r2"), Some(4))
    );
    assert_eq!(
        (pieces[1].storage.register, pieces[1].lsb_byte),
        (id("r1"), Some(0))
    );
    assert_eq!(register_at(Output { model: 0, entry: 0 }), id("r0"));

    // Bindings are emitted spec-level first and then model by model, and each
    // record's index entry points at itself.
    let sites: Vec<_> = compiled.bindings().iter().map(|b| b.site).collect();
    assert_eq!(sites[0], SpecReturnAddress);
    assert_eq!(&sites[1..3], &[PreferSplit(0), PreferSplit(1)]);
    // spec return, prefer-split, inputs, outputs, unaffected, killed,
    // likely-trash, internal, model 1 returns (model 2's list is empty).
    assert_eq!(sites.len(), 1 + 2 + 4 + 2 + 2 + 3 + 1 + 1 + 2);
    for binding in compiled.bindings() {
        assert_eq!(compiled.binding(binding.site), Some(binding));
    }
    for range in compiled.ranges() {
        assert_eq!(compiled.range(range.site), Some(range));
    }
    // Total pieces: 16 single bindings, two 2-piece joins and two register tags.
    assert_eq!(compiled.total_pieces(), 16 + 4 + 2);
}

#[test]
fn parameter_capacity_is_not_an_allocated_width() {
    let compiled = fixture();
    let input = |entry| {
        compiled
            .binding(BindingSite::Input { model: 0, entry })
            .unwrap()
    };
    let constraints = |entry| input(entry).parameter.clone().unwrap();
    assert_eq!(
        constraints(0),
        ParameterConstraints {
            min_size: 1,
            max_size: 4,
            alignment: 0,
            storage_class: StorageClass::Float,
            extension: Extension::None,
            group: Some(0),
        }
    );
    assert_eq!(constraints(1).group, Some(0));
    assert_eq!(constraints(1).storage_class, StorageClass::General);
    assert_eq!(
        (constraints(2).group, constraints(2).extension),
        (None, Extension::Sign)
    );
    // The unsized stack pool keeps a 500-byte capacity but no allocated width.
    let pool = input(3);
    assert_eq!(pool.storage.size(), None);
    assert_eq!(single(&pool.storage).address, stack(8));
    assert_eq!(
        (constraints(3).max_size, constraints(3).alignment),
        (500, 4)
    );
    // align equal to maxsize is a single slot (alignment 0), as in ParamEntry.
    let output = compiled
        .binding(BindingSite::Output { model: 0, entry: 0 })
        .unwrap();
    assert_eq!(output.parameter.as_ref().unwrap().alignment, 0);
    // Non-parameter bindings carry no constraints.
    assert!(
        compiled
            .binding(BindingSite::SpecReturnAddress)
            .unwrap()
            .parameter
            .is_none()
    );
}

fn one_entry(entry: ParamEntry) -> CompilerSpec {
    let mut spec = parse(
        r#"<compiler_spec><default_proto><prototype name="p" extrapop="0" stackshift="0">
        <input><pentry minsize="1" maxsize="4"><register name="r0"/></pentry></input><output/>
        </prototype></default_proto></compiler_spec>"#,
    );
    spec.prototypes[0].input.entries[0] = entry;
    spec
}

#[test]
fn parameter_bounds_and_storage_width_are_validated() {
    let file = small_file();
    let template = parse(
        r#"<compiler_spec><default_proto><prototype name="p" extrapop="0" stackshift="0">
        <input><pentry minsize="1" maxsize="4"><register name="r0"/></pentry></input><output/>
        </prototype></default_proto></compiler_spec>"#,
    )
    .prototypes[0]
        .input
        .entries[0]
        .clone();
    let site = BindingSite::Input { model: 0, entry: 0 };
    let check = |min_size, max_size, storage: Storage| {
        let entry = ParamEntry {
            min_size,
            max_size,
            storage,
            ..template.clone()
        };
        CompilerStorage::new(
            Arc::new(one_entry(entry)),
            file.clone(),
            AbiLimits::default(),
        )
    };
    let r0 = || Storage::Register { name: "r0".into() };
    // Exactly the register width passes; one more byte does not.
    check(1, 4, r0()).unwrap();
    assert!(matches!(
        at(check(1, 5, r0()).unwrap_err(), site),
        AbiError::TooSmall {
            actual: 4,
            required: 5
        }
    ));
    for (min, max) in [(0, 4), (5, 4)] {
        assert!(matches!(
            at(check(min, max, r0()).unwrap_err(), site),
            AbiError::InvalidStorage("parameter size bounds")
        ));
    }
    // A sized address is checked against max_size; an unsized one is not.
    assert!(matches!(
        at(check(1, 8, address("stack", 0, Some(4))).unwrap_err(), site),
        AbiError::TooSmall {
            actual: 4,
            required: 8
        }
    ));
    check(1, u32::MAX, address("stack", 0, None)).unwrap();
    // A float extension's logical size is the width that is checked.
    let extension = Storage::Join {
        pieces: vec![JoinPiece::Register { name: "f0d".into() }],
        logical_size: Some(4),
    };
    check(1, 4, extension.clone()).unwrap();
    assert!(matches!(
        at(check(1, 8, extension).unwrap_err(), site),
        AbiError::TooSmall {
            actual: 4,
            required: 8
        }
    ));
}

#[test]
fn return_addresses_are_inherited_explicit_or_suppressed() {
    let compiled = fixture();
    let spec_level = compiled.binding(BindingSite::SpecReturnAddress).unwrap();
    assert_eq!(single(&spec_level.storage).address, stack(0));
    // Model 0 and 3 declare nothing and inherit the spec-level location.
    for model in [0, 3] {
        let inherited = compiled.return_addresses(model).unwrap();
        assert_eq!(inherited, std::slice::from_ref(spec_level));
    }
    let explicit = compiled.return_addresses(1).unwrap();
    assert_eq!(
        explicit.iter().map(|b| b.site).collect::<Vec<_>>(),
        [
            BindingSite::ReturnAddress { model: 1, index: 0 },
            BindingSite::ReturnAddress { model: 1, index: 1 }
        ]
    );
    assert_eq!(
        single(&explicit[0].storage).register,
        compiled.register_file().register_id("lr")
    );
    assert_eq!(single(&explicit[1].storage).address, stack(4));
    // An explicit empty list suppresses the fallback.
    assert!(compiled.return_addresses(2).unwrap().is_empty());
    assert!(compiled.return_addresses(4).is_err());
    assert!(compiled.return_addresses(usize::MAX).is_err());

    // Without a spec-level location, undeclared models have none.
    let mut spec = parse(FIXTURE);
    spec.return_address = None;
    let bare = storage(spec, &small_file(), AbiLimits::default()).unwrap();
    assert!(bare.return_addresses(0).unwrap().is_empty());
    assert_eq!(bare.return_addresses(1).unwrap().len(), 2);
    assert!(bare.binding(BindingSite::SpecReturnAddress).is_none());
}

#[test]
fn ranges_space_bases_and_delays_keep_positions_and_signedness() {
    let compiled = fixture();
    let file = compiled.register_file().clone();
    let range = |site| {
        let r = compiled.range(site).unwrap_or_else(|| panic!("{site:?}"));
        (r.first, r.last, r.register)
    };
    use BindingSite::*;
    assert_eq!(range(Global(0)), (ram(0x1000), ram(0x1fff), None));
    // A register tag covers the register's bytes (case-variant name).
    let lr = AbiAddress {
        space: AbiSpace::Language(REGISTER),
        offset: 0x50,
    };
    assert_eq!(
        range(Global(1)),
        (
            lr,
            AbiAddress { offset: 0x53, ..lr },
            file.register_id("lr")
        )
    );
    // Open bounds default to 0 and the space maximum.
    assert_eq!(range(Global(2)), (ram(0), ram(0xffff_ffff), None));
    assert_eq!(range(ReadOnly(0)), (ram(0x2000), ram(0x2fff), None));
    assert_eq!(range(NoHighPointer(0)), (ram(0x100), ram(0x1ff), None));
    assert_eq!(range(InferPointerBounds(0)), (ram(0x10), ram(0x20), None));
    // Stack ranges normalize to signed offsets.
    assert_eq!(
        range(LocalRange { model: 0, index: 0 }),
        (stack(-16), stack(-1), None)
    );
    assert_eq!(
        range(LocalRange { model: 0, index: 1 }),
        (stack(0), stack(7), None)
    );
    assert_eq!(
        range(ParameterRange { model: 0, index: 0 }),
        (stack(8), stack(0x7fff_ffff), None)
    );
    assert_eq!(
        range(ParameterRange { model: 0, index: 1 }).2,
        file.register_id("r1")
    );
    assert!(compiled.range(LocalRange { model: 1, index: 0 }).is_none());
    assert_eq!(compiled.ranges().len(), 3 + 1 + 1 + 1 + 2 + 2);

    let bases = compiled.space_bases();
    assert_eq!(bases.len(), 2);
    assert_eq!(
        (bases[0].source_index, bases[0].register, bases[0].space),
        (0, file.register_id("r3").unwrap(), AbiSpace::Language(RAM))
    );
    assert_eq!(
        (bases[1].source_index, bases[1].register, bases[1].space),
        (1, file.register_id("r2").unwrap(), AbiSpace::Stack)
    );
    let delays = compiled.dead_code_delays();
    assert_eq!(
        delays
            .iter()
            .map(|d| (d.source_index, d.space, d.delay))
            .collect::<Vec<_>>(),
        [
            (0, AbiSpace::Language(REGISTER), 3),
            (1, AbiSpace::Other, -1)
        ]
    );
    // Overlay inputs are shared, not copied.
    let shared = small_file();
    let spec = Arc::new(parse(FIXTURE));
    let overlay = CompilerStorage::new(spec.clone(), shared.clone(), AbiLimits::default()).unwrap();
    assert!(Arc::ptr_eq(overlay.register_file(), &shared));
    assert!(Arc::ptr_eq(overlay.source(), &spec));
    assert_eq!(overlay.source().prototypes.len(), 4);
}

#[test]
fn reversed_ranges_and_failures_report_their_site() {
    let file = small_file();
    let mut spec = parse(FIXTURE);
    // Signed comparison: first -4 above last -8 is reversed.
    spec.prototypes[0].local_range = Some(vec![MemoryTag::Range(AddressRange {
        space: "stack".into(),
        first: Some(-4_i64 as u64),
        last: Some(-8_i64 as u64),
    })]);
    let error = storage(spec, &file, AbiLimits::default()).unwrap_err();
    assert!(matches!(
        at(error, BindingSite::LocalRange { model: 0, index: 0 }),
        AbiError::InvalidStorage("reversed address range")
    ));
    // -8..=-4 is ordered.
    let mut spec = parse(FIXTURE);
    spec.prototypes[0].local_range = Some(vec![MemoryTag::Range(AddressRange {
        space: "stack".into(),
        first: Some(-8_i64 as u64),
        last: Some(-4_i64 as u64),
    })]);
    storage(spec, &file, AbiLimits::default()).unwrap();

    let mut spec = parse(FIXTURE);
    spec.prototypes[1].killed_by_call = vec![
        Storage::Register { name: "r0".into() },
        Storage::Register { name: "r9".into() },
    ];
    let error = storage(spec, &file, AbiLimits::default()).unwrap_err();
    assert!(matches!(
        at(error, BindingSite::KilledByCall { model: 1, index: 1 }),
        AbiError::UnknownRegister(n) if n == "r9"
    ));
    let mut spec = parse(FIXTURE);
    spec.space_bases[1].space = "nowhere".into();
    assert!(matches!(
        at(
            storage(spec, &file, AbiLimits::default()).unwrap_err(),
            BindingSite::SpaceBase(1)
        ),
        AbiError::UnknownSpace(_)
    ));
    let mut spec = parse(FIXTURE);
    spec.dead_code_delays[0].space = "join".into();
    assert!(matches!(
        at(
            storage(spec, &file, AbiLimits::default()).unwrap_err(),
            BindingSite::DeadCodeDelay(0)
        ),
        AbiError::InvalidStorage(_)
    ));
    let mut spec = parse(FIXTURE);
    spec.global.push(MemoryTag::Range(AddressRange {
        space: "ram".into(),
        first: Some(1 << 32),
        last: None,
    }));
    assert!(matches!(
        at(
            storage(spec, &file, AbiLimits::default()).unwrap_err(),
            BindingSite::Global(3)
        ),
        AbiError::AddressRange { .. }
    ));
}

#[test]
fn global_style_reversed_ranges_are_swapped_while_local_ranges_stay_strict() {
    let file = small_file();
    let mut spec = parse(FIXTURE);
    let range = AddressRange {
        space: "ram".into(),
        first: Some(20),
        last: Some(4),
    };
    spec.global = vec![MemoryTag::Range(range.clone())];
    spec.no_high_ptr = Some(vec![MemoryTag::Range(range.clone())]);
    spec.read_only = Some(vec![MemoryTag::Range(range.clone())]);
    spec.infer_pointer_bounds = vec![range];
    let resolved = storage(spec, &file, AbiLimits::default()).unwrap();
    for site in [
        BindingSite::Global(0),
        BindingSite::NoHighPointer(0),
        BindingSite::ReadOnly(0),
        BindingSite::InferPointerBounds(0),
    ] {
        let range = resolved.range(site).unwrap();
        assert_eq!((range.first.offset, range.last.offset), (4, 20));
    }
}

/// Independently counted output records for FIXTURE.
const RECORDS: usize = 18 /* bindings */ + 10 /* ranges */ + 2 /* bases */ + 2 /* delays */;

#[test]
fn construction_budgets_hold_at_exact_size_and_fail_one_below() {
    let file = small_file();
    let reference = fixture();
    assert_eq!(reference.bindings().len(), 18);
    let exact = AbiLimits {
        max_models: 4,
        max_space_bases: 2,
        max_bindings: RECORDS,
        max_join_pieces: 2,
        max_total_pieces: 22,
        // The longest resolved name is the `register` dead-code-delay space.
        max_name_length: 8,
        max_name_bytes: reference.name_bytes(),
        max_work: reference.build_work(),
        ..Default::default()
    };
    let rebuilt = storage(parse(FIXTURE), &file, exact).unwrap();
    assert_eq!(rebuilt.build_work(), reference.build_work());
    assert_eq!(rebuilt.bindings(), reference.bindings());
    for (limits, resource) in [
        (
            AbiLimits {
                max_models: 3,
                ..exact
            },
            "models",
        ),
        (
            AbiLimits {
                max_space_bases: 1,
                ..exact
            },
            "space bases",
        ),
        (
            AbiLimits {
                max_bindings: RECORDS - 1,
                ..exact
            },
            "bindings",
        ),
        (
            AbiLimits {
                max_join_pieces: 1,
                ..exact
            },
            "join pieces",
        ),
        (
            AbiLimits {
                max_total_pieces: 21,
                ..exact
            },
            "storage pieces",
        ),
        (
            AbiLimits {
                max_name_length: 7,
                ..exact
            },
            "name length",
        ),
        (
            AbiLimits {
                max_name_bytes: exact.max_name_bytes - 1,
                ..exact
            },
            "name bytes",
        ),
        (
            AbiLimits {
                max_work: exact.max_work - 1,
                ..exact
            },
            "work",
        ),
    ] {
        is_limit(storage(parse(FIXTURE), &file, limits), resource);
    }
    // Every name is visited at least once and charges stay proportional.
    assert!(
        reference.name_bytes() >= 60 && reference.name_bytes() < 2_000,
        "{}",
        reference.name_bytes()
    );
}

fn many_models(models: usize) -> CompilerSpec {
    let mut text = String::from("<compiler_spec><default_proto>");
    for index in 0..models {
        text.push_str(&format!(
            r#"<prototype name="m{index}" extrapop="0" stackshift="0"><input>
            <pentry minsize="1" maxsize="4"><register name="r0"/></pentry>
            <pentry minsize="1" maxsize="500" align="4"><addr space="stack" offset="4"/></pentry></input>
            <output><pentry minsize="1" maxsize="4"><register name="r0"/></pentry></output>
            <killedbycall><register name="r1"/></killedbycall></prototype>"#
        ));
        if index == 0 {
            text.push_str("</default_proto>");
        }
    }
    text.push_str("</compiler_spec>");
    parse(&text)
}

#[test]
fn overlay_work_scales_without_amplification() {
    let file = small_file();
    let small = storage(many_models(200), &file, AbiLimits::default()).unwrap();
    let large = storage(many_models(800), &file, AbiLimits::default()).unwrap();
    assert_eq!(large.bindings().len(), 4 * 800);
    assert_eq!(large.total_pieces(), 4 * 800);
    // 4x the models: linear name charges, near n log n work (not 16x).
    let names = large.name_bytes() as f64 / small.name_bytes() as f64;
    assert!((3.9..=4.1).contains(&names), "{names}");
    let work = large.build_work() as f64 / small.build_work() as f64;
    assert!(work < 6.0, "{work}");
    // Lookup of the last model's return addresses neither scans nor allocates.
    assert!(large.return_addresses(799).unwrap().is_empty());
}
