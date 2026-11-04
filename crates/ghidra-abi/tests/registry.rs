//! RegisterFile behavior: caller-built layouts, names, aliases and budgets.
//! Expected values come from Ghidra's `RegisterBuilder`/`AbstractAddressSpace`
//! rules or from byte-set models, never from replaying the implementation.
mod common;

use std::collections::{BTreeSet, HashMap};

use common::*;
use ghidra_abi::{AbiError, AbiLimits, RegisterFile, RegisterId};
use ghidra_pcode::{AddressSpace, Endianness, SpaceId, SpaceKind};

fn build(
    spaces: Vec<AddressSpace>,
    default: SpaceId,
    registers: Vec<ghidra_abi::RegisterDefinition>,
) -> Result<RegisterFile, AbiError> {
    RegisterFile::new(spaces, default, registers, AbiLimits::default())
}

fn layout_error(result: Result<RegisterFile, AbiError>) -> &'static str {
    match result {
        Err(AbiError::InvalidLayout(reason)) => reason,
        other => panic!("expected an invalid layout, got {other:?}"),
    }
}

#[test]
fn malformed_spaces_and_default_space_are_rejected_with_specific_reasons() {
    is_limit(build(vec![], RAM, vec![]), "spaces");
    for (address_size, word_size) in [(0, 1), (9, 1), (4, 0)] {
        let mut spaces = spaces(4);
        spaces[1].address_size = address_size;
        spaces[1].word_size = word_size;
        assert_eq!(
            layout_error(build(spaces, RAM, vec![])),
            "invalid address space"
        );
    }
    // 257 bytes is inside the registry name budget but outside AddressSpace's own 256.
    let mut long = spaces(4);
    long[1].name = "r".repeat(257);
    assert_eq!(
        layout_error(build(long, RAM, vec![])),
        "invalid address space"
    );
    let mut empty = spaces(4);
    empty[1].name.clear();
    is_limit(build(empty, RAM, vec![]), "name length");

    let mut duplicate_id = spaces(4);
    duplicate_id[2].id = RAM;
    assert_eq!(
        layout_error(build(duplicate_id, RAM, vec![])),
        "duplicate space ID"
    );
    let mut duplicate_name = spaces(4);
    duplicate_name[2].name = "ram".into();
    assert_eq!(
        layout_error(build(duplicate_name, RAM, vec![])),
        "duplicate space name"
    );
    // Space names are exact; a case variant is a different space.
    let mut case_variant = spaces(4);
    case_variant[2].name = "RAM".into();
    let file = build(case_variant, RAM, vec![]).unwrap();
    assert_eq!(file.space_named("RAM").unwrap().id, REGISTER);
    assert_eq!(file.space_named("ram").unwrap().id, RAM);
    assert!(file.space_named("Ram").is_none());

    assert_eq!(
        layout_error(build(spaces(4), SpaceId(77), vec![])),
        "unknown default space"
    );
    let mut with_unique = spaces(4);
    with_unique.push(space(3, "unique", SpaceKind::Unique, 4, 1));
    with_unique.push(space(4, "other", SpaceKind::Other, 8, 1));
    for (default, accepted) in [
        (CONST, false),
        (REGISTER, false),
        (SpaceId(3), false),
        (RAM, true),
        (SpaceId(4), true),
    ] {
        let result = build(with_unique.clone(), default, vec![]);
        if accepted {
            assert_eq!(result.unwrap().default_space(), default);
        } else {
            assert_eq!(layout_error(result), "default space must be memory");
        }
    }
}

#[test]
fn register_spaces_names_and_extents_are_validated() {
    let mut spaces = spaces(4);
    spaces.push(space(3, "unique", SpaceKind::Unique, 4, 1));
    let check = |registers| layout_error(build(spaces.clone(), RAM, registers));
    assert_eq!(
        check(vec![register("x", SpaceId(9), 0, 4)]),
        "register names unknown space"
    );
    for id in [CONST, SpaceId(3)] {
        assert_eq!(
            check(vec![register("x", id, 0, 4)]),
            "register is not in register or RAM space"
        );
    }
    assert_eq!(
        check(vec![register("x", REGISTER, 0, 0)]),
        "register extent outside space"
    );
    assert_eq!(
        check(vec![
            register("x", REGISTER, 0, 1),
            register("x", REGISTER, 8, 1)
        ]),
        "duplicate register name"
    );
    is_limit(
        build(spaces.clone(), RAM, vec![register("", REGISTER, 0, 1)]),
        "name length",
    );

    // Narrow, word-addressed and full-width register spaces. Offsets are bytes.
    let narrow = vec![
        space(1, "ram", SpaceKind::Ram, 4, 1),
        space(2, "register", SpaceKind::Register, 4, 1),
        space(3, "words", SpaceKind::Register, 1, 4),
        space(4, "wide", SpaceKind::Register, 8, 1),
    ];
    let accepts = |r| build(narrow.clone(), RAM, vec![r]).is_ok();
    // 4-byte space: last byte is 0xffff_ffff.
    assert!(accepts(register("a", REGISTER, 0xffff_fffc, 4)));
    assert!(!accepts(register("a", REGISTER, 0xffff_fffc, 5)));
    assert!(!accepts(register("a", REGISTER, 0x1_0000_0000, 1)));
    // 1-byte address of 4-byte words: 256 * 4 = 1024 bytes.
    assert!(accepts(register("a", SpaceId(3), 1020, 4)));
    assert!(!accepts(register("a", SpaceId(3), 1021, 4)));
    assert!(!accepts(register("a", SpaceId(3), 1024, 1)));
    // 64-bit space: the extent may end exactly at u64::MAX but not wrap.
    assert!(accepts(register("a", SpaceId(4), u64::MAX, 1)));
    assert!(accepts(register("a", SpaceId(4), u64::MAX - 7, 8)));
    assert!(!accepts(register("a", SpaceId(4), u64::MAX, 2)));
    assert!(!accepts(register("a", SpaceId(4), u64::MAX - 6, 8)));
    // Large declarative registers are allowed when they fit.
    assert!(accepts(register("a", SpaceId(4), 0, u32::MAX)));
}

/// Ghidra's `RegisterBuilder.addRegisterToNameMap`: put(name), put(lower), put(upper)
/// for each register in order, so later case-variation collisions win.
fn java_name_map(names: &[&str]) -> HashMap<String, usize> {
    let mut map = HashMap::new();
    for (index, name) in names.iter().enumerate() {
        map.insert((*name).to_owned(), index);
        map.insert(name.to_ascii_lowercase(), index);
        map.insert(name.to_ascii_uppercase(), index);
    }
    map
}

#[test]
fn case_variant_lookup_matches_java_put_order() {
    // Hand-derived: Ab puts {Ab,ab,AB}->0; ab overwrites {ab,AB}->1; AB overwrites {AB,ab}->2.
    let names = ["Ab", "ab", "AB"];
    let registers = names
        .iter()
        .enumerate()
        .map(|(i, n)| register(n, REGISTER, i as u64 * 4, 4))
        .collect();
    let file = build(spaces(4), RAM, registers).unwrap();
    assert_eq!(file.register_id("Ab"), Some(RegisterId(0)));
    assert_eq!(file.register_id("ab"), Some(RegisterId(2)));
    assert_eq!(file.register_id("AB"), Some(RegisterId(2)));
    assert_eq!(file.register_id("aB"), None);
    // IDs retain input order.
    for (index, name) in names.iter().enumerate() {
        assert_eq!(file.register(RegisterId(index)).unwrap().name, *name);
    }

    // Generated: every distinct spelling over {a,A,b,B} of length 1..=2, in a
    // fixed scrambled order, against the Java put-order model.
    let alphabet = ["a", "A", "b", "B"];
    let mut spellings: Vec<String> = alphabet.iter().map(|s| (*s).to_owned()).collect();
    for x in alphabet {
        for y in alphabet {
            spellings.push(format!("{x}{y}"));
        }
    }
    // Deterministic permutation (multiplier coprime with 20).
    let order: Vec<&str> = (0..spellings.len())
        .map(|i| spellings[(i * 7) % spellings.len()].as_str())
        .collect();
    let model = java_name_map(&order);
    let registers = order
        .iter()
        .enumerate()
        .map(|(i, n)| register(n, REGISTER, i as u64, 1))
        .collect();
    let file = build(spaces(4), RAM, registers).unwrap();
    let mut probes: BTreeSet<String> = spellings.iter().cloned().collect();
    probes.extend(["c", "ab ", "aa\u{0}"].map(String::from));
    for probe in probes {
        assert_eq!(
            file.register_id(&probe).map(|id| id.0),
            model.get(&probe).copied(),
            "lookup {probe:?}"
        );
    }
}

#[test]
fn non_ascii_case_folding_and_oversized_lookups_are_not_synthesized() {
    let file = build(
        spaces(4),
        RAM,
        vec![
            register("Äx", REGISTER, 0, 4),
            register("ſ", REGISTER, 4, 4),
        ],
    )
    .unwrap();
    // ASCII-only upper/lower forms: "ÄX" exists, Java's "äx" lowercase does not.
    assert_eq!(file.register_id("ÄX"), Some(RegisterId(0)));
    assert_eq!(file.register_id("äx"), None);
    assert_eq!(file.register_id("S"), None);
    assert_eq!(file.register_id("ſ"), Some(RegisterId(1)));

    let limits = AbiLimits {
        max_name_length: 8,
        ..Default::default()
    };
    let exact = RegisterFile::new(
        spaces(4),
        RAM,
        vec![register("abcdefgh", REGISTER, 0, 1)],
        limits,
    )
    .unwrap();
    assert_eq!(exact.register_id("ABCDEFGH"), Some(RegisterId(0)));
    assert_eq!(exact.register_id("abcdefghi"), None);
    is_limit(
        RegisterFile::new(
            spaces(4),
            RAM,
            vec![register("abcdefghi", REGISTER, 0, 1)],
            limits,
        ),
        "name length",
    );
}

#[test]
fn ram_mapped_named_registers_resolve_and_keep_physical_aliases() {
    let file = build(
        spaces(4),
        RAM,
        vec![
            register("RW1C", RAM, 0x1c, 2),
            register("RW1CL", RAM, 0x1c, 1),
            register("separate", REGISTER, 0x1c, 2),
        ],
    )
    .unwrap();
    assert!(
        file.registers_overlap(RegisterId(0), RegisterId(1))
            .unwrap()
    );
    assert!(
        !file
            .registers_overlap(RegisterId(0), RegisterId(2))
            .unwrap()
    );
    let resolved = ghidra_abi::resolve_storage(
        &file,
        None,
        &ghidra_languages::Storage::Register {
            name: "RW1C".into(),
        },
        None,
        AbiLimits::default(),
    )
    .unwrap();
    let ghidra_abi::ResolvedStorage::Single(range) = resolved else {
        panic!()
    };
    assert_eq!(range.address.space, ghidra_abi::AbiSpace::Language(RAM));
    assert_eq!(range.address.offset, 0x1c);
    assert_eq!(range.size, Some(2));
    assert!(
        build(
            spaces(4),
            RAM,
            vec![register("bad", RAM, u32::MAX as u64, 2)]
        )
        .is_err()
    );
}

/// Byte-set intersection over explicit bytes; independent of interval arithmetic.
fn bytes_overlap(a: (u32, u64, u32), b: (u32, u64, u32)) -> bool {
    a.0 == b.0 && {
        let left: BTreeSet<u64> = (a.1..a.1 + u64::from(a.2)).collect();
        (b.1..b.1 + u64::from(b.2)).any(|x| left.contains(&x))
    }
}

#[test]
fn alias_overlap_matches_byte_sets_and_is_byte_order_independent() {
    // Two 1-byte-address register spaces (256 bytes each).
    let mut extents = Vec::new();
    for space in [2_u32, 3] {
        for offset in [0_u64, 1, 3, 4, 7, 8, 250, 252, 255] {
            for size in [1_u32, 2, 4] {
                if offset + u64::from(size) <= 256 {
                    extents.push((space, offset, size));
                }
            }
        }
    }
    let mut matrices = Vec::new();
    for endianness in [Endianness::Little, Endianness::Big] {
        let spaces = vec![
            space(1, "ram", SpaceKind::Ram, 4, 1),
            AddressSpace {
                endianness,
                ..space(2, "register", SpaceKind::Register, 1, 1)
            },
            AddressSpace {
                endianness,
                ..space(3, "vector", SpaceKind::Register, 1, 1)
            },
        ];
        let registers = extents
            .iter()
            .enumerate()
            .map(|(i, &(s, o, n))| register(&format!("x{i}"), SpaceId(s), o, n))
            .collect();
        let file = build(spaces, RAM, registers).unwrap();
        let mut matrix = Vec::new();
        for (i, a) in extents.iter().enumerate() {
            for (j, b) in extents.iter().enumerate() {
                let actual = file
                    .registers_overlap(RegisterId(i), RegisterId(j))
                    .unwrap();
                assert_eq!(actual, bytes_overlap(*a, *b), "{a:?} vs {b:?}");
                matrix.push(actual);
            }
        }
        matrices.push(matrix);
    }
    assert_eq!(matrices[0], matrices[1]);

    // MIPS32 big-endian FPU layout: f13/f12 halves of f12_13 (byte aliases,
    // whichever half is numerically low).
    let mut be = spaces(4);
    be[2].endianness = Endianness::Big;
    let file = build(
        be,
        RAM,
        vec![
            register("f12_13", REGISTER, 0x1030, 8),
            register("f13", REGISTER, 0x1030, 4),
            register("f12", REGISTER, 0x1034, 4),
            register("f14", REGISTER, 0x103c, 4),
        ],
    )
    .unwrap();
    let id = |n| file.register_id(n).unwrap();
    assert!(file.registers_overlap(id("f12_13"), id("f12")).unwrap());
    assert!(file.registers_overlap(id("f13"), id("f12_13")).unwrap());
    assert!(!file.registers_overlap(id("f12"), id("f13")).unwrap());
    assert!(!file.registers_overlap(id("f12_13"), id("f14")).unwrap());
}

#[test]
fn overlap_at_the_top_of_a_64_bit_space_does_not_wrap() {
    let file = build(
        spaces(8),
        RAM,
        vec![
            register("top", REGISTER, u64::MAX, 1),
            register("top2", REGISTER, u64::MAX - 1, 2),
            register("below", REGISTER, u64::MAX - 1, 1),
            register("zero", REGISTER, 0, 8),
            register("top8", REGISTER, u64::MAX - 7, 8),
        ],
    )
    .unwrap();
    let id = |n| file.register_id(n).unwrap();
    assert!(file.registers_overlap(id("top"), id("top2")).unwrap());
    assert!(file.registers_overlap(id("below"), id("top2")).unwrap());
    assert!(!file.registers_overlap(id("top"), id("below")).unwrap());
    assert!(!file.registers_overlap(id("top"), id("zero")).unwrap());
    assert!(!file.registers_overlap(id("zero"), id("top8")).unwrap());
    assert!(file.registers_overlap(id("top8"), id("top")).unwrap());
    for bad in [RegisterId(5), RegisterId(usize::MAX)] {
        assert!(matches!(file.register(bad), Err(AbiError::UnknownRegisterId(x)) if x == bad));
        assert!(file.registers_overlap(id("top"), bad).is_err());
        assert!(file.registers_overlap(bad, id("top")).is_err());
    }
}

fn numbered(count: usize) -> Vec<ghidra_abi::RegisterDefinition> {
    (0..count)
        .map(|i| register(&format!("r{i:05}"), REGISTER, i as u64 * 8, 8))
        .collect()
}

#[test]
fn registry_budgets_hold_at_exact_size_and_fail_one_below() {
    let registers = numbered(64);
    let file = RegisterFile::new(spaces(4), RAM, registers.clone(), AbiLimits::default()).unwrap();
    // Every name is visited at least once; the policy charge stays a small multiple.
    let declared: usize = spaces(4).iter().map(|s| s.name.len()).sum::<usize>()
        + registers.iter().map(|r| r.name.len()).sum::<usize>();
    assert!(file.name_bytes() >= declared);
    assert!(file.name_bytes() <= 8 * declared, "{}", file.name_bytes());
    assert!(file.build_work() >= file.name_bytes() as u64);

    let exact = AbiLimits {
        max_spaces: 3,
        max_registers: 64,
        max_name_length: 8,
        max_name_bytes: file.name_bytes(),
        max_work: file.build_work(),
        ..Default::default()
    };
    let rebuilt = RegisterFile::new(spaces(4), RAM, registers.clone(), exact).unwrap();
    assert_eq!(rebuilt.build_work(), file.build_work());
    assert_eq!(rebuilt.name_bytes(), file.name_bytes());
    for (limits, resource) in [
        (
            AbiLimits {
                max_spaces: 2,
                ..exact
            },
            "spaces",
        ),
        (
            AbiLimits {
                max_registers: 63,
                ..exact
            },
            "registers",
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
        is_limit(
            RegisterFile::new(spaces(4), RAM, registers.clone(), limits),
            resource,
        );
    }
    // Zero-register files are valid at a zero register budget.
    RegisterFile::new(
        spaces(4),
        RAM,
        vec![],
        AbiLimits {
            max_registers: 0,
            ..Default::default()
        },
    )
    .unwrap();
}

#[test]
fn registry_work_and_name_charges_scale_without_amplification() {
    let small = RegisterFile::new(spaces(8), RAM, numbered(1024), AbiLimits::default()).unwrap();
    let large = RegisterFile::new(spaces(8), RAM, numbered(4096), AbiLimits::default()).unwrap();
    // Same-width names: name bytes are linear; work is near n log n (<6x), not n^2 (16x).
    let names = large.name_bytes() as f64 / small.name_bytes() as f64;
    assert!((3.9..=4.1).contains(&names), "{names}");
    let work = large.build_work() as f64 / small.build_work() as f64;
    assert!(work < 6.0, "{work}");
    assert_eq!(large.registers().len(), 4096);
    assert_eq!(large.register_id("R04095"), Some(RegisterId(4095)));
}

#[test]
fn shared_types_are_thread_safe() {
    fn check<T: Send + Sync>() {}
    check::<RegisterFile>();
    check::<ghidra_abi::CompilerStorage>();
    check::<AbiError>();
}

/// Reported divergence: Ghidra's `RegisterBuilder.addRegister` turns a register
/// with an identical address and bit range into an alias of the earlier
/// `Register`. Here each declaration keeps its own ID; the aliases still
/// overlap. None of the four compiled probe layouts contain such a pair.
#[test]
fn divergence_identical_extents_keep_distinct_register_ids() {
    let file = build(
        spaces(4),
        RAM,
        vec![
            register("ctx", REGISTER, 0x10, 4),
            register("ctx_alias", REGISTER, 0x10, 4),
        ],
    )
    .unwrap();
    let (a, b) = (
        file.register_id("ctx").unwrap(),
        file.register_id("CTX_ALIAS").unwrap(),
    );
    assert_ne!(a, b);
    assert!(file.registers_overlap(a, b).unwrap());
    assert_eq!(file.register(b).unwrap().name, "ctx_alias");
}
