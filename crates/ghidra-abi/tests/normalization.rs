//! Address normalization against a reference model transcribed from Ghidra's
//! `AbstractAddressSpace` constructor and `makeValidOffset`, plus the crate's
//! documented stricter whole-extent rule. Stack geometry follows
//! `BasicCompilerSpec.setStackPointer` and its no-stack-pointer fallback.
mod common;

use std::sync::Arc;

use common::*;
use ghidra_abi::{
    AbiAddress, AbiError, AbiLimits, AbiSpace, RegisterFile, ResolvedStorage, StackProperties,
    resolve_storage,
};
use ghidra_languages::{StackGrowth, StackPointer, Storage};
use ghidra_pcode::SpaceKind;

/// `AbstractAddressSpace.makeValidOffset` for `size` address bits and unit size.
fn java_make_valid(offset: i64, bits: u32, unit: i128, signed: bool) -> Option<i128> {
    if bits == 64 {
        return Some(if signed {
            i128::from(offset)
        } else {
            i128::from(offset as u64)
        });
    }
    let space_size = unit << bits;
    let (min, max) = if signed {
        let max = (space_size - 1) >> 1;
        (-max - 1, max)
    } else {
        (0, space_size - 1)
    };
    let o = i128::from(offset);
    if o >= min && o <= max {
        Some(o)
    } else if signed && o > max && o < space_size {
        Some(o - space_size)
    } else if !signed && o < 0 && o >= -max - 1 {
        Some(o + space_size)
    } else {
        None
    }
}

/// Documented extent rule: a sized, non-constant location must fit wholly.
fn expected(
    offset: i64,
    size: Option<u32>,
    bits: u32,
    unit: i128,
    signed: bool,
    constant: bool,
) -> Option<u64> {
    let value = java_make_valid(offset, bits, unit, signed)?;
    let max = match (bits, signed) {
        (64, true) => i128::from(i64::MAX),
        (64, false) => i128::from(u64::MAX),
        (_, true) => ((unit << bits) - 1) >> 1,
        (_, false) => (unit << bits) - 1,
    };
    if !constant
        && let Some(size) = size
        && (size == 0 || value + i128::from(size) - 1 > max)
    {
        return None;
    }
    Some(value as u64)
}

fn candidates(bits: u32, unit: i128) -> Vec<i64> {
    let span = if bits == 64 {
        1_i128 << 64
    } else {
        unit << bits
    };
    let half = span / 2;
    let mut values = vec![
        0_i128,
        1,
        2,
        3,
        half - 2,
        half - 1,
        half,
        half + 1,
        span - 2,
        span - 1,
        span,
        span + 1,
        -1,
        -2,
        -half + 1,
        -half,
        -half - 1,
        -span + 1,
        -span,
        -span - 1,
    ];
    values.extend([
        i128::from(i64::MIN),
        i128::from(i64::MIN) + 1,
        i128::from(i64::MAX),
    ]);
    let mut out: Vec<i64> = values
        .into_iter()
        .filter_map(|v| {
            i64::try_from(v)
                .ok()
                .or_else(|| u64::try_from(v).ok().map(|u| u as i64))
        })
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

fn geometries() -> Vec<(u8, u32)> {
    let mut out = Vec::new();
    for address_size in [1_u8, 2, 4, 8] {
        for word_size in [1_u32, 2, 4, 8] {
            // Ghidra rejects 2^size * wordsize > 2^64.
            if address_size < 8 || word_size == 1 {
                out.push((address_size, word_size));
            }
        }
    }
    out
}

#[test]
fn ram_stack_and_constant_offsets_match_the_reference_model() {
    let sizes = [None, Some(1), Some(2), Some(4), Some(8)];
    let mut checked = 0;
    for (address_size, word_size) in geometries() {
        let bits = u32::from(address_size) * 8;
        let unit = i128::from(word_size);
        // No stack pointer: the stack takes the default space's width and unit.
        let file = RegisterFile::new(
            vec![
                space(0, "const", SpaceKind::Constant, address_size, word_size),
                space(1, "ram", SpaceKind::Ram, address_size, word_size),
                space(2, "register", SpaceKind::Register, 8, 1),
            ],
            RAM,
            vec![],
            AbiLimits::default(),
        )
        .unwrap();
        for offset in candidates(bits, unit) {
            for size in sizes {
                for (name, abi_space, signed, constant) in [
                    ("ram", AbiSpace::Language(RAM), false, false),
                    ("stack", AbiSpace::Stack, true, false),
                    ("const", AbiSpace::Language(CONST), true, true),
                ] {
                    let declaration = address(name, offset as u64, size);
                    let actual =
                        resolve_storage(&file, None, &declaration, None, AbiLimits::default());
                    let want = expected(offset, size, bits, unit, signed, constant);
                    let context =
                        format!("{name} a{address_size} w{word_size} {offset:#x} {size:?}");
                    match (actual, want) {
                        (Ok(storage), Some(normalized)) => {
                            let range = single(&storage);
                            assert_eq!(
                                range.address,
                                AbiAddress {
                                    space: abi_space,
                                    offset: normalized
                                },
                                "{context}"
                            );
                            assert_eq!(range.size, size, "{context}");
                            assert_eq!(range.register, None);
                            assert_eq!(
                                range.address.signed_stack_offset(),
                                (name == "stack").then_some(normalized as i64)
                            );
                        }
                        (
                            Err(AbiError::AddressRange {
                                space,
                                offset: raw,
                                size: s,
                            }),
                            None,
                        ) => {
                            assert_eq!(
                                (space, raw, s),
                                (abi_space, offset as u64, size),
                                "{context}"
                            );
                        }
                        (other, want) => panic!("{context}: got {other:?}, expected {want:?}"),
                    }
                    checked += 1;
                }
            }
        }
    }
    assert!(checked > 3000, "{checked}");
}

#[test]
fn hand_derived_boundaries_for_java_long_negatives_and_extent_wrap() {
    let file = small_file();
    let pointer = stack_pointer("sp", "ram");
    let resolve = |storage: Storage| {
        resolve_storage(&file, Some(&pointer), &storage, None, AbiLimits::default())
            .map(|s| single(&s).address)
    };
    let ram = |offset| AbiAddress {
        space: AbiSpace::Language(RAM),
        offset,
    };
    let stack = |offset: i64| AbiAddress {
        space: AbiSpace::Stack,
        offset: offset as u64,
    };
    // 4-byte unsigned ram: accidental sign extension down to -2^32 is recovered.
    assert_eq!(
        resolve(address("ram", -4_i64 as u64, Some(4))).unwrap(),
        ram(0xffff_fffc)
    );
    assert_eq!(
        resolve(address("ram", -(1_i64 << 32) as u64, Some(1))).unwrap(),
        ram(0)
    );
    assert!(resolve(address("ram", (-(1_i64 << 32) - 1) as u64, None)).is_err());
    assert!(resolve(address("ram", 1 << 32, None)).is_err());
    // 4-byte signed stack.
    assert_eq!(
        resolve(address("stack", 0x7fff_ffff, Some(1))).unwrap(),
        stack(0x7fff_ffff)
    );
    assert!(resolve(address("stack", 0x7fff_ffff, Some(2))).is_err());
    assert_eq!(
        resolve(address("stack", 0x8000_0000, None)).unwrap(),
        stack(-0x8000_0000)
    );
    assert_eq!(
        resolve(address("stack", -1_i64 as u64, Some(2))).unwrap(),
        stack(-1)
    );
    assert_eq!(
        resolve(address("stack", 0xffff_fffc, Some(4))).unwrap(),
        stack(-4)
    );
    assert!(resolve(address("stack", -0x8000_0001_i64 as u64, None)).is_err());
    // 8-byte ram and 64-bit OTHER: an extent may end at u64::MAX but not wrap.
    let wide = Arc::new(
        RegisterFile::new(spaces(8), RAM, small_registers(), AbiLimits::default()).unwrap(),
    );
    let resolve_wide = |storage: Storage| {
        resolve_storage(&wide, None, &storage, None, AbiLimits::default())
            .map(|s| single(&s).address)
    };
    assert_eq!(
        resolve_wide(address("ram", u64::MAX, Some(1))).unwrap(),
        ram(u64::MAX)
    );
    assert!(resolve_wide(address("ram", u64::MAX, Some(2))).is_err());
    assert_eq!(
        resolve_wide(address("stack", i64::MAX as u64, Some(1))).unwrap(),
        stack(i64::MAX)
    );
    assert!(resolve_wide(address("stack", i64::MAX as u64, Some(2))).is_err());
    assert_eq!(
        resolve_wide(address("stack", i64::MIN as u64, Some(8))).unwrap(),
        stack(i64::MIN)
    );
    assert_eq!(
        resolve_wide(address("OTHER", u64::MAX - 3, Some(4))).unwrap(),
        AbiAddress {
            space: AbiSpace::Other,
            offset: u64::MAX - 3
        }
    );
    assert!(resolve_wide(address("OTHER", u64::MAX - 3, Some(5))).is_err());
}

fn stack_pointer(register: &str, space: &str) -> StackPointer {
    StackPointer {
        register: register.into(),
        space: space.into(),
        growth: StackGrowth::Negative,
        reverse_justify: false,
        line: 0,
    }
}

fn stack_of(file: &Arc<RegisterFile>, pointer: &str) -> Result<StackProperties, AbiError> {
    let text = format!(
        r#"<compiler_spec>{pointer}<default_proto><prototype name="p" extrapop="0" stackshift="0">
        <input/><output/></prototype></default_proto></compiler_spec>"#
    );
    storage(parse(&text), file, AbiLimits::default()).map(|s| s.stack().clone())
}

#[test]
fn stack_geometry_uses_pointer_minimum_width_backing_units_and_fallback() {
    let file = small_file();
    let id = |n| file.register_id(n);
    // No stack pointer: the default space supplies width and unit.
    assert_eq!(
        stack_of(&file, "").unwrap(),
        StackProperties {
            pointer: None,
            backing_space: AbiSpace::Language(RAM),
            address_size: 4,
            word_size: 1,
            growth: StackGrowth::Negative,
            reverse_justify: false,
        }
    );
    // min(pointer width, backing width).
    for (name, width) in [("sp16", 2), ("sp", 4), ("sp64", 4)] {
        let stack = stack_of(
            &file,
            &format!(r#"<stackpointer register="{name}" space="ram"/>"#),
        )
        .unwrap();
        assert_eq!(
            (stack.pointer, stack.address_size),
            (id(name), width),
            "{name}"
        );
    }
    let positive = stack_of(
        &file,
        r#"<stackpointer register="SP" space="ram" growth="positive" reversejustify="true"/>"#,
    )
    .unwrap();
    assert_eq!(positive.pointer, id("sp"));
    assert_eq!(
        (positive.growth, positive.reverse_justify),
        (StackGrowth::Positive, true)
    );
    // OTHER is a 64-bit compiler space distinct from every language ID.
    let other = stack_of(&file, r#"<stackpointer register="sp64" space="OTHER"/>"#).unwrap();
    assert_eq!(
        (other.backing_space, other.address_size),
        (AbiSpace::Other, 8)
    );
    assert!(matches!(
        at_root(stack_of(&file, r#"<stackpointer register="nope" space="ram"/>"#)),
        AbiError::UnknownRegister(name) if name == "nope"
    ));
    assert!(matches!(
        at_root(stack_of(&file, r#"<stackpointer register="sp" space="nope"/>"#)),
        AbiError::UnknownSpace(name) if name == "nope"
    ));

    // A 16-bit stack from a narrow pointer.
    let pointer = stack_pointer("sp16", "ram");
    let resolve = |offset: u64, size| {
        resolve_storage(
            &file,
            Some(&pointer),
            &address("stack", offset, size),
            None,
            AbiLimits::default(),
        )
        .map(|s| single(&s).address.signed_stack_offset().unwrap())
    };
    assert_eq!(resolve(0x7fff, Some(1)).unwrap(), 0x7fff);
    assert!(resolve(0x7fff, Some(2)).is_err());
    assert_eq!(resolve(0x8000, None).unwrap(), -0x8000);
    assert_eq!(resolve(0xffff, None).unwrap(), -1);
    assert_eq!(resolve(-0x8000_i64 as u64, None).unwrap(), -0x8000);
    assert!(resolve(0x1_0000, None).is_err());
    assert!(resolve(-0x8001_i64 as u64, None).is_err());

    // Word-addressed backing: 2-byte addresses of 2-byte words span 2^17 bytes.
    let words = Arc::new(
        RegisterFile::new(
            vec![
                space(1, "ram", SpaceKind::Ram, 2, 2),
                space(2, "register", SpaceKind::Register, 2, 1),
            ],
            RAM,
            vec![register("sp", REGISTER, 0, 2)],
            AbiLimits::default(),
        )
        .unwrap(),
    );
    let pointer = stack_pointer("sp", "ram");
    let resolve = |offset: u64, size| {
        resolve_storage(
            &words,
            Some(&pointer),
            &address("stack", offset, size),
            None,
            AbiLimits::default(),
        )
        .map(|s| single(&s).address.signed_stack_offset().unwrap())
    };
    assert_eq!(
        stack_of(&words, r#"<stackpointer register="sp" space="ram"/>"#)
            .unwrap()
            .word_size,
        2
    );
    assert_eq!(resolve(0xffff, Some(1)).unwrap(), 0xffff);
    assert!(resolve(0xffff, Some(2)).is_err());
    assert_eq!(resolve(0x1_0000, None).unwrap(), -0x1_0000);
    assert_eq!(resolve(0x1_ffff, None).unwrap(), -1);
    assert!(resolve(0x2_0000, None).is_err());
}

fn at_root(result: Result<StackProperties, AbiError>) -> AbiError {
    match result {
        Err(AbiError::At { source, .. }) => *source,
        Err(other) => other,
        Ok(stack) => panic!("unexpected success {stack:?}"),
    }
}

#[test]
fn stack_domains_beyond_64_byte_address_bits_are_rejected() {
    // An 8-byte address of 2-byte words cannot be a byte-addressed stack.
    let file = Arc::new(
        RegisterFile::new(
            vec![
                space(1, "ram", SpaceKind::Ram, 8, 2),
                space(2, "register", SpaceKind::Register, 8, 1),
            ],
            RAM,
            vec![
                register("sp", REGISTER, 0, 4),
                register("sp64", REGISTER, 8, 8),
            ],
            AbiLimits::default(),
        )
        .unwrap(),
    );
    for pointer in ["", r#"<stackpointer register="sp64" space="ram"/>"#] {
        assert!(matches!(
            stack_of(&file, pointer),
            Err(AbiError::InvalidStorage(
                "stack exceeds the 64-bit byte-address domain"
            ))
        ));
    }
    // A 4-byte pointer narrows the stack to 2^32 words, which fits.
    let narrow = stack_of(&file, r#"<stackpointer register="sp" space="ram"/>"#).unwrap();
    assert_eq!((narrow.address_size, narrow.word_size), (4, 2));
}

/// Reported divergence: Ghidra's `AbstractAddressSpace` rejects unit sizes
/// outside 1..=8 and spaces wider than 2^64 bytes. `RegisterFile` currently
/// accepts them and caps the byte domain at 2^64. This test pins the current
/// behavior so a fix is a deliberate, visible change.
#[test]
fn divergence_oversized_word_domains_are_capped_rather_than_rejected() {
    let build = |address_size, word_size, offset| {
        RegisterFile::new(
            vec![
                space(1, "ram", SpaceKind::Ram, 4, 1),
                space(2, "register", SpaceKind::Register, address_size, word_size),
            ],
            RAM,
            vec![register("x", REGISTER, offset, 1)],
            AbiLimits::default(),
        )
    };
    // Each of these spaces would throw in Ghidra's constructor.
    for (address_size, word_size) in [(8_u8, 2_u32), (4, 16), (1, u32::MAX)] {
        assert!(
            build(address_size, word_size, 0).is_ok(),
            "a{address_size} w{word_size}"
        );
    }
    // 2^64 addresses of 2-byte words is capped to a 2^64-byte domain.
    assert!(build(8, 2, u64::MAX).is_ok());
}

#[test]
fn special_spaces_default_sizes_and_invalid_declarations() {
    let file = small_file();
    let resolve = |storage: Storage, default| {
        resolve_storage(&file, None, &storage, default, AbiLimits::default())
    };
    // Numeric locations in register space carry no register identity.
    let range = resolve(varnode("register", 0, 8), None).unwrap();
    assert_eq!(single(&range).address.space, AbiSpace::Language(REGISTER));
    assert_eq!(single(&range).register, None);
    // Constant-space literals are values, not extents.
    let literal = resolve(varnode("const", u64::MAX, 8), None).unwrap();
    assert_eq!(single(&literal).address.offset, u64::MAX);
    assert!(matches!(
        resolve(address("join", 0, Some(4)), None),
        Err(AbiError::InvalidStorage(_))
    ));
    assert!(matches!(
        resolve(varnode("ram", 0, 0), None),
        Err(AbiError::InvalidStorage("zero-sized varnode"))
    ));
    // An unsized address takes a genuine default size, which is extent-checked.
    assert_eq!(
        resolve(address("ram", 0, None), Some(4)).unwrap().size(),
        Some(4)
    );
    assert_eq!(
        resolve(address("ram", 0, Some(0)), None).unwrap().size(),
        None
    );
    assert_eq!(
        resolve(address("ram", 0, Some(0)), Some(2)).unwrap().size(),
        Some(2)
    );
    assert_eq!(
        resolve(address("ram", 0, Some(1)), Some(8)).unwrap().size(),
        Some(1)
    );
    assert!(resolve(address("ram", 0xffff_fffe, None), Some(4)).is_err());
    assert!(matches!(
        resolve(address("ram", 0, None), Some(0)),
        Err(AbiError::InvalidStorage("zero default size"))
    ));
    // Register names resolve case-variantly; numeric spaces are exact.
    let named = resolve(Storage::Register { name: "D0".into() }, None).unwrap();
    assert_eq!(single(&named).register, file.register_id("d0"));
    assert_eq!(named.size(), Some(8));
    assert!(
        matches!(resolve(address("RAM", 0, None), None), Err(AbiError::UnknownSpace(n)) if n == "RAM")
    );
    // Error labels keep at most 64 UTF-8 bytes on a character boundary.
    let long = format!("a{}", "é".repeat(40));
    let Err(AbiError::UnknownRegister(label)) =
        resolve(Storage::Register { name: long.clone() }, None)
    else {
        panic!()
    };
    assert_eq!(label, format!("a{}…", "é".repeat(31)));
    assert!(long.starts_with(label.trim_end_matches('…')));
    let short = "x".repeat(64);
    let Err(AbiError::UnknownSpace(label)) = resolve(address(&short, 0, None), None) else {
        panic!()
    };
    assert_eq!(label, short);
    let ResolvedStorage::Single(_) = resolve(address("OTHER", 0, None), None).unwrap() else {
        panic!()
    };
}

/// The smallest passing value of one budget, found by bisection, so its exact
/// size and one below can both be checked without replaying the charge rules.
fn threshold(run: impl Fn(u64) -> bool, high: u64) -> u64 {
    assert!(run(high));
    let (mut low, mut high) = (0, high);
    while low < high {
        let middle = low + (high - low) / 2;
        if run(middle) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    low
}

#[test]
fn standalone_resolution_budgets_have_exact_boundaries() {
    let file = small_file();
    let pointer = stack_pointer("sp", "ram");
    let declaration = Storage::Join {
        pieces: vec![
            ghidra_languages::JoinPiece::Register { name: "r1".into() },
            ghidra_languages::JoinPiece::Varnode {
                space: "stack".into(),
                offset: 8,
                size: 4,
            },
        ],
        logical_size: None,
    };
    let run =
        |limits: AbiLimits| resolve_storage(&file, Some(&pointer), &declaration, None, limits);
    let work = threshold(
        |w| {
            run(AbiLimits {
                max_work: w,
                ..Default::default()
            })
            .is_ok()
        },
        10_000,
    );
    is_limit(
        run(AbiLimits {
            max_work: work - 1,
            ..Default::default()
        }),
        "work",
    );
    let names = threshold(
        |n| {
            run(AbiLimits {
                max_name_bytes: n as usize,
                ..Default::default()
            })
            .is_ok()
        },
        10_000,
    ) as usize;
    is_limit(
        run(AbiLimits {
            max_name_bytes: names - 1,
            ..Default::default()
        }),
        "name bytes",
    );
    // Names visited: sp, ram, r1, stack. Charging stays proportional.
    assert!((10..=60).contains(&names), "{names}");
    assert!(work >= names as u64 && work < 1_000, "{work}");
    // Name length: "stack" is the longest name here.
    run(AbiLimits {
        max_name_length: 5,
        ..Default::default()
    })
    .unwrap();
    is_limit(
        run(AbiLimits {
            max_name_length: 4,
            ..Default::default()
        }),
        "name length",
    );
    // Two pieces at exact join/total piece budgets.
    let exact = AbiLimits {
        max_join_pieces: 2,
        max_total_pieces: 2,
        ..Default::default()
    };
    run(exact).unwrap();
    is_limit(
        run(AbiLimits {
            max_join_pieces: 1,
            ..exact
        }),
        "join pieces",
    );
    is_limit(
        run(AbiLimits {
            max_total_pieces: 1,
            ..exact
        }),
        "storage pieces",
    );
}
