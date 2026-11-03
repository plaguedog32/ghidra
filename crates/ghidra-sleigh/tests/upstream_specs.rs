//! Explicit probes against this checkout's retained upstream specifications.
//! Opt-in because compiling full processor sources is more expensive than the
//! small, always-on fixtures. A passing probe is not processor-wide parity.

use std::{collections::BTreeMap, path::PathBuf};

use ghidra_pcode::{Endianness, Opcode};
use ghidra_sleigh::SleighLanguage;

fn spec(processor: &str, name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../Ghidra/Processors")
        .join(processor)
        .join("data/languages")
        .join(name)
}

#[test]
#[ignore = "compiles the full retained x86-64 SLEIGH specification"]
fn upstream_x86_64_source_compiles_and_lifts() {
    let context = BTreeMap::from([
        ("longMode".into(), 1),
        ("addrsize".into(), 2),
        ("opsize".into(), 1),
    ]);
    let mut language = SleighLanguage::from_spec(&spec("x86", "x86-64.slaspec"), &context).unwrap();
    for bytes in [
        &[0x48, 0x89, 0xd8][..],
        &[0x48, 0x01, 0xd8][..],
        &[0x75, 2][..],
        &[0xc3][..],
    ] {
        let instruction = language.decode(0x1000, bytes).unwrap();
        assert_eq!(instruction.length as usize, bytes.len());
        assert!(!instruction.instruction.ops.is_empty());
    }
    assert_eq!(language.register("RAX").unwrap().size, 8);
    assert_eq!(
        language.register("EAX").unwrap().offset,
        language.register("RAX").unwrap().offset
    );
}

fn arm(big: bool) {
    let context = BTreeMap::from([("TMode".into(), 0)]);
    let mut language = SleighLanguage::from_spec(
        &spec(
            "ARM",
            if big {
                "ARM7_be.slaspec"
            } else {
                "ARM7_le.slaspec"
            },
        ),
        &context,
    )
    .unwrap();
    let bytes = if big {
        [0xe0, 0x81, 0x10, 0x01]
    } else {
        [0x01, 0x10, 0x81, 0xe0]
    };
    let instruction = language.decode(0x1000, &bytes).unwrap();
    assert_eq!(instruction.length, 4);
    assert!(
        instruction
            .instruction
            .ops
            .iter()
            .any(|operation| operation.opcode == Opcode::IntAdd)
    );
    let endian = if big {
        Endianness::Big
    } else {
        Endianness::Little
    };
    assert!(
        language
            .spaces()
            .iter()
            .all(|space| space.endianness == endian)
    );
}

#[test]
#[ignore = "compiles the full retained ARM7 little-endian specification"]
fn upstream_arm7_little_endian_source_compiles_and_lifts() {
    arm(false);
}

#[test]
#[ignore = "compiles the full retained ARM7 big-endian specification"]
fn upstream_arm7_big_endian_source_compiles_and_lifts() {
    arm(true);
}

fn mips(big: bool) {
    let context = BTreeMap::from([("RELP".into(), 1), ("PAIR_INSTRUCTION_FLAG".into(), 0)]);
    let mut language = SleighLanguage::from_spec(
        &spec(
            "MIPS",
            if big {
                "mips32be.slaspec"
            } else {
                "mips32le.slaspec"
            },
        ),
        &context,
    )
    .unwrap();
    let lui = if big {
        [0x3c, 0x1c, 0, 2]
    } else {
        [2, 0, 0x1c, 0x3c]
    };
    let instruction = language.decode(0x1000, &lui).unwrap();
    assert_eq!(instruction.length, 4);
    assert!(!instruction.instruction.ops.is_empty());
    let jr = if big {
        [3, 0xe0, 0, 8, 0, 0, 0, 0]
    } else {
        [8, 0, 0xe0, 3, 0, 0, 0, 0]
    };
    let instruction = language.decode(0x1004, &jr).unwrap();
    assert_eq!(instruction.length, 4);
    assert_eq!(instruction.next_address, 0x100c);
    assert_eq!(instruction.instruction.length, 8);
    assert_eq!(instruction.delay_slots.len(), 1);
}

#[test]
#[ignore = "compiles the full retained MIPS32 little-endian specification"]
fn upstream_mips32_little_endian_source_compiles_and_lifts() {
    mips(false);
}

#[test]
#[ignore = "compiles the full retained MIPS32 big-endian specification"]
fn upstream_mips32_big_endian_source_compiles_and_lifts() {
    mips(true);
}
