//! Explicit probes against this checkout's retained upstream specifications.
//! Opt-in because compiling full processor sources is more expensive than the
//! small, always-on fixtures. A passing probe is not processor-wide parity.

use std::{collections::BTreeMap, path::PathBuf};

use ghidra_pcode::{Endianness, Opcode, Value, machine::Machine};
use ghidra_sleigh::SleighLanguage;

fn language(id: &str) -> SleighLanguage {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../Ghidra/Processors");
    let catalog = ghidra_languages::Catalog::discover(&root).unwrap();
    SleighLanguage::from_language(catalog.by_id(id).unwrap(), &BTreeMap::new()).unwrap()
}

#[test]
#[ignore = "compiles the full retained x86-64 SLEIGH specification"]
fn upstream_x86_64_source_compiles_and_lifts() {
    let mut language = language("x86:LE:64:default");
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
    let mut language = language(if big { "ARM:BE:32:v7" } else { "ARM:LE:32:v7" });
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
    let mut language = language(if big {
        "MIPS:BE:32:default"
    } else {
        "MIPS:LE:32:default"
    });
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

#[test]
#[ignore = "compiles the full retained ARM7 mixed-endian specification"]
fn upstream_arm7_little_instructions_big_data_load_executes() {
    let mut language = language("ARM:LEBE:32:v7LEInstruction");
    assert_eq!(language.instruction_endianness(), Endianness::Little);
    let lifted = language.decode(0x1000, &[0x00, 0x00, 0x91, 0xe5]).unwrap();
    let mut machine = Machine::new(language.spaces().to_vec(), 65536).unwrap();
    for register in language.registers().unwrap() {
        let storage = ghidra_pcode::Varnode {
            space: register.space,
            offset: register.offset,
            size: register.size,
        };
        machine
            .write_varnode(&storage, &Value::from_u64(storage.size, 0).unwrap())
            .unwrap();
    }
    machine
        .write_varnode(
            &language.register("r1").unwrap(),
            &Value::from_u64(4, 0x2000).unwrap(),
        )
        .unwrap();
    machine
        .map_bytes(language.code_space(), 0x2000, &[0x12, 0x34, 0x56, 0x78])
        .unwrap();
    machine
        .run(&[lifted.instruction], language.code_space(), 0x1000, 1000)
        .unwrap();
    assert_eq!(
        machine
            .read_varnode(&language.register("r0").unwrap())
            .unwrap()
            .to_u64(),
        Some(0x12345678)
    );
}
