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
#[ignore = "compiles the retained SH-2A source including its wide bank declaration"]
fn upstream_sh2a_wide_metadata_and_ordinary_instruction_lifting_coexist() {
    let mut language = language("SuperH:BE:32:SH-2A");
    let bank = language.register_metadata("resbank_base").unwrap().unwrap();
    assert_eq!((bank.offset, bank.size), (0x10000, 40960));
    assert!(language.registers().unwrap().contains(&bank));
    assert!(language.register("resbank_base").is_none());
    assert!(language.register("r0").is_some());
    let nop = language.decode(0x1000, &[0x00, 0x09]).unwrap();
    assert_eq!(nop.length, 2);
    assert!(
        nop.text.to_ascii_lowercase().starts_with("nop"),
        "{}",
        nop.text
    );
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
    assert_eq!(language.source_endianness(), Endianness::Little);
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

#[test]
#[ignore = "compiles the full retained AArch64 big-data/little-token specification"]
fn upstream_aarch64_big_data_little_instruction_tokens_execute() {
    let mut language = language("AARCH64:BE:64:v8A");
    assert_eq!(language.source_endianness(), Endianness::Big);
    let mov = language.decode(0x1000, &[0x20, 0x00, 0x80, 0xd2]).unwrap();
    assert!(mov.text.contains("mov"));
    let mut machine = Machine::new(language.spaces().to_vec(), 65536).unwrap();
    machine
        .run(&[mov.instruction], language.code_space(), 0x1000, 1000)
        .unwrap();
    let x0 = language.register("x0").unwrap();
    assert_eq!(machine.read_varnode(&x0).unwrap().to_u64(), Some(1));
    let load = language.decode(0x1004, &[0x20, 0x00, 0x40, 0xf9]).unwrap();
    machine
        .write_varnode(
            &language.register("x1").unwrap(),
            &Value::from_u64(8, 0x2000).unwrap(),
        )
        .unwrap();
    machine
        .map_bytes(
            language.code_space(),
            0x2000,
            &[0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0],
        )
        .unwrap();
    machine
        .run(&[load.instruction], language.code_space(), 0x1004, 1000)
        .unwrap();
    assert_eq!(
        machine.read_varnode(&x0).unwrap().to_u64(),
        Some(0x123456789abcdef0)
    );
}
