//! Explicit probes against this checkout's retained upstream specifications.
//! Opt-in because compiling full processor sources is more expensive than the
//! small, always-on fixtures. A passing probe is not processor-wide parity.

use std::{collections::BTreeMap, path::PathBuf};

use ghidra_pcode::{Endianness, Opcode, Value, machine::Machine};
use ghidra_sleigh::{Error, SleighLanguage};

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

/// Encode the canonical A32 word, or the two Thumb halfwords in fetch order.
/// Thumb's little-endian token fields swap halfwords in ARMinstructions.sinc.
fn arm8_bytes(word: u32, thumb: bool, big: bool) -> [u8; 4] {
    if big {
        word.to_be_bytes()
    } else if thumb {
        word.rotate_left(16).to_le_bytes()
    } else {
        word.to_le_bytes()
    }
}

fn arm8_set(machine: &mut Machine, language: &SleighLanguage, name: &str, value: u64) {
    let register = language.register(name).unwrap();
    machine
        .write_varnode(&register, &Value::from_u64(register.size, value).unwrap())
        .unwrap();
}

fn arm8_get(machine: &Machine, language: &SleighLanguage, name: &str) -> u64 {
    machine
        .read_varnode(&language.register(name).unwrap())
        .unwrap()
        .to_u64()
        .unwrap()
}

#[test]
#[ignore = "compiles all seven retained ARM v8 catalog variants and executes selected semantics"]
fn upstream_arm8_catalog_modes_data_order_and_m_profile_guards_execute() {
    // Source-derived encodings: ARMv8.sinc LDA/LDAB, VSEL and VPNOT;
    // ARMinstructions.sinc A32/Thumb token fields; ARM.sinc VPR_P0.
    // A duplicate VERSION_8M guard previously left ARMv8.sinc unbalanced.
    // VSEL is after that block, so adding an endif at EOF is not a valid fix.
    for (id, thumb, instruction_big, data_big, m_profile) in [
        ("ARM:LE:32:v8", false, false, false, false),
        ("ARM:BE:32:v8", false, true, true, false),
        ("ARM:LEBE:32:v8LEInstruction", false, false, true, false),
        ("ARM:LE:32:v8T", true, false, false, false),
        ("ARM:BE:32:v8T", true, true, true, false),
        ("ARM:LE:32:v8-m", true, false, false, true),
        ("ARM:BE:32:v8-m", true, true, true, true),
    ] {
        let mut language = language(id);
        let code = language.code_space();
        let mut machine = Machine::new(language.spaces().to_vec(), 65536).unwrap();
        arm8_set(&mut machine, &language, "r1", 0x2000);
        machine
            .map_bytes(code, 0x2000, &[0x80, 0x23, 0x45, 0x67])
            .unwrap();
        for (word, mnemonic, expected) in [
            (
                if thumb { 0xe8d1_0faf } else { 0xe191_0c9f },
                "lda r0,[r1]",
                if data_big { 0x8023_4567 } else { 0x6745_2380 },
            ),
            (
                if thumb { 0xe8d1_0f8f } else { 0xe1d1_0c9f },
                "ldab r0,[r1]",
                0x80,
            ),
        ] {
            language.reset_context();
            let lifted = language
                .decode(0x1000, &arm8_bytes(word, thumb, instruction_big))
                .unwrap();
            assert_eq!(lifted.text, mnemonic, "{id}");
            assert_eq!((lifted.length, lifted.next_address), (4, 0x1004), "{id}");
            machine
                .run(&[lifted.instruction], code, 0x1000, 1000)
                .unwrap();
            assert_eq!(arm8_get(&machine, &language, "r0"), expected, "{id}");
        }

        // This non-M instruction must remain outside the repaired M guard.
        language.reset_context();
        let select = language
            .decode(0x1000, &arm8_bytes(0xfe01_0a02, thumb, instruction_big))
            .unwrap();
        assert!(
            select.text.starts_with("vseleq.f32"),
            "{id}: {}",
            select.text
        );
        arm8_set(&mut machine, &language, "s2", 0x1122_3344);
        arm8_set(&mut machine, &language, "s4", 0x5566_7788);
        for (zero, expected) in [(0, 0x5566_7788), (1, 0x1122_3344)] {
            arm8_set(&mut machine, &language, "ZR", zero);
            machine
                .run(
                    std::slice::from_ref(&select.instruction),
                    code,
                    0x1000,
                    1000,
                )
                .unwrap();
            assert_eq!(arm8_get(&machine, &language, "s0"), expected, "{id}");
        }

        // VPNOT is inside the repaired guard. Inspect it in Thumb mode even
        // for the A32-default languages, so the negative test checks the ISA
        // feature gate rather than merely selecting a different instruction set.
        language.reset_context();
        let invert = language.decode_with_defaults(
            0x1000,
            &arm8_bytes(0xfe31_0f4d, true, instruction_big),
            &BTreeMap::from([("TMode".into(), 1)]),
        );
        if m_profile {
            let invert = invert.unwrap();
            assert_eq!(invert.text, "vpnot", "{id}");
            arm8_set(&mut machine, &language, "vpr", 0x1122_5678);
            machine
                .run(&[invert.instruction], code, 0x1000, 1000)
                .unwrap();
            assert_eq!(arm8_get(&machine, &language, "vpr"), 0x1122_a987, "{id}");
        } else {
            assert!(
                !matches!(invert, Ok(ref instruction) if instruction.text == "vpnot"),
                "{id}"
            );
        }
    }
}

#[test]
#[ignore = "compiles retained RV32/RV64 sources with word-addressed CSR storage"]
fn upstream_riscv_fixed_csr_registers_keep_byte_offsets() {
    // riscv.reg.sinc declares CSR names in bytes, stepping by XLEN.
    // riscv.csr.sinc gives the FRCSR/FRRM/FSCSR encodings and COPY semantics.
    for (id, width) in [("RISCV:LE:32:default", 4), ("RISCV:LE:64:default", 8)] {
        let mut language = language(id);
        let csr = language
            .spaces()
            .iter()
            .find(|space| space.name == "csreg")
            .unwrap();
        assert_eq!(csr.word_size, width);
        assert_eq!(
            language.register("fcsr").unwrap().offset,
            u64::from(3 * width)
        );
        assert_eq!(
            language.register("frm").unwrap().offset,
            u64::from(2 * width)
        );
        let code = language.code_space();
        let mut machine = Machine::new(language.spaces().to_vec(), 65536).unwrap();
        arm8_set(&mut machine, &language, "fcsr", 0x1234_5678);
        arm8_set(&mut machine, &language, "frm", 3);
        for (bytes, expected) in [
            ([0xf3, 0x22, 0x30, 0x00], 0x1234_5678),
            ([0xf3, 0x22, 0x20, 0x00], 3),
        ] {
            let instruction = language.decode(0x1000, &bytes).unwrap();
            machine
                .run(&[instruction.instruction], code, 0x1000, 100)
                .unwrap();
            assert_eq!(arm8_get(&machine, &language, "t0"), expected, "{id}");
        }
        arm8_set(&mut machine, &language, "t1", 0x8765_4321);
        let exchange = language.decode(0x1000, &[0xf3, 0x12, 0x33, 0x00]).unwrap();
        machine
            .run(&[exchange.instruction], code, 0x1000, 100)
            .unwrap();
        assert_eq!(arm8_get(&machine, &language, "t0"), 0x1234_5678);
        assert_eq!(arm8_get(&machine, &language, "fcsr"), 0x8765_4321);
        // Generic CSR exports still have a default-code-width pointer in the
        // dependency (4/8 bytes), rather than csreg's 2-byte pointer. Refuse it
        // explicitly instead of guessing how to narrow a dynamic expression.
        assert!(matches!(
            language.decode(0x1000, &[0xf3, 0x12, 0x03, 0x30]),
            Err(Error::Lower(_))
        ));
    }
}

#[test]
#[ignore = "compiles retained NDS32 source and executes word-addressed user-register storage"]
fn upstream_nds32_word_pointers_and_unaligned_fixed_registers_execute() {
    // nds32.sinc UsrName pfmc1 exports address0x201, not byte0x201.
    // ipc is separately DECLARED at byte0xa9; it is not word-aligned.
    let mut language = language("NDS32:BE:32:default");
    let csr = language
        .spaces()
        .iter()
        .find(|space| space.name == "csreg")
        .unwrap();
    assert_eq!(csr.word_size, 4);
    let csr = csr.id;
    let code = language.code_space();
    let ipc = language.register("ipc").unwrap();
    assert_eq!(ipc.offset, 0xa9);
    let mut machine = Machine::new(language.spaces().to_vec(), 65536).unwrap();
    machine
        .map_bytes(csr, 0x804, &[0x12, 0x34, 0x56, 0x78])
        .unwrap();
    let read = language.decode(0x1000, &[0x42, 0x00, 0x88, 0x20]).unwrap();
    assert_eq!(read.text, "mfusr a0, pfmc1");
    machine.run(&[read.instruction], code, 0x1000, 100).unwrap();
    assert_eq!(arm8_get(&machine, &language, "a0"), 0x1234_5678);
    arm8_set(&mut machine, &language, "a0", 0x8765_4321);
    let write = language.decode(0x1000, &[0x42, 0x00, 0x88, 0x21]).unwrap();
    machine
        .run(&[write.instruction], code, 0x1000, 100)
        .unwrap();
    let stored = ghidra_pcode::Varnode {
        space: csr,
        offset: 0x804,
        size: 4,
    };
    assert_eq!(
        machine.read_varnode(&stored).unwrap().to_u64(),
        Some(0x8765_4321)
    );
    arm8_set(&mut machine, &language, "ipc", 0x2000);
    let ret = language.decode(0x1000, &[0x64, 0x00, 0x00, 0x04]).unwrap();
    let report = machine.run(&[ret.instruction], code, 0x1000, 100).unwrap();
    assert!(
        matches!(report.stop, ghidra_pcode::machine::StopReason::ExternalTransfer { target: 0x2000, ref kind } if kind == "return")
    );
}
