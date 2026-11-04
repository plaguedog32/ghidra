use std::collections::BTreeMap;

use ghidra_pcode::{Opcode, Value, machine::Machine};
use ghidra_sleigh::{Error, SleighLanguage};

fn compile(text: &str) -> Result<SleighLanguage, Error> {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("word.slaspec");
    std::fs::write(&source, text).unwrap();
    SleighLanguage::from_spec(&source, &BTreeMap::new())
}

fn source(word: u32, big: bool) -> String {
    let order = if big { "big" } else { "little" };
    let first = word * 128;
    let last = word * 256 - 1;
    format!(
        r#"
define endian={order};
define space ram type=ram_space size=2 default;
define space register type=register_space size=2;
define space csr type=ram_space size=1 wordsize={word};
define register offset=0 size=2 [ r0 ];
define register offset=4 size=1 [ p ];
define csr offset={first} size=2 [ cell cell_next ];
define csr offset={last} size=1 [ last ];
define csr offset={last} size=2 [ bad ];
define bitrange low=r0[2,3];
define token encoding(8) op=(0,7);
operand: is op {{ export *[csr]:2 128:1; }}
:fixed_read is op=1 {{ r0 = cell; }}
:fixed_write is op=2 {{ cell = r0; }}
:indirect_read is op=3 {{ r0 = *[csr]:2 p; }}
:indirect_write is op=4 {{ *[csr]:2 p = r0; }}
:export_read is op=5 & operand {{ r0 = operand; }}
:export_write is op=6 & operand {{ operand = r0; }}
:word_address is op=7 {{ p = &:1 cell; }}
:byte_address is op=8 {{ p = &:1 p; }}
:last_read is op=9 {{ p = last; }}
:outside_read is op=10 {{ r0 = bad; }}
:bits is op=11 {{ p = zext(low); }}
"#
    )
}

fn set(machine: &mut Machine, language: &SleighLanguage, name: &str, value: u64) {
    let register = language.register(name).unwrap();
    machine
        .write_varnode(&register, &Value::from_u64(register.size, value).unwrap())
        .unwrap();
}

fn get(machine: &Machine, language: &SleighLanguage, name: &str) -> u64 {
    machine
        .read_varnode(&language.register(name).unwrap())
        .unwrap()
        .to_u64()
        .unwrap()
}

#[test]
fn declared_offsets_are_bytes_and_memory_pointers_scale_exactly_once() {
    for word in 1..=8 {
        for big in [false, true] {
            let mut language = compile(&source(word, big)).unwrap();
            let space = language
                .spaces()
                .iter()
                .find(|space| space.name == "csr")
                .unwrap();
            assert_eq!(space.word_size, word);
            let csr = space.id;
            let first = u64::from(word * 128);
            assert_eq!(language.register("cell").unwrap().offset, first);
            assert_eq!(language.register("cell_next").unwrap().offset, first + 2);
            let mut machine = Machine::new(language.spaces().to_vec(), 65536).unwrap();
            let code = language.code_space();
            let expected = if big { 0x8123 } else { 0x2381 };
            for op in [1, 3, 5] {
                machine.map_bytes(csr, first, &[0x81, 0x23]).unwrap();
                set(&mut machine, &language, "p", 128);
                let instruction = language.decode(0x1000, &[op]).unwrap();
                if op == 1 {
                    assert!(instruction.instruction.ops.iter().any(|op| {
                        op.opcode == Opcode::Copy
                            && op
                                .inputs
                                .iter()
                                .any(|input| input.space == csr && input.offset == first)
                    }));
                } else {
                    let load = instruction
                        .instruction
                        .ops
                        .iter()
                        .find(|op| op.opcode == Opcode::Load)
                        .unwrap();
                    assert_eq!(load.inputs[1].size, 1);
                }
                machine
                    .run(&[instruction.instruction], code, 0x1000, 100)
                    .unwrap();
                assert_eq!(
                    get(&machine, &language, "r0"),
                    expected,
                    "word={word}, big={big}, op={op}"
                );
            }
            for op in [2, 4, 6] {
                set(&mut machine, &language, "r0", 0x5678);
                set(&mut machine, &language, "p", 128);
                let instruction = language.decode(0x1000, &[op]).unwrap();
                machine
                    .run(&[instruction.instruction], code, 0x1000, 100)
                    .unwrap();
                for (index, expected) in if big { [0x56, 0x78] } else { [0x78, 0x56] }
                    .into_iter()
                    .enumerate()
                {
                    let byte = ghidra_pcode::Varnode {
                        space: csr,
                        offset: first + index as u64,
                        size: 1,
                    };
                    assert_eq!(
                        machine.read_varnode(&byte).unwrap().to_u64(),
                        Some(expected)
                    );
                }
            }
            // The custom lowering context must preserve register bit-range facts.
            set(&mut machine, &language, "r0", 0b10100);
            let bits = language.decode(0x1000, &[11]).unwrap();
            machine.run(&[bits.instruction], code, 0x1000, 100).unwrap();
            assert_eq!(get(&machine, &language, "p"), 5, "word={word}, big={big}");
        }
    }
}

#[test]
fn byte_domain_includes_the_final_word_and_refuses_the_next_byte() {
    for word in [2, 3, 4, 8] {
        let mut language = compile(&source(word, false)).unwrap();
        let csr = language
            .spaces()
            .iter()
            .find(|space| space.name == "csr")
            .unwrap()
            .id;
        let last = u64::from(word * 256 - 1);
        let register = language.register_metadata("last").unwrap().unwrap();
        assert_eq!((register.offset, register.size), (last, 1));
        assert!(matches!(
            language.register_metadata("bad"),
            Err(Error::AddressOverflow)
        ));
        let mut machine = Machine::new(language.spaces().to_vec(), 65536).unwrap();
        machine.map_bytes(csr, last, &[0xab]).unwrap();
        assert!(machine.map_bytes(csr, last + 1, &[0]).is_err());
        let instruction = language.decode(0x1000, &[9]).unwrap();
        machine
            .run(
                &[instruction.instruction],
                language.code_space(),
                0x1000,
                100,
            )
            .unwrap();
        assert_eq!(get(&machine, &language, "p"), 0xab);
        assert!(matches!(
            language.decode(0x1000, &[10]),
            Err(Error::AddressOverflow)
        ));
    }
}

#[test]
fn incorrect_address_of_word_storage_is_refused_per_instruction() {
    let mut language = compile(&source(4, false)).unwrap();
    assert!(
        matches!(language.decode(0x1000, &[7]), Err(Error::Unsupported(message)) if message.contains("address-of word-space"))
    );
    // Refusing one instruction neither poisons the language nor rejects
    // address-of a byte-addressed register in that same language.
    assert!(language.decode(0x1000, &[1]).is_ok());
    let mut machine = Machine::new(language.spaces().to_vec(), 65536).unwrap();
    let instruction = language.decode(0x1000, &[8]).unwrap();
    machine
        .run(
            &[instruction.instruction],
            language.code_space(),
            0x1000,
            100,
        )
        .unwrap();
    assert_eq!(get(&machine, &language, "p"), 4);
}

#[test]
fn invalid_or_unrepresentable_space_dimensions_are_explicit_errors() {
    for (width, word) in [(1, 0), (1, 9), (8, 2)] {
        let source = format!(
            "define endian=little; define space ram type=ram_space size=2 default; define space data type=ram_space size={width} wordsize={word}; define token encoding(8) op=(0,7); :nop is op=0 {{ }}"
        );
        assert!(
            matches!(compile(&source), Err(Error::Unsupported(_))),
            "width={width}, word={word}"
        );
    }
    let source = "define endian=little; define space ram type=ram_space size=2 wordsize=2 default; define token encoding(8) op=(0,7); :nop is op=0 { }";
    assert!(
        matches!(compile(source), Err(Error::Unsupported(message)) if message.contains("instruction addresses"))
    );
}

#[test]
fn address_of_guard_visits_memory_control_flow_ranges_and_userop_arguments() {
    for body in [
        "p = *[csr]:1 (&:1 cell);",
        "*[csr]:1 (&:1 cell) = p;",
        "r0[0,8] = &:1 cell;",
        "goto [zext(&:1 cell)];",
        "call [zext(&:1 cell)];",
        "return [zext(&:1 cell)];",
        "if ((&:1 cell) == 0) goto <done>; <done>",
        "sink(zext(&:1 cell));",
    ] {
        let source = format!(
            "{}\ndefine pcodeop sink;\n:bad_address is op=12 {{ {body} }}",
            source(4, false)
        );
        let mut language = compile(&source).unwrap();
        assert!(
            matches!(language.decode(0x1000, &[12]), Err(Error::Unsupported(message)) if message.contains("address-of word-space")),
            "{body}"
        );
    }
}
