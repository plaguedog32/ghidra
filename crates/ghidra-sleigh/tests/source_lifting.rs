use std::{collections::BTreeMap, path::PathBuf};

use ghidra_pcode::machine::Machine;
use ghidra_pcode::{Endianness, Opcode, SpaceKind, Value};
use ghidra_sleigh::{Error, SleighLanguage};

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn raw_source_and_include_compile_into_pcode_that_executes_in_rust() {
    let mut language =
        SleighLanguage::from_spec(&fixture("tiny.slaspec"), &BTreeMap::new()).unwrap();
    let r0 = language.register("r0").unwrap();
    let r1 = language.register("r1").unwrap();
    let increment = language.decode(0x1000, &[1]).unwrap();
    let copy = language.decode(0x1001, &[2]).unwrap();
    assert_eq!(increment.text, "inc");
    assert_eq!(increment.length, 1);
    assert_eq!(increment.next_address, 0x1001);
    assert!(
        increment
            .instruction
            .ops
            .iter()
            .any(|operation| operation.opcode == Opcode::IntAdd)
    );
    let mut machine = Machine::new(language.spaces().to_vec(), 65536).unwrap();
    machine
        .write_varnode(&r0, &Value::from_u64(4, 9).unwrap())
        .unwrap();
    machine
        .run(
            &[increment.instruction, copy.instruction],
            language.code_space(),
            0x1000,
            100,
        )
        .unwrap();
    assert_eq!(
        machine.read_varnode(&r1).unwrap(),
        Value::from_u64(4, 10).unwrap()
    );
}

#[test]
fn address_defaults_do_not_leak_or_overwrite_committed_context() {
    let mut language =
        SleighLanguage::from_spec(&fixture("tiny.slaspec"), &BTreeMap::new()).unwrap();
    let phase_one = BTreeMap::from([("phase".into(), 1)]);
    assert_eq!(
        language
            .decode_with_defaults(0x1000, &[6], &phase_one)
            .unwrap()
            .text,
        "mode"
    );
    assert_eq!(language.decode(0x1000, &[6]).unwrap().text, "base");
    assert_eq!(language.decode(0x1000, &[5]).unwrap().context_commits, 1);
    let phase_zero = BTreeMap::from([("phase".into(), 0)]);
    assert_eq!(
        language
            .decode_with_defaults(0x1001, &[6], &phase_zero)
            .unwrap()
            .text,
        "mode"
    );
    assert!(
        language
            .decode_with_defaults(0x1001, &[6], &BTreeMap::from([("phase".into(), 2)]))
            .is_err()
    );
    assert_eq!(language.decode(0x1001, &[6]).unwrap().text, "mode");
    language.reset_context();
    assert_eq!(language.decode(0x1001, &[6]).unwrap().text, "base");
}

#[test]
fn memory_space_and_userop_identifiers_are_preserved() {
    let mut language =
        SleighLanguage::from_spec(&fixture("tiny.slaspec"), &BTreeMap::new()).unwrap();
    let load = language.decode(0x1000, &[3]).unwrap();
    let operation = load
        .instruction
        .ops
        .iter()
        .find(|operation| operation.opcode == Opcode::Load)
        .unwrap();
    assert_eq!(
        operation.inputs[0].offset,
        u64::from(language.code_space().0)
    );
    let constant = language
        .spaces()
        .iter()
        .find(|space| space.kind == SpaceKind::Constant)
        .unwrap();
    assert_eq!(operation.inputs[0].space, constant.id);
    let user = language.decode(0x1001, &[4]).unwrap();
    let operation = user
        .instruction
        .ops
        .iter()
        .find(|operation| operation.opcode == Opcode::Callother)
        .unwrap();
    assert_eq!(
        language.userops()[operation.inputs[0].offset as usize],
        "custom"
    );
}

#[test]
fn context_commits_apply_at_addresses_and_reset_to_the_supplied_default() {
    let mut language =
        SleighLanguage::from_spec(&fixture("tiny.slaspec"), &BTreeMap::new()).unwrap();
    assert_eq!(language.decode(0x1001, &[6]).unwrap().text, "base");
    language.decode(0x1000, &[5]).unwrap();
    assert_eq!(language.decode(0x1001, &[6]).unwrap().text, "mode");
    language.reset_context();
    assert_eq!(language.decode(0x1001, &[6]).unwrap().text, "base");
    let defaults = BTreeMap::from([("phase".into(), 1)]);
    let mut language = SleighLanguage::from_spec(&fixture("tiny.slaspec"), &defaults).unwrap();
    assert_eq!(language.decode(0, &[6]).unwrap().text, "mode");
    assert!(matches!(
        SleighLanguage::from_spec(
            &fixture("tiny.slaspec"),
            &BTreeMap::from([("missing".into(), 0)])
        ),
        Err(Error::Context(_))
    ));
}

#[test]
fn delay_slots_are_expanded_once_and_truncation_fails() {
    let mut language =
        SleighLanguage::from_spec(&fixture("tiny.slaspec"), &BTreeMap::new()).unwrap();
    let lifted = language.decode(0x1000, &[16, 1]).unwrap();
    assert_eq!(lifted.length, 1);
    assert_eq!(lifted.next_address, 0x1002);
    assert_eq!(lifted.instruction.length, 2);
    assert_eq!(lifted.delay_slots.len(), 1);
    assert_eq!(lifted.delay_slots[0].address, 0x1001);
    assert!(
        lifted
            .instruction
            .ops
            .iter()
            .any(|operation| operation.opcode == Opcode::IntAdd)
    );
    let r0 = language.register("r0").unwrap();
    let mut machine = Machine::new(language.spaces().to_vec(), 65536).unwrap();
    machine
        .write_varnode(&r0, &Value::from_u64(4, 9).unwrap())
        .unwrap();
    machine
        .run(&[lifted.instruction], language.code_space(), 0x1000, 100)
        .unwrap();
    assert_eq!(
        machine.read_varnode(&r0).unwrap(),
        Value::from_u64(4, 10).unwrap()
    );
    assert!(language.decode(0x1000, &[16]).is_err());
}

#[test]
fn global_byte_order_is_derived_from_preprocessed_source() {
    let mut language =
        SleighLanguage::from_spec(&fixture("big.slaspec"), &BTreeMap::new()).unwrap();
    assert!(
        language
            .spaces()
            .iter()
            .all(|space| space.endianness == Endianness::Big)
    );
    assert_eq!(language.decode(0x1000, &[0x12, 0x34]).unwrap().text, "inc");
    assert!(language.decode(0x1000, &[0x34, 0x12]).is_err());
    assert!(language.decode(0x1000, &[]).is_err());
    assert!(matches!(
        language.decode(u64::MAX, &[0x12, 0x34]),
        Err(Error::AddressOverflow)
    ));
}

#[test]
fn variant_dependent_equal_width_extension_is_an_identity_copy() {
    let mut language =
        SleighLanguage::from_spec(&fixture("tiny.slaspec"), &BTreeMap::new()).unwrap();
    let lifted = language.decode(0x1000, &[7]).unwrap();
    assert!(
        lifted
            .instruction
            .ops
            .iter()
            .all(|operation| operation.opcode == Opcode::Copy)
    );
    let r0 = language.register("r0").unwrap();
    let value = Value::from_u64(4, 0xffff_fffe).unwrap();
    let mut machine = Machine::new(language.spaces().to_vec(), 65536).unwrap();
    machine.write_varnode(&r0, &value).unwrap();
    machine
        .run(&[lifted.instruction], language.code_space(), 0x1000, 100)
        .unwrap();
    assert_eq!(machine.read_varnode(&r0).unwrap(), value);
}

#[test]
fn big_endian_memory_semantics_execute_with_the_declared_byte_order() {
    let mut language =
        SleighLanguage::from_spec(&fixture("big.slaspec"), &BTreeMap::new()).unwrap();
    let lifted = language.decode(0x1000, &[0x12, 0x35]).unwrap();
    let mut machine = Machine::new(language.spaces().to_vec(), 65536).unwrap();
    machine
        .map_bytes(language.code_space(), 0x2000, &[0x12, 0x34, 0x56, 0x78])
        .unwrap();
    machine
        .run(&[lifted.instruction], language.code_space(), 0x1000, 100)
        .unwrap();
    let registers = language.registers().unwrap();
    assert!(
        registers
            .iter()
            .any(|register| register.name == "r0" && register.size == 4)
    );
    assert_eq!(
        machine
            .read_varnode(&language.register("r0").unwrap())
            .unwrap(),
        Value::from_u64(4, 0x12345678).unwrap()
    );
}

#[test]
fn unimplemented_address_units_are_rejected_explicitly() {
    assert!(
        matches!(SleighLanguage::from_spec(&fixture("word_addressed.slaspec"), &BTreeMap::new()), Err(Error::Unsupported(message)) if message.contains("word size"))
    );
}

#[test]
fn wide_register_metadata_is_independent_of_executable_value_limits() {
    let mut language =
        SleighLanguage::from_spec(&fixture("wide_registers.slaspec"), &BTreeMap::new()).unwrap();
    let bank = language.register_metadata("bank").unwrap().unwrap();
    assert_eq!((bank.offset, bank.size), (0x1000, 40960));
    assert_eq!(language.register_metadata("missing").unwrap(), None);
    let registers = language.registers().unwrap();
    assert!(registers.contains(&bank));
    let low = language.register_metadata("bank_low").unwrap().unwrap();
    assert_eq!(
        (low.space, low.offset, low.size),
        (bank.space, bank.offset, 4)
    );
    assert_eq!(language.register("bank"), None);
    assert!(language.decode(0x1000, &[0]).is_ok());
    assert!(matches!(
        language.decode(0x1000, &[1]),
        Err(Error::Pcode(ghidra_pcode::Error::InvalidSize(40960)))
    ));
    assert!(ghidra_pcode::Value::from_u64(40960, 0).is_err());
}
