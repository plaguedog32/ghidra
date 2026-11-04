//! Direct branch and call targets through sub-table exports.
//!
//! Native SLEIGH branches to an exported operand's fixed handle: for
//! `export *[aux]:2 0x10:1` that is two bytes at address unit 0x10 of `aux`,
//! byte offset 0x10 * word size (`HandleTpl::fix`, `AddrSpace::addressToByte`).
//! The expected offsets below are that product, worked by hand.

use std::collections::BTreeMap;

use ghidra_cfg::{Cfg, CfgError, CfgInput, Limits, OperandError};
use ghidra_pcode::{
    Opcode, PcodeOperation, SpaceId, Varnode,
    machine::{Machine, MachineError},
};
use ghidra_sleigh::{Error, SleighLanguage};

fn compile(text: &str) -> SleighLanguage {
    let directory = tempfile::tempdir().unwrap();
    let source = directory.path().join("targets.slaspec");
    std::fs::write(&source, text).unwrap();
    SleighLanguage::from_spec(&source, &BTreeMap::new()).unwrap()
}

/// The reviewed reproduction, plus a conditional branch, a call, a dynamic
/// export with a context commit, and probes that reveal that commit.
fn source(word: u32, big: bool) -> String {
    let order = if big { "big" } else { "little" };
    format!(
        r#"
define endian={order};
define space ram type=ram_space size=2 default;
define space register type=register_space size=2;
define space aux type=ram_space size=1 wordsize={word};
define register offset=0 size=2 [r0];
define register offset=4 size=2 [ctx];
define aux offset=0 size=1 [cell];
define context ctx phase=(0,0);
define token encoding(8) op=(0,7);
tgt: is epsilon {{ export *[aux]:2 0x10:1; }}
dyn: is epsilon {{ export *[aux]:2 r0; }}
:jb is op=19 & tgt {{ goto tgt; }}
:cb is op=20 & tgt {{ if (r0 == 0) goto tgt; }}
:cl is op=21 & tgt {{ call tgt; }}
:jy is op=22 & dyn [ phase=1; globalset(inst_next, phase); ] {{ goto dyn; }}
:jok is op=23 & tgt [ phase=1; globalset(inst_next, phase); ] {{ goto tgt; }}
:probe is op=24 & phase=0 {{ r0 = 0; }}
:committed is op=24 & phase=1 {{ r0 = 1; }}
:lit is op=26 {{ goto 0x30; }}
"#
    )
}

fn space(language: &SleighLanguage, name: &str) -> SpaceId {
    language
        .spaces()
        .iter()
        .find(|space| space.name == name)
        .unwrap()
        .id
}

#[test]
fn branch_conditional_branch_and_call_keep_the_exported_space_width_and_units() {
    let expected = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80];
    for (word, offset) in (1..=8).zip(expected) {
        for big in [false, true] {
            let mut language = compile(&source(word, big));
            let aux = space(&language, "aux");
            assert_ne!(aux, language.code_space());
            let target = Varnode {
                space: aux,
                offset,
                size: 2,
            };
            let ops = |language: &mut SleighLanguage, op: u8| {
                language.decode(0x1000, &[op]).unwrap().instruction.ops
            };
            assert_eq!(
                ops(&mut language, 19),
                vec![PcodeOperation {
                    opcode: Opcode::Branch,
                    output: None,
                    inputs: vec![target],
                }],
                "word {word}, big {big}"
            );
            let conditional = ops(&mut language, 20);
            assert_eq!(conditional[1].opcode, Opcode::Cbranch);
            assert_eq!(conditional[1].inputs[0], target);
            assert_eq!(
                ops(&mut language, 21),
                vec![PcodeOperation {
                    opcode: Opcode::Call,
                    output: None,
                    inputs: vec![target],
                }]
            );
        }
    }
}

#[test]
fn ordinary_literal_targets_keep_the_default_code_space() {
    let mut language = compile(&source(3, false));
    let ops = language.decode(0x1000, &[26]).unwrap().instruction.ops;
    assert_eq!(
        ops[0].inputs,
        vec![Varnode {
            space: language.code_space(),
            offset: 0x30,
            size: 2,
        }]
    );
}

#[test]
fn machine_and_cfg_refuse_the_preserved_auxiliary_target() {
    for word in [1, 3] {
        let mut language = compile(&source(word, false));
        let aux = space(&language, "aux");
        for op in [19, 21] {
            let lifted = language.decode(0x1000, &[op]).unwrap();
            assert_eq!(lifted.instruction.ops[0].inputs[0].space, aux);
            let mut machine = Machine::new(language.spaces().to_vec(), 65536).unwrap();
            assert!(matches!(
                machine.run(
                    std::slice::from_ref(&lifted.instruction),
                    language.code_space(),
                    0x1000,
                    10
                ),
                Err(MachineError::At { address: 0x1000, operation: 0, source })
                    if matches!(*source, MachineError::CrossSpaceTransfer)
            ));
            let input = CfgInput::new(
                language.spaces().to_vec(),
                language.code_space(),
                0x1000,
                vec![lifted.instruction],
            );
            assert!(matches!(
                Cfg::new(input, Limits::default()),
                Err(CfgError::InvalidOperand {
                    problem: OperandError::CrossSpaceLabel { space },
                    ..
                }) if space == aux
            ));
        }
    }
}

#[test]
fn dynamic_targets_are_refused_without_committing_context() {
    let mut language = compile(&source(3, false));
    assert!(matches!(
        language.decode(0x1000, &[22]),
        Err(Error::Lower(message)) if message.contains("dynamic exported pointer")
    ));
    // The refused instruction's `globalset` was not applied: the next
    // address still decodes with the default phase.
    assert_eq!(language.decode(0x1001, &[24]).unwrap().text, "probe");
    // The same commit from an instruction that lowers is applied.
    let lifted = language.decode(0x1000, &[23]).unwrap();
    assert_eq!(lifted.context_commits, 1);
    assert_eq!(language.decode(0x1001, &[24]).unwrap().text, "committed");
}

#[test]
fn word_space_address_of_audit_still_visits_qualified_target_pointers() {
    let text = format!(
        "{}\nheld: is epsilon {{ export *[aux]:2 &:1 cell; }}\n:held is op=25 & held {{ goto held; }}\n",
        source(4, false)
    );
    let mut language = compile(&text);
    assert!(matches!(
        language.decode(0x1000, &[25]),
        Err(Error::Unsupported(message)) if message.contains("address-of word-space")
    ));
    // The refusal is per instruction.
    assert!(language.decode(0x1000, &[19]).is_ok());
}
