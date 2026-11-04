use ghidra_pcode::machine::{ExecutionInput, Machine, StopReason};
use std::{
    fs::File,
    io::{Read, Write},
    path::Path,
};

pub fn lift(spec: &Path, address: &str, hex: &str, contexts: &[String]) -> Result<(), String> {
    let (address, bytes, context) = lift_arguments(address, hex, contexts)?;
    let mut language =
        ghidra_sleigh::SleighLanguage::from_spec(spec, &context).map_err(|e| e.to_string())?;
    let lifted = language
        .decode(address, &bytes)
        .map_err(|e| e.to_string())?;
    print_lifted(&language, lifted, address)
}

pub fn list_languages(root: &Path) -> Result<(), String> {
    let catalog = ghidra_languages::Catalog::discover(root).map_err(|e| e.to_string())?;
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    serde_json::to_writer_pretty(&mut writer, &catalog).map_err(|e| e.to_string())?;
    writeln!(writer).map_err(|e| e.to_string())
}

pub fn compiler_spec(root: &Path, language_id: &str, compiler_id: &str) -> Result<(), String> {
    let catalog = ghidra_languages::Catalog::discover(root).map_err(|e| e.to_string())?;
    let definition = catalog
        .by_id(language_id)
        .ok_or_else(|| format!("Unknown language ID: {language_id}"))?;
    let spec = definition
        .load_compiler_spec(compiler_id)
        .map_err(|e| e.to_string())?;
    #[derive(serde::Serialize)]
    struct Output<'a> {
        schema: &'static str,
        schema_version: u32,
        language_id: &'a str,
        compiler_id: &'a str,
        coverage: ghidra_languages::SpecCoverage,
        specification: &'a ghidra_languages::CompilerSpec,
    }
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    serde_json::to_writer_pretty(
        &mut writer,
        &Output {
            schema: "ghidra-rs.compiler-spec",
            schema_version: 1,
            language_id,
            compiler_id,
            coverage: spec.coverage(),
            specification: &spec,
        },
    )
    .map_err(|e| e.to_string())?;
    writeln!(writer).map_err(|e| e.to_string())
}

pub fn lift_language(
    root: &Path,
    id: &str,
    address: &str,
    hex: &str,
    contexts: &[String],
) -> Result<(), String> {
    let (address, bytes, context) = lift_arguments(address, hex, contexts)?;
    let catalog = ghidra_languages::Catalog::discover(root).map_err(|e| e.to_string())?;
    let definition = catalog
        .by_id(id)
        .ok_or_else(|| format!("Unknown language ID: {id}"))?;
    let mut language = ghidra_sleigh::SleighLanguage::from_language(definition, &context)
        .map_err(|e| e.to_string())?;
    let lifted = language
        .decode(address, &bytes)
        .map_err(|e| e.to_string())?;
    print_lifted(&language, lifted, address)
}

type LiftArguments = (u64, Vec<u8>, std::collections::BTreeMap<String, u64>);

fn lift_arguments(address: &str, hex: &str, contexts: &[String]) -> Result<LiftArguments, String> {
    Ok((
        hex_address(address)?,
        parse_hex(hex)?,
        context_overrides(contexts)?,
    ))
}

pub(crate) fn hex_address(address: &str) -> Result<u64, String> {
    let digits = address
        .strip_prefix("0x")
        .or_else(|| address.strip_prefix("0X"))
        .unwrap_or(address);
    let address = u64::from_str_radix(digits, 16)
        .map_err(|_| "Instruction address must be hexadecimal".to_string())?;
    Ok(address)
}

pub(crate) fn context_overrides(
    contexts: &[String],
) -> Result<std::collections::BTreeMap<String, u64>, String> {
    let mut context = std::collections::BTreeMap::new();
    if contexts.len() > 256 {
        return Err("Too many processor context overrides".into());
    }
    for argument in contexts {
        let (name, value) = argument
            .split_once('=')
            .ok_or("Context overrides use name=value")?;
        if name.is_empty() || name.len() > ghidra_project::MAX_CONTEXT_NAME_BYTES {
            return Err("Processor context field name is empty or exceeds 256 bytes".into());
        }
        let value = if let Some(hex) = value
            .strip_prefix("0x")
            .or_else(|| value.strip_prefix("0X"))
        {
            u64::from_str_radix(hex, 16)
        } else {
            value.parse()
        }
        .map_err(|_| format!("Invalid context value: {argument}"))?;
        if context.insert(name.to_string(), value).is_some() {
            return Err(format!("Duplicate context field: {name}"));
        }
    }
    Ok(context)
}

fn print_lifted(
    language: &ghidra_sleigh::SleighLanguage,
    lifted: ghidra_sleigh::LiftedInstruction,
    address: u64,
) -> Result<(), String> {
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    write_lifted(&mut writer, language, &lifted, address)?;
    writeln!(writer).map_err(|e| e.to_string())
}

pub fn lifted_json(
    language: &ghidra_sleigh::SleighLanguage,
    lifted: &ghidra_sleigh::LiftedInstruction,
    address: u64,
) -> Result<String, String> {
    let mut bytes = Vec::new();
    write_lifted(&mut bytes, language, lifted, address)?;
    String::from_utf8(bytes).map_err(|e| e.to_string())
}

fn write_lifted(
    writer: &mut impl Write,
    language: &ghidra_sleigh::SleighLanguage,
    lifted: &ghidra_sleigh::LiftedInstruction,
    address: u64,
) -> Result<(), String> {
    #[derive(serde::Serialize)]
    struct Register {
        name: String,
        storage: ghidra_pcode::Varnode,
    }
    #[derive(serde::Serialize)]
    struct DelaySlot<'a> {
        address: u64,
        length: u32,
        text: &'a str,
    }
    #[derive(serde::Serialize)]
    struct Output<'a> {
        schema: &'static str,
        schema_version: u32,
        disassembly: &'a str,
        length: u32,
        next_address: u64,
        delay_slots: Vec<DelaySlot<'a>>,
        context_commits: usize,
        userops: &'a [String],
        registers: Vec<Register>,
        program: ExecutionInput,
    }
    let registers = language
        .registers()
        .map_err(|e| e.to_string())?
        .into_iter()
        .map(|r| Register {
            name: r.name,
            storage: ghidra_pcode::Varnode {
                space: r.space,
                offset: r.offset,
                size: r.size,
            },
        })
        .collect();
    let output = Output {
        schema: "ghidra-rs.lifted-instruction",
        schema_version: 1,
        disassembly: &lifted.text,
        length: lifted.length,
        next_address: lifted.next_address,
        context_commits: lifted.context_commits,
        userops: language.userops(),
        registers,
        delay_slots: lifted
            .delay_slots
            .iter()
            .map(|s| DelaySlot {
                address: s.address,
                length: s.length,
                text: &s.text,
            })
            .collect(),
        program: ExecutionInput {
            spaces: language.spaces().to_vec(),
            code_space: language.code_space(),
            entry: address,
            instructions: vec![lifted.instruction.clone()],
            memory: vec![],
            max_operations: 100_000,
        },
    };
    serde_json::to_writer_pretty(writer, &output).map_err(|e| e.to_string())
}

fn parse_hex(text: &str) -> Result<Vec<u8>, String> {
    let text = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    let mut compact = String::new();
    for character in text.chars() {
        if character.is_ascii_hexdigit() {
            compact.push(character);
        } else if !character.is_ascii_whitespace() && character != '_' {
            return Err("Instruction bytes must be hexadecimal".into());
        }
        if compact.len() > ghidra_sleigh::MAX_DECODE_BYTES * 2 {
            return Err("Instruction window exceeds 4096 bytes".into());
        }
    }
    if compact.is_empty() || !compact.len().is_multiple_of(2) {
        return Err("Provide a nonempty, whole number of hex bytes".into());
    }
    (0..compact.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&compact[i..i + 2], 16).map_err(|e| e.to_string()))
        .collect()
}

pub fn execute(path: &Path) -> Result<bool, String> {
    let input = read_program(path)?;
    execute_program(input)
}

pub(crate) fn read_program(path: &Path) -> Result<ExecutionInput, String> {
    const MAX_INPUT: u64 = 16 * 1024 * 1024;
    let file = File::open(path).map_err(|e| format!("Cannot open P-code input: {e}"))?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > MAX_INPUT {
        return Err("P-code input must be a regular JSON file no larger than 16 MiB".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_INPUT + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_INPUT {
        return Err("P-code input exceeds 16 MiB".into());
    }
    let input: ExecutionInput =
        serde_json::from_slice(&bytes).map_err(|e| format!("Invalid P-code input: {e}"))?;
    if input.memory.len() > 100_000 {
        return Err("Too many initial memory regions".into());
    }
    Ok(input)
}

fn execute_program(input: ExecutionInput) -> Result<bool, String> {
    let mut machine = Machine::new(input.spaces, 16 * 1024 * 1024).map_err(|e| e.to_string())?;
    for memory in input.memory {
        machine
            .map_bytes(memory.space, memory.offset, &memory.bytes)
            .map_err(|e| e.to_string())?;
    }
    let report = machine
        .run(
            &input.instructions,
            input.code_space,
            input.entry,
            input.max_operations,
        )
        .map_err(|e| e.to_string())?;
    let exhausted = matches!(report.stop, StopReason::BudgetExhausted { .. });
    #[derive(serde::Serialize)]
    struct Output<'a> {
        schema_version: u32,
        execution: &'a ghidra_pcode::machine::ExecutionReport,
        memory: ghidra_pcode::machine::MemorySnapshot,
    }
    let output = Output {
        schema_version: 1,
        execution: &report,
        memory: machine.snapshot(),
    };
    let stdout = std::io::stdout();
    let mut writer = stdout.lock();
    serde_json::to_writer_pretty(&mut writer, &output).map_err(|e| e.to_string())?;
    writeln!(writer).map_err(|e| e.to_string())?;
    Ok(!exhausted)
}

#[cfg(test)]
mod tests {
    #[test]
    fn hexadecimal_addresses_allow_a_single_optional_prefix() {
        for text in ["1000", "0x1000", "0X1000"] {
            assert_eq!(super::hex_address(text).unwrap(), 0x1000);
        }
        for text in [
            "0x0x1000",
            "0X0X1000",
            "0x0X1000",
            "0X0x1000",
            "0x",
            "",
            "-1000",
            "10000000000000000",
        ] {
            assert!(super::hex_address(text).is_err(), "{text}");
        }
    }

    #[test]
    fn checked_in_example_executes_without_native_code() {
        let input: ghidra_pcode::machine::ExecutionInput =
            serde_json::from_str(include_str!("../../../examples/pcode/sum-loop.json")).unwrap();
        let mut machine = ghidra_pcode::machine::Machine::new(input.spaces, 4096 * 8).unwrap();
        let report = machine
            .run(
                &input.instructions,
                input.code_space,
                input.entry,
                input.max_operations,
            )
            .unwrap();
        assert_eq!(report.operations, 14);
        let value = machine
            .read_varnode(&ghidra_pcode::Varnode {
                space: ghidra_pcode::SpaceId(2),
                offset: 0,
                size: 4,
            })
            .unwrap();
        assert_eq!(value.to_u64(), Some(6));
    }
}
