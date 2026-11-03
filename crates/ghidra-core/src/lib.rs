//! Native binary loading and bounded x86 analysis. Imported files are never executed.
//!
//! Analysis is a linear sweep of a file-backed executable section, not function
//! discovery. Blocks describe the decoded range; successors can point outside it.
//! No Ghidra Java classes, JVM, JNI, native decompiler, or external processes are used.

use std::collections::{BTreeSet, HashSet};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Formatter, IntelFormatter, OpKind};
use object::{Object, ObjectSection, ObjectSegment, ObjectSymbol, SectionFlags, SectionKind};
use serde::Serialize;
use thiserror::Error;

pub const MAX_FILE_SIZE: usize = 128 * 1024 * 1024;
pub const MAX_INSTRUCTIONS: usize = 100_000;
const MAX_SECTIONS: usize = 4096;
const MAX_SYMBOLS: usize = 100_000;
const MAX_STRINGS: usize = 100_000;
const MAX_STRING_LENGTH: usize = 1024;

#[derive(Debug, Error)]
pub enum Error {
    #[error("file exceeds the 128 MiB import limit")]
    FileTooLarge,
    #[error("invalid or unsupported binary: {0}")]
    InvalidBinary(String),
    #[error("only PE, ELF, and thin Mach-O binaries are supported")]
    UnsupportedFormat,
    #[error("disassembly requires little-endian x86 or x86-64; this file is {0}")]
    UnsupportedArchitecture(String),
    #[error("address 0x{0:X} is not in a file-backed executable section")]
    UnmappedAddress(u64),
    #[error("instruction limit must be between 1 and {MAX_INSTRUCTIONS}")]
    InvalidInstructionLimit,
    #[error("address range overflows the selected architecture")]
    AddressOverflow,
}

#[derive(Debug, Serialize)]
pub struct BinaryImage {
    pub format: String,
    pub architecture: String,
    pub bitness: u32,
    pub entry: u64,
    pub image_base: u64,
    pub sections: Vec<Section>,
    pub symbols: Vec<Symbol>,
    pub strings: Vec<BinaryString>,
    pub warnings: Vec<String>,
    #[serde(skip)]
    bytes: Vec<u8>,
    #[serde(skip)]
    x86: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Section {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub file_offset: u64,
    pub file_size: u64,
    pub executable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Symbol {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub is_function: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct BinaryString {
    pub file_offset: u64,
    pub value: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Analysis {
    pub instructions: Vec<Instruction>,
    pub references: Vec<Reference>,
    pub blocks: Vec<BasicBlock>,
    /// More bytes remain after the instruction budget was exhausted.
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Instruction {
    pub address: u64,
    pub bytes: Vec<u8>,
    pub text: String,
    pub flow: String,
    /// A direct near branch/call target; indirect targets are unresolved.
    pub target: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Reference {
    pub from: u64,
    pub to: u64,
    /// `call`, `branch`, or `data` (an IP-relative memory operand).
    pub kind: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct BasicBlock {
    pub start: u64,
    /// Exclusive end address.
    pub end: u64,
    /// Control-flow successors, excluding callees. External targets are retained.
    pub successors: Vec<u64>,
}

impl BinaryImage {
    pub fn parse(data: Vec<u8>) -> Result<Self, Error> {
        if data.len() > MAX_FILE_SIZE {
            return Err(Error::FileTooLarge);
        }
        let file = object::File::parse(data.as_slice())
            .map_err(|error| Error::InvalidBinary(error.to_string()))?;
        let format = match file.format() {
            object::BinaryFormat::Pe => "PE",
            object::BinaryFormat::Elf => "ELF",
            object::BinaryFormat::MachO => "Mach-O",
            _ => return Err(Error::UnsupportedFormat),
        }
        .to_owned();
        let architecture = format!("{:?}", file.architecture());
        let x86 = matches!(
            file.architecture(),
            object::Architecture::I386 | object::Architecture::X86_64
        ) && file.is_little_endian();
        let bitness = if file.is_64() { 64 } else { 32 };
        let mut image_base = file.relative_address_base();
        let mut entry = file.entry();
        if format == "Mach-O" {
            image_base = file
                .segments()
                .filter(|segment| {
                    let (offset, size) = segment.file_range();
                    offset == 0 && size != 0
                })
                .map(|segment| segment.address())
                .min()
                .unwrap_or(0);
            // object 0.37 exposes LC_MAIN.entryoff as a file offset, unlike the
            // virtual entry addresses returned for PE/ELF. Translate it once.
            if entry != 0 {
                entry = file
                    .segments()
                    .find_map(|segment| {
                        let (offset, size) = segment.file_range();
                        let delta = entry.checked_sub(offset)?;
                        (delta < size)
                            .then(|| segment.address().checked_add(delta))
                            .flatten()
                    })
                    .ok_or_else(|| {
                        Error::InvalidBinary("Mach-O entry offset is not mapped".into())
                    })?;
            }
        }
        let mut sections = Vec::new();
        for section in file.sections() {
            if sections.len() == MAX_SECTIONS {
                return Err(Error::InvalidBinary("too many sections".into()));
            }
            let (file_offset, file_size) = section.file_range().unwrap_or((0, 0));
            if file_offset
                .checked_add(file_size)
                .is_none_or(|end| end > data.len() as u64)
                || section.address().checked_add(section.size()).is_none()
            {
                return Err(Error::InvalidBinary(
                    "section range is out of bounds".into(),
                ));
            }
            // PE addresses exposed by `object` already include the image base.
            // Validate the unwrapped sum, because object deliberately uses wrapping_add.
            if format == "PE" && section.address() < image_base {
                return Err(Error::InvalidBinary("PE section address overflow".into()));
            }
            let executable = match section.flags() {
                SectionFlags::Elf { sh_flags } => {
                    sh_flags & u64::from(object::elf::SHF_EXECINSTR) != 0
                }
                SectionFlags::Coff { characteristics } => {
                    characteristics & object::pe::IMAGE_SCN_MEM_EXECUTE != 0
                }
                SectionFlags::MachO { flags } => {
                    flags
                        & (object::macho::S_ATTR_PURE_INSTRUCTIONS
                            | object::macho::S_ATTR_SOME_INSTRUCTIONS)
                        != 0
                }
                _ => section.kind() == SectionKind::Text,
            };
            sections.push(Section {
                name: section
                    .name()
                    .unwrap_or("<invalid name>")
                    .chars()
                    .take(256)
                    .collect(),
                address: section.address(),
                size: section.size(),
                file_offset,
                file_size,
                executable,
            });
        }
        sections.sort_by_key(|section| section.address);
        // object 0.37's COFF accessor adds base + section RVA + symbol value
        // without checked arithmetic. Validate the raw values before using it.
        match &file {
            object::File::Pe32(pe) => validate_pe_symbol_addresses(pe, image_base)?,
            object::File::Pe64(pe) => validate_pe_symbol_addresses(pe, image_base)?,
            _ => {}
        }
        let mut symbols = Vec::new();
        let mut warnings = Vec::new();
        let mut seen = HashSet::new();
        for symbol in file.symbols().chain(file.dynamic_symbols()) {
            if symbols.len() == MAX_SYMBOLS {
                warnings.push(format!("Symbol display limited to {MAX_SYMBOLS} entries."));
                break;
            }
            if symbol.is_undefined() {
                continue;
            }
            let Ok(name) = symbol.name() else { continue };
            if name.is_empty() {
                continue;
            }
            let name: String = name.chars().take(1024).collect();
            if seen.insert((symbol.address(), name.clone())) {
                symbols.push(Symbol {
                    name,
                    address: symbol.address(),
                    size: symbol.size(),
                    is_function: symbol.kind() == object::SymbolKind::Text,
                });
            }
        }
        symbols
            .sort_by(|left, right| (left.address, &left.name).cmp(&(right.address, &right.name)));
        let (strings, capped) = extract_strings(&data);
        if capped {
            warnings.push(format!("String display limited to {MAX_STRINGS} entries; individual strings limited to {MAX_STRING_LENGTH} characters."));
        }
        if format == "PE" && entry < image_base {
            return Err(Error::InvalidBinary("PE entry address overflow".into()));
        }
        Ok(Self {
            format,
            architecture,
            bitness,
            entry,
            image_base,
            sections,
            symbols,
            strings,
            warnings,
            bytes: data,
            x86,
        })
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Decode from `address` to the end of its executable section, subject to
    /// `max_instructions`. Zero-fill tails and disk alignment padding are excluded.
    pub fn disassemble(&self, address: u64, max_instructions: usize) -> Result<Analysis, Error> {
        if !self.x86 {
            return Err(Error::UnsupportedArchitecture(self.architecture.clone()));
        }
        let (section, delta) = self
            .sections
            .iter()
            .filter(|section| section.executable)
            .find_map(|section| {
                let delta = address.checked_sub(section.address)?;
                (delta < section.size.min(section.file_size)).then_some((section, delta))
            })
            .ok_or(Error::UnmappedAddress(address))?;
        let start = (section.file_offset + delta) as usize;
        let end = (section.file_offset + section.size.min(section.file_size)) as usize;
        analyze_x86(
            &self.bytes[start..end],
            address,
            self.bitness,
            max_instructions,
        )
    }
}

fn validate_pe_symbol_addresses<'data, Pe: object::read::pe::ImageNtHeaders>(
    pe: &object::read::pe::PeFile<'data, Pe>,
    image_base: u64,
) -> Result<(), Error> {
    use object::read::coff::ImageSymbol;
    for symbol in pe.symbols() {
        let raw = symbol.coff_symbol();
        if !matches!(
            raw.storage_class(),
            object::pe::IMAGE_SYM_CLASS_STATIC
                | object::pe::IMAGE_SYM_CLASS_WEAK_EXTERNAL
                | object::pe::IMAGE_SYM_CLASS_LABEL
                | object::pe::IMAGE_SYM_CLASS_EXTERNAL
        ) {
            continue;
        }
        let Some(index) = raw.section() else {
            continue;
        };
        let section = pe
            .section_table()
            .section(index)
            .map_err(|e| Error::InvalidBinary(e.to_string()))?;
        image_base
            .checked_add(u64::from(section.virtual_address.get(object::LittleEndian)))
            .and_then(|address| address.checked_add(u64::from(raw.value())))
            .ok_or_else(|| Error::InvalidBinary("PE symbol address overflow".into()))?;
    }
    Ok(())
}

fn extract_strings(data: &[u8]) -> (Vec<BinaryString>, bool) {
    let mut strings = Vec::new();
    let mut start = 0;
    let mut capped = false;
    for end in 0..=data.len() {
        if end < data.len() && (0x20..=0x7e).contains(&data[end]) {
            continue;
        }
        if end - start >= 4 {
            if strings.len() == MAX_STRINGS {
                return (strings, true);
            }
            let length = (end - start).min(MAX_STRING_LENGTH);
            capped |= length < end - start;
            // The range was explicitly checked as printable ASCII above.
            let value = String::from_utf8_lossy(&data[start..start + length]).into_owned();
            strings.push(BinaryString {
                file_offset: start as u64,
                value,
            });
        }
        start = end + 1;
    }
    (strings, capped)
}

/// Linear-sweep x86 decoder with direct control-flow and RIP-relative references.
/// Invalid encodings are shown as `invalid` instructions and terminate blocks.
/// This does not prove that every decoded byte is reachable executable code.
pub fn analyze_x86(
    bytes: &[u8],
    address: u64,
    bitness: u32,
    max_instructions: usize,
) -> Result<Analysis, Error> {
    if !matches!(bitness, 32 | 64) {
        return Err(Error::UnsupportedArchitecture(format!("x86-{bitness}")));
    }
    if !(1..=MAX_INSTRUCTIONS).contains(&max_instructions) {
        return Err(Error::InvalidInstructionLimit);
    }
    let end = address
        .checked_add(bytes.len() as u64)
        .ok_or(Error::AddressOverflow)?;
    if bitness == 32 && (address > u32::MAX as u64 || end > u32::MAX as u64 + 1) {
        return Err(Error::AddressOverflow);
    }
    let mut decoder = Decoder::with_ip(bitness, bytes, address, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    formatter.options_mut().set_hex_prefix("0x");
    formatter.options_mut().set_hex_suffix("");
    let mut analysis = Analysis::default();
    while decoder.can_decode() && analysis.instructions.len() < max_instructions {
        let offset = decoder.position();
        let decoded = decoder.decode();
        let mut text = String::new();
        formatter.format(&decoded, &mut text);
        let flow = if decoded.is_invalid() {
            "invalid"
        } else {
            match decoded.flow_control() {
                FlowControl::Next => "next",
                FlowControl::UnconditionalBranch => "branch",
                FlowControl::ConditionalBranch => "conditional",
                FlowControl::IndirectBranch => "indirect-branch",
                FlowControl::Call => "call",
                FlowControl::IndirectCall => "indirect-call",
                FlowControl::Return => "return",
                FlowControl::Interrupt => "interrupt",
                FlowControl::Exception => "exception",
                FlowControl::XbeginXabortXend => "transaction",
            }
        };
        let target = matches!(
            decoded.op0_kind(),
            OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
        )
        .then(|| decoded.near_branch_target());
        if let Some(to) = target {
            analysis.references.push(Reference {
                from: decoded.ip(),
                to,
                kind: if flow == "call" { "call" } else { "branch" }.into(),
            });
        }
        if decoded.is_ip_rel_memory_operand() {
            analysis.references.push(Reference {
                from: decoded.ip(),
                to: decoded.ip_rel_memory_address(),
                kind: "data".into(),
            });
        }
        analysis.instructions.push(Instruction {
            address: address + offset as u64,
            bytes: bytes[offset..decoder.position()].to_vec(),
            text,
            flow: flow.into(),
            target,
        });
    }
    analysis.truncated = decoder.can_decode();
    analysis.blocks = build_blocks(&analysis.instructions);
    Ok(analysis)
}

fn build_blocks(instructions: &[Instruction]) -> Vec<BasicBlock> {
    let Some(first) = instructions.first() else {
        return Vec::new();
    };
    let addresses: HashSet<_> = instructions
        .iter()
        .map(|instruction| instruction.address)
        .collect();
    let mut leaders = BTreeSet::from([first.address]);
    for (index, instruction) in instructions.iter().enumerate() {
        if let Some(target) = instruction
            .target
            .filter(|target| addresses.contains(target))
        {
            leaders.insert(target);
        }
        if instruction.flow != "next"
            && let Some(next) = instructions.get(index + 1)
        {
            leaders.insert(next.address);
        }
    }
    let mut blocks = Vec::new();
    let mut start = 0;
    for end in 0..instructions.len() {
        if end + 1 < instructions.len() && !leaders.contains(&instructions[end + 1].address) {
            continue;
        }
        let last = &instructions[end];
        let next = last.address + last.bytes.len() as u64;
        let mut successors = Vec::new();
        match last.flow.as_str() {
            "branch" => successors.extend(last.target),
            "conditional" | "transaction" => {
                successors.extend(last.target);
                successors.push(next);
            }
            "return" | "indirect-branch" | "exception" | "invalid" | "interrupt" => {}
            _ => successors.push(next),
        }
        successors.sort_unstable();
        successors.dedup();
        blocks.push(BasicBlock {
            start: instructions[start].address,
            end: next,
            successors,
        });
        start = end + 1;
    }
    blocks
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put16(data: &mut [u8], offset: usize, value: u16) {
        data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put32(data: &mut [u8], offset: usize, value: u32) {
        data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(data: &mut [u8], offset: usize, value: u64) {
        data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    /// Minimal PE32+ image with .text, disk padding, and an unbacked virtual tail.
    fn pe_fixture() -> Vec<u8> {
        let mut data = vec![0; 1024];
        data[..2].copy_from_slice(b"MZ");
        put32(&mut data, 0x3c, 0x80);
        data[0x80..0x84].copy_from_slice(b"PE\0\0");
        put16(&mut data, 0x84, 0x8664);
        put16(&mut data, 0x86, 1);
        put16(&mut data, 0x94, 0xf0);
        put16(&mut data, 0x96, 0x22);
        put16(&mut data, 0x98, 0x20b);
        put32(&mut data, 0xa8, 0x1000);
        put64(&mut data, 0xb0, 0x140000000);
        put32(&mut data, 0xb8, 0x1000);
        put32(&mut data, 0xbc, 0x200);
        put32(&mut data, 0xd0, 0x2000);
        put32(&mut data, 0xd4, 0x200);
        put16(&mut data, 0xdc, 3);
        put32(&mut data, 0x104, 16);
        data[0x188..0x18d].copy_from_slice(b".text");
        put32(&mut data, 0x190, 8);
        put32(&mut data, 0x194, 0x1000);
        put32(&mut data, 0x198, 0x200);
        put32(&mut data, 0x19c, 0x200);
        put32(&mut data, 0x1ac, 0x60000020);
        data[0x200..0x208].copy_from_slice(&[0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3]);
        data[0x220..0x22c].copy_from_slice(b"hello world\0");
        data
    }

    fn elf_fixture() -> Vec<u8> {
        let mut data = vec![0; 0x140];
        data[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put16(&mut data, 16, 2);
        put16(&mut data, 18, 62);
        put32(&mut data, 20, 1);
        put64(&mut data, 24, 0x401000);
        put64(&mut data, 40, 0x80);
        put16(&mut data, 52, 64);
        put16(&mut data, 58, 64);
        put16(&mut data, 60, 3);
        put16(&mut data, 62, 2);
        data[0x40..0x44].copy_from_slice(&[0x31, 0xc0, 0xc3, 0x90]);
        data[0x50..0x62].copy_from_slice(b"\0.text\0.shstrtab\0\0");
        put32(&mut data, 0xc0, 1);
        put32(&mut data, 0xc4, 1);
        put64(&mut data, 0xc8, 6);
        put64(&mut data, 0xd0, 0x401000);
        put64(&mut data, 0xd8, 0x40);
        put64(&mut data, 0xe0, 4);
        put64(&mut data, 0xf0, 16);
        put32(&mut data, 0x100, 7);
        put32(&mut data, 0x104, 3);
        put64(&mut data, 0x118, 0x50);
        put64(&mut data, 0x120, 18);
        put64(&mut data, 0x130, 1);
        data
    }

    fn macho_fixture() -> Vec<u8> {
        let mut data = vec![0; 0x104];
        put32(&mut data, 0, 0xfeedfacf);
        put32(&mut data, 4, 0x01000007); // CPU_TYPE_X86_64
        put32(&mut data, 8, 3);
        put32(&mut data, 12, 2); // MH_EXECUTE
        put32(&mut data, 16, 2);
        put32(&mut data, 20, 176);
        put32(&mut data, 0x20, 0x19); // LC_SEGMENT_64
        put32(&mut data, 0x24, 152);
        data[0x28..0x2e].copy_from_slice(b"__TEXT");
        put64(&mut data, 0x38, 0x100000000);
        put64(&mut data, 0x40, 0x1000);
        put64(&mut data, 0x50, 0x104);
        put32(&mut data, 0x58, 7);
        put32(&mut data, 0x5c, 5);
        put32(&mut data, 0x60, 1);
        data[0x68..0x6e].copy_from_slice(b"__text");
        data[0x78..0x7e].copy_from_slice(b"__TEXT");
        put64(&mut data, 0x88, 0x100000100);
        put64(&mut data, 0x90, 4);
        put32(&mut data, 0x98, 0x100);
        put32(&mut data, 0x9c, 4);
        put32(&mut data, 0xa8, 0x80000400);
        put32(&mut data, 0xb8, 0x80000028); // LC_MAIN
        put32(&mut data, 0xbc, 24);
        put64(&mut data, 0xc0, 0x100);
        data[0x100..0x104].copy_from_slice(&[0x31, 0xc0, 0xc3, 0x90]);
        data
    }

    #[test]
    fn pe_addresses_already_include_image_base_and_padding_is_not_decoded() {
        let image = BinaryImage::parse(pe_fixture()).unwrap();
        assert_eq!(image.format, "PE");
        assert_eq!(image.entry, 0x140001000);
        assert_eq!(image.sections[0].address, image.entry);
        let analysis = image.disassemble(image.entry, 100).unwrap();
        assert_eq!(analysis.instructions.len(), 5);
        assert_eq!(analysis.instructions.last().unwrap().flow, "return");
        assert!(!analysis.truncated);
        assert!(matches!(
            image.disassemble(image.entry + 8, 100),
            Err(Error::UnmappedAddress(_))
        ));
        assert!(
            image
                .strings
                .iter()
                .any(|s| s.file_offset == 0x220 && s.value == "hello world")
        );
    }

    #[test]
    fn elf_loads_and_decodes_at_virtual_address() {
        let image = BinaryImage::parse(elf_fixture()).unwrap();
        assert_eq!(image.format, "ELF");
        assert_eq!(image.bitness, 64);
        assert!(
            image
                .sections
                .iter()
                .any(|s| s.name == ".text" && s.executable)
        );
        let analysis = image.disassemble(0x401000, 10).unwrap();
        assert_eq!(analysis.instructions.len(), 3);
        assert_eq!(analysis.instructions[0].address, image.entry);
    }

    #[test]
    fn thin_macho_loads_and_decodes_at_virtual_address() {
        let image = BinaryImage::parse(macho_fixture()).unwrap();
        assert_eq!(image.format, "Mach-O");
        assert_eq!(image.entry, 0x100000100);
        assert_eq!(image.sections[0].name, "__text");
        let analysis = image.disassemble(image.entry, 10).unwrap();
        assert_eq!(analysis.instructions.len(), 3);
        assert_eq!(analysis.instructions[1].flow, "return");
    }

    #[test]
    fn malformed_and_truncated_imports_return_errors_without_panics() {
        assert!(BinaryImage::parse(Vec::new()).is_err());
        assert!(BinaryImage::parse(b"not an executable".to_vec()).is_err());
        let data = pe_fixture();
        for length in [1, 63, 127, 130, 255, 511, 512, 519] {
            assert!(
                BinaryImage::parse(data[..length].to_vec()).is_err(),
                "length {length}"
            );
        }
        let mut corrupt = data;
        put32(&mut corrupt, 0x19c, u32::MAX);
        assert!(BinaryImage::parse(corrupt).is_err());
    }

    #[test]
    fn metadata_loads_for_unsupported_architecture() {
        let mut data = elf_fixture();
        put16(&mut data, 18, 183); // AArch64
        let image = BinaryImage::parse(data).unwrap();
        assert!(matches!(
            image.disassemble(image.entry, 10),
            Err(Error::UnsupportedArchitecture(_))
        ));
    }

    #[test]
    fn malformed_pe_symbol_address_cannot_overflow_dependency_accessor() {
        let mut data = pe_fixture();
        put64(&mut data, 0xb0, 0xffff_ffff_ffff_d000);
        put32(&mut data, 0x8c, 0x240); // COFF symbol table
        put32(&mut data, 0x90, 1);
        data[0x240..0x244].copy_from_slice(b"evil");
        put32(&mut data, 0x248, u32::MAX);
        put16(&mut data, 0x24c, 1); // section 1
        data[0x250] = object::pe::IMAGE_SYM_CLASS_EXTERNAL;
        put32(&mut data, 0x252, 4); // empty string table, after 18-byte symbol
        let error = BinaryImage::parse(data).unwrap_err();
        assert!(error.to_string().contains("PE symbol address overflow"));
    }

    #[test]
    fn branches_split_blocks_and_calls_are_references_not_cfg_successors() {
        // jne +2; nop; ret; call +1; ret; ret
        let bytes = [0x75, 0x02, 0x90, 0xc3, 0xe8, 0x01, 0, 0, 0, 0xc3, 0xc3];
        let result = analyze_x86(&bytes, 0x1000, 64, 100).unwrap();
        assert_eq!(result.references[0].to, 0x1004);
        assert_eq!(result.references[1].to, 0x100a);
        assert_eq!(result.references[1].kind, "call");
        assert_eq!(result.blocks[0].successors, vec![0x1002, 0x1004]);
        let call_block = result
            .blocks
            .iter()
            .find(|block| block.start == 0x1004)
            .unwrap();
        assert_eq!(call_block.successors, vec![0x1009]);
        assert!(
            result
                .blocks
                .iter()
                .filter(|block| [0x1002, 0x1009, 0x100a].contains(&block.start))
                .all(|block| block.successors.is_empty())
        );
    }

    #[test]
    fn backward_branch_and_external_target_are_retained() {
        let loop_result = analyze_x86(&[0x90, 0xeb, 0xfd], 0x1000, 32, 10).unwrap();
        assert_eq!(loop_result.blocks[0].successors, vec![0x1000]);
        let external = analyze_x86(&[0xeb, 0x7f], 0x1000, 64, 10).unwrap();
        assert_eq!(external.blocks[0].successors, vec![0x1081]);
    }

    #[test]
    fn instruction_budget_truncation_and_input_ranges_are_checked() {
        let result = analyze_x86(&[0x90; 8], 0, 64, 2).unwrap();
        assert_eq!(result.instructions.len(), 2);
        assert!(result.truncated);
        assert!(matches!(
            analyze_x86(&[], 0, 64, 0),
            Err(Error::InvalidInstructionLimit)
        ));
        assert!(matches!(
            analyze_x86(&[], 0, 64, MAX_INSTRUCTIONS + 1),
            Err(Error::InvalidInstructionLimit)
        ));
        assert!(matches!(
            analyze_x86(&[0; 2], u64::MAX, 64, 10),
            Err(Error::AddressOverflow)
        ));
        assert!(matches!(
            analyze_x86(&[0; 2], u32::MAX as u64, 32, 10),
            Err(Error::AddressOverflow)
        ));
        assert!(analyze_x86(&[], 0, 64, 1).unwrap().blocks.is_empty());
    }

    #[test]
    fn incomplete_instruction_and_rip_relative_data_references() {
        let invalid = analyze_x86(&[0x0f], 0x1000, 64, 10).unwrap();
        assert_eq!(invalid.instructions[0].flow, "invalid");
        assert!(invalid.blocks[0].successors.is_empty());
        let result = analyze_x86(&[0x48, 0x8b, 0x05, 0x10, 0, 0, 0], 0x1000, 64, 10).unwrap();
        assert_eq!(result.references[0].kind, "data");
        assert_eq!(result.references[0].to, 0x1017);
    }

    #[test]
    fn string_extraction_handles_eof_and_caps_long_runs() {
        let (strings, capped) = extract_strings(b"abc\0hello\0world");
        assert_eq!(strings.len(), 2);
        assert_eq!(strings[1].file_offset, 10);
        assert!(!capped);
        let (strings, capped) = extract_strings(&vec![b'A'; MAX_STRING_LENGTH + 1]);
        assert!(capped);
        assert_eq!(strings[0].value.len(), MAX_STRING_LENGTH);
    }
}
