//! Linkage metadata only: imports, exports, and relocation records are never applied.
//! Relocation sizes are in bits; zero means the format-specific width is unknown.

use std::collections::HashSet;

use object::{
    Object, ObjectSection, ObjectSymbol, ObjectSymbolTable, RelocationTarget,
    endian::LittleEndian as LE,
    read::pe::{ExportTarget, ImageNtHeaders, PeFile},
};
use serde::Serialize;

use crate::{BinaryImage, Error};

const MAX_ENTRIES: usize = 100_000;
const MAX_NAME: usize = 1024;

#[derive(Debug, Clone, Default, Serialize)]
pub struct Linkage {
    pub imports: Vec<Import>,
    pub exports: Vec<Export>,
    pub relocations: Vec<Relocation>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Import {
    pub library: String,
    pub name: String,
    /// PE import address table slot VA.
    /// `None` means that no slot address is available from the supported metadata.
    pub address: Option<u64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Export {
    pub name: String,
    pub address: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Relocation {
    pub address: u64,
    /// Width in bits, matching `object::Relocation::size`.
    pub size: u8,
    pub kind: String,
    pub target: String,
    /// Explicit table addend only. In-place implicit addends are not evaluated.
    pub addend: i64,
}

impl Linkage {
    fn warn(&mut self, warning: &str) {
        if !self.warnings.iter().any(|item| item == warning) {
            self.warnings.push(warning.into());
        }
    }
}

impl BinaryImage {
    pub fn linkage(&self) -> Result<Linkage, Error> {
        let file = object::File::parse(self.bytes()).map_err(invalid)?;
        let mut result = Linkage::default();
        match &file {
            object::File::Pe32(pe) => read_pe(pe, &mut result)?,
            object::File::Pe64(pe) => read_pe(pe, &mut result)?,
            object::File::Elf32(elf) => {
                check_count(elf.elf_dynamic_symbol_table().len(), "ELF dynamic symbols")?;
                read_generic_symbols(&file, &mut result)?;
                result.warn("ELF linkage uses section headers; sectionless dynamic tables and packed RELR relocations are not decoded.");
            }
            object::File::Elf64(elf) => {
                check_count(elf.elf_dynamic_symbol_table().len(), "ELF dynamic symbols")?;
                read_generic_symbols(&file, &mut result)?;
                result.warn("ELF linkage uses section headers; sectionless dynamic tables and packed RELR relocations are not decoded.");
            }
            object::File::MachO32(macho) => {
                check_count(macho.macho_symbol_table().len(), "Mach-O symbols")?;
                check_count(
                    macho.macho_header().ncmds.get(macho.endian()) as usize,
                    "Mach-O load commands",
                )?;
                read_generic_symbols(&file, &mut result)?;
                result.warn("Mach-O linkage covers the traditional symbol table and section relocations; dyld bind/rebase streams, export tries, chained fixups, and scattered relocations are not decoded.");
            }
            object::File::MachO64(macho) => {
                check_count(macho.macho_symbol_table().len(), "Mach-O symbols")?;
                check_count(
                    macho.macho_header().ncmds.get(macho.endian()) as usize,
                    "Mach-O load commands",
                )?;
                read_generic_symbols(&file, &mut result)?;
                result.warn("Mach-O linkage covers the traditional symbol table and section relocations; dyld bind/rebase streams, export tries, chained fixups, and scattered relocations are not decoded.");
            }
            _ => return Err(Error::UnsupportedFormat),
        }
        read_relocations(&file, &mut result)?;
        result.imports.sort_by(|a, b| {
            (&a.library, &a.name, a.address).cmp(&(&b.library, &b.name, b.address))
        });
        result
            .exports
            .sort_by(|a, b| (a.address, &a.name).cmp(&(b.address, &b.name)));
        result
            .relocations
            .sort_by_key(|relocation| relocation.address);
        Ok(result)
    }
}

fn invalid(error: impl std::fmt::Display) -> Error {
    Error::InvalidBinary(format!("linkage: {error}"))
}

fn check_count(count: usize, category: &str) -> Result<(), Error> {
    if count > MAX_ENTRIES {
        return Err(invalid(format!(
            "{category} exceeds the {MAX_ENTRIES} entry limit"
        )));
    }
    Ok(())
}

fn name(bytes: &[u8]) -> String {
    let mut value = String::from_utf8_lossy(&bytes[..bytes.len().min(MAX_NAME)]).into_owned();
    let mut end = value.len().min(MAX_NAME);
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value.truncate(end);
    value
}

fn cstring(bytes: &[u8], result: &mut Linkage) -> Result<String, Error> {
    match bytes.iter().take(MAX_NAME + 1).position(|&byte| byte == 0) {
        Some(end) => Ok(name(&bytes[..end])),
        None if bytes.len() > MAX_NAME => {
            result.warn("Linkage names longer than 1024 bytes are truncated.");
            Ok(name(bytes))
        }
        None => Err(invalid("unterminated linkage name")),
    }
}

fn pe_data<'data, Pe: ImageNtHeaders>(
    pe: &PeFile<'data, Pe>,
    rva: u32,
) -> Result<&'data [u8], Error> {
    pe.section_table()
        .pe_data_at(pe.data(), rva)
        .ok_or_else(|| invalid("PE linkage RVA is not file-backed"))
}

fn pe_address(base: u64, rva: u64, width: u64, is_64: bool) -> Result<u64, Error> {
    let rva_end = rva.checked_add(width).ok_or(Error::AddressOverflow)?;
    if rva > u32::MAX as u64 || rva_end > u32::MAX as u64 + 1 {
        return Err(Error::AddressOverflow);
    }
    let address = base.checked_add(rva).ok_or(Error::AddressOverflow)?;
    let end = address.checked_add(width).ok_or(Error::AddressOverflow)?;
    if !is_64 && end > u32::MAX as u64 + 1 {
        return Err(Error::AddressOverflow);
    }
    Ok(address)
}

fn read_pe<Pe: ImageNtHeaders>(pe: &PeFile<'_, Pe>, result: &mut Linkage) -> Result<(), Error> {
    let base = pe.relative_address_base();
    let is_64 = pe.nt_headers().is_type_64();
    if let Some(table) = pe.import_table().map_err(invalid)? {
        let mut descriptors = table.descriptors().map_err(invalid)?;
        let mut descriptor_count = 0;
        let mut thunks_seen = 0;
        'descriptors: while let Some(descriptor) = descriptors.next().map_err(invalid)? {
            if descriptor_count == MAX_ENTRIES {
                result.warn("PE import descriptors are limited to 100000 entries.");
                break;
            }
            descriptor_count += 1;
            let library = cstring(pe_data(pe, descriptor.name.get(LE))?, result)?;
            let original = descriptor.original_first_thunk.get(LE);
            let first = descriptor.first_thunk.get(LE);
            if first == 0 {
                return Err(invalid("PE import descriptor has no IAT"));
            }
            let lookup = if original == 0 { first } else { original };
            let bytes = pe_data(pe, lookup)?;
            let width = if is_64 { 8 } else { 4 };
            let mut terminated = false;
            for (index, chunk) in bytes.chunks_exact(width).enumerate() {
                let raw = if is_64 {
                    u64::from_le_bytes(chunk.try_into().map_err(invalid)?)
                } else {
                    u32::from_le_bytes(chunk.try_into().map_err(invalid)?) as u64
                };
                if raw == 0 {
                    terminated = true;
                    break;
                }
                if thunks_seen == MAX_ENTRIES {
                    result.warn("Imports are limited to 100000 entries.");
                    break 'descriptors;
                }
                thunks_seen += 1;
                let slot_rva = u64::from(first)
                    .checked_add(
                        (index as u64)
                            .checked_mul(width as u64)
                            .ok_or(Error::AddressOverflow)?,
                    )
                    .ok_or(Error::AddressOverflow)?;
                let address = pe_address(base, slot_rva, width as u64, is_64)?;
                if pe_data(pe, u32::try_from(slot_rva).map_err(invalid)?)?.len() < width {
                    return Err(invalid("truncated PE IAT slot"));
                }
                let ordinal_flag = if is_64 { 1u64 << 63 } else { 1u64 << 31 };
                let import_name = if raw & ordinal_flag != 0 {
                    format!("ordinal#{}", raw & 0xffff)
                } else if raw > u32::MAX as u64 && original == 0 {
                    result.warn("PE imports with only a bound IAT cannot be resolved without their original lookup table.");
                    continue;
                } else {
                    let hint_name = pe_data(pe, u32::try_from(raw).map_err(invalid)?)?;
                    cstring(
                        hint_name
                            .get(2..)
                            .ok_or_else(|| invalid("truncated PE import hint"))?,
                        result,
                    )?
                };
                result.imports.push(Import {
                    library: library.clone(),
                    name: import_name,
                    address: Some(address),
                });
            }
            if !terminated {
                return Err(invalid("unterminated PE import thunk table"));
            }
        }
    }
    if pe
        .data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT)
        .is_some()
    {
        result.warn("PE delay-load imports are not decoded.");
    }
    if let Some(table) = pe.export_table().map_err(invalid)? {
        check_count(table.addresses().len(), "PE exports")?;
        check_count(table.name_pointers().len(), "PE export names")?;
        if let Some(last) = table.addresses().len().checked_sub(1) {
            table
                .ordinal_base()
                .checked_add(u32::try_from(last).map_err(invalid)?)
                .ok_or(Error::AddressOverflow)?;
        }
        for export in table.exports().map_err(invalid)? {
            match export.target {
                ExportTarget::Address(0) => {}
                ExportTarget::Address(rva) => {
                    if export.name.is_some_and(|value| value.len() > MAX_NAME) {
                        result.warn("Linkage names longer than 1024 bytes are truncated.");
                    }
                    let export_name = export
                        .name
                        .map(name)
                        .unwrap_or_else(|| format!("ordinal#{}", export.ordinal));
                    result.exports.push(Export {
                        name: export_name,
                        address: pe_address(base, rva.into(), 0, is_64)?,
                    });
                }
                _ => result.warn(
                    "Forwarded PE exports are omitted because they have no address in this image.",
                ),
            }
        }
    }
    if let Some(directory) = pe.data_directory(object::pe::IMAGE_DIRECTORY_ENTRY_BASERELOC) {
        let bytes = directory
            .data(pe.data(), &pe.section_table())
            .map_err(invalid)?;
        read_pe_base_relocations(bytes, base, is_64, result)?;
    }
    Ok(())
}

fn read_pe_base_relocations(
    mut bytes: &[u8],
    base: u64,
    is_64: bool,
    result: &mut Linkage,
) -> Result<(), Error> {
    let mut entries_seen = 0;
    let mut blocks_seen = 0;
    while !bytes.is_empty() {
        if blocks_seen == MAX_ENTRIES {
            result.warn("PE base relocation blocks are limited to 100000 entries.");
            return Ok(());
        }
        blocks_seen += 1;
        let header = bytes
            .get(..8)
            .ok_or_else(|| invalid("truncated PE base relocation header"))?;
        let page = u32::from_le_bytes(header[..4].try_into().map_err(invalid)?);
        let size = u32::from_le_bytes(header[4..].try_into().map_err(invalid)?) as usize;
        if size < 8 || !size.is_multiple_of(4) {
            return Err(invalid("invalid PE base relocation block size"));
        }
        let block = bytes
            .get(8..size)
            .ok_or_else(|| invalid("truncated PE base relocation block"))?;
        let mut entries = block.as_chunks::<2>().0.iter();
        while let Some(entry) = entries.next() {
            if entries_seen >= MAX_ENTRIES {
                result.warn("Relocation records are limited to 100000 entries.");
                return Ok(());
            }
            entries_seen += 1;
            let entry = u16::from_le_bytes(*entry);
            let typ = entry >> 12;
            if typ == 0 {
                continue;
            }
            let rva = page
                .checked_add(u32::from(entry & 0xfff))
                .ok_or(Error::AddressOverflow)?;
            let (kind, bits, addend) = match typ {
                1 => ("PE_BASE_HIGH".into(), 16, 0),
                2 => ("PE_BASE_LOW".into(), 16, 0),
                3 => ("PE_BASE_HIGHLOW".into(), 32, 0),
                4 => {
                    let pair = entries
                        .next()
                        .ok_or_else(|| invalid("missing PE HIGHADJ relocation pair"))?;
                    entries_seen += 1;
                    (
                        "PE_BASE_HIGHADJ".into(),
                        16,
                        i16::from_le_bytes(*pair) as i64,
                    )
                }
                10 => ("PE_BASE_DIR64".into(), 64, 0),
                _ => {
                    result.warn("Some machine-specific PE base relocation widths are unknown; their numeric types are retained.");
                    (format!("PE_BASE_TYPE_{typ}"), 0, 0)
                }
            };
            result.relocations.push(Relocation {
                address: pe_address(base, rva.into(), u64::from(bits).div_ceil(8), is_64)?,
                size: bits,
                kind,
                target: "image-base".into(),
                addend,
            });
        }
        bytes = &bytes[size..];
    }
    Ok(())
}

fn read_generic_symbols(file: &object::File<'_>, result: &mut Linkage) -> Result<(), Error> {
    for import in file
        .imports()
        .map_err(invalid)?
        .into_iter()
        .take(MAX_ENTRIES)
    {
        if import.name().len() > MAX_NAME || import.library().len() > MAX_NAME {
            result.warn("Linkage names longer than 1024 bytes are truncated.");
        }
        result.imports.push(Import {
            library: name(import.library()),
            name: name(import.name()),
            address: None,
        });
    }
    for export in file
        .exports()
        .map_err(invalid)?
        .into_iter()
        .take(MAX_ENTRIES)
    {
        if export.name().len() > MAX_NAME {
            result.warn("Linkage names longer than 1024 bytes are truncated.");
        }
        result.exports.push(Export {
            name: name(export.name()),
            address: export.address(),
        });
    }
    Ok(())
}

fn read_relocations(file: &object::File<'_>, result: &mut Linkage) -> Result<(), Error> {
    let mut seen = HashSet::new();
    let mut inspected = result.relocations.len();
    for section in file.sections() {
        for (offset, relocation) in section.relocations() {
            if inspected == MAX_ENTRIES {
                result.warn("Relocation records are limited to 100000 entries.");
                return Ok(());
            }
            inspected += 1;
            // ELF ET_EXEC/ET_DYN r_offset values are already virtual addresses.
            let address = if file.format() == object::BinaryFormat::Elf
                && file.kind() != object::ObjectKind::Relocatable
            {
                offset
            } else {
                section
                    .address()
                    .checked_add(offset)
                    .ok_or(Error::AddressOverflow)?
            };
            push_relocation(file, address, &relocation, false, result, &mut seen)?;
        }
    }
    if let Some(relocations) = file.dynamic_relocations() {
        for (address, relocation) in relocations {
            if inspected == MAX_ENTRIES {
                result.warn("Relocation records are limited to 100000 entries.");
                return Ok(());
            }
            inspected += 1;
            push_relocation(file, address, &relocation, true, result, &mut seen)?;
        }
    }
    Ok(())
}

fn push_relocation(
    file: &object::File<'_>,
    address: u64,
    relocation: &object::Relocation,
    dynamic: bool,
    result: &mut Linkage,
    seen: &mut HashSet<(u64, String, String, i64)>,
) -> Result<(), Error> {
    address
        .checked_add(u64::from(relocation.size()).div_ceil(8))
        .ok_or(Error::AddressOverflow)?;
    let target = match relocation.target() {
        RelocationTarget::Symbol(index) => if dynamic {
            file.dynamic_symbol_table()
                .and_then(|table| table.symbol_by_index(index).ok())
                .and_then(|symbol| symbol.name_bytes().ok().map(name))
        } else {
            file.symbol_by_index(index)
                .ok()
                .and_then(|symbol| symbol.name_bytes().ok().map(name))
        }
        .unwrap_or_else(|| format!("symbol#{}", index.0)),
        RelocationTarget::Section(index) => file
            .section_by_index(index)
            .ok()
            .and_then(|section| section.name_bytes().ok().map(name))
            .unwrap_or_else(|| format!("section#{}", index.0)),
        RelocationTarget::Absolute => "absolute".into(),
        _ => "unresolved".into(),
    };
    let kind = format!("{:?} ({:?})", relocation.kind(), relocation.flags());
    if seen.insert((address, kind.clone(), target.clone(), relocation.addend())) {
        if relocation.has_implicit_addend() {
            result.warn("Relocation addends stored at the relocation site are not evaluated; addend reports only the explicit table component.");
        }
        result.relocations.push(Relocation {
            address,
            size: relocation.size(),
            kind,
            target,
            addend: relocation.addend(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put16(bytes: &mut [u8], offset: usize, value: u16) {
        bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
    }
    fn put32(bytes: &mut [u8], offset: usize, value: u32) {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    fn put64(bytes: &mut [u8], offset: usize, value: u64) {
        bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
    }

    fn pe_fixture(is_64: bool) -> Vec<u8> {
        let mut bytes = vec![0; 0xa00];
        bytes[..2].copy_from_slice(b"MZ");
        put32(&mut bytes, 0x3c, 0x80);
        bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
        put16(&mut bytes, 0x84, if is_64 { 0x8664 } else { 0x14c });
        put16(&mut bytes, 0x86, 1);
        put16(&mut bytes, 0x94, if is_64 { 0xf0 } else { 0xe0 });
        put16(&mut bytes, 0x96, 0x22);
        let optional = 0x98;
        put16(&mut bytes, optional, if is_64 { 0x20b } else { 0x10b });
        put32(&mut bytes, optional + 16, 0x1000);
        if is_64 {
            put64(&mut bytes, optional + 24, 0x140000000);
        } else {
            put32(&mut bytes, optional + 28, 0x400000);
        }
        put32(&mut bytes, optional + 32, 0x1000);
        put32(&mut bytes, optional + 36, 0x200);
        put32(&mut bytes, optional + 56, 0x2000);
        put32(&mut bytes, optional + 60, 0x200);
        put32(&mut bytes, optional + if is_64 { 108 } else { 92 }, 16);
        let directories = optional + if is_64 { 112 } else { 96 };
        put32(&mut bytes, directories, 0x1300);
        put32(&mut bytes, directories + 4, 0x100);
        put32(&mut bytes, directories + 8, 0x1100);
        put32(&mut bytes, directories + 12, 40);
        put32(&mut bytes, directories + 5 * 8, 0x1400);
        put32(&mut bytes, directories + 5 * 8 + 4, 12);
        let section = optional + if is_64 { 0xf0 } else { 0xe0 };
        bytes[section..section + 5].copy_from_slice(b".text");
        put32(&mut bytes, section + 8, 0x800);
        put32(&mut bytes, section + 12, 0x1000);
        put32(&mut bytes, section + 16, 0x800);
        put32(&mut bytes, section + 20, 0x200);
        put32(&mut bytes, section + 36, 0x60000020);
        bytes[0x200] = 0xc3;
        put32(&mut bytes, 0x300, 0x11a0); // Import lookup table RVA.
        put32(&mut bytes, 0x30c, 0x1180); // Library name RVA.
        put32(&mut bytes, 0x310, 0x11c0); // IAT RVA.
        bytes[0x380..0x38d].copy_from_slice(b"KERNEL32.dll\0");
        if is_64 {
            put64(&mut bytes, 0x3a0, 0x1200);
            put64(&mut bytes, 0x3a8, (1 << 63) | 12);
            put64(&mut bytes, 0x3c0, 0x1200);
            put64(&mut bytes, 0x3c8, (1 << 63) | 12);
        } else {
            put32(&mut bytes, 0x3a0, 0x1200);
            put32(&mut bytes, 0x3a4, (1 << 31) | 12);
            put32(&mut bytes, 0x3c0, 0x1200);
            put32(&mut bytes, 0x3c4, (1 << 31) | 12);
        }
        bytes[0x402..0x40e].copy_from_slice(b"ExitProcess\0");
        put32(&mut bytes, 0x510, 7); // Export ordinal base.
        put32(&mut bytes, 0x514, 2); // Address count.
        put32(&mut bytes, 0x518, 1); // Name count.
        put32(&mut bytes, 0x51c, 0x1340);
        put32(&mut bytes, 0x520, 0x1350);
        put32(&mut bytes, 0x524, 0x1358);
        put32(&mut bytes, 0x540, 0x1000);
        put32(&mut bytes, 0x544, 0x1004);
        put32(&mut bytes, 0x550, 0x1360);
        bytes[0x560..0x569].copy_from_slice(b"exported\0");
        put32(&mut bytes, 0x600, 0x1000);
        put32(&mut bytes, 0x604, 12);
        put16(&mut bytes, 0x608, if is_64 { 0xa008 } else { 0x3008 });
        bytes
    }

    #[test]
    fn pe32_and_pe64_resolve_iat_slots_exports_and_base_relocations() {
        for is_64 in [false, true] {
            let linkage = BinaryImage::parse(pe_fixture(is_64))
                .unwrap()
                .linkage()
                .unwrap();
            let base = if is_64 { 0x140000000 } else { 0x400000 };
            let import = linkage
                .imports
                .iter()
                .find(|import| import.name == "ExitProcess")
                .unwrap();
            assert_eq!(import.library, "KERNEL32.dll");
            assert_eq!(import.address, Some(base + 0x11c0));
            let ordinal = linkage
                .imports
                .iter()
                .find(|import| import.name == "ordinal#12")
                .unwrap();
            assert_eq!(
                ordinal.address,
                Some(base + 0x11c0 + if is_64 { 8 } else { 4 })
            );
            assert_eq!(linkage.exports.len(), 2);
            assert_eq!(linkage.exports[0].name, "exported");
            assert_eq!(linkage.exports[0].address, base + 0x1000);
            assert_eq!(linkage.exports[1].name, "ordinal#8");
            assert_eq!(linkage.relocations.len(), 1);
            assert_eq!(linkage.relocations[0].address, base + 0x1008);
            assert_eq!(linkage.relocations[0].size, if is_64 { 64 } else { 32 });
        }
    }

    #[test]
    fn forwarded_exports_are_explicitly_omitted_and_highadj_pairs_are_not_extra_relocations() {
        let mut bytes = pe_fixture(true);
        put32(&mut bytes, 0x544, 0x13a0);
        bytes[0x5a0..0x5ad].copy_from_slice(b"OTHER.target\0");
        put16(&mut bytes, 0x608, 0x4008);
        put16(&mut bytes, 0x60a, 0xffff);
        let linkage = BinaryImage::parse(bytes).unwrap().linkage().unwrap();
        assert_eq!(linkage.exports.len(), 1);
        assert!(
            linkage
                .warnings
                .iter()
                .any(|warning| warning.contains("Forwarded"))
        );
        assert_eq!(linkage.relocations.len(), 1);
        assert_eq!(linkage.relocations[0].kind, "PE_BASE_HIGHADJ");
        assert_eq!(linkage.relocations[0].addend, -1);
    }

    fn elf_fixture() -> Vec<u8> {
        let mut bytes = vec![0; 0x600];
        bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
        put16(&mut bytes, 16, 3); // ET_DYN.
        put16(&mut bytes, 18, 62);
        put32(&mut bytes, 20, 1);
        put64(&mut bytes, 24, 0x401000);
        put64(&mut bytes, 40, 0x400);
        put16(&mut bytes, 52, 64);
        put16(&mut bytes, 58, 64);
        put16(&mut bytes, 60, 6);
        put16(&mut bytes, 62, 5);
        bytes[0x100] = 0xc3;
        let dynstr = b"\0puts\0exported\0";
        bytes[0x120..0x120 + dynstr.len()].copy_from_slice(dynstr);
        put32(&mut bytes, 0x178, 1);
        bytes[0x17c] = 0x12; // STB_GLOBAL, STT_FUNC, SHN_UNDEF.
        put32(&mut bytes, 0x190, 6);
        bytes[0x194] = 0x12;
        put16(&mut bytes, 0x196, 1);
        put64(&mut bytes, 0x198, 0x401000);
        put64(&mut bytes, 0x1a0, 16);
        put64(&mut bytes, 0x1c0, 0x401008);
        put64(&mut bytes, 0x1c8, (1 << 32) | 1); // Symbol 1, R_X86_64_64.
        put64(&mut bytes, 0x1d0, (-4i64) as u64);
        let shstr = b"\0.text\0.dynstr\0.dynsym\0.rela.dyn\0.shstrtab\0";
        bytes[0x220..0x220 + shstr.len()].copy_from_slice(shstr);
        for (index, (section_name, typ, flags, address, offset, size, link, entry_size)) in [
            (".text", 1, 6, 0x401000, 0x100, 16, 0, 0),
            (".dynstr", 3, 2, 0x402000, 0x120, dynstr.len() as u64, 0, 0),
            (".dynsym", 11, 2, 0x402040, 0x160, 72, 2, 24),
            (".rela.dyn", 4, 2, 0x402100, 0x1c0, 24, 3, 24),
            (".shstrtab", 3, 0, 0, 0x220, shstr.len() as u64, 0, 0),
        ]
        .into_iter()
        .enumerate()
        {
            let header = 0x400 + (index + 1) * 64;
            let name_offset = shstr
                .windows(section_name.len())
                .position(|window| window == section_name.as_bytes())
                .unwrap();
            put32(&mut bytes, header, name_offset as u32);
            put32(&mut bytes, header + 4, typ);
            put64(&mut bytes, header + 8, flags);
            put64(&mut bytes, header + 16, address);
            put64(&mut bytes, header + 24, offset);
            put64(&mut bytes, header + 32, size);
            put32(&mut bytes, header + 40, link);
            put64(&mut bytes, header + 48, 8);
            put64(&mut bytes, header + 56, entry_size);
        }
        bytes
    }

    #[test]
    fn elf_dynamic_import_export_and_relocation_preserve_virtual_addresses() {
        let linkage = BinaryImage::parse(elf_fixture())
            .unwrap()
            .linkage()
            .unwrap();
        assert_eq!(linkage.imports.len(), 1);
        assert_eq!(linkage.imports[0].name, "puts");
        assert_eq!(linkage.imports[0].address, None);
        assert_eq!(linkage.exports.len(), 1);
        assert_eq!(linkage.exports[0].name, "exported");
        assert_eq!(linkage.exports[0].address, 0x401000);
        assert_eq!(linkage.relocations.len(), 1);
        assert_eq!(linkage.relocations[0].address, 0x401008);
        assert_eq!(linkage.relocations[0].target, "puts");
        assert_eq!(linkage.relocations[0].size, 64);
        assert_eq!(linkage.relocations[0].addend, -4);
    }

    #[test]
    fn truncated_tables_and_overflowing_relocations_return_errors() {
        let mut bytes = pe_fixture(true);
        put32(&mut bytes, 0x604, 0x1000);
        assert!(BinaryImage::parse(bytes).unwrap().linkage().is_err());
        let mut bytes = pe_fixture(true);
        put32(&mut bytes, 0x600, u32::MAX);
        put16(&mut bytes, 0x608, 0xa001);
        assert!(BinaryImage::parse(bytes).unwrap().linkage().is_err());
        let mut bytes = elf_fixture();
        put64(&mut bytes, 0x1c0, u64::MAX);
        assert!(BinaryImage::parse(bytes).unwrap().linkage().is_err());
        assert!(pe_address(u64::MAX - 1, 8, 8, true).is_err());
        assert!(pe_address(0xfffff000, 0xfff, 4, false).is_err());
    }

    #[test]
    fn names_are_bounded_and_relocation_block_padding_cannot_bypass_the_budget() {
        assert!(name(&[0xff; MAX_NAME + 10]).len() <= MAX_NAME);
        let block = [0u8, 0, 0, 0, 8, 0, 0, 0];
        let bytes = block.repeat(MAX_ENTRIES + 1);
        let mut linkage = Linkage::default();
        read_pe_base_relocations(&bytes, 0x400000, true, &mut linkage).unwrap();
        assert!(linkage.relocations.is_empty());
        assert!(
            linkage
                .warnings
                .iter()
                .any(|warning| warning.contains("blocks are limited"))
        );
    }
}
