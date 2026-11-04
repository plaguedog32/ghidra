//! Shared fixtures for the behavioral tests. Each fixture is hand-written so
//! that expected values come from the declarations, not from the resolver.
#![allow(dead_code)]

use std::sync::Arc;

use ghidra_abi::{
    AbiError, AbiLimits, AbiResult, BindingSite, CompilerStorage, RegisterDefinition, RegisterFile,
    ResolvedStorage, StorageRange,
};
use ghidra_languages::{CompilerSpec, Storage};
use ghidra_pcode::{AddressSpace, Endianness, SpaceId, SpaceKind};

pub const CONST: SpaceId = SpaceId(0);
pub const RAM: SpaceId = SpaceId(1);
pub const REGISTER: SpaceId = SpaceId(2);

pub fn space(
    id: u32,
    name: &str,
    kind: SpaceKind,
    address_size: u8,
    word_size: u32,
) -> AddressSpace {
    AddressSpace {
        id: SpaceId(id),
        name: name.into(),
        kind,
        address_size,
        word_size,
        endianness: Endianness::Little,
    }
}

pub fn register(name: &str, space: SpaceId, offset: u64, size: u32) -> RegisterDefinition {
    RegisterDefinition {
        name: name.into(),
        space,
        offset,
        size,
    }
}

/// const(8), ram(`ram_size`, word 1), register(8).
pub fn spaces(ram_size: u8) -> Vec<AddressSpace> {
    vec![
        space(0, "const", SpaceKind::Constant, 8, 1),
        space(1, "ram", SpaceKind::Ram, ram_size, 1),
        space(2, "register", SpaceKind::Register, 8, 1),
    ]
}

/// A small 32-bit target: r0..r3 (4 bytes at 0,4,8,12), d0 = r0:r1 alias,
/// a 16-bit `half` stack pointer variant and a 4-byte `sp`.
pub fn small_registers() -> Vec<RegisterDefinition> {
    vec![
        register("r0", REGISTER, 0, 4),
        register("r1", REGISTER, 4, 4),
        register("r2", REGISTER, 8, 4),
        register("r3", REGISTER, 12, 4),
        register("d0", REGISTER, 0, 8),
        register("sp", REGISTER, 0x40, 4),
        register("sp16", REGISTER, 0x40, 2),
        register("sp64", REGISTER, 0x48, 8),
        register("lr", REGISTER, 0x50, 4),
        register("f0", REGISTER, 0x100, 4),
        register("f0d", REGISTER, 0x100, 8),
    ]
}

pub fn small_file() -> Arc<RegisterFile> {
    Arc::new(RegisterFile::new(spaces(4), RAM, small_registers(), AbiLimits::default()).unwrap())
}

pub fn parse(text: &str) -> CompilerSpec {
    let spec = CompilerSpec::parse_str(text, None, &Default::default()).unwrap();
    assert_eq!(
        spec.diagnostics
            .iter()
            .filter(|d| d.severity >= ghidra_languages::Severity::Error)
            .count(),
        0,
        "{:#?}",
        spec.diagnostics
    );
    spec
}

pub fn storage(
    spec: CompilerSpec,
    file: &Arc<RegisterFile>,
    limits: AbiLimits,
) -> AbiResult<CompilerStorage> {
    CompilerStorage::new(Arc::new(spec), file.clone(), limits)
}

pub fn single(storage: &ResolvedStorage) -> &StorageRange {
    match storage {
        ResolvedStorage::Single(range) => range,
        other => panic!("expected a single location, got {other:?}"),
    }
}

pub fn address(space: &str, offset: u64, size: Option<u32>) -> Storage {
    Storage::Address {
        space: space.into(),
        offset,
        size,
    }
}

pub fn varnode(space: &str, offset: u64, size: u32) -> Storage {
    Storage::Varnode {
        space: space.into(),
        offset,
        size,
    }
}

/// Unwrap an `At` error and check its source site.
pub fn at(error: AbiError, expected: BindingSite) -> AbiError {
    match error {
        AbiError::At { site, source } => {
            assert_eq!(site, expected);
            *source
        }
        other => panic!("expected an error at {expected:?}, got {other:?}"),
    }
}

pub fn is_limit(result: AbiResult<impl std::fmt::Debug>, resource: &str) {
    match result {
        Err(AbiError::Limit(name)) => assert_eq!(name, resource),
        Err(AbiError::At { source, .. }) => match *source {
            AbiError::Limit(name) => assert_eq!(name, resource),
            other => panic!("expected {resource} limit, got {other:?}"),
        },
        other => panic!("expected {resource} limit, got {other:?}"),
    }
}
