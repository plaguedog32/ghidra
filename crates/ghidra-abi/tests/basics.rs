use ghidra_abi::*;
use ghidra_languages::{JoinPiece, StackGrowth, StackPointer, Storage};
use ghidra_pcode::{AddressSpace, Endianness, SpaceId, SpaceKind};

fn layout() -> (Vec<AddressSpace>, Vec<RegisterDefinition>) {
    let spaces = [
        (0, "const", SpaceKind::Constant, 8),
        (1, "ram", SpaceKind::Ram, 4),
        (2, "register", SpaceKind::Register, 8),
    ]
    .into_iter()
    .map(|(id, name, kind, address_size)| AddressSpace {
        id: SpaceId(id),
        name: name.into(),
        kind,
        address_size,
        word_size: 1,
        endianness: Endianness::Little,
    })
    .collect();
    let registers = [("R0", 0, 8), ("R0L", 0, 4), ("R1", 8, 8), ("SP", 64, 4)]
        .into_iter()
        .map(|(name, offset, size)| RegisterDefinition {
            name: name.into(),
            space: SpaceId(2),
            offset,
            size,
        })
        .collect();
    (spaces, registers)
}
fn file() -> RegisterFile {
    let (spaces, registers) = layout();
    RegisterFile::new(spaces, SpaceId(1), registers, Default::default()).unwrap()
}
fn stack() -> StackPointer {
    StackPointer {
        register: "SP".into(),
        space: "ram".into(),
        growth: StackGrowth::Negative,
        reverse_justify: false,
        line: 0,
    }
}
fn address(space: &str, offset: u64, size: Option<u32>) -> Storage {
    Storage::Address {
        space: space.into(),
        offset,
        size,
    }
}
fn single(storage: ResolvedStorage) -> StorageRange {
    let ResolvedStorage::Single(range) = storage else {
        panic!("expected single location")
    };
    range
}

#[test]
fn register_aliases_and_registry_budgets_have_exact_boundaries() {
    let file = file();
    let r0 = file.register_id("r0").unwrap();
    let low = file.register_id("R0L").unwrap();
    let r1 = file.register_id("R1").unwrap();
    assert!(file.registers_overlap(r0, low).unwrap());
    assert!(!file.registers_overlap(r0, r1).unwrap());
    assert!(file.register(RegisterId(usize::MAX)).is_err());
    assert!(file.registers_overlap(r0, RegisterId(usize::MAX)).is_err());
    let exact = AbiLimits {
        max_spaces: 3,
        max_registers: 4,
        max_name_bytes: file.name_bytes(),
        max_work: file.build_work(),
        ..Default::default()
    };
    let (spaces, registers) = layout();
    RegisterFile::new(spaces, SpaceId(1), registers, exact).unwrap();
    for limits in [
        AbiLimits {
            max_spaces: 2,
            ..exact
        },
        AbiLimits {
            max_registers: 3,
            ..exact
        },
        AbiLimits {
            max_name_bytes: exact.max_name_bytes - 1,
            ..exact
        },
        AbiLimits {
            max_work: exact.max_work - 1,
            ..exact
        },
    ] {
        let (spaces, registers) = layout();
        assert!(matches!(
            RegisterFile::new(spaces, SpaceId(1), registers, limits),
            Err(AbiError::Limit(_))
        ));
    }
    let (spaces, mut registers) = layout();
    registers.push(registers[0].clone());
    assert!(matches!(
        RegisterFile::new(spaces, SpaceId(1), registers, Default::default()),
        Err(AbiError::InvalidLayout("duplicate register name"))
    ));
}

#[test]
fn signed_stack_normalization_is_distinct_from_unsigned_memory_extent_checks() {
    let file = file();
    let pointer = stack();
    let resolve = |storage: Storage| {
        resolve_storage(&file, Some(&pointer), &storage, None, Default::default())
    };
    let stack_range = single(resolve(address("stack", (-2_i64) as u64, Some(4))).unwrap());
    assert_eq!(stack_range.address.signed_stack_offset(), Some(-2));
    assert_eq!(
        single(resolve(address("stack", 0xffff_ffff, None)).unwrap())
            .address
            .signed_stack_offset(),
        Some(-1)
    );
    let ram_range = single(resolve(address("ram", (-2_i64) as u64, Some(2))).unwrap());
    assert_eq!(ram_range.address.offset, 0xffff_fffe);
    assert!(resolve(address("ram", (-2_i64) as u64, Some(4))).is_err());
    assert!(resolve(address("stack", 1_u64 << 32, None)).is_err());
    assert!(resolve(address("stack", (-2_147_483_649_i64) as u64, None)).is_err());
    assert!(resolve(address("stack", 0x7fff_ffff, Some(2))).is_err());
    assert_eq!(
        single(resolve(address("OTHER", u64::MAX, Some(1))).unwrap())
            .address
            .space,
        AbiSpace::Other
    );
    assert!(resolve(address("OTHER", u64::MAX, Some(2))).is_err());
    assert!(resolve(address("join", 0, Some(8))).is_err());
}

#[test]
fn join_pieces_keep_significance_and_float_extensions_are_not_bit_slices() {
    let file = file();
    let pieces = vec![
        JoinPiece::Register { name: "R0".into() },
        JoinPiece::Register { name: "R1".into() },
    ];
    let join = Storage::Join {
        pieces,
        logical_size: None,
    };
    let resolved = resolve_storage(&file, None, &join, None, Default::default()).unwrap();
    let ResolvedStorage::Join {
        kind,
        logical_size,
        physical_size,
        pieces,
    } = resolved
    else {
        panic!()
    };
    assert_eq!(kind, JoinKind::Concatenation);
    assert_eq!((logical_size, physical_size), (16, 16));
    assert_eq!((pieces[0].lsb_byte, pieces[1].lsb_byte), (Some(8), Some(0)));
    assert_eq!(
        (
            pieces[0].storage.address.offset,
            pieces[1].storage.address.offset
        ),
        (0, 8)
    );
    assert!(
        resolve_storage(
            &file,
            None,
            &join,
            None,
            AbiLimits {
                max_total_pieces: 1,
                ..Default::default()
            }
        )
        .is_err()
    );
    let float = Storage::Join {
        pieces: vec![JoinPiece::Register { name: "R0".into() }],
        logical_size: Some(4),
    };
    let ResolvedStorage::Join {
        kind,
        logical_size,
        physical_size,
        pieces,
    } = resolve_storage(&file, None, &float, None, Default::default()).unwrap()
    else {
        panic!()
    };
    assert_eq!(kind, JoinKind::FloatExtension);
    assert_eq!((logical_size, physical_size), (4, 8));
    assert_eq!(pieces[0].lsb_byte, None);
}
