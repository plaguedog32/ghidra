//! Join storage: most-significant-first pieces (`AddressXML.readJoinXML`) and
//! native `AddrSpaceManager::findAddJoin` validity rules.
mod common;

use std::path::PathBuf;

use common::*;
use ghidra_abi::{
    AbiError, AbiLimits, AbiSpace, JoinKind, ResolvedPiece, ResolvedStorage, resolve_storage,
};
use ghidra_languages::{JoinPiece, Storage};

fn reg(name: &str) -> JoinPiece {
    JoinPiece::Register { name: name.into() }
}

fn piece(space: &str, offset: u64, size: u32) -> JoinPiece {
    JoinPiece::Varnode {
        space: space.into(),
        offset,
        size,
    }
}

fn join(pieces: Vec<JoinPiece>, logical_size: Option<u32>) -> Storage {
    Storage::Join {
        pieces,
        logical_size,
    }
}

fn resolve(storage: &Storage) -> Result<ResolvedStorage, AbiError> {
    let file = small_file();
    resolve_storage(&file, None, storage, None, AbiLimits::default())
}

fn parts(storage: ResolvedStorage) -> (JoinKind, u32, u32, Vec<ResolvedPiece>) {
    match storage {
        ResolvedStorage::Join {
            kind,
            logical_size,
            physical_size,
            pieces,
        } => (kind, logical_size, physical_size, pieces),
        other => panic!("expected a join, got {other:?}"),
    }
}

#[test]
fn mixed_width_concatenation_keeps_declared_order_and_byte_significance() {
    let file = small_file();
    // d0 (8) : r2 (4) : ram[0x10..0x12) (2) = 14 bytes, most significant first.
    let (kind, logical, physical, pieces) = parts(
        resolve(&join(
            vec![reg("D0"), reg("r2"), piece("ram", 0x10, 2)],
            None,
        ))
        .unwrap(),
    );
    assert_eq!((kind, logical, physical), (JoinKind::Concatenation, 14, 14));
    let lsb: Vec<_> = pieces.iter().map(|p| p.lsb_byte).collect();
    assert_eq!(lsb, [Some(6), Some(2), Some(0)]);
    assert_eq!(pieces[0].storage.register, file.register_id("d0"));
    assert_eq!(pieces[1].storage.register, file.register_id("r2"));
    assert_eq!(pieces[2].storage.register, None);
    assert_eq!(pieces[2].storage.address.space, AbiSpace::Language(RAM));
    assert_eq!(pieces[2].storage.size, Some(2));
    // Reversing declaration order reverses significance; nothing is sorted.
    let (_, _, _, reversed) = parts(
        resolve(&join(
            vec![piece("ram", 0x10, 2), reg("r2"), reg("d0")],
            None,
        ))
        .unwrap(),
    );
    assert_eq!(
        reversed.iter().map(|p| p.lsb_byte).collect::<Vec<_>>(),
        [Some(12), Some(8), Some(0)]
    );
    // Stack pieces use signed stack offsets; aliases may repeat.
    let (_, _, physical, pieces) = parts(
        resolve(&join(
            vec![piece("stack", -8_i64 as u64, 4), reg("r0"), reg("r0")],
            None,
        ))
        .unwrap(),
    );
    assert_eq!(physical, 12);
    assert_eq!(pieces[0].storage.address.signed_stack_offset(), Some(-8));
    assert_eq!(pieces[2].lsb_byte, Some(0));
}

/// Parse `pieceN="name"` attributes from one retained `<addr space="join" .../>`
/// line and return names in piece-number order (piece1 most significant).
fn declared_pieces(line: &str) -> Vec<String> {
    let mut pieces = Vec::new();
    for attribute in line.split_whitespace() {
        if let Some(rest) = attribute.strip_prefix("piece")
            && let Some((number, value)) = rest.split_once('=')
        {
            let name = value.trim_matches(|c| c == '"' || c == '/' || c == '>');
            pieces.push((number.parse::<usize>().unwrap(), name.to_owned()));
        }
    }
    pieces.sort();
    assert!(
        pieces.iter().enumerate().all(|(i, (n, _))| *n == i + 1),
        "{line}"
    );
    pieces.into_iter().map(|(_, name)| name).collect()
}

#[test]
fn retained_aarch64_go_joins_resolve_most_significant_first() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../Ghidra/Processors/AARCH64/data/languages/AARCH64_golang.cspec");
    let text = std::fs::read_to_string(path).unwrap();
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|l| l.contains(r#"space="join""#))
        .collect();
    // Eight abi-internal results (2..=9 registers) and duffcopy's x20:x21.
    assert_eq!(lines.len(), 9);
    // x0..x30 at their AArch64 register-space offsets (8 bytes from 0x4000).
    let registers = (0..31)
        .map(|i| register(&format!("x{i}"), REGISTER, 0x4000 + 8 * i, 8))
        .collect();
    let file =
        ghidra_abi::RegisterFile::new(spaces(8), RAM, registers, AbiLimits::default()).unwrap();
    let mut seen_counts = Vec::new();
    for line in lines {
        let names = declared_pieces(line);
        let pentry = format!(
            r#"<compiler_spec><default_proto><prototype name="p" extrapop="0" stackshift="0">
            <input/><output><pentry minsize="1" maxsize="{}">{line}</pentry></output>
            </prototype></default_proto></compiler_spec>"#,
            8 * names.len()
        );
        let spec = parse(&pentry);
        let declaration = &spec.prototypes[0].output.entries[0].storage;
        let (kind, logical, physical, pieces) =
            parts(resolve_storage(&file, None, declaration, None, AbiLimits::default()).unwrap());
        let count = names.len() as u32;
        assert_eq!(
            (kind, logical, physical),
            (JoinKind::Concatenation, 8 * count, 8 * count)
        );
        for (index, (piece, name)) in pieces.iter().zip(&names).enumerate() {
            let number: u64 = name[1..].parse().unwrap();
            assert_eq!(piece.storage.register, file.register_id(name), "{line}");
            assert_eq!(piece.storage.address.offset, 0x4000 + 8 * number);
            assert_eq!(
                piece.lsb_byte,
                Some(8 * (count - 1 - index as u32)),
                "{line}"
            );
        }
        seen_counts.push((
            names.first().cloned().unwrap(),
            names.last().cloned().unwrap(),
        ));
    }
    // Hand-checked against the retained file: the highest register is most
    // significant for the result tuples (x0 is least significant) and
    // duffcopy declares x20 above x21.
    assert!(seen_counts.contains(&("x1".into(), "x0".into())));
    assert!(seen_counts.contains(&("x8".into(), "x0".into())));
    assert!(seen_counts.contains(&("x20".into(), "x21".into())));
}

#[test]
fn single_piece_logical_sizes_are_float_extensions_not_bit_slices() {
    let file = small_file();
    for (name, logical, physical) in [("f0d", 4, 8), ("f0", 8, 4)] {
        let resolved = resolve(&join(vec![reg(name)], Some(logical))).unwrap();
        assert_eq!(resolved.size(), Some(logical));
        let (kind, l, p, pieces) = parts(resolved);
        assert_eq!((kind, l, p), (JoinKind::FloatExtension, logical, physical));
        assert_eq!(pieces.len(), 1);
        assert_eq!(pieces[0].lsb_byte, None);
        assert_eq!(pieces[0].storage.register, file.register_id(name));
    }
    // A single constant piece is the one native exception needing no logical size.
    let (kind, logical, physical, pieces) =
        parts(resolve(&join(vec![piece("const", 5, 4)], None)).unwrap());
    assert_eq!(
        (kind, logical, physical, pieces[0].lsb_byte),
        (JoinKind::Concatenation, 4, 4, Some(0))
    );
    let (kind, ..) = parts(resolve(&join(vec![piece("const", 5, 4)], Some(8))).unwrap());
    assert_eq!(kind, JoinKind::FloatExtension);
}

fn invalid(storage: Storage) -> &'static str {
    match resolve(&storage) {
        Err(AbiError::InvalidStorage(reason)) => reason,
        other => panic!("expected invalid storage, got {other:?}"),
    }
}

#[test]
fn invalid_join_variants_fail_explicitly() {
    assert_eq!(invalid(join(vec![], None)), "empty join");
    assert_eq!(invalid(join(vec![], Some(4))), "empty join");
    // Java writes a logical size equal to the piece sum as 0, so a single
    // non-constant piece is rejected either way.
    for logical in [None, Some(0), Some(4)] {
        assert_eq!(
            invalid(join(vec![reg("r0")], logical)),
            "single physical join requires a distinct logical size"
        );
    }
    assert_eq!(
        invalid(join(vec![reg("r0"), reg("r1")], Some(4))),
        "logical size override requires one join piece"
    );
    for logical in [None, Some(0), Some(8)] {
        let (kind, l, ..) = parts(resolve(&join(vec![reg("r0"), reg("r1")], logical)).unwrap());
        assert_eq!((kind, l), (JoinKind::Concatenation, 8));
    }
    assert_eq!(
        invalid(join(vec![reg("r0"), piece("ram", 0, 0)], None)),
        "zero join piece size"
    );
    assert!(matches!(
        resolve(&join(vec![reg("r0"), piece("join", 0, 4)], None)),
        Err(AbiError::InvalidStorage(_))
    ));
    assert!(matches!(
        resolve(&join(vec![reg("r0"), reg("nope")], None)),
        Err(AbiError::UnknownRegister(n)) if n == "nope"
    ));
    assert!(matches!(
        resolve(&join(vec![reg("r0"), piece("nope", 0, 4)], None)),
        Err(AbiError::UnknownSpace(n)) if n == "nope"
    ));
    assert!(matches!(
        resolve(&join(vec![reg("r0"), piece("ram", 0xffff_fffe, 4)], None)),
        Err(AbiError::AddressRange {
            offset: 0xffff_fffe,
            size: Some(4),
            ..
        })
    ));
}

#[test]
fn join_byte_totals_and_piece_counts_are_bounded_exactly() {
    // u32::MAX bytes in total is representable; one more byte overflows.
    let (_, _, physical, pieces) = parts(
        resolve(&join(
            vec![piece("OTHER", 0, u32::MAX - 1), piece("OTHER", 0, 1)],
            None,
        ))
        .unwrap(),
    );
    assert_eq!(physical, u32::MAX);
    assert_eq!((pieces[0].lsb_byte, pieces[1].lsb_byte), (Some(1), Some(0)));
    is_limit(
        resolve(&join(
            vec![piece("OTHER", 0, u32::MAX), piece("OTHER", 0, 1)],
            None,
        )),
        "join bytes",
    );

    let file = small_file();
    let run = |count: usize, name: &str, limits: AbiLimits| {
        resolve_storage(
            &file,
            None,
            &join(vec![reg(name); count], None),
            None,
            limits,
        )
    };
    let default = AbiLimits::default();
    assert_eq!(default.max_join_pieces, 1024);
    let (_, _, physical, pieces) = parts(run(1024, "r0", default).unwrap());
    assert_eq!((physical, pieces.len()), (4096, 1024));
    assert_eq!(pieces[0].lsb_byte, Some(4092));
    // The count is checked before any name is resolved.
    is_limit(run(1025, "unknown", default), "join pieces");
    let small = AbiLimits {
        max_join_pieces: 3,
        max_total_pieces: 3,
        ..default
    };
    run(3, "r0", small).unwrap();
    is_limit(run(4, "unknown", small), "join pieces");
    is_limit(
        run(
            3,
            "r0",
            AbiLimits {
                max_total_pieces: 2,
                ..small
            },
        ),
        "storage pieces",
    );
}
