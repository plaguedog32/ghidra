//! Every retained Java bitfield composite expectation, compared field by field.
//!
//! The declarations below transcribe
//! Ghidra/Features/Base/src/test/resources/ghidra/app/util/cparser/bitfields.h
//! (`unsigned short` is `ushort`, `long long` is `longlong`, and `struct`,
//! `union` and `enum` keywords are dropped). Expected text is mechanically
//! extracted from the six Java test classes into `data/retained_bitfields.rs`
//! by `data/extract_fixtures.py`. The data organizations follow
//! Ghidra/Framework/SoftwareModeling/src/test/java/ghidra/program/model/data/
//! DataOrganizationTestUtils.java. No Java code is run.

use std::collections::HashMap;

use ghidra_languages::{DataOrganization, SizeAlignment};
use ghidra_types::*;

#[path = "data/retained_bitfields.rs"]
mod retained;

fn map(entries: &[(u32, u32)]) -> Vec<SizeAlignment> {
    entries
        .iter()
        .map(|&(size, alignment)| SizeAlignment { size, alignment })
        .collect()
}

/// initDataOrganizationGcc64BitX86.
fn gcc_x86_64() -> ResolvedDataOrganization {
    let mut org = DataOrganization::default().resolve(8);
    org.absolute_max_alignment = 0;
    org.machine_alignment = 2;
    org.default_alignment = 1;
    org.default_pointer_alignment = 8;
    org.pointer_size = 8;
    org.wchar_size = 4;
    org.short_size = 2;
    org.integer_size = 4;
    org.long_size = 8;
    org.long_long_size = 8;
    org.float_size = 4;
    org.double_size = 8;
    org.long_double_size = 16;
    org.size_alignment_map = map(&[(1, 1), (2, 2), (4, 4), (8, 8), (16, 16)]);
    org.use_ms_bitfield_convention = false;
    org.bitfield_type_alignment_enabled = true;
    org.bitfield_zero_length_boundary = 0;
    org
}

/// initDataOrganizationWindows64BitX86.
fn windows_x86_64() -> ResolvedDataOrganization {
    let mut org = gcc_x86_64();
    org.wchar_size = 2;
    org.long_size = 4;
    org.long_double_size = 8;
    org.size_alignment_map = map(&[(1, 1), (2, 2), (4, 4), (8, 8)]);
    org.use_ms_bitfield_convention = true;
    org
}

/// initDataOrganization32BitMips over getDefaultOrganization(null).
fn mips32() -> ResolvedDataOrganization {
    let mut org = DataOrganization::default().resolve(4);
    org.pointer_size = 4;
    org.float_size = 4;
    org.double_size = 8;
    org.long_double_size = 8;
    org.size_alignment_map = map(&[(1, 1), (2, 2), (4, 4), (8, 8)]);
    org
}

/// (name, pack, union, C member list) in bitfields.h order.
const DECLARATIONS: &[(&str, Option<u32>, bool, &str)] = &[
    ("oddStruct", Some(1), false, "char x; int y"),
    (
        "A1",
        None,
        false,
        "char a[5]; int b:3; int c:8; int d:8; int e:6",
    ),
    (
        "A2",
        None,
        false,
        "oddStruct a; int b:3; int c:8; int d:8; int e:6",
    ),
    (
        "A3",
        None,
        false,
        "char a[5]; int b:3; int c:8; int d:85; int e:6",
    ),
    ("B1", None, false, "char a; ushort b:6; int c:8; short d:4"),
    (
        "B1flex",
        None,
        false,
        "char a; ushort b:6; int c:8; short d:4; long flex[]",
    ),
    ("B2", None, false, "char a; ushort b:6; int c:8; int d:4"),
    ("B3", None, false, "char a; ushort b:6; int c:8; char d"),
    (
        "Z1",
        None,
        false,
        "char a; int :0; ushort b:6; int c:8; short d:4",
    ),
    (
        "Z2",
        None,
        false,
        "char a; ushort b:6; int c:8; int :0; short d:4",
    ),
    (
        "Z3",
        None,
        false,
        "char a; ushort b:6; int c:8; int d:4; longlong :0",
    ),
    (
        "Z4",
        None,
        false,
        "char a; ushort b:6; int c:8; longlong :0; char d",
    ),
    (
        "Z5",
        None,
        false,
        "char a; int :0; longlong b:6; int c:8; char d",
    ),
    (
        "Z6",
        None,
        false,
        "char a; int :0; longlong b:6; int c:8; char d; longlong e:6; int f:8; char g",
    ),
    (
        "B1p1",
        Some(1),
        false,
        "char a; ushort b:6; int c:8; short d:4",
    ),
    (
        "B2p1",
        Some(1),
        false,
        "char a; ushort b:6; int c:8; int d:4",
    ),
    (
        "B3p1",
        Some(1),
        false,
        "char a; ushort b:6; int c:8; char d",
    ),
    (
        "Z1p1",
        Some(1),
        false,
        "char a; int :0; ushort b:6; int c:8; short d:4",
    ),
    (
        "Z2p1",
        Some(1),
        false,
        "char a; ushort b:6; int c:8; int :0; short d:4",
    ),
    (
        "Z3p1",
        Some(1),
        false,
        "char a; ushort b:6; int c:8; int d:4; longlong :0",
    ),
    (
        "Z4p1",
        Some(1),
        false,
        "char a; ushort b:6; int c:8; longlong :0; char d",
    ),
    ("Z3p1T", None, false, "char a; Z3p1 z3p1"),
    (
        "B1p2",
        Some(2),
        false,
        "char a; ushort b:6; int c:8; short d:4",
    ),
    (
        "B2p2",
        Some(2),
        false,
        "char a; ushort b:6; int c:8; int d:4",
    ),
    (
        "B3p2",
        Some(2),
        false,
        "char a; ushort b:6; int c:8; char d",
    ),
    (
        "B4p2",
        Some(2),
        false,
        "char a; ushort b:6; int c:8; longlong d; int e:4",
    ),
    (
        "Z1p2",
        Some(2),
        false,
        "char a; int :0; ushort b:6; int c:8; short d:4",
    ),
    (
        "Z1p2x",
        Some(2),
        false,
        "char a; int :0; ushort b:6; int c:8; short d:4; short d1:4; short d2:4; \
         short d3:4; short d4:4; short d5:4; short d6:4; short d7:4; short :0; \
         ushort _b:6; int _c:8; short _d:4; short _d1:4; short _d2:4; short _d3:4; \
         short _d4:4; short _d5:4; short _d6:4; short _d7:4",
    ),
    (
        "Z2p2",
        Some(2),
        false,
        "char a; ushort b:6; int c:8; int :0; short d:4",
    ),
    (
        "Z3p2",
        Some(2),
        false,
        "char a; ushort b:6; int c:8; int d:4; longlong :0",
    ),
    (
        "Z4p2",
        Some(2),
        false,
        "char a; ushort b:6; int c:8; longlong :0; char d",
    ),
    (
        "Z5p2",
        Some(2),
        false,
        "char a; ushort b:12; int c:8; longlong :0; char d",
    ),
    ("x1p2", Some(2), false, "char a"),
    ("x2p2", Some(2), false, "char a; int b:27"),
    ("x3p2", Some(2), false, "char a; short :0; int b:27"),
    ("x4p2", Some(2), false, "char a; int b:27; longlong :0"),
    (
        "Z5p4",
        Some(4),
        false,
        "char a; ushort b:12; int c:8; longlong :0; char d",
    ),
    ("x1p4", Some(4), false, "char a"),
    ("x2p4", Some(4), false, "char a; int b:27"),
    ("x3p4", Some(4), false, "char a; short :0; int b:27"),
    ("x4p4", Some(4), false, "char a; int b:27; longlong :0"),
    ("S1", None, false, "B1 b1; B2 b2; Z1 z1; Z2 z2; Z3 z3"),
    ("S1p1", Some(1), false, "B1 b1; B2 b2; Z1 z1; Z2 z2; Z3 z3"),
    (
        "S2p1",
        Some(1),
        false,
        "B1p1 b1p1; B2p1 b2p1; Z1p1 z1p1; Z2p1 z2p1; Z3p1 z3p1",
    ),
    ("S1p2", Some(2), false, "B1 b1; B2 b2; Z1 z1; Z2 z2; Z3 z3"),
    (
        "S2p2",
        Some(2),
        false,
        "B1p2 b1p2; B2p2 b2p2; Z1p2 z1p2; Z2p2 z2p2; Z3p2 z3p2",
    ),
    (
        "T1",
        None,
        false,
        "charTypedef a; myEnum b:3; enumTypedef c:3; charTypedef d:7",
    ),
    (
        "T2",
        None,
        false,
        "charTypedef a; intTypedef b:17; enumTypedef c:3; charTypedef d:3",
    ),
    ("U1", None, true, "int a:4; int b:2"),
    ("U1z", None, true, "int a:4; longlong :0; int b:2"),
    ("U1p1", Some(1), true, "int a:4; int b:2"),
    ("U1p1z", Some(1), true, "int a:4; longlong :0; int b:2"),
    ("SUp1", Some(1), false, "char a; U1p1z u"),
    ("U1p2", Some(2), true, "int a:4; int b:2"),
];

struct Graph {
    definitions: Vec<TypeDefinition>,
    names: HashMap<String, TypeId>,
}

impl Graph {
    fn add(&mut self, name: &str, kind: TypeKind) -> TypeId {
        let id = TypeId(self.definitions.len());
        self.definitions.push(TypeDefinition::new(name, kind));
        assert!(self.names.insert(name.to_string(), id).is_none(), "{name}");
        id
    }

    /// `char a[5]` and `long flex[]` become array types named as Java shows them.
    fn member(&mut self, declaration: &str) -> Field {
        let declaration = declaration.trim();
        let (ty, rest) = declaration.split_once(' ').expect("type and declarator");
        let (name, bits) = match rest.split_once(':') {
            Some((name, bits)) => (name.trim(), Some(bits.parse::<u32>().unwrap())),
            None => (rest.trim(), None),
        };
        let (name, ty) = match name.split_once('[') {
            Some((name, count)) => {
                let count = count.trim_end_matches(']');
                let count: u64 = if count.is_empty() {
                    0
                } else {
                    count.parse().unwrap()
                };
                let array = format!("{ty}[{count}]");
                if !self.names.contains_key(&array) {
                    let element = self.names[ty];
                    self.add(&array, TypeKind::Array { element, count });
                }
                (name, array)
            }
            None => (name, ty.to_string()),
        };
        let ty = self.names[&ty];
        match bits {
            Some(bits) => Field::bitfield(name, ty, bits),
            None => Field::new(name, ty),
        }
    }
}

fn graph() -> Graph {
    let mut graph = Graph {
        definitions: Vec::new(),
        names: HashMap::new(),
    };
    for (name, builtin) in [
        ("char", Builtin::Char),
        ("ushort", Builtin::UnsignedShort),
        ("short", Builtin::Short),
        ("int", Builtin::Int),
        ("long", Builtin::Long),
        ("longlong", Builtin::LongLong),
    ] {
        graph.add(name, TypeKind::Builtin(builtin));
    }
    // The C parser gives this enum four bytes, as the T1 fixtures show.
    let my_enum = graph.add(
        "myEnum",
        TypeKind::Enum {
            bytes: 4,
            signed: false,
        },
    );
    graph.add("enumTypedef", TypeKind::Alias(my_enum));
    for (alias, target) in [
        ("intTypedef", "int"),
        ("charTypedef", "char"),
        ("shortTypedef", "short"),
    ] {
        let target = graph.names[target];
        graph.add(alias, TypeKind::Alias(target));
    }
    for &(name, pack, union, members) in DECLARATIONS {
        let fields = members.split(';').map(|m| graph.member(m)).collect();
        let composite = Composite {
            fields,
            packing: pack.map_or(Packing::Default, Packing::Explicit),
            minimum_alignment: MinimumAlignment::Default,
        };
        let kind = if union {
            TypeKind::Union(composite)
        } else {
            TypeKind::Structure(composite)
        };
        graph.add(name, kind);
    }
    graph
}

#[derive(Debug, PartialEq, Eq)]
struct Row {
    offset: u64,
    type_name: String,
    /// Declared width and bit offset.
    bits: Option<(u32, u8)>,
    bytes: u64,
    name: String,
}

#[derive(Debug, PartialEq, Eq)]
struct Expected {
    pack: String,
    kind: String,
    rows: Vec<Row>,
    length: u64,
    alignment: u32,
}

fn parse(name: &str, text: &str) -> Expected {
    let mut lines = text.lines();
    assert_eq!(lines.next(), Some(format!("/{name}").as_str()));
    let pack = lines.next().unwrap().to_string();
    let header = lines.next().unwrap();
    let kind = header.split_whitespace().next().unwrap().to_string();
    assert_eq!(header, format!("{kind} {name} {{"));
    let mut rows = Vec::new();
    for line in lines.by_ref() {
        if line == "}" {
            break;
        }
        let tokens: Vec<_> = line.split_whitespace().collect();
        assert_eq!(*tokens.last().unwrap(), "\"\"", "{line}");
        let (type_name, bits) = match tokens[1].split_once(':') {
            Some((base, rest)) => {
                let (width, offset) = rest.trim_end_matches(')').split_once('(').unwrap();
                (
                    base.to_string(),
                    Some((width.parse().unwrap(), offset.parse().unwrap())),
                )
            }
            None => (tokens[1].to_string(), None),
        };
        rows.push(Row {
            offset: tokens[0].parse().unwrap(),
            type_name,
            bits,
            bytes: tokens[2].parse().unwrap(),
            name: if tokens.len() == 5 {
                tokens[3].to_string()
            } else {
                String::new()
            },
        });
    }
    let summary: Vec<_> = lines.next().unwrap().split_whitespace().collect();
    assert_eq!((summary[0], summary[2]), ("Length:", "Alignment:"));
    Expected {
        pack,
        kind,
        rows,
        length: summary[1].parse().unwrap(),
        alignment: summary[3].parse().unwrap(),
    }
}

fn actual(graph: &Graph, layouts: &TypeLayouts, name: &str) -> Expected {
    let id = graph.names[name];
    let (kind, composite) = match &layouts.definition(id).unwrap().kind {
        TypeKind::Structure(c) => ("Structure", c),
        TypeKind::Union(c) => ("Union", c),
        other => panic!("{name} is {other:?}"),
    };
    let layout = layouts.layout(id).unwrap();
    let rows = composite
        .fields
        .iter()
        .zip(&layout.fields)
        .map(|(field, placed)| Row {
            offset: placed.offset,
            type_name: graph.definitions[field.ty.0].name.clone(),
            bits: placed.bitfield.map(|b| (b.declared_bits, b.bit_offset)),
            bytes: placed.bytes,
            name: field.name.clone(),
        })
        .collect();
    Expected {
        pack: match composite.packing {
            Packing::Default => "pack()".to_string(),
            Packing::Explicit(n) => format!("pack({n})"),
        },
        kind: kind.to_string(),
        rows,
        length: layout.geometry.length.unwrap(),
        alignment: layout.geometry.alignment,
    }
}

fn check(
    org: ResolvedDataOrganization,
    endianness: Endianness,
    profile: &str,
    fixtures: &[&[(&str, u32, u32, &str)]],
) -> usize {
    let graph = graph();
    let layouts = TypeLayouts::new_with_endianness(
        graph.definitions.clone().into(),
        org,
        endianness,
        Limits::default(),
    )
    .unwrap();
    let mut checked = 0;
    for &(name, first, last, text) in fixtures.iter().copied().flatten() {
        assert_eq!(
            actual(&graph, &layouts, name),
            parse(name, text),
            "{profile} {name}, Java lines {first}-{last}"
        );
        checked += 1;
    }
    checked
}

#[test]
fn gcc_little_endian_matches_every_retained_fixture() {
    let checked = check(
        gcc_x86_64(),
        Endianness::Little,
        "StructureLittleEndianBitFieldTest/UnionLittleEndianBitFieldTest",
        &[retained::GCC_LE_STRUCTURES, retained::GCC_LE_UNIONS],
    );
    assert_eq!(checked, 52);
}

#[test]
fn gcc_big_endian_matches_every_retained_fixture() {
    let checked = check(
        mips32(),
        Endianness::Big,
        "StructureBigEndianBitFieldTest/UnionBigEndianBitFieldTest",
        &[retained::GCC_BE_STRUCTURES, retained::GCC_BE_UNIONS],
    );
    assert_eq!(checked, 52);
}

#[test]
fn ms_little_endian_matches_every_retained_fixture() {
    let checked = check(
        windows_x86_64(),
        Endianness::Little,
        "MSVCStructureBitFieldTest/MSVCUnionBitFieldTest",
        &[retained::MS_LE_STRUCTURES, retained::MS_LE_UNIONS],
    );
    assert_eq!(checked, 52);
}

#[test]
fn byte_order_changes_only_bit_offsets_for_every_retained_declaration() {
    // Every retained declaration, under each convention, has identical byte
    // geometry in both byte orders; bit offsets mirror within minimal storage.
    for org in [gcc_x86_64(), windows_x86_64(), mips32()] {
        let graph = graph();
        let build = |endianness| {
            TypeLayouts::new_with_endianness(
                graph.definitions.clone().into(),
                org.clone(),
                endianness,
                Limits::default(),
            )
            .unwrap()
        };
        let little = build(Endianness::Little);
        let big = build(Endianness::Big);
        for (l, b) in little.layouts().iter().zip(big.layouts()) {
            assert_eq!(l.geometry, b.geometry);
            for (lf, bf) in l.fields.iter().zip(&b.fields) {
                assert_eq!(
                    (lf.ty, lf.offset, lf.bytes, lf.alignment),
                    (bf.ty, bf.offset, bf.bytes, bf.alignment)
                );
                let (Some(lb), Some(bb)) = (lf.bitfield, bf.bitfield) else {
                    assert_eq!(lf.bitfield, bf.bitfield);
                    continue;
                };
                assert_eq!(
                    (
                        lb.declared_bits,
                        lb.effective_bits,
                        lb.base_bytes,
                        lb.storage_bytes
                    ),
                    (
                        bb.declared_bits,
                        bb.effective_bits,
                        bb.base_bytes,
                        bb.storage_bytes
                    )
                );
                if lb.is_zero_width() {
                    assert_eq!((lb.bit_offset, bb.bit_offset), (0, 7));
                } else {
                    assert_eq!(
                        u64::from(bb.bit_offset),
                        8 * lb.storage_bytes
                            - u64::from(lb.effective_bits)
                            - u64::from(lb.bit_offset)
                    );
                }
            }
        }
    }
}
