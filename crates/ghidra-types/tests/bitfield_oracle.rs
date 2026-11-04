//! Generated bitfield composites against an independent bit-cursor reference.
//!
//! Production follows the retained AlignedComponentPacker byte state machine:
//! a byte offset plus "bits consumed" read back from the previous bitfield's
//! normalized offset and minimal storage. This reference instead keeps one
//! absolute allocation-order bit cursor and derives byte offsets, minimal
//! storage and both byte orders' bit offsets from bit ranges. Its placement
//! rule is the window statement of the source boundary test: a continuation
//! bitfield of base size S and placement alignment a moves to the next
//! a-aligned byte if it would leave the S-byte window starting at the
//! a-aligned byte at or below its first byte. Scalar alignment uses a linear
//! map scan, separate from production geometry.
//!
//! Rules the source states procedurally are restated here and labeled:
//! MS allocation-unit reservation, zero-width deferral, and the
//! declaration-order policy for adjacent zero-width bitfields. The reference
//! is limited to nondecreasing power-of-two size maps, where LCM is maximum.
//!
//! Independently of the reference, every generated layout must also satisfy
//! storage, nonoverlap, ordering, containment and byte-order properties.

use ghidra_languages::{DataOrganization, ResolvedDataOrganization, SizeAlignment};
use ghidra_types::*;

struct Deterministic(u64);

impl Deterministic {
    fn pick(&mut self, bound: usize) -> usize {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        ((self.0 >> 24) % bound as u64) as usize
    }
}

fn round(value: u64, alignment: u32) -> u64 {
    value.div_ceil(u64::from(alignment)) * u64::from(alignment)
}

fn round_down(value: u64, alignment: u32) -> u64 {
    value / u64::from(alignment) * u64::from(alignment)
}

fn size_alignment(bytes: u64, org: &ResolvedDataOrganization) -> u32 {
    let mut alignment = org.default_alignment;
    for entry in &org.size_alignment_map {
        if u64::from(entry.size) <= bytes {
            alignment = entry.alignment;
        }
    }
    alignment
}

/// Reference facts about a prelude type, computed without production code.
#[derive(Debug, Clone, Copy)]
struct Meta {
    raw: u64,
    member_bytes: u64,
    alignment: u32,
    /// Alignment of the unsigned integer of the raw size (enum bases).
    primitive: u32,
    eligible: bool,
}

fn integer_meta(bytes: u64, org: &ResolvedDataOrganization) -> Meta {
    let aligned = round(bytes, size_alignment(bytes, org));
    let alignment = size_alignment(aligned, org);
    Meta {
        raw: bytes,
        member_bytes: aligned,
        alignment,
        primitive: alignment,
        eligible: true,
    }
}

/// The fixed prelude and its reference facts.
fn prelude(org: &ResolvedDataOrganization) -> (Vec<TypeDefinition>, Vec<Meta>) {
    let mut entries: Vec<(TypeKind, Meta)> = Vec::new();
    let mut push = |kind: TypeKind, meta: Meta| entries.push((kind, meta));
    for (builtin, bytes) in [
        (Builtin::Char, org.char_size),
        (Builtin::UnsignedChar, org.char_size),
        (Builtin::Short, org.short_size),
        (Builtin::UnsignedShort, org.short_size),
        (Builtin::Int, org.integer_size),
        (Builtin::UnsignedInt, org.integer_size),
        (Builtin::LongLong, org.long_long_size),
        (Builtin::Bool, 1),
    ] {
        push(
            TypeKind::Builtin(builtin),
            integer_meta(u64::from(bytes), org),
        );
    }
    push(
        TypeKind::Integer {
            bytes: 3,
            signed: true,
        },
        integer_meta(3, org),
    );
    for bytes in [1, 2, 3, 4, 8] {
        push(
            TypeKind::Enum {
                bytes,
                signed: false,
            },
            Meta {
                raw: u64::from(bytes),
                member_bytes: u64::from(bytes),
                alignment: size_alignment(u64::from(bytes), org),
                primitive: integer_meta(u64::from(bytes), org).alignment,
                eligible: true,
            },
        );
    }
    let int = integer_meta(u64::from(org.integer_size), org);
    let char_meta = integer_meta(u64::from(org.char_size), org);
    let short = integer_meta(u64::from(org.short_size), org);
    let enum3 = Meta {
        raw: 3,
        member_bytes: 3,
        alignment: size_alignment(3, org),
        primitive: integer_meta(3, org).alignment,
        eligible: true,
    };
    push(TypeKind::Alias(TypeId(4)), int);
    push(TypeKind::Alias(TypeId(11)), enum3);
    push(TypeKind::Alias(TypeId(15)), enum3);
    let ineligible = |member_bytes, alignment| Meta {
        raw: member_bytes,
        member_bytes,
        alignment,
        primitive: alignment,
        eligible: false,
    };
    push(
        TypeKind::Array {
            element: TypeId(0),
            count: 3,
        },
        ineligible(3 * char_meta.member_bytes, char_meta.alignment),
    );
    push(
        TypeKind::Array {
            element: TypeId(4),
            count: 0,
        },
        ineligible(0, int.alignment),
    );
    push(TypeKind::Structure(Composite::default()), ineligible(0, 1));
    push(
        TypeKind::Structure(Composite {
            minimum_alignment: MinimumAlignment::Explicit(8),
            ..Default::default()
        }),
        ineligible(0, 8),
    );
    // { short; char }: three bytes padded to the short's alignment.
    let padded = round(short.member_bytes + char_meta.member_bytes, short.alignment);
    push(
        TypeKind::Structure(Composite {
            fields: vec![Field::new("s", TypeId(2)), Field::new("c", TypeId(0))],
            ..Default::default()
        }),
        ineligible(padded, short.alignment),
    );
    entries
        .into_iter()
        .map(|(kind, meta)| (TypeDefinition::new("", kind), meta))
        .unzip()
}

#[derive(Debug, Clone, Copy)]
enum Decl {
    Ordinary { ty: usize },
    Bits { ty: usize, declared: u32 },
}

#[derive(Debug, Clone, Copy)]
struct Config {
    ms: bool,
    big: bool,
    type_alignment: bool,
    boundary: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Placed {
    offset: u64,
    bytes: u64,
    /// (declared, effective, base bytes, storage bytes, bit offset)
    bits: Option<(u32, u32, u64, u64, u8)>,
}

#[derive(Debug, PartialEq, Eq)]
struct Shape {
    fields: Vec<Placed>,
    size: u64,
    alignment: u32,
}

/// Turn an allocation-order bit range into reported storage.
fn bit_range(start: u64, width: u64, big: bool) -> (u64, u64, u8) {
    let offset = start / 8;
    let storage = (start + width).div_ceil(8) - offset;
    let low = start % 8;
    let bit_offset = if big { 8 * storage - width - low } else { low };
    (offset, storage, bit_offset as u8)
}

#[derive(Debug, Clone, Copy)]
enum Previous {
    Start,
    Ordinary {
        end: u64,
    },
    Bits {
        end_bit: u64,
        unit: u64,
    },
    /// A zero-width bitfield awaiting its successor.
    Zero {
        index: usize,
        group: u64,
        imposed: Option<u32>,
        natural: u32,
        unit: u64,
    },
    Trailing {
        offset: u64,
    },
}

fn reference_structure(
    decls: &[Decl],
    metas: &[Meta],
    config: Config,
    packing: Option<u32>,
    minimum: u32,
) -> Shape {
    let cap = |alignment: u32| packing.map_or(alignment, |p| alignment.min(p));
    let mut alignment = 1;
    let mut contribute = |a: u32| alignment = alignment.max(cap(a));
    let mut fields: Vec<Placed> = Vec::new();
    let mut previous = Previous::Start;
    // MS: start of the reserved allocation unit (Java groupOffset).
    let mut reserve = 0u64;
    let zero_bit = if config.big { 7 } else { 0 };
    for (index, decl) in decls.iter().enumerate() {
        let last = index + 1 == decls.len();
        // Byte position where a new group starts (Java getLength).
        let group_start = |previous: Previous| match previous {
            Previous::Start => 0,
            Previous::Ordinary { end } => end,
            Previous::Bits { unit, .. } if config.ms => reserve + unit,
            Previous::Bits { end_bit, .. } => end_bit.div_ceil(8),
            Previous::Zero { unit, .. } if config.ms => reserve + unit,
            // Policy: an unresolved :0 sits at its trailing placement.
            Previous::Zero { group, natural, .. } => round(group, natural),
            Previous::Trailing { offset } => offset,
        };
        match *decl {
            Decl::Ordinary { ty } => {
                let meta = metas[ty];
                let a = cap(meta.alignment);
                let start = match previous {
                    Previous::Zero {
                        index: z,
                        group,
                        imposed,
                        ..
                    } => {
                        let start = round(group, a).max(imposed.map_or(group, |i| round(group, i)));
                        fields[z].offset = start;
                        start
                    }
                    Previous::Start => 0,
                    Previous::Ordinary { end } if !config.ms => round(end, a),
                    Previous::Bits { end_bit, .. } if !config.ms => round(end_bit.div_ceil(8), a),
                    // MS starts a new group for every ordinary member.
                    _ => {
                        let start = round(group_start(previous), a);
                        reserve = start;
                        start
                    }
                };
                contribute(a);
                fields.push(Placed {
                    offset: start,
                    bytes: meta.member_bytes,
                    bits: None,
                });
                previous = Previous::Ordinary {
                    end: start + meta.member_bytes,
                };
            }
            Decl::Bits { ty, declared: 0 } => {
                let meta = metas[ty];
                // Policy for adjacent :0 members: the first keeps its
                // trailing placement.
                if let Previous::Zero {
                    index: z,
                    group,
                    natural,
                    ..
                } = previous
                {
                    fields[z].offset = round(group, natural);
                }
                let group = group_start(previous);
                reserve = group;
                let after_bitfield =
                    matches!(previous, Previous::Bits { .. } | Previous::Zero { .. });
                let imposed = if config.ms {
                    // MS ignores :0 unless it follows a bitfield; flags are fixed.
                    after_bitfield.then(|| cap(meta.alignment))
                } else if !config.type_alignment {
                    Some(config.boundary.max(1))
                } else if last {
                    Some(cap(meta.alignment))
                } else {
                    // GCC places an interior :0 by natural alignment.
                    Some(meta.alignment)
                };
                if let (true, Some(i)) = (config.ms, imposed) {
                    contribute(i);
                }
                fields.push(Placed {
                    offset: 0,
                    bytes: 0,
                    bits: Some((0, 0, meta.raw, 1, zero_bit)),
                });
                if last {
                    // Natural base alignment places a trailing :0, even packed.
                    let offset = round(group, meta.alignment);
                    fields[index].offset = offset;
                    contribute(imposed.unwrap_or(1));
                    previous = Previous::Trailing { offset };
                } else {
                    previous = Previous::Zero {
                        index,
                        group,
                        imposed,
                        natural: meta.alignment,
                        unit: meta.raw,
                    };
                }
            }
            Decl::Bits { ty, declared } => {
                let meta = metas[ty];
                let width = u64::from(declared).min(8 * meta.raw);
                contribute(meta.primitive);
                let start_bit = match previous {
                    Previous::Zero {
                        index: z,
                        group,
                        imposed,
                        ..
                    } => {
                        // MS uses this bitfield's alignment; GCC uses the :0's.
                        let minimum = if config.ms {
                            Some(cap(meta.alignment))
                        } else {
                            imposed
                        };
                        let natural = minimum.map_or(group, |m| round(group, m));
                        let start = natural.max(imposed.map_or(group, |i| round(group, i)));
                        fields[z].offset = start;
                        if let Some(m) = minimum {
                            contribute(m);
                        }
                        reserve = start;
                        // No boundary test follows a :0 (source behavior).
                        8 * start
                    }
                    Previous::Start if !config.ms => 0,
                    Previous::Ordinary { end } if !config.ms => {
                        let window = if packing.is_some() {
                            1
                        } else {
                            cap(meta.alignment)
                        };
                        contribute(window);
                        place(8 * end, width, meta.raw, window)
                    }
                    Previous::Bits { end_bit, .. } if !config.ms => {
                        let window = if packing.is_some() {
                            1
                        } else {
                            cap(meta.alignment)
                        };
                        contribute(window);
                        place(end_bit, width, meta.raw, window)
                    }
                    Previous::Bits { end_bit, unit } if config.ms && unit == meta.raw => {
                        let window = cap(meta.alignment);
                        contribute(window);
                        let bit = place(end_bit, width, meta.raw, window);
                        // Source reservation rule: the tentative last byte uses
                        // the bits consumed before any move.
                        let tentative = ((end_bit % 8) + width).div_ceil(8);
                        if bit / 8 + tentative > reserve + unit {
                            reserve = bit / 8;
                        }
                        bit
                    }
                    // MS starts a new unit at a transition or base-size change.
                    _ => {
                        let start = round(group_start(previous), cap(meta.primitive));
                        reserve = start;
                        8 * start
                    }
                };
                let (offset, storage, bit_offset) = bit_range(start_bit, width, config.big);
                fields.push(Placed {
                    offset,
                    bytes: storage,
                    bits: Some((declared, width as u32, meta.raw, storage, bit_offset)),
                });
                previous = Previous::Bits {
                    end_bit: start_bit + width,
                    unit: meta.raw,
                };
            }
        }
    }
    let length = match previous {
        Previous::Start => 0,
        Previous::Ordinary { end } => end,
        Previous::Bits { unit, .. } if config.ms => reserve + unit,
        Previous::Bits { end_bit, .. } => end_bit.div_ceil(8),
        Previous::Trailing { offset } => offset,
        Previous::Zero { .. } => unreachable!("a final :0 is trailing"),
    };
    let alignment = alignment.max(minimum);
    Shape {
        fields,
        size: round(length, alignment),
        alignment,
    }
}

/// Window rule: stay in the S-byte window at the a-aligned byte at or below
/// the first byte, else move to the next a-aligned byte.
fn place(bit: u64, width: u64, unit: u64, window: u32) -> u64 {
    let window_start = 8 * round_down(bit / 8, window);
    if bit + width > window_start + 8 * unit {
        window_start + 8 * u64::from(window)
    } else {
        bit
    }
}

fn reference_union(
    decls: &[Decl],
    metas: &[Meta],
    config: Config,
    packing: Option<u32>,
    minimum: u32,
) -> Shape {
    let cap = |alignment: u32| packing.map_or(alignment, |p| alignment.min(p));
    let mut alignment = 1;
    let mut length = 0;
    let mut fields = Vec::new();
    for decl in decls {
        match *decl {
            Decl::Ordinary { ty } => {
                let meta = metas[ty];
                alignment = alignment.max(cap(meta.alignment));
                length = length.max(meta.member_bytes);
                fields.push(Placed {
                    offset: 0,
                    bytes: meta.member_bytes,
                    bits: None,
                });
            }
            Decl::Bits { ty, declared } => {
                let meta = metas[ty];
                let width = u64::from(declared).min(8 * meta.raw);
                let storage = width.div_ceil(8).max(1);
                let allocation = if config.ms {
                    meta.raw
                } else if width == 0 {
                    0
                } else {
                    match packing {
                        Some(p) if meta.raw > u64::from(p) => {
                            // Least common multiple by search.
                            let mut multiple = storage;
                            while multiple % u64::from(p) != 0 {
                                multiple += storage;
                            }
                            multiple
                        }
                        _ => meta.raw,
                    }
                };
                if config.ms || width != 0 {
                    alignment = alignment.max(cap(meta.alignment));
                }
                length = length.max(allocation);
                let bit_offset = match (config.big, width) {
                    (false, _) => 0,
                    (true, 0) => 7,
                    (true, _) => 8 * storage - width,
                };
                fields.push(Placed {
                    offset: 0,
                    bytes: if width == 0 { 0 } else { storage },
                    bits: Some((declared, width as u32, meta.raw, storage, bit_offset as u8)),
                });
            }
        }
    }
    let alignment = alignment.max(minimum);
    Shape {
        fields,
        size: round(length, alignment),
        alignment,
    }
}

fn actual(layout: &TypeLayout) -> Shape {
    Shape {
        fields: layout
            .fields
            .iter()
            .map(|f| Placed {
                offset: f.offset,
                bytes: f.bytes,
                bits: f.bitfield.map(|b| {
                    (
                        b.declared_bits,
                        b.effective_bits,
                        b.base_bytes,
                        b.storage_bytes,
                        b.bit_offset,
                    )
                }),
            })
            .collect(),
        size: layout.geometry.size.unwrap(),
        alignment: layout.geometry.alignment,
    }
}

/// Properties that hold without any reference model.
fn check_properties(shape: &Shape, union: bool, big: bool, context: &str) {
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    let mut frontier = 0;
    for (index, field) in shape.fields.iter().enumerate() {
        let (start, end) = match field.bits {
            Some((declared, effective, base, storage, bit_offset)) => {
                assert_eq!(
                    u64::from(effective),
                    u64::from(declared).min(8 * base),
                    "{context}"
                );
                if effective == 0 {
                    assert_eq!((field.bytes, storage), (0, 1), "{context}");
                    assert_eq!(bit_offset, if big { 7 } else { 0 }, "{context}");
                    continue;
                }
                assert_eq!(field.bytes, storage, "{context}");
                assert!(storage <= base, "{context}: storage within its base");
                let spare = 8 * storage - u64::from(effective);
                assert!(u64::from(bit_offset) <= spare, "{context}");
                // Minimal storage: fewer than eight spare bits at either end.
                assert!(
                    u64::from(bit_offset) < 8 && spare - u64::from(bit_offset) < 8,
                    "{context}"
                );
                let low = if big {
                    spare - u64::from(bit_offset)
                } else {
                    u64::from(bit_offset)
                };
                let start = 8 * field.offset + low;
                (start, start + u64::from(effective))
            }
            None if field.bytes == 0 => continue,
            None => (8 * field.offset, 8 * (field.offset + field.bytes)),
        };
        assert!(
            end <= 8 * shape.size,
            "{context}: field {index} is contained"
        );
        if union {
            assert_eq!(
                start, 0,
                "{context}: union member {index} starts at bit zero"
            );
        } else {
            assert!(
                start >= frontier,
                "{context}: field {index} follows its predecessors"
            );
            frontier = end;
            for &(other_start, other_end) in &ranges {
                assert!(
                    end <= other_start || start >= other_end,
                    "{context}: overlap"
                );
            }
            ranges.push((start, end));
        }
    }
    assert_eq!(shape.size % u64::from(shape.alignment), 0, "{context}");
}

fn map(entries: &[(u32, u32)]) -> Vec<SizeAlignment> {
    entries
        .iter()
        .map(|&(size, alignment)| SizeAlignment { size, alignment })
        .collect()
}

/// Nondecreasing power-of-two maps, including an 8-byte type aligned to 4.
fn profiles() -> Vec<ResolvedDataOrganization> {
    let conventional = DataOrganization::default().resolve(8);
    let mut i386 = conventional.clone();
    i386.size_alignment_map = map(&[(1, 1), (2, 2), (4, 4), (8, 4)]);
    let mut wide = conventional.clone();
    wide.short_size = 4;
    wide.integer_size = 8;
    wide.long_long_size = 16;
    wide.size_alignment_map = map(&[(1, 1), (2, 2), (4, 4), (8, 8), (16, 16)]);
    vec![conventional, i386, wide]
}

fn generate(random: &mut Deterministic, metas: &[Meta]) -> (bool, Vec<Decl>, Option<u32>, u32) {
    let union = random.pick(4) == 0;
    let packing = [None, None, Some(1), Some(2), Some(4), Some(8)][random.pick(6)];
    let minimum = [1, 1, 1, 2, 16][random.pick(5)];
    let eligible: Vec<usize> = (0..metas.len()).filter(|i| metas[*i].eligible).collect();
    let count = 1 + random.pick(10);
    let decls = (0..count)
        .map(|_| match random.pick(20) {
            0..=6 => Decl::Ordinary {
                ty: random.pick(metas.len()),
            },
            7..=9 => Decl::Bits {
                ty: eligible[random.pick(eligible.len())],
                declared: 0,
            },
            _ => {
                let ty = eligible[random.pick(eligible.len())];
                let limit = 8 * metas[ty].raw as usize;
                let declared = match random.pick(10) {
                    0 => limit + random.pick(256 - limit.min(255)),
                    1 => limit,
                    _ => 1 + random.pick(limit.min(24)),
                };
                Decl::Bits {
                    ty,
                    declared: declared.min(255) as u32,
                }
            }
        })
        .collect();
    (union, decls, packing, minimum)
}

#[test]
fn generated_bitfield_composites_match_the_bit_cursor_reference() {
    let mut composites = 0;
    let mut bitfields = 0;
    let mut zero_widths = 0;
    let mut moved = 0;
    for (profile, base_org) in profiles().into_iter().enumerate() {
        // GCC zero-width settings; MS forces its own and must ignore these.
        let settings = [
            (false, true, 0),
            (false, false, 0),
            (false, false, 16),
            (true, true, 0),
            (true, false, 16),
        ];
        for (ms, type_alignment, boundary) in settings {
            let mut org = base_org.clone();
            org.use_ms_bitfield_convention = ms;
            org.bitfield_type_alignment_enabled = type_alignment;
            org.bitfield_zero_length_boundary = boundary;
            let (mut definitions, metas) = prelude(&org);
            let first = definitions.len();
            let mut random = Deterministic(
                0x5eed_0000 ^ (profile as u64) << 8 ^ u64::from(ms) << 4 ^ u64::from(boundary),
            );
            let mut generated = Vec::new();
            for _ in 0..300 {
                let (union, decls, packing, minimum) = generate(&mut random, &metas);
                let composite = Composite {
                    fields: decls
                        .iter()
                        .map(|decl| match *decl {
                            Decl::Ordinary { ty } => Field::new("", TypeId(ty)),
                            Decl::Bits { ty, declared } => {
                                Field::bitfield("", TypeId(ty), declared)
                            }
                        })
                        .collect(),
                    packing: packing.map_or(Packing::Default, Packing::Explicit),
                    minimum_alignment: if minimum == 1 {
                        MinimumAlignment::Default
                    } else {
                        MinimumAlignment::Explicit(minimum)
                    },
                };
                definitions.push(TypeDefinition::new(
                    "",
                    if union {
                        TypeKind::Union(composite)
                    } else {
                        TypeKind::Structure(composite)
                    },
                ));
                generated.push((union, decls, packing, minimum));
            }
            let definitions: std::sync::Arc<[TypeDefinition]> = definitions.into();
            let mut shapes = Vec::new();
            for big in [false, true] {
                let config = Config {
                    ms,
                    big,
                    type_alignment,
                    boundary,
                };
                let endianness = if big {
                    Endianness::Big
                } else {
                    Endianness::Little
                };
                let layouts = TypeLayouts::new_with_endianness(
                    definitions.clone(),
                    org.clone(),
                    endianness,
                    Limits::default(),
                )
                .unwrap();
                let mut by_order = Vec::new();
                for (index, (union, decls, packing, minimum)) in generated.iter().enumerate() {
                    let context = format!(
                        "profile={profile} MS={ms} typeAlign={type_alignment} boundary={boundary} \
                         big={big} union={union} pack={packing:?} min={minimum} decls={decls:?}"
                    );
                    let reference = if *union {
                        reference_union(decls, &metas, config, *packing, *minimum)
                    } else {
                        reference_structure(decls, &metas, config, *packing, *minimum)
                    };
                    let shape = actual(layouts.layout(TypeId(first + index)).unwrap());
                    assert_eq!(shape, reference, "{context}");
                    check_properties(&shape, *union, big, &context);
                    if !big {
                        composites += 1;
                        for decl in decls {
                            if let Decl::Bits { declared, .. } = decl {
                                bitfields += 1;
                                zero_widths += usize::from(*declared == 0);
                            }
                        }
                        moved += usize::from(!union && moved_bitfield(&shape));
                    }
                    by_order.push(shape);
                }
                shapes.push(by_order);
            }
            // Byte geometry is independent of byte order.
            for (little, big) in shapes[0].iter().zip(&shapes[1]) {
                assert_eq!((little.size, little.alignment), (big.size, big.alignment));
                for (l, b) in little.fields.iter().zip(&big.fields) {
                    assert_eq!((l.offset, l.bytes), (b.offset, b.bytes));
                }
            }
        }
    }
    println!(
        "{composites} composites, {bitfields} bitfields, {zero_widths} zero-width, {moved} with a moved bitfield"
    );
    assert_eq!(composites, 4500);
    // The generator exercises enough bitfields, zero widths and window moves.
    assert!(bitfields > 15_000, "{bitfields}");
    assert!(zero_widths > 3_500, "{zero_widths}");
    assert!(moved > 500, "{moved}");
}

/// True when an adjacent nonzero bitfield does not start where its
/// predecessor ended: the window rule or a new MS unit moved it.
fn moved_bitfield(shape: &Shape) -> bool {
    let mut previous_end = None;
    for placed in &shape.fields {
        match placed.bits {
            Some((_, effective, _, _, bit_offset)) if effective > 0 => {
                let start = 8 * placed.offset + u64::from(bit_offset);
                if previous_end.is_some_and(|end| start != end) {
                    return true;
                }
                previous_end = Some(start + u64::from(effective));
            }
            _ => previous_end = None,
        }
    }
    false
}
