//! An independent interpreter of the native fallback source, compared with
//! `AllocationState::assign_native_fallback` over generated layouts.
//!
//! The interpreter transcribes `ParamListStandard::assignAddressFallback`
//! (fspec.cc:731-758) and `ParamEntry::getAddrBySlot` (fspec.cc:453-494) over
//! its own declarations: a signed `int4` status array updated by reference,
//! floor-division waste, and every `int4` operation checked where the source
//! evaluates it. Physical values, held extents and the Rust safeguards
//! (address domain, other groups in use, physical overlap) are computed in
//! interval form from the fixture's register table, so huge sizes and cursors
//! need no byte sets. Group membership is taken from the validated resource
//! pass, as in the published fallback oracle; nothing else is read from the
//! production allocator.
mod common;

use std::collections::BTreeMap;
use std::sync::Arc;

use ghidra_abi::*;
use ghidra_languages::StorageClass;
use ghidra_pcode::Endianness;

const G: StorageClass = StorageClass::General;
const F: StorageClass = StorageClass::Float;
const P: StorageClass = StorageClass::Ptr;
const INT: i64 = i32::MAX as i64;
const MAX: u32 = i32::MAX as u32;
const PAD: &str = "const:0xffffffffffffffff:4";

/// (name, register-space offset, size).
const REGISTERS: &[(&str, u64, u32)] = &[
    ("r0", 0, 4),
    ("r1", 4, 4),
    ("r2", 8, 4),
    ("r3", 12, 4),
    ("wide", 0, 8),
    ("quad", 0, 16),
    ("f0", 0x100, 4),
    ("f1", 0x104, 4),
    ("d0", 0x100, 8),
    ("d1", 0x108, 8),
    ("sp", 0x400, 4),
];

fn register(name: &str) -> (i128, u32) {
    let &(_, offset, size) = REGISTERS.iter().find(|(n, ..)| *n == name).unwrap();
    (i128::from(offset), size)
}

fn file(big: bool) -> Arc<RegisterFile> {
    let mut spaces = common::spaces(4);
    for space in &mut spaces[1..] {
        space.endianness = if big {
            Endianness::Big
        } else {
            Endianness::Little
        };
    }
    let registers = REGISTERS
        .iter()
        .map(|&(name, offset, size)| common::register(name, common::REGISTER, offset, size))
        .collect();
    Arc::new(RegisterFile::new(spaces, common::RAM, registers, Default::default()).unwrap())
}

#[derive(Clone, Debug)]
enum Shape {
    Register(&'static str),
    Join(Vec<&'static str>),
    Stack(i64),
}

#[derive(Clone, Debug)]
struct Decl {
    shape: Shape,
    min: u32,
    max: u32,
    /// As declared; see [`Decl::alignment`].
    align: u32,
    class: StorageClass,
    group: Option<usize>,
    float_ext: bool,
}

impl Decl {
    /// `ParamEntry::decode`: an alignment equal to the size is an exclusion
    /// entry (fspec.cc:549-550).
    fn alignment(&self) -> u32 {
        if self.align == self.max {
            0
        } else {
            self.align
        }
    }
}

fn to_xml(entries: &[Decl]) -> String {
    let mut text = String::new();
    let mut open = None;
    for e in entries {
        if open != e.group {
            if open.is_some() {
                text.push_str("</group>");
            }
            if e.group.is_some() {
                text.push_str("<group>");
            }
            open = e.group;
        }
        let class = match e.class {
            StorageClass::Float => "float",
            _ => "general",
        };
        let align = if e.align == 0 {
            String::new()
        } else {
            format!(r#" align="{}""#, e.align)
        };
        let extension = if e.float_ext {
            r#" extension="float""#
        } else {
            ""
        };
        let location = match &e.shape {
            Shape::Register(name) => format!(r#"<register name="{name}"/>"#),
            Shape::Stack(offset) => format!(
                r#"<addr space="stack" offset="0x{:x}"/>"#,
                *offset as i32 as u32
            ),
            Shape::Join(pieces) => {
                let attrs: String = pieces
                    .iter()
                    .enumerate()
                    .map(|(i, p)| format!(r#" piece{}="{p}""#, i + 1))
                    .collect();
                format!(r#"<addr space="join"{attrs}/>"#)
            }
        };
        text.push_str(&format!(
            r#"<pentry minsize="{}" maxsize="{}" storage="{class}"{align}{extension}>{location}</pentry>"#,
            e.min, e.max
        ));
    }
    if open.is_some() {
        text.push_str("</group>");
    }
    text
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[(self.next() % items.len() as u64) as usize]
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.next() % 100 < percent
    }
}

/// Positive growth needs a whole number of slots in every aligned pool.
fn whole(max: u32, align: u32, positive: bool) -> u32 {
    if positive && align != 0 {
        (max - max % align).max(align)
    } else {
        max
    }
}

fn generate(rng: &mut Rng, positive: bool) -> Vec<Decl> {
    let single = |name, min, max, class| Decl {
        shape: Shape::Register(name),
        min,
        max,
        align: 0,
        class,
        group: None,
        float_ext: false,
    };
    let mut entries = Vec::new();
    if rng.chance(50) {
        entries.push(Decl {
            float_ext: rng.chance(30),
            ..single("f0", rng.pick(&[1, 2, 4]), 4, F)
        });
    }
    if rng.chance(40) {
        entries.push(Decl {
            group: Some(0),
            ..single("f1", 1, 4, F)
        });
        entries.push(Decl {
            group: Some(0),
            ..single("r1", rng.pick(&[1, 2]), 4, G)
        });
    } else if rng.chance(70) {
        entries.push(single("r1", rng.pick(&[1, 2, 4]), 4, rng.pick(&[G, G, F])));
    }
    if rng.chance(70) {
        entries.push(single("r0", rng.pick(&[1, 2, 4]), 4, rng.pick(&[G, G, F])));
    }
    for name in ["r2", "r3"] {
        if rng.chance(60) {
            entries.push(single(name, rng.pick(&[1, 4]), 4, G));
        }
    }
    if rng.chance(35) {
        if rng.chance(45) {
            let align = rng.pick(&[2, 3, 4, 5]);
            entries.push(Decl {
                align,
                ..single("wide", 1, whole(8, align, positive), G)
            });
        } else {
            entries.push(single("wide", rng.pick(&[1, 5]), 8, G));
        }
    }
    if rng.chance(25) {
        entries.push(Decl {
            float_ext: rng.chance(40),
            ..single("d0", 5, 8, F)
        });
    }
    if rng.chance(20) {
        entries.push(Decl {
            float_ext: rng.chance(40),
            ..single("d1", rng.pick(&[1, 5]), 8, F)
        });
    }
    if rng.chance(15) {
        if rng.chance(50) {
            let align = rng.pick(&[2, 3, 4, 5, 8]);
            entries.push(Decl {
                align,
                ..single("quad", 1, whole(rng.pick(&[15, 16]), align, positive), G)
            });
        } else {
            entries.push(single("quad", 9, 16, G));
        }
    }
    for pieces in [
        vec!["r1", "r0"],
        vec!["r3", "r2"],
        vec!["r2", "r1"],
        vec![PAD, "r0"],
        vec!["r3", "r2", "r1", "r0"],
    ] {
        if rng.chance(20) {
            let total: u32 = pieces
                .iter()
                .map(|p| if *p == PAD { 4 } else { register(p).1 })
                .sum();
            entries.push(Decl {
                shape: Shape::Join(pieces),
                min: rng.pick(&[1, 5, total]),
                max: total,
                align: 0,
                class: G,
                group: None,
                float_ext: false,
            });
        }
    }
    let offset = rng.pick(&[0_i64, 8, -16, 0x7fff_ff00, -0x8000_0000]);
    if rng.chance(20) {
        entries.push(Decl {
            shape: Shape::Stack(offset + 4),
            min: 1,
            max: 4,
            align: 0,
            class: rng.pick(&[G, F]),
            group: None,
            float_ext: false,
        });
    }
    if rng.chance(15) {
        entries.push(Decl {
            shape: Shape::Stack(offset),
            min: 1,
            max: 8,
            align: 4,
            class: G,
            group: None,
            float_ext: false,
        });
    }
    if rng.chance(92) {
        // Huge alignment-1 pools let cursors approach i32::MAX unaligned.
        let huge = rng.chance(35);
        let align = if huge && rng.chance(35) {
            1
        } else {
            rng.pick(&[1, 2, 3, 4, 5, 6, 8, 12, 16])
        };
        let max = if huge {
            rng.pick(&[0x7fff_fff0, MAX, 0x4000_0000, 0x1234_5679])
        } else {
            rng.pick(&[16, 24, 30, 32, 36, 60, 64])
        };
        entries.push(Decl {
            shape: Shape::Stack(offset),
            min: rng.pick(&[1, 1, 2]),
            max: whole(max, align, positive),
            align,
            class: G,
            group: None,
            float_ext: false,
        });
    }
    entries
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Space {
    Const,
    Register,
    Stack,
}

/// (space, signed first byte, size).
type Piece = (Space, i128, u32);

#[derive(Debug, PartialEq)]
enum Value {
    /// Most significant first; padding pieces keep their declared offset.
    Pieces(Vec<Piece>),
    Conversion {
        container: Piece,
        logical: u32,
    },
}

#[derive(Debug, PartialEq)]
struct Fit {
    entry: usize,
    cursor: i64,
    slots: Option<(i64, i64)>,
    exclusion: bool,
    value: Value,
}

#[derive(Debug, PartialEq)]
struct Expected {
    rejected: Vec<(usize, usize, i64, i64, NoFit)>,
    fit: Option<Fit>,
    examined: u64,
    updates: u64,
}

#[derive(Debug, PartialEq)]
enum Hazard {
    Overflow(usize, NativeSlotOverflow),
    Domain(usize),
    GroupInUse(usize, usize),
    Overlap(usize, usize),
}

/// Checked native `int4` result.
fn int(value: i64, operation: NativeSlotOverflow) -> Result<i64, NativeSlotOverflow> {
    if value > INT {
        Err(operation)
    } else {
        Ok(value)
    }
}

struct Oracle<'a> {
    entries: &'a [Decl],
    groups: &'a [Vec<usize>],
    positive: bool,
    big: bool,
    reverse: bool,
    /// The source's `vector<int4> status`: -1 is consumed.
    status: Vec<i64>,
    /// (space, first, last, entry) held by earlier assignments.
    held: Vec<(Space, i128, i128, usize)>,
}

/// What `getAddrBySlot` returned: (byte offset in the pool, space used, first
/// slot) on success.
type Slot = Result<(i64, i64, i64), NoFit>;

impl Oracle<'_> {
    /// fspec.cc:453-490, with `slotnum` passed by reference.
    fn get_addr_by_slot(
        &self,
        e: &Decl,
        slotnum: &mut i64,
        sz: i64,
        type_align: i64,
    ) -> Result<Slot, NativeSlotOverflow> {
        if sz < i64::from(e.min) {
            return Ok(Err(NoFit::BelowMinimum));
        }
        if e.alignment() == 0 {
            if *slotnum != 0 {
                return Ok(Err(NoFit::ExclusionUsed));
            }
            if sz > i64::from(e.max) {
                return Ok(Err(NoFit::AboveCapacity));
            }
            return Ok(Ok((0, i64::from(e.max), 0)));
        }
        let alignment = i64::from(e.alignment());
        if type_align > alignment {
            let tmp = int(*slotnum * alignment, NativeSlotOverflow::CursorBytes)? % type_align;
            if tmp != 0 {
                *slotnum = int(
                    *slotnum + (type_align - tmp) / alignment,
                    NativeSlotOverflow::AlignedCursor,
                )?;
            }
        }
        let mut slotsused = sz / alignment;
        if sz % alignment != 0 {
            slotsused += 1;
        }
        let numslots = i64::from(e.max) / alignment;
        if int(*slotnum + slotsused, NativeSlotOverflow::CursorPlusSlots)? > numslots {
            return Ok(Err(NoFit::SlotsExhausted));
        }
        let index = if self.positive {
            numslots - *slotnum - slotsused
        } else {
            *slotnum
        };
        let first = *slotnum;
        *slotnum += slotsused;
        Ok(Ok((index * alignment, slotsused * alignment, first)))
    }

    fn base(shape: &Shape) -> (Space, i128) {
        match shape {
            Shape::Register(name) => (Space::Register, register(name).0),
            Shape::Stack(offset) => (Space::Stack, i128::from(*offset)),
            Shape::Join(_) => unreachable!(),
        }
    }

    /// The physical value: float extension before justification, then the
    /// default justification and, for joins, the native piece walk.
    fn value(&self, e: &Decl, offset: i64, spaceused: i64, sz: i64) -> Value {
        let stack = matches!(e.shape, Shape::Stack(_));
        let right = self.big && !(stack && self.reverse);
        let justify = if right { spaceused - sz } else { 0 };
        let Shape::Join(pieces) = &e.shape else {
            let (space, base) = Self::base(&e.shape);
            if e.alignment() == 0 && e.float_ext && sz != i64::from(e.max) {
                return Value::Conversion {
                    container: (space, base, e.max),
                    logical: sz as u32,
                };
            }
            return Value::Pieces(vec![(
                space,
                base + i128::from(offset + justify),
                sz as u32,
            )]);
        };
        // Logical coordinates over the concatenation; traversal byte order is
        // the first piece's space (the constant space is little endian).
        let parts: Vec<(Space, i128, i64)> = pieces
            .iter()
            .map(|p| {
                if *p == PAD {
                    (Space::Const, -1, 4)
                } else {
                    let (offset, size) = register(p);
                    (Space::Register, offset, i64::from(size))
                }
            })
            .collect();
        let total: i64 = parts.iter().map(|p| p.2).sum();
        let big = self.big && parts[0].0 != Space::Const;
        let (low, high) = (justify, justify + sz);
        let mut coordinate = if big { 0 } else { total };
        let mut out = Vec::new();
        for &(space, offset, size) in &parts {
            let base = if big { coordinate } else { coordinate - size };
            coordinate = if big { coordinate + size } else { base };
            let (left, right) = (low.max(base), high.min(base + size));
            if left >= right {
                continue;
            }
            let first = if space == Space::Const {
                offset
            } else {
                offset + i128::from(left - base)
            };
            out.push((space, first, (right - left) as u32));
        }
        Value::Pieces(out)
    }

    fn assign(
        &mut self,
        size: u32,
        type_align: u32,
        class: StorageClass,
        exact: bool,
    ) -> Result<Expected, Hazard> {
        let mut status = self.status.clone();
        let (sz, type_align) = (i64::from(size), i64::from(type_align));
        let mut expected = Expected {
            rejected: Vec::new(),
            fit: None,
            examined: 0,
            updates: 0,
        };
        for (i, e) in self.entries.iter().enumerate() {
            expected.examined += 1;
            let grp = self.groups[i][0];
            if status[grp] < 0 {
                continue;
            }
            if class != e.class && (exact || e.class != G) {
                continue;
            }
            let cursor = status[grp];
            let mut slotnum = cursor;
            let slot = self
                .get_addr_by_slot(e, &mut slotnum, sz, type_align)
                .map_err(|op| Hazard::Overflow(i, op))?;
            let (offset, spaceused, first_slot) = match slot {
                Err(reason) => {
                    if slotnum != cursor {
                        status[grp] = slotnum;
                        expected.updates += 1;
                    }
                    expected.rejected.push((i, grp, cursor, slotnum, reason));
                    continue;
                }
                Ok(fit) => fit,
            };
            let value = self.value(e, offset, spaceused, sz);
            let (low, high) = (-(1_i128 << 31), (1_i128 << 31) - 1);
            let outside = |&(space, first, size): &Piece| {
                space == Space::Stack && (first < low || first + i128::from(size) - 1 > high)
            };
            let escapes = match &value {
                Value::Pieces(pieces) => pieces.iter().any(outside),
                Value::Conversion { container, .. } => outside(container),
            };
            if escapes {
                return Err(Hazard::Domain(i));
            }
            if let Some(&g) = self.groups[i].iter().find(|&&g| g != grp && status[g] != 0) {
                return Err(Hazard::GroupInUse(i, g));
            }
            // Held storage: the whole exclusion pool (nonconstant join pieces)
            // or the used aligned slots.
            let spans: Vec<(Space, i128, i128)> = match (&e.shape, e.alignment()) {
                (Shape::Join(pieces), _) => pieces
                    .iter()
                    .filter(|p| **p != PAD)
                    .map(|p| {
                        let (offset, size) = register(p);
                        (Space::Register, offset, offset + i128::from(size) - 1)
                    })
                    .collect(),
                (shape, 0) => {
                    let (space, base) = Self::base(shape);
                    vec![(space, base, base + i128::from(e.max) - 1)]
                }
                (shape, _) => {
                    let (space, base) = Self::base(shape);
                    let first = base + i128::from(offset);
                    vec![(space, first, first + i128::from(spaceused) - 1)]
                }
            };
            let mut held = self.held.clone();
            for (space, first, last) in spans {
                let previous = held
                    .iter()
                    .filter(|h| h.0 == space && h.1 <= last && h.2 >= first)
                    .max_by_key(|h| h.1);
                if let Some(previous) = previous {
                    return Err(Hazard::Overlap(i, previous.3));
                }
                held.push((space, first, last, i));
            }
            let exclusion = e.alignment() == 0;
            if exclusion {
                for &g in &self.groups[i] {
                    status[g] = -1;
                    expected.updates += 1;
                }
            } else {
                status[grp] = slotnum;
                expected.updates += 1;
            }
            expected.fit = Some(Fit {
                entry: i,
                cursor,
                slots: (!exclusion).then_some((first_slot, slotnum)),
                exclusion,
                value,
            });
            self.status = status;
            self.held = held;
            return Ok(expected);
        }
        // fail: the status array keeps the failed candidates' waste.
        self.status = status;
        Ok(expected)
    }
}

fn entry(site: BindingSite) -> usize {
    match site {
        BindingSite::Input { entry, .. } => entry,
        other => panic!("{other:?}"),
    }
}

fn space(space: AbiSpace) -> Space {
    match space {
        AbiSpace::Stack => Space::Stack,
        AbiSpace::Language(id) if id == common::CONST => Space::Const,
        AbiSpace::Language(id) if id == common::REGISTER => Space::Register,
        other => panic!("{other:?}"),
    }
}

fn observed(value: &PlacedValue) -> Value {
    let piece = |s: &StorageRange| {
        (
            space(s.address.space),
            i128::from(s.address.offset as i64),
            s.size.unwrap(),
        )
    };
    match &value.storage {
        PlacedStorage::Bits { pieces } => Value::Pieces(
            pieces
                .iter()
                .map(|p| {
                    assert_eq!(
                        p.role == PieceRole::Padding,
                        space(p.storage.address.space) == Space::Const
                    );
                    piece(&p.storage)
                })
                .collect(),
        ),
        PlacedStorage::FloatConversion {
            container,
            logical_size,
        } => Value::Conversion {
            container: piece(container),
            logical: *logical_size,
        },
    }
}

fn hazard(error: &NativeFallbackError) -> Hazard {
    match error {
        NativeFallbackError::NativeIntRange { site, operation } => {
            Hazard::Overflow(entry(*site), *operation)
        }
        NativeFallbackError::Unsupported {
            site,
            reason: "selected storage leaves its address domain",
        } => Hazard::Domain(entry(*site)),
        NativeFallbackError::GroupInUse { site, group } => {
            Hazard::GroupInUse(entry(*site), group.0)
        }
        NativeFallbackError::Overlap { site, previous } => {
            Hazard::Overlap(entry(*site), entry(*previous))
        }
        other => panic!("unexpected error {other:?}"),
    }
}

fn request(rng: &mut Rng) -> (u32, u32, StorageClass, bool) {
    let size = if rng.chance(18) {
        rng.pick(&[
            0x1000_0000,
            0x3fff_fffc,
            0x7fff_fff0,
            0x7fff_fff3,
            MAX - 1,
            MAX,
            0x2000_0001,
        ])
    } else {
        rng.pick(&[1, 2, 3, 4, 5, 6, 7, 8, 9, 12, 16, 20, 24, 32])
    };
    let alignment = if rng.chance(18) {
        rng.pick(&[0x100, 0x4000_0000, 0x6000_0000, MAX - 1, MAX, 0x1000_0003])
    } else {
        rng.pick(&[1, 2, 3, 4, 5, 6, 8, 12, 16])
    };
    (size, alignment, rng.pick(&[G, G, F, P]), rng.chance(25))
}

#[test]
fn generated_layouts_match_a_native_interpreter() {
    let mut rng = Rng(0x0a7e_fa11_bac5);
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    let mut count = |name: &str| *counts.entry(name.to_owned()).or_default() += 1;
    let mut valid = 0;
    for _ in 0..5000 {
        let positive = rng.chance(30);
        let big = rng.chance(35);
        let reverse = big && rng.chance(30);
        let entries = generate(&mut rng, positive);
        let text = format!(
            r#"<compiler_spec><stackpointer register="sp" space="ram" {} {}/>
<default_proto><prototype name="p" extrapop="0" stackshift="0">
<input separatefloat="false">{}</input><output/></prototype></default_proto></compiler_spec>"#,
            if positive { r#"growth="positive""# } else { "" },
            if reverse {
                r#"reversejustify="true""#
            } else {
                ""
            },
            to_xml(&entries)
        );
        let spec = common::parse(&text);
        let Ok(storage) = CompilerStorage::new(Arc::new(spec), file(big), Default::default())
        else {
            count("unresolvable layout");
            continue;
        };
        let Ok(resources) = CompilerResources::new(Arc::new(storage), Default::default()) else {
            count("invalid resource layout");
            continue;
        };
        valid += 1;
        let list = resources.list(0, ParameterDirection::Input).unwrap();
        let groups: Vec<Vec<usize>> = list
            .entries
            .iter()
            .map(|e| e.groups.iter().map(|g| g.0).collect())
            .collect();
        if groups.iter().any(|g| g.len() > 1) {
            count("layouts with multi-group entries");
        }
        count(match (big, positive) {
            (false, false) => "layout: little endian",
            (true, false) => "layout: big endian",
            (_, true) => "layout: positive growth",
        });
        let mut oracle = Oracle {
            entries: &entries,
            groups: &groups,
            positive,
            big,
            reverse,
            status: vec![0; list.group_count],
            held: Vec::new(),
        };
        let mut state =
            AllocationState::new(&resources, 0, ParameterDirection::Input, Default::default())
                .unwrap();
        for step in 0..1 + rng.next() % 8 {
            let (size, alignment, class, exact) = request(&mut rng);
            let context =
                || format!("step {step}: {size:#x}/{alignment:#x} {class:?} exact={exact}\n{text}");
            let before = (
                state.groups().to_vec(),
                state.occupied().collect::<Vec<_>>(),
            );
            let expected = oracle.assign(size, alignment, class, exact);
            let actual = state.assign_native_fallback(
                &resources,
                NativeFallbackRequest::new(size, alignment, class),
                FallbackPolicy {
                    class_match: if exact {
                        ClassMatch::Exact
                    } else {
                        ClassMatch::GeneralAcceptsAny
                    },
                    ..Default::default()
                },
                Default::default(),
            );
            match (expected, actual) {
                (Ok(expected), Ok(result)) => {
                    let rejected: Vec<_> = result
                        .rejected
                        .iter()
                        .map(|c| {
                            assert_eq!(c.site, list.entries[c.entry].site);
                            (
                                c.entry,
                                c.group.0,
                                c.cursor as i64,
                                c.next_cursor as i64,
                                c.rejection,
                            )
                        })
                        .collect();
                    assert_eq!(rejected, expected.rejected, "{}", context());
                    for r in &rejected {
                        count(&format!("rejection: {:?}", r.4));
                        if r.3 != r.2 {
                            count("rejection with retained waste");
                        }
                    }
                    assert_eq!(
                        result.usage.examined_entries,
                        expected.examined,
                        "{}",
                        context()
                    );
                    assert_eq!(
                        result.usage.group_updates,
                        expected.updates,
                        "{}",
                        context()
                    );
                    match (expected.fit, &result.outcome) {
                        (None, NativeFallbackOutcome::NoFit) => count("no-fit"),
                        (Some(fit), NativeFallbackOutcome::Assigned(a)) => {
                            assert_eq!(a.entry, fit.entry, "{}", context());
                            assert_eq!(a.cursor as i64, fit.cursor, "{}", context());
                            assert_eq!(a.exclusion, fit.exclusion, "{}", context());
                            assert_eq!(
                                a.slots.map(|s| (s.first as i64, s.next as i64)),
                                fit.slots,
                                "{}",
                                context()
                            );
                            assert_eq!(
                                a.alignment_waste,
                                a.slots.map_or(0, |s| s.first - a.cursor)
                            );
                            assert_eq!(observed(&a.value), fit.value, "{}", context());
                            assert_eq!(a.value.size, size);
                            count("assignment");
                            if a.alignment_waste != 0 {
                                count("assignment after waste");
                            }
                            if size >= 0x1000_0000 {
                                count("assignment of a huge value");
                            }
                            if fit.slots.is_some_and(|s| s.1 > 0x1000_0000) {
                                count("assignment past a huge cursor");
                            }
                            if matches!(fit.value, Value::Conversion { .. }) {
                                count("float conversion");
                            }
                            let pool = entries[a.entry].alignment();
                            if (pool % 2 == 1 && pool > 1) || (alignment % 2 == 1 && alignment > 1)
                            {
                                count("assignment with odd alignment");
                            }
                        }
                        (fit, outcome) => panic!("{fit:?} vs {outcome:?}\n{}", context()),
                    }
                }
                (Err(expected), Err(error)) => {
                    assert_eq!(hazard(&error), expected, "{}", context());
                    count(format!("refused: {expected:?}").split('(').next().unwrap());
                    if let Hazard::Overflow(_, op) = expected {
                        count(&format!("overflow: {op:?}"));
                    }
                    let after = (
                        state.groups().to_vec(),
                        state.occupied().collect::<Vec<_>>(),
                    );
                    assert_eq!(after, before, "{}", context());
                }
                (expected, actual) => panic!("{expected:?} vs {actual:?}\n{}", context()),
            }
            // The full status array and held extents agree after every step.
            let statuses: Vec<_> = oracle
                .status
                .iter()
                .map(|&s| {
                    if s < 0 {
                        GroupState::Consumed
                    } else {
                        GroupState::Available {
                            used_slots: s as u64,
                        }
                    }
                })
                .collect();
            assert_eq!(state.groups(), statuses, "{}", context());
            let mut held: Vec<_> = state
                .occupied()
                .map(|e| (space(e.space), e.first, e.last, entry(e.site)))
                .collect();
            let mut expected_held = oracle.held.clone();
            held.sort();
            expected_held.sort();
            assert_eq!(held, expected_held, "{}", context());
        }
    }
    eprintln!("{valid} valid layouts: {counts:#?}");
    let at_least = |name: &str, n: usize| {
        assert!(
            counts.get(name).copied().unwrap_or(0) >= n,
            "{name}: {counts:#?}"
        )
    };
    assert!(valid >= 4000, "{counts:?}");
    at_least("assignment", 4000);
    at_least("no-fit", 500);
    at_least("assignment after waste", 100);
    at_least("assignment with odd alignment", 300);
    at_least("assignment of a huge value", 50);
    at_least("assignment past a huge cursor", 20);
    at_least("float conversion", 20);
    at_least("rejection with retained waste", 200);
    for reason in [
        "BelowMinimum",
        "ExclusionUsed",
        "AboveCapacity",
        "SlotsExhausted",
    ] {
        at_least(&format!("rejection: {reason}"), 50);
    }
    for op in ["CursorBytes", "AlignedCursor", "CursorPlusSlots"] {
        at_least(&format!("overflow: {op}"), 10);
    }
    for refusal in ["refused: Domain", "refused: GroupInUse", "refused: Overlap"] {
        at_least(refusal, 10);
    }
    at_least("layouts with multi-group entries", 200);
    at_least("layout: big endian", 300);
    at_least("layout: positive growth", 300);
}
