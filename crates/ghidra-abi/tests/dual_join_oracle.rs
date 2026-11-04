//! Independent source-literal reference for native `MultiSlotDualAssign`.
//!
//! The reference transcribes modelrules.cc (`PrimitiveExtractor::extract`,
//! `handleUnion`, `commonRefinement`, `checkOverlap`, recursively over the
//! public graph accessors; `initializeEntries`, `getFirstUnused`,
//! `getTileClass`, `assignAddress`, `justifyPieces`), fspec.cc
//! (`extractTiles`, `getStackEntry`, `getAddrBySlot` with native floor
//! division, `assignAddressFromPieces`) and type.cc `metatype2typeclass`
//! over native `int4` statuses. The fixture owns its entries, groups and byte
//! layout; the reference never calls ABI placement, the production extractor
//! or the action. It models the Rust held-extent policy independently (whole
//! exclusion tiles, used stack slots, refusal of double ownership).
mod common;
mod native_common;

use std::collections::BTreeSet;
use std::sync::Arc;

use ghidra_abi::*;
use ghidra_languages::{MetaType, StorageClass};
use ghidra_pcode::Endianness;
use ghidra_types::{Builtin, Field, MinimumAlignment, Packing, TypeId, TypeKind};
use native_common::Source;

const G: StorageClass = StorageClass::General;
const F: StorageClass = StorageClass::Float;
const P: StorageClass = StorageClass::Ptr;
const V: StorageClass = StorageClass::Vector;

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
    fn pick<T: Copy>(&mut self, items: &[T]) -> T {
        items[self.below(items.len() as u64) as usize]
    }
}

// ------------------------------------------------------------------ fixture

#[derive(Clone, Debug)]
struct Entry {
    class: StorageClass,
    min: i32,
    size: i32,
    /// `ParamEntry::alignment` after decode (zero when align == size).
    alignment: i32,
    groups: Vec<usize>,
    /// Declared `<group>` index, for the XML only.
    declared: Option<usize>,
    stack: bool,
    base: i64,
}

#[derive(Clone, Debug)]
struct Fixture {
    entries: Vec<Entry>,
    group_count: usize,
    declared_groups: usize,
    big: bool,
    positive: bool,
    output: bool,
    aligned_pool: Option<usize>,
}

impl Fixture {
    fn generate(rng: &mut Rng) -> Self {
        let tile = rng.pick(&[4, 8, 8, 8]);
        let mut f = Fixture {
            entries: Vec::new(),
            group_count: 0,
            declared_groups: 0,
            big: rng.chance(40),
            positive: rng.chance(20),
            output: rng.chance(25),
            aligned_pool: None,
        };
        let count = 1 + rng.below(12) as usize;
        let mut slot = 0;
        let mut seen = Vec::new();
        let width = |rng: &mut Rng, class: StorageClass, seen: &mut Vec<StorageClass>| {
            let first = !seen.contains(&class);
            if first {
                seen.push(class);
            }
            if first {
                if rng.chance(5) {
                    rng.pick(&[tile / 2, tile * 2])
                } else {
                    tile
                }
            } else {
                rng.pick(&[tile, tile, tile, tile, tile / 2, tile * 2])
            }
        };
        let mut i = 0;
        while i < count {
            if i + 1 < count && rng.chance(40) {
                // A MIPS64-style pair: float then general sharing one group.
                let group = f.group_count;
                let declared = f.declared_groups;
                f.group_count += 1;
                f.declared_groups += 1;
                for class in [F, G] {
                    let size = width(rng, class, &mut seen);
                    f.entries.push(Entry {
                        class,
                        min: 1,
                        size,
                        alignment: 0,
                        groups: vec![group],
                        declared: Some(declared),
                        stack: false,
                        base: 0x1000 + 0x10 * slot,
                    });
                    slot += 1;
                }
                i += 2;
                continue;
            }
            let class = if rng.chance(45) {
                G
            } else if rng.chance(75) {
                F
            } else {
                P
            };
            let size = width(rng, class, &mut seen);
            let group = f.group_count;
            f.group_count += 1;
            f.entries.push(Entry {
                class,
                min: 1,
                size,
                alignment: 0,
                groups: vec![group],
                declared: None,
                stack: false,
                base: 0x1000 + 0x10 * slot,
            });
            slot += 1;
            i += 1;
        }
        // An aligned pool over the first two single register entries inherits
        // both groups and keeps its slot cursor in the first one.
        if f.entries.len() >= 2
            && f.entries[0].declared.is_none()
            && f.entries[1].declared.is_none()
            && rng.chance(35)
        {
            let groups = vec![f.entries[0].groups[0], f.entries[1].groups[0]];
            f.aligned_pool = Some(f.entries.len());
            f.entries.push(Entry {
                class: V,
                min: 1,
                size: 32,
                alignment: 8,
                groups,
                declared: None,
                stack: false,
                base: 0x1000,
            });
        }
        if rng.chance(90) {
            let alignment = rng.pick(&[4, 8, 8]);
            let size = alignment * rng.pick(&[2, 4, 8, 16]);
            let group = f.group_count;
            f.group_count += 1;
            f.entries.push(Entry {
                class: G,
                min: if size >= 12 && rng.chance(25) { 12 } else { 1 },
                size,
                // An exclusion stack entry is not getStackEntry's spill pool
                // (it is a general tile instead).
                alignment: if rng.chance(5) { 0 } else { alignment },
                groups: vec![group],
                declared: None,
                stack: true,
                base: rng.pick(&[0, 8, 16, -16]),
            });
        }
        f
    }

    fn xml(&self) -> String {
        let mut list = String::new();
        let mut open = None;
        for e in &self.entries {
            if open != e.declared {
                if open.is_some() {
                    list.push_str("</group>");
                }
                if e.declared.is_some() {
                    list.push_str("<group>");
                }
                open = e.declared;
            }
            let class = match e.class {
                StorageClass::General => "general",
                StorageClass::Float => "float",
                StorageClass::Ptr => "ptr",
                StorageClass::Vector => "vector",
                other => panic!("{other:?}"),
            };
            let align = if e.alignment == 0 && !e.stack {
                String::new()
            } else if e.alignment == 0 {
                // align == maxsize decodes to an exclusion entry.
                format!(r#" align="{}""#, e.size)
            } else {
                format!(r#" align="{}""#, e.alignment)
            };
            let space = if e.stack { "stack" } else { "register" };
            list.push_str(&format!(
                r#"<pentry minsize="{}" maxsize="{}"{align} storage="{class}"><addr space="{space}" offset="{}"/></pentry>"#,
                e.min, e.size, e.base
            ));
        }
        if open.is_some() {
            list.push_str("</group>");
        }
        let (input, output) = if self.output {
            (String::new(), list)
        } else {
            (list, String::new())
        };
        let growth = if self.positive {
            r#" growth="positive""#
        } else {
            ""
        };
        format!(
            r#"<compiler_spec><stackpointer register="sp" space="ram"{growth}/>
<default_proto><prototype name="p" extrapop="0" stackshift="0">
<input separatefloat="false">{input}</input><output separatefloat="false">{output}</output>
</prototype></default_proto></compiler_spec>"#
        )
    }

    fn build(&self) -> CompilerResources {
        let source = common::parse(&self.xml());
        let mut spaces = common::spaces(4);
        for s in &mut spaces {
            s.endianness = if self.big {
                Endianness::Big
            } else {
                Endianness::Little
            };
        }
        let file = Arc::new(
            RegisterFile::new(
                spaces,
                common::RAM,
                vec![common::register("sp", common::REGISTER, 0x40, 4)],
                Default::default(),
            )
            .unwrap(),
        );
        let storage = common::storage(source, &file, Default::default()).unwrap();
        let resources = CompilerResources::new(Arc::new(storage), Default::default()).unwrap();
        // The fixture-owned groups must describe the parsed declarations.
        let actual = resources.list(0, self.direction()).unwrap();
        assert_eq!(actual.group_count, self.group_count, "{self:#?}");
        for (entry, expected) in actual.entries.iter().zip(&self.entries) {
            assert_eq!(
                entry.groups.iter().map(|g| g.0).collect::<Vec<_>>(),
                expected.groups,
                "{self:#?}"
            );
        }
        resources
    }

    fn direction(&self) -> ParameterDirection {
        if self.output {
            ParameterDirection::Output
        } else {
            ParameterDirection::Input
        }
    }
}

// ---------------------------------------------------------------- datatypes

/// Random declared types: scalars of every native class, structures,
/// packed structures (holes), arrays, unions, aliases and bitfields.
fn random_types(rng: &mut Rng) -> (Source, Vec<TypeId>) {
    let mut t = Source::default();
    let u8_ = t.int(1, false);
    let i16_ = t.int(2, true);
    let i32_ = t.int(4, true);
    let u32_ = t.int(4, false);
    let i64_ = t.int(8, true);
    let f32_ = t.float(4);
    let f64_ = t.float(8);
    let pointer = t.add(TypeKind::Pointer {
        target: i32_,
        bytes: None,
    });
    let flag = t.add(TypeKind::Builtin(Builtin::Bool));
    let enumeration = t.add(TypeKind::Enum {
        bytes: 4,
        signed: false,
    });
    let opaque4 = t.opaque(4);
    let opaque8 = t.opaque(8);
    let alias = t.alias(f64_);
    let mut pool = vec![
        u8_,
        i16_,
        i32_,
        u32_,
        i64_,
        f32_,
        f32_,
        f64_,
        f64_,
        f64_,
        pointer,
        flag,
        enumeration,
        opaque4,
        opaque8,
        alias,
    ];
    if rng.chance(20) {
        pool.push(t.float(10));
    }
    if rng.chance(20) {
        pool.push(t.opaque(16));
    }
    let mut roots = pool.clone();
    for _ in 0..4 + rng.below(8) {
        let pick = |rng: &mut Rng, pool: &[TypeId]| pool[rng.below(pool.len() as u64) as usize];
        let ty = match rng.below(14) {
            0..=6 => {
                let members: Vec<_> = (0..1 + rng.below(6)).map(|_| pick(rng, &pool)).collect();
                t.structure(&members)
            }
            7 => {
                let members: Vec<_> = (0..2 + rng.below(3)).map(|_| pick(rng, &pool)).collect();
                t.packed(&members)
            }
            8 | 9 => {
                let element = pick(rng, &pool[..16]);
                t.array(element, 1 + rng.below(6))
            }
            10 => {
                let members: Vec<_> = (0..1 + rng.below(3)).map(|_| pick(rng, &pool)).collect();
                t.union(&members)
            }
            11 => {
                let target = pick(rng, &pool);
                t.alias(target)
            }
            12 => t.with_fields(
                vec![
                    Field::bitfield("b", u32_, rng.pick(&[3, 8, 16])),
                    Field::new("f", pick(rng, &pool)),
                ],
                Packing::Default,
                MinimumAlignment::Default,
                false,
            ),
            _ => {
                let element = pick(rng, &pool);
                t.array(element, 1 + rng.below(3))
            }
        };
        pool.push(ty);
        roots.push(ty);
    }
    if rng.chance(10) {
        roots.push(t.structure(&[]));
    }
    if rng.chance(10) {
        roots.push(t.add(TypeKind::Void));
    }
    (t, roots)
}

// --------------------------------------------- PrimitiveExtractor (recursive)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Prim {
    ty: NativeTypeId,
    offset: i64,
    meta: MetaType,
    size: i64,
    align_size: i64,
}

struct Ex {
    prims: Vec<Prim>,
    unknown: bool,
    unaligned: bool,
    extra_space: bool,
    union_invalid: bool,
    array_primitive: bool,
}

impl Ex {
    /// `PrimitiveExtractor(dt, unionIllegal, arrayPrimitive, offset, max)`;
    /// the bool is `isValid()`.
    fn new(
        g: &NativeTypeGraph,
        dt: NativeTypeId,
        union_illegal: bool,
        array_primitive: bool,
        offset: i64,
        max: usize,
    ) -> (Self, bool) {
        let mut ex = Ex {
            prims: Vec::new(),
            unknown: false,
            unaligned: false,
            extra_space: false,
            union_invalid: union_illegal,
            array_primitive,
        };
        let valid = ex.extract(g, dt, max, offset, 0);
        (ex, valid)
    }

    fn extract(
        &mut self,
        g: &NativeTypeGraph,
        dt: NativeTypeId,
        max: usize,
        offset: i64,
        depth: i64,
    ) -> bool {
        let native = *g.get(dt).unwrap();
        let leaf = |ex: &mut Ex| {
            if ex.prims.len() >= max {
                return false;
            }
            ex.prims.push(Prim {
                ty: dt,
                offset,
                meta: native.meta,
                size: i64::from(native.size),
                align_size: i64::from(native.aligned_size),
            });
            true
        };
        match native.meta {
            MetaType::Unknown => {
                self.unknown = true;
                leaf(self)
            }
            MetaType::Int
            | MetaType::Uint
            | MetaType::Bool
            | MetaType::Code
            | MetaType::Float
            | MetaType::Ptr
            | MetaType::PtrRel => leaf(self),
            MetaType::Array => {
                if self.array_primitive && depth != 0 {
                    return leaf(self);
                }
                let array = g.array(dt).unwrap().unwrap();
                let base = *g.get(array.element).unwrap();
                let mut offset = offset;
                for _ in 0..array.count {
                    if !self.extract(g, array.element, max, offset, depth + 1) {
                        return false;
                    }
                    offset += i64::from(base.aligned_size);
                }
                true
            }
            MetaType::Union => self.handle_union(g, dt, max, offset),
            MetaType::Struct => {
                let mut expected = offset;
                for field in g.fields(dt).unwrap() {
                    let comp = *g.get(field.ty).unwrap();
                    let cur = i64::from(field.offset) + offset;
                    let align = i64::from(comp.alignment);
                    if cur % align != 0 {
                        self.unaligned = true;
                    }
                    let rem = expected % align;
                    if rem != 0 {
                        expected += align - rem;
                    }
                    if expected != cur {
                        self.extra_space = true;
                    }
                    if !self.extract(g, field.ty, max, cur, depth + 1) {
                        return false;
                    }
                    expected = cur + i64::from(comp.aligned_size);
                }
                true
            }
            _ => false,
        }
    }

    fn handle_union(
        &mut self,
        g: &NativeTypeGraph,
        dt: NativeTypeId,
        max: usize,
        offset: i64,
    ) -> bool {
        if self.union_invalid {
            return false;
        }
        let fields = g.fields(dt).unwrap();
        if fields.is_empty() {
            return false;
        }
        let (mut common, valid) = Ex::new(
            g,
            fields[0].ty,
            false,
            self.array_primitive,
            offset + i64::from(fields[0].offset),
            max,
        );
        if !valid {
            return false;
        }
        for field in &fields[1..] {
            let (next, valid) = Ex::new(
                g,
                field.ty,
                false,
                self.array_primitive,
                offset + i64::from(field.offset),
                max,
            );
            if !valid {
                return false;
            }
            match common_refinement(&common.prims, &next.prims) {
                Some(list) => common.prims = list,
                None => return false,
            }
        }
        if self.prims.len() + common.prims.len() > max {
            return false;
        }
        self.prims.extend(common.prims);
        true
    }
}

fn check_overlap(
    res: &mut Vec<Prim>,
    small: &[Prim],
    mut point: usize,
    big: Prim,
) -> Option<usize> {
    let end_off = big.offset + big.align_size;
    let use_small = big.meta == MetaType::Float;
    while point < small.len() {
        let mut cur = small[point].offset;
        if cur >= end_off {
            break;
        }
        cur += small[point].align_size;
        if cur > end_off {
            return None;
        }
        if use_small {
            res.push(small[point]);
        }
        point += 1;
    }
    if !use_small {
        res.push(big);
    }
    Some(point)
}

fn common_refinement(first: &[Prim], second: &[Prim]) -> Option<Vec<Prim>> {
    let (mut a, mut b) = (0, 0);
    let mut common = Vec::new();
    while a < first.len() && b < second.len() {
        let (x, y) = (first[a], second[b]);
        if x.offset < y.offset && x.offset + x.align_size <= y.offset {
            common.push(x);
            a += 1;
            continue;
        }
        if y.offset < x.offset && y.offset + y.align_size <= x.offset {
            common.push(y);
            b += 1;
            continue;
        }
        if x.align_size >= y.align_size {
            b = check_overlap(&mut common, second, b, x)?;
            a += 1;
        } else {
            a = check_overlap(&mut common, first, a, y)?;
            b += 1;
        }
    }
    common.extend_from_slice(&first[a..]);
    common.extend_from_slice(&second[b..]);
    Some(common)
}

// ------------------------------------------------------ MultiSlotDualAssign

#[derive(Clone, Copy, Debug)]
struct Config {
    base: StorageClass,
    alt: StorageClass,
    big: bool,
    stack: bool,
    most_sig: bool,
    right: bool,
    fill: bool,
}

/// `MultiSlotDualAssign(res)` then `decode`.
fn configure(f: &Fixture, a: &DualJoinAttributes) -> Config {
    let mut c = Config {
        base: G,
        alt: F,
        big: f.big,
        stack: false,
        most_sig: false,
        right: false,
        fill: false,
    };
    if c.big {
        c.most_sig = true;
        c.right = true;
    }
    if a.reverse_justify == Some(true) {
        c.right = !c.right;
    }
    if a.reverse_significance == Some(true) {
        c.most_sig = !c.most_sig;
    }
    if let Some(class) = a.storage_a {
        c.base = class;
    }
    if let Some(class) = a.storage_b {
        c.alt = class;
    }
    if let Some(v) = a.stack_spill {
        c.stack = v;
    }
    if let Some(v) = a.fill_alternate {
        c.fill = v;
    }
    c
}

fn extract_tiles(f: &Fixture, class: StorageClass) -> Vec<usize> {
    let mut tiles = Vec::new();
    for (i, e) in f.entries.iter().enumerate() {
        if e.alignment != 0 {
            continue;
        }
        if e.class != class || e.groups.len() != 1 {
            continue;
        }
        tiles.push(i);
    }
    tiles
}

fn get_stack_entry(f: &Fixture) -> Option<usize> {
    let last = f.entries.len().checked_sub(1)?;
    let e = &f.entries[last];
    (e.alignment != 0 && e.stack).then_some(last)
}

/// fspec.cc getAddrBySlot; also returns the slot index and slot count used.
fn get_addr_by_slot(
    f: &Fixture,
    e: &Entry,
    slotnum: &mut i32,
    sz: i32,
    type_align: i32,
    justify_right: bool,
) -> Option<(i64, i32, i32)> {
    let mut res;
    let spaceused;
    let mut index = 0;
    let mut slotsused = 1;
    if sz < e.min {
        return None;
    }
    if e.alignment == 0 {
        if *slotnum != 0 {
            return None;
        }
        if sz > e.size {
            return None;
        }
        res = e.base;
        spaceused = e.size;
    } else {
        if type_align > e.alignment {
            let tmp = (*slotnum * e.alignment) % type_align;
            if tmp != 0 {
                *slotnum += (type_align - tmp) / e.alignment;
            }
        }
        slotsused = sz / e.alignment;
        if (sz % e.alignment) != 0 {
            slotsused += 1;
        }
        let numslots = e.size / e.alignment;
        if *slotnum + slotsused > numslots {
            return None;
        }
        spaceused = slotsused * e.alignment;
        index = if f.positive {
            numslots - *slotnum - slotsused
        } else {
            *slotnum
        };
        res = e.base + i64::from(index) * i64::from(e.alignment);
        *slotnum += slotsused;
    }
    if justify_right {
        res += i64::from(spaceused - sz);
    }
    Some((res, index, slotsused))
}

/// Fixture-owned byte extent: (stack, first, last).
type Held = (bool, i64, i64);

fn held_slots(e: &Entry, index: i32, slots: i32) -> Held {
    let first = e.base + i64::from(index) * i64::from(e.alignment);
    (e.stack, first, first + i64::from(slots * e.alignment) - 1)
}

fn whole(e: &Entry) -> Held {
    (e.stack, e.base, e.base + i64::from(e.size) - 1)
}

fn intersects(a: Held, b: Held) -> bool {
    a.0 == b.0 && a.1 <= b.2 && b.1 <= a.2
}

/// type.cc metatype2typeclass.
fn metatype2typeclass(meta: MetaType) -> StorageClass {
    match meta {
        MetaType::Float => F,
        MetaType::Ptr => P,
        _ => G,
    }
}

/// getTileClass: 0 base, 1 alternate, Err(-1 reason).
fn get_tile_class(
    prims: &[Prim],
    off: i64,
    index: &mut usize,
    tile_size: i64,
    c: &Config,
) -> Result<i32, Window> {
    let mut res = 1;
    let mut count = 0;
    let end_boundary = off + tile_size;
    if *index >= prims.len() {
        return Err(Window::NoPrimitiveLeft);
    }
    let first = prims[*index];
    while *index < prims.len() {
        let element = prims[*index];
        if element.offset < off {
            return Err(Window::StartsBefore(*index));
        }
        if element.offset >= end_boundary {
            break;
        }
        if element.offset + element.size > end_boundary {
            return Err(Window::Crosses(*index));
        }
        count += 1;
        *index += 1;
        if metatype2typeclass(element.meta) != c.alt {
            res = 0;
        }
    }
    if count == 0 {
        return Err(Window::Empty);
    }
    if c.fill {
        if count > 1 {
            res = 0;
        }
        if first.size != tile_size {
            res = 0;
        }
    }
    Ok(res)
}

fn get_first_unused(mut iter: usize, tiles: &[usize], f: &Fixture, status: &[i32]) -> usize {
    while iter != tiles.len() {
        if status[f.entries[tiles[iter]].groups[0]] != 0 {
            iter += 1;
            continue;
        }
        return iter;
    }
    tiles.len()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Window {
    NoPrimitiveLeft,
    StartsBefore(usize),
    Crosses(usize),
    Empty,
}

#[derive(Debug)]
enum Expected {
    TypeError,
    NoTiles(StorageClass),
    SizeMismatch(i32, i32),
    MissingStack,
    Invalid,
    NoPrimitives,
    Holes,
    Window(i64, Window),
    Exhausted {
        alt: bool,
        offset: i64,
        uncovered: i64,
    },
    StackFail {
        uncovered: i64,
    },
    /// Status -1 for the stack when native would allocate.
    ConsumedStack,
    InvalidJustify,
    Overlap,
    Success {
        /// (stack, offset, size) most significant first.
        pieces: Vec<(bool, i64, i32)>,
        held: Vec<Held>,
        prims: Vec<Prim>,
        /// Per tile: (alternate, entry); widths other than tileSize used.
        tiles: Vec<(bool, usize)>,
        spilled: bool,
        cropped: bool,
    },
}

fn assign(
    f: &Fixture,
    c: &Config,
    status: &mut Vec<i32>,
    held_before: &BTreeSet<Held>,
    g: &NativeTypeGraph,
    dt: NativeTypeId,
    counters: &mut Coverage,
) -> Expected {
    let Ok(native) = g.get(dt) else {
        return Expected::TypeError;
    };
    // initializeEntries.
    let base_tiles = extract_tiles(f, c.base);
    let alt_tiles = extract_tiles(f, c.alt);
    let stack_entry = get_stack_entry(f);
    if base_tiles.is_empty() {
        return Expected::NoTiles(c.base);
    }
    if alt_tiles.is_empty() {
        return Expected::NoTiles(c.alt);
    }
    let tile_size = f.entries[base_tiles[0]].size;
    if tile_size != f.entries[alt_tiles[0]].size {
        return Expected::SizeMismatch(tile_size, f.entries[alt_tiles[0]].size);
    }
    if c.stack && stack_entry.is_none() {
        return Expected::MissingStack;
    }
    // assignAddress.
    let (ex, valid) = Ex::new(g, dt, false, false, 0, 1024);
    if !valid {
        return Expected::Invalid;
    }
    if ex.prims.is_empty() {
        return Expected::NoPrimitives;
    }
    if ex.extra_space {
        return Expected::Holes;
    }
    counters.unknown += usize::from(ex.unknown);
    let mut primitive_index = 0;
    let mut tmp = status.clone();
    let mut pieces: Vec<(bool, i64, i32)> = Vec::new();
    let mut tiles = Vec::new();
    let type_size = i64::from(native.size);
    let align = native.alignment as i32;
    let mut size_left = type_size;
    let mut iter_base = 0;
    let mut iter_alt = 0;
    while size_left > 0 {
        let offset = type_size - size_left;
        let before_fill = {
            let mut probe = primitive_index;
            let plain = Config { fill: false, ..*c };
            get_tile_class(&ex.prims, offset, &mut probe, i64::from(tile_size), &plain)
        };
        let iter_type = match get_tile_class(
            &ex.prims,
            offset,
            &mut primitive_index,
            i64::from(tile_size),
            c,
        ) {
            Ok(class) => class,
            Err(window) => return Expected::Window(offset, window),
        };
        if before_fill == Ok(1) && iter_type == 0 {
            counters.fill_demotions += 1;
        }
        let entry = if iter_type == 0 {
            iter_base = get_first_unused(iter_base, &base_tiles, f, &tmp);
            if iter_base == base_tiles.len() {
                if !c.stack {
                    return Expected::Exhausted {
                        alt: false,
                        offset,
                        uncovered: size_left,
                    };
                }
                break;
            }
            base_tiles[iter_base]
        } else {
            iter_alt = get_first_unused(iter_alt, &alt_tiles, f, &tmp);
            if iter_alt == alt_tiles.len() {
                if !c.stack {
                    return Expected::Exhausted {
                        alt: true,
                        offset,
                        uncovered: size_left,
                    };
                }
                break;
            }
            alt_tiles[iter_alt]
        };
        let e = &f.entries[entry];
        let trial_size = e.size;
        let mut slot = tmp[e.groups[0]];
        // getAddrBySlot(slot, trialSize, 1): isLeftJustified follows the
        // space byte order; a full-width slot has no justification offset.
        let (addr, _, _) = get_addr_by_slot(f, e, &mut slot, trial_size, 1, f.big)
            .expect("an untouched exclusion tile holds its own width");
        tmp[e.groups[0]] = -1;
        pieces.push((e.stack, addr, trial_size));
        tiles.push((iter_type == 1, entry));
        size_left -= i64::from(trial_size);
    }
    let mut stack_held = None;
    if size_left > 0 {
        assert!(c.stack);
        let stack = &f.entries[stack_entry.unwrap()];
        let grp = stack.groups[0];
        let original = tmp[grp];
        let mut slot = tmp[grp];
        let Some((addr, index, slots)) =
            get_addr_by_slot(f, stack, &mut slot, size_left as i32, align, c.right)
        else {
            return Expected::StackFail {
                uncovered: size_left,
            };
        };
        if original < 0 {
            return Expected::ConsumedStack;
        }
        tmp[grp] = slot;
        pieces.push((true, addr, size_left as i32));
        stack_held = Some(held_slots(stack, index, slots));
    }
    let mut cropped = false;
    let crop_pos = if c.right { 0 } else { pieces.len() - 1 };
    if size_left < 0 {
        // justifyPieces.
        let offset = (-size_left) as i32;
        let add_offset = c.big ^ c.most_sig ^ c.right;
        let vndata = &mut pieces[crop_pos];
        if add_offset {
            vndata.1 += i64::from(offset);
        }
        vndata.2 -= offset;
        cropped = true;
    }
    // Rust safeguards in materialization order: per tile, the crop check
    // then its whole-entry extent; then the stack slots.
    let mut held = Vec::new();
    let mut all: BTreeSet<Held> = held_before.clone();
    for (step, &(_, entry)) in tiles.iter().enumerate() {
        if cropped && step == crop_pos && pieces[step].2 <= 0 {
            return Expected::InvalidJustify;
        }
        let extent = whole(&f.entries[entry]);
        if all.iter().any(|&h| intersects(h, extent)) {
            return Expected::Overlap;
        }
        all.insert(extent);
        held.push(extent);
    }
    if let Some(extent) = stack_held {
        if all.iter().any(|&h| intersects(h, extent)) {
            return Expected::Overlap;
        }
        held.push(extent);
    }
    *status = tmp;
    // assignAddressFromPieces.
    if !c.most_sig && pieces.len() > 1 {
        pieces.reverse();
    }
    Expected::Success {
        pieces,
        held,
        prims: ex.prims,
        tiles,
        spilled: stack_held.is_some(),
        cropped,
    }
}

// --------------------------------------------------------------- comparison

fn statuses(s: &AllocationState) -> Vec<i32> {
    s.groups()
        .iter()
        .map(|g| match g {
            GroupState::Consumed => -1,
            GroupState::Available { used_slots } => *used_slots as i32,
        })
        .collect()
}

fn held(s: &AllocationState) -> BTreeSet<Held> {
    s.occupied()
        .map(|e| (e.space == AbiSpace::Stack, e.first as i64, e.last as i64))
        .collect()
}

fn actual_pieces(a: &DualJoinAllocation) -> Vec<(bool, i64, i32)> {
    let JoinStorage::Pieces(pieces) = &a.storage else {
        panic!("register tiles never convert: {a:?}")
    };
    let mut lsb = 0;
    for p in pieces.iter().rev() {
        assert_eq!(p.piece.lsb_byte, lsb);
        lsb += p.piece.storage.size.unwrap();
    }
    assert_eq!(lsb, a.size);
    pieces
        .iter()
        .map(|p| {
            let address = p.piece.storage.address;
            (
                address.space == AbiSpace::Stack,
                address.offset as i64,
                p.piece.storage.size.unwrap() as i32,
            )
        })
        .collect()
}

fn window_matches(expected: Window, actual: DualTileRejection) -> bool {
    matches!(
        (expected, actual),
        (Window::NoPrimitiveLeft, DualTileRejection::NoPrimitiveLeft)
            | (Window::Empty, DualTileRejection::EmptyWindow)
    ) || matches!((expected, actual),
        (Window::StartsBefore(a), DualTileRejection::StartsBeforeWindow { primitive: b })
        | (Window::Crosses(a), DualTileRejection::CrossesWindow { primitive: b }) if a == b)
}

fn option(rng: &mut Rng) -> Option<bool> {
    rng.pick(&[None, None, Some(false), Some(true)])
}

#[derive(Default, Debug)]
struct Coverage {
    layouts: usize,
    comparisons: usize,
    assigned: usize,
    mixed_classes: usize,
    heterogeneous: usize,
    spilled: usize,
    stack_only: usize,
    cropped: usize,
    fill_demotions: usize,
    unknown: usize,
    shared_group_skips: usize,
    positive_cursor_skips: usize,
    windows_empty: usize,
    windows_left: usize,
    windows_crossing: usize,
    windows_before: usize,
    exhausted_base: usize,
    exhausted_alt: usize,
    stack_fail: usize,
    invalid: usize,
    no_primitives: usize,
    holes: usize,
    no_tiles: usize,
    size_mismatch: usize,
    missing_stack: usize,
    invalid_justify: usize,
    overlap: usize,
    type_errors: usize,
    big_endian: usize,
    output: usize,
    positive_growth: usize,
}

#[test]
fn dual_join_action_matches_a_source_literal_native_reference() {
    let mut rng = Rng(0x3c6e_f372_fe94_f82b);
    let mut cov = Coverage::default();
    while cov.layouts < 8_000 {
        let f = Fixture::generate(&mut rng);
        let r = f.build();
        let (types, roots) = random_types(&mut rng);
        let order = if f.big {
            Endianness::Big
        } else {
            Endianness::Little
        };
        let g = native_common::bridge(types.layouts_with(native_common::organization(), order));
        cov.layouts += 1;
        cov.big_endian += usize::from(f.big);
        cov.output += usize::from(f.output);
        cov.positive_growth += usize::from(f.positive);
        let mut s = AllocationState::new(&r, 0, f.direction(), Default::default()).unwrap();
        let mut status = vec![0_i32; f.group_count];
        let mut expected_held = BTreeSet::new();
        let pool = |s: &mut AllocationState, entry: usize, size: u32| {
            s.assign_pool(
                &r,
                PoolRequest {
                    entry,
                    size,
                    alignment: 1,
                    justification: Justification::Default,
                },
                Default::default(),
            )
            .unwrap()
        };
        // Seed a positive cursor in the first register entry's group; two or
        // three slots also hold the second entry's bytes.
        if let Some(index) = f.aligned_pool
            && rng.chance(60)
        {
            let size = rng.pick(&[4, 8, 12, 20]);
            pool(&mut s, index, size as u32);
            let e = &f.entries[index];
            let mut slot = 0;
            let (_, first, slots) = get_addr_by_slot(&f, e, &mut slot, size, 1, false).unwrap();
            status[e.groups[0]] = slot;
            expected_held.insert(held_slots(e, first, slots));
        }
        // Pre-consume some exclusion register entries that hold no held byte.
        for (index, e) in f.entries.iter().enumerate() {
            if e.alignment != 0 || e.stack || !rng.chance(20) {
                continue;
            }
            if status[e.groups[0]] != 0 || expected_held.iter().any(|&h| intersects(h, whole(e))) {
                continue;
            }
            pool(&mut s, index, e.size as u32);
            status[e.groups[0]] = -1;
            expected_held.insert(whole(e));
        }
        // Advance the stack cursor.
        if let Some(index) = get_stack_entry(&f)
            && rng.chance(40)
        {
            let size = 1 + rng.below(12) as i32;
            pool(&mut s, index, size as u32);
            let e = &f.entries[index];
            let mut slot = status[e.groups[0]];
            if let Some((_, first, slots)) = get_addr_by_slot(&f, e, &mut slot, size, 1, false) {
                status[e.groups[0]] = slot;
                expected_held.insert(held_slots(e, first, slots));
            }
        }
        assert_eq!(statuses(&s), status, "seeded {f:#?}");
        assert_eq!(held(&s), expected_held);

        for _ in 0..2 + rng.below(6) {
            let attributes = DualJoinAttributes {
                storage_a: if rng.chance(75) {
                    None
                } else {
                    Some(rng.pick(&[G, G, F, P]))
                },
                storage_b: if rng.chance(75) {
                    None
                } else {
                    Some(rng.pick(&[F, F, G, P]))
                },
                reverse_justify: option(&mut rng),
                reverse_significance: option(&mut rng),
                stack_spill: option(&mut rng),
                fill_alternate: option(&mut rng),
            };
            let root = if rng.chance(3) {
                NativeTypeId(g.native_count() + 3)
            } else {
                native_common::id(roots[rng.below(roots.len() as u64) as usize])
            };
            let config = configure(&f, &attributes);
            let before = status.clone();
            let expected = assign(&f, &config, &mut status, &expected_held, &g, root, &mut cov);
            let before_state = (s.groups().to_vec(), held(&s));
            let result = s.assign_dual_join(&r, &attributes, g.clone(), root, Default::default());
            cov.comparisons += 1;
            let context = || format!("{f:#?}\n{attributes:?} root {root:?}");
            let outcome = |result: &Result<DualJoinAssignment, DualJoinError>| match result {
                Ok(a) => Some(a.outcome.clone()),
                Err(_) => None,
            };
            let outcome_expected = matches!(
                expected,
                Expected::Invalid
                    | Expected::NoPrimitives
                    | Expected::Holes
                    | Expected::Window(..)
                    | Expected::Exhausted { .. }
                    | Expected::StackFail { .. }
                    | Expected::Success { .. }
            );
            match (&expected, &result) {
                (_, Ok(_)) if outcome_expected => {}
                (Expected::TypeError, Err(DualJoinError::Type(_))) => cov.type_errors += 1,
                (Expected::NoTiles(class), Err(DualJoinError::NoTiles { class: actual })) => {
                    assert_eq!(class, actual, "{}", context());
                    cov.no_tiles += 1;
                }
                (
                    Expected::SizeMismatch(base, alternate),
                    Err(DualJoinError::TileSizeMismatch {
                        base: b,
                        alternate: a,
                    }),
                ) => {
                    assert_eq!((*base as u32, *alternate as u32), (*b, *a));
                    cov.size_mismatch += 1;
                }
                (Expected::MissingStack, Err(DualJoinError::MissingStack)) => {
                    cov.missing_stack += 1
                }
                (
                    Expected::InvalidJustify,
                    Err(DualJoinError::Unsupported {
                        reason: "excess bytes cover the whole justified piece",
                        ..
                    }),
                ) => cov.invalid_justify += 1,
                (Expected::Overlap, Err(DualJoinError::Overlap { .. })) => cov.overlap += 1,
                (
                    Expected::ConsumedStack,
                    Err(DualJoinError::Unsupported {
                        reason: "the stack pool's resource group is consumed",
                        ..
                    }),
                ) => {}
                (expected, other) => panic!("{}\nexpected {expected:?}, got {other:?}", context()),
            }
            let actual = outcome(&result);
            match &expected {
                Expected::Invalid => {
                    assert!(
                        matches!(
                            actual,
                            Some(DualJoinOutcome::NoFit(DualJoinNoFit::InvalidExtraction(_)))
                        ),
                        "{}\n{actual:?}",
                        context()
                    );
                    cov.invalid += 1;
                }
                Expected::NoPrimitives => {
                    assert_eq!(
                        actual,
                        Some(DualJoinOutcome::NoFit(DualJoinNoFit::NoPrimitives)),
                        "{}",
                        context()
                    );
                    cov.no_primitives += 1;
                }
                Expected::Holes => {
                    assert_eq!(
                        actual,
                        Some(DualJoinOutcome::NoFit(DualJoinNoFit::Holes)),
                        "{}",
                        context()
                    );
                    cov.holes += 1;
                }
                Expected::Window(offset, window) => {
                    let Some(DualJoinOutcome::NoFit(DualJoinNoFit::Window {
                        offset: o,
                        rejection,
                    })) = actual
                    else {
                        panic!("{}\nexpected window, got {actual:?}", context())
                    };
                    assert_eq!(i64::from(o), *offset, "{}", context());
                    assert!(
                        window_matches(*window, rejection),
                        "{}\n{window:?} {rejection:?}",
                        context()
                    );
                    match window {
                        Window::Empty => cov.windows_empty += 1,
                        Window::NoPrimitiveLeft => cov.windows_left += 1,
                        Window::Crosses(_) => cov.windows_crossing += 1,
                        Window::StartsBefore(_) => cov.windows_before += 1,
                    }
                }
                Expected::Exhausted {
                    alt,
                    offset,
                    uncovered,
                } => {
                    let class = if *alt {
                        DualClass::Alternate
                    } else {
                        DualClass::Base
                    };
                    assert_eq!(
                        actual,
                        Some(DualJoinOutcome::NoFit(DualJoinNoFit::Exhausted {
                            class,
                            offset: *offset as u32,
                            uncovered: *uncovered as u32
                        })),
                        "{}",
                        context()
                    );
                    if *alt {
                        cov.exhausted_alt += 1;
                    } else {
                        cov.exhausted_base += 1;
                    }
                }
                Expected::StackFail { uncovered } => {
                    assert!(
                        matches!(actual, Some(DualJoinOutcome::NoFit(DualJoinNoFit::Stack { uncovered: u, .. })) if i64::from(u) == *uncovered),
                        "{}\n{actual:?}",
                        context()
                    );
                    cov.stack_fail += 1;
                }
                Expected::Success {
                    pieces,
                    held: new,
                    prims,
                    tiles,
                    spilled,
                    cropped,
                } => {
                    let Ok(a) = &result else {
                        panic!("{}\nexpected success, got {result:?}", context())
                    };
                    let DualJoinOutcome::Assigned(allocation) = &a.outcome else {
                        panic!("{}\nexpected success, got {:?}", context(), a.outcome)
                    };
                    assert_eq!(&actual_pieces(allocation), pieces, "{}", context());
                    assert_eq!(
                        a.primitives
                            .iter()
                            .map(|p| (p.ty, i64::from(p.offset), i64::from(p.size)))
                            .collect::<Vec<_>>(),
                        prims
                            .iter()
                            .map(|p| (p.ty, p.offset, p.size))
                            .collect::<Vec<_>>()
                    );
                    assert_eq!(
                        (
                            a.config.base,
                            a.config.alternate,
                            a.config.big_endian,
                            a.config.consume_from_stack,
                            a.config.consume_most_significant,
                            a.config.justify_right,
                            a.config.fill_alternate
                        ),
                        (
                            config.base,
                            config.alt,
                            config.big,
                            config.stack,
                            config.most_sig,
                            config.right,
                            config.fill
                        )
                    );
                    let steps: Vec<_> = allocation
                        .steps
                        .iter()
                        .filter_map(|s| match s.kind {
                            DualJoinStepKind::Tile { class, .. } => Some((
                                class == DualClass::Alternate,
                                match s.site {
                                    BindingSite::Input { entry, .. }
                                    | BindingSite::Output { entry, .. } => entry,
                                    other => panic!("{other:?}"),
                                },
                            )),
                            DualJoinStepKind::Stack { .. } => None,
                        })
                        .collect();
                    assert_eq!(&steps, tiles, "{}", context());
                    for &extent in new {
                        assert!(expected_held.insert(extent), "{}", context());
                    }
                    cov.assigned += 1;
                    cov.spilled += usize::from(*spilled);
                    cov.stack_only += usize::from(*spilled && tiles.is_empty());
                    cov.cropped += usize::from(*cropped);
                    if tiles.iter().any(|t| t.0) && tiles.iter().any(|t| !t.0) {
                        cov.mixed_classes += 1;
                    }
                    if tiles
                        .iter()
                        .any(|&(_, e)| f.entries[e].size != a.config.tile_size as i32)
                    {
                        cov.heterogeneous += 1;
                    }
                    // A tile list passed over an entry whose group was free
                    // before the action but consumed in it by another entry
                    // (a declared pair seen through the other list).
                    let mut consumed_by = std::collections::BTreeMap::new();
                    for &(alt, entry) in tiles {
                        let class = if alt { config.alt } else { config.base };
                        let list = extract_tiles(&f, class);
                        let position = list.iter().position(|&t| t == entry).unwrap();
                        if list[..position].iter().any(|&t| {
                            let group = f.entries[t].groups[0];
                            before[group] == 0 && consumed_by.get(&group).is_some_and(|&e| e != t)
                        }) {
                            cov.shared_group_skips += 1;
                        }
                        if list[..position]
                            .iter()
                            .any(|&t| before[f.entries[t].groups[0]] > 0)
                        {
                            cov.positive_cursor_skips += 1;
                        }
                        consumed_by.insert(f.entries[entry].groups[0], entry);
                    }
                }
                _ => {}
            }
            if !matches!(expected, Expected::Success { .. }) {
                assert_eq!(status, before);
                assert_eq!(
                    (s.groups().to_vec(), held(&s)),
                    before_state,
                    "{}",
                    context()
                );
            }
            assert_eq!(statuses(&s), status, "{}", context());
            assert_eq!(held(&s), expected_held, "{}", context());
        }
    }
    println!("{cov:#?}");
    assert!(cov.comparisons > 35_000, "{cov:?}");
    for (name, count) in [
        ("assigned", cov.assigned),
        ("mixed classes", cov.mixed_classes),
        ("heterogeneous widths", cov.heterogeneous),
        ("spilled", cov.spilled),
        ("stack only", cov.stack_only),
        ("cropped", cov.cropped),
        ("fill demotions", cov.fill_demotions),
        ("unknown accepted", cov.unknown),
        ("shared group skips", cov.shared_group_skips),
        ("positive cursor skips", cov.positive_cursor_skips),
        ("empty windows", cov.windows_empty),
        ("no primitive left", cov.windows_left),
        ("crossing windows", cov.windows_crossing),
        ("starts before window", cov.windows_before),
        ("exhausted base", cov.exhausted_base),
        ("exhausted alternate", cov.exhausted_alt),
        ("stack no-fit", cov.stack_fail),
        ("invalid extraction", cov.invalid),
        ("no primitives", cov.no_primitives),
        ("holes", cov.holes),
        ("no tiles", cov.no_tiles),
        ("size mismatch", cov.size_mismatch),
        ("missing stack", cov.missing_stack),
        ("invalid justify", cov.invalid_justify),
        ("overlap", cov.overlap),
        ("type errors", cov.type_errors),
        ("big endian", cov.big_endian),
        ("output", cov.output),
        ("positive growth", cov.positive_growth),
    ] {
        assert!(count >= 20, "{name}: {cov:#?}");
    }
}
