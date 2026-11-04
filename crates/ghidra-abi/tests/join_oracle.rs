//! Independent source-literal reference for native `MultiSlotAssign`.
//!
//! The reference transcribes modelrules.cc (`checkFit` including its
//! non-advancing adjacency loop, `initializeEntries`, `assignAddress`,
//! `justifyPieces`) and fspec.cc (`extractTiles`, `getStackEntry`,
//! `getAddrBySlot` with native floor-division slot alignment,
//! `assignAddressFromPieces`) over native `int4` statuses. The fixture owns
//! its entries, groups and byte layout; the reference never calls ABI
//! placement or reads resolved entries to find tiles. It also models the
//! Rust held-extent policy independently (whole exclusion tiles, used stack
//! slots) to check physical occupancy byte-exactly.
mod common;

use std::collections::BTreeSet;
use std::sync::Arc;

use ghidra_abi::*;
use ghidra_languages::StorageClass;
use ghidra_pcode::Endianness;

const G: StorageClass = StorageClass::General;
const F: StorageClass = StorageClass::Float;
const P: StorageClass = StorageClass::Ptr;
const V: StorageClass = StorageClass::Vector;

#[derive(Clone, Debug)]
struct Entry {
    class: StorageClass,
    min: i32,
    size: i32,
    alignment: i32,
    groups: Vec<usize>,
    stack: bool,
    base: i64,
}

#[derive(Clone, Debug)]
struct Fixture {
    entries: Vec<Entry>,
    group_count: usize,
    big: bool,
    positive: bool,
    output: bool,
    aligned_pool: Option<usize>,
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

impl Fixture {
    fn generate(rng: &mut Rng) -> Self {
        let mut f = Fixture {
            entries: Vec::new(),
            group_count: 0,
            big: rng.chance(50),
            positive: rng.chance(20),
            output: rng.chance(30),
            aligned_pool: None,
        };
        let count = 1 + rng.below(7) as usize;
        let mut ptr_index = 0;
        for i in 0..count {
            if rng.chance(20) {
                f.single(P, 4, 0x2000 + 0x10 * ptr_index);
                ptr_index += 1;
            }
            let class = if rng.chance(55) {
                G
            } else if rng.chance(80) {
                F
            } else {
                P
            };
            let size = rng.pick(&[1, 2, 4, 4, 4, 8, 8]);
            f.single(class, size, 0x1000 + 0x10 * i as i64);
        }
        // An aligned pool over the first two register entries inherits both
        // groups and keeps its slot cursor in the first one.
        if count >= 2 && f.entries[0].base == 0x1000 && rng.chance(30) {
            let first = f.entries[0].groups[0];
            let second = f.entries.iter().find(|e| e.base == 0x1010).unwrap().groups[0];
            f.aligned_pool = Some(f.entries.len());
            f.entries.push(Entry {
                class: V,
                min: 1,
                size: 32,
                alignment: 8,
                groups: vec![first, second],
                stack: false,
                base: 0x1000,
            });
        }
        if rng.chance(90) {
            let alignment = rng.pick(&[1, 2, 4, 4, 8]);
            let size = alignment * rng.pick(&[2, 4, 8, 16]);
            let group = f.group_count;
            f.group_count += 1;
            f.entries.push(Entry {
                class: G,
                min: if size >= 4 && rng.chance(20) { 4 } else { 1 },
                size,
                // An exclusion stack entry is not getStackEntry's spill pool.
                alignment: if rng.chance(5) { 0 } else { alignment },
                groups: vec![group],
                stack: true,
                base: rng.pick(&[0, 8, 16, -16]),
            });
        }
        f
    }

    fn single(&mut self, class: StorageClass, size: i32, base: i64) {
        let group = self.group_count;
        self.group_count += 1;
        self.entries.push(Entry {
            class,
            min: 1,
            size,
            alignment: 0,
            groups: vec![group],
            stack: false,
            base,
        });
    }

    fn xml(&self) -> String {
        let mut list = String::new();
        for e in &self.entries {
            let class = match e.class {
                StorageClass::General => "general",
                StorageClass::Float => "float",
                StorageClass::Ptr => "ptr",
                StorageClass::Vector => "vector",
                other => panic!("{other:?}"),
            };
            let align = if e.alignment == 0 {
                String::new()
            } else {
                format!(r#" align="{}""#, e.alignment)
            };
            let space = if e.stack { "stack" } else { "register" };
            list.push_str(&format!(
                r#"<pentry minsize="{}" maxsize="{}"{align} storage="{class}"><addr space="{space}" offset="{}"/></pentry>"#,
                e.min, e.size, e.base
            ));
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
        // Ensure the fixture-owned groups describe the parsed declarations.
        let actual = resources.list(0, self.direction()).unwrap();
        assert_eq!(actual.group_count, self.group_count);
        for (entry, expected) in actual.entries.iter().zip(&self.entries) {
            assert_eq!(
                entry.groups.iter().map(|g| g.0).collect::<Vec<_>>(),
                expected.groups
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

    fn site(&self, entry: usize) -> BindingSite {
        if self.output {
            BindingSite::Output { model: 0, entry }
        } else {
            BindingSite::Input { model: 0, entry }
        }
    }
}

/// Fixture-owned byte extent: (stack, first, last).
type Held = (bool, i64, i64);

#[derive(Clone, Copy)]
struct Config {
    class: StorageClass,
    big: bool,
    stack: bool,
    most_sig: bool,
    enforce: bool,
    right: bool,
    backfill: bool,
}

/// `MultiSlotAssign(res)` then `decode`.
fn configure(f: &Fixture, a: &JoinAttributes) -> Config {
    let mut c = Config {
        class: G,
        big: f.big,
        stack: !f.output,
        most_sig: false,
        enforce: false,
        right: false,
        backfill: false,
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
    if let Some(class) = a.storage {
        c.class = class;
    }
    if let Some(v) = a.align {
        c.enforce = v;
    }
    if let Some(v) = a.stack_spill {
        c.stack = v;
    }
    if let Some(v) = a.backfill {
        c.backfill = v;
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

fn held_slots(e: &Entry, index: i32, slots: i32) -> Held {
    let first = e.base + i64::from(index) * i64::from(e.alignment);
    (e.stack, first, first + i64::from(slots * e.alignment) - 1)
}

#[allow(clippy::too_many_arguments)]
fn check_fit(
    f: &Fixture,
    c: &Config,
    tiles: &[usize],
    iter: usize,
    mut size_left: i32,
    align: i32,
    resources_consumed: i32,
    tmp: &[i32],
) -> bool {
    let mut entry = &f.entries[tiles[iter]];
    if tmp[entry.groups[0]] != 0 {
        return false;
    }
    if c.enforce {
        let reg_size = entry.size;
        if align > reg_size && (resources_consumed % align) != 0 {
            return false;
        }
    }
    // adjacentEntries is always true. The retained loop never increments
    // iter; it is transcribed literally (and terminates for positive sizes).
    while iter != tiles.len() && size_left > 0 {
        entry = &f.entries[tiles[iter]];
        if tmp[entry.groups[0]] != 0 {
            return false;
        }
        size_left -= entry.size;
    }
    true
}

#[derive(Debug, PartialEq)]
enum Value {
    /// (stack, offset, size) most significant first.
    Pieces(Vec<(bool, i64, i32)>),
    Float {
        base: i64,
        size: i32,
        logical: i32,
    },
}

#[derive(Debug)]
enum Expected {
    NoTiles,
    MissingStack,
    /// `fail`, with whether the stack was attempted.
    Fail {
        stack_attempted: bool,
    },
    /// justifyPieces would build a nonpositive piece width.
    InvalidJustify,
    Success {
        value: Value,
        held: Vec<Held>,
    },
}

fn assign(f: &Fixture, c: &Config, status: &mut Vec<i32>, size: i32, align: i32) -> Expected {
    let tiles = extract_tiles(f, c.class);
    let stack_entry = get_stack_entry(f);
    if tiles.is_empty() {
        return Expected::NoTiles;
    }
    if c.stack && stack_entry.is_none() {
        return Expected::MissingStack;
    }
    let mut tmp = status.clone();
    let mut pieces: Vec<(bool, i64, i32)> = Vec::new();
    let mut held = Vec::new();
    let mut size_left = size;
    let mut align = align;
    let mut iter = 0;
    let mut resources_consumed = 0;
    while iter != tiles.len() {
        if check_fit(
            f,
            c,
            &tiles,
            iter,
            size_left,
            align,
            resources_consumed,
            &tmp,
        ) {
            break;
        }
        let entry = &f.entries[tiles[iter]];
        if !c.backfill {
            tmp[entry.groups[0]] = -1;
        }
        resources_consumed += entry.size;
        iter += 1;
    }
    while size_left > 0 && iter != tiles.len() {
        let entry = &f.entries[tiles[iter]];
        iter += 1;
        if tmp[entry.groups[0]] != 0 {
            continue;
        }
        let trial_size = entry.size;
        // isLeftJustified follows the space byte order; a full-width
        // exclusion slot has no justification offset either way.
        let mut slot = tmp[entry.groups[0]];
        let (addr, _, _) = get_addr_by_slot(f, entry, &mut slot, trial_size, align, f.big)
            .expect("an untouched exclusion tile holds its own width");
        tmp[entry.groups[0]] = -1;
        // An exclusion stack entry of the class is a tile too.
        pieces.push((entry.stack, addr, trial_size));
        held.push((
            entry.stack,
            entry.base,
            entry.base + i64::from(entry.size) - 1,
        ));
        size_left -= trial_size;
        align = 1;
    }
    let mut value = None;
    if size_left > 0 {
        if !c.stack {
            return Expected::Fail {
                stack_attempted: false,
            };
        }
        let stack = &f.entries[stack_entry.unwrap()];
        let grp = stack.groups[0];
        let mut slot = tmp[grp];
        let Some((addr, index, slots)) =
            get_addr_by_slot(f, stack, &mut slot, size_left, align, c.right)
        else {
            return Expected::Fail {
                stack_attempted: true,
            };
        };
        tmp[grp] = slot;
        pieces.push((true, addr, size_left));
        held.push(held_slots(stack, index, slots));
    } else if size_left < 0 {
        if c.class == F && pieces.len() == 1 {
            value = Some(Value::Float {
                base: pieces[0].1,
                size: pieces[0].2,
                logical: size,
            });
        } else {
            // justifyPieces
            let offset = -size_left;
            let add_offset = c.big ^ c.most_sig ^ c.right;
            let pos = if c.right { 0 } else { pieces.len() - 1 };
            let vndata = &mut pieces[pos];
            if add_offset {
                vndata.1 += i64::from(offset);
            }
            vndata.2 -= offset;
            if vndata.2 <= 0 {
                return Expected::InvalidJustify;
            }
        }
    }
    *status = tmp;
    let value = value.unwrap_or_else(|| {
        if !c.most_sig && pieces.len() > 1 {
            pieces.reverse();
        }
        Value::Pieces(pieces)
    });
    Expected::Success { value, held }
}

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

fn actual_value(a: &JoinAllocation) -> Value {
    match &a.storage {
        JoinStorage::Pieces(pieces) => {
            // Significance must be consistent with most-significant-first order.
            let mut lsb = 0;
            for p in pieces.iter().rev() {
                assert_eq!(p.piece.lsb_byte, lsb);
                lsb += p.piece.storage.size.unwrap();
            }
            assert_eq!(lsb, a.size);
            Value::Pieces(
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
                    .collect(),
            )
        }
        JoinStorage::FloatConversion {
            container,
            logical_size,
        } => Value::Float {
            base: container.address.offset as i64,
            size: container.size.unwrap() as i32,
            logical: *logical_size as i32,
        },
    }
}

fn option(rng: &mut Rng) -> Option<bool> {
    rng.pick(&[None, None, Some(false), Some(true)])
}

#[derive(Default, Debug)]
struct Coverage {
    layouts: usize,
    comparisons: usize,
    assigned: usize,
    spilled: usize,
    stack_only: usize,
    cropped: usize,
    float_conversions: usize,
    skipped: usize,
    backfilled_skips: usize,
    positive_cursor_skips: usize,
    gap_spans: usize,
    no_fit_disabled: usize,
    no_fit_stack: usize,
    invalid_justify: usize,
    no_tiles: usize,
    missing_stack: usize,
    big_endian: usize,
    output: usize,
    positive_growth: usize,
}

#[test]
fn join_action_matches_a_source_literal_native_reference() {
    let mut rng = Rng(0x6a09_e667_f3bc_c908);
    let mut cov = Coverage::default();
    while cov.layouts < 6_000 {
        let f = Fixture::generate(&mut rng);
        let r = f.build();
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
        // Seed a positive cursor in the first register entry's group.
        if let Some(index) = f.aligned_pool
            && rng.chance(60)
        {
            pool(&mut s, index, 4);
            let e = &f.entries[index];
            // Positive growth reverses every aligned pool, registers included.
            let mut slot = 0;
            let (_, first, slots) = get_addr_by_slot(&f, e, &mut slot, 4, 1, false).unwrap();
            status[e.groups[0]] = slot;
            expected_held.insert(held_slots(e, first, slots));
        }
        // Pre-consume some exclusion register entries.
        for (index, e) in f.entries.iter().enumerate() {
            if e.alignment != 0 || e.stack || !rng.chance(20) {
                continue;
            }
            pool(&mut s, index, e.size as u32);
            if status[e.groups[0]] == 0 {
                status[e.groups[0]] = -1;
                expected_held.insert((false, e.base, e.base + i64::from(e.size) - 1));
            }
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

        for _ in 0..1 + rng.below(5) {
            let attributes = JoinAttributes {
                storage: if rng.chance(50) {
                    None
                } else {
                    Some(rng.pick(&[G, G, F, F, P]))
                },
                reverse_justify: option(&mut rng),
                reverse_significance: option(&mut rng),
                align: option(&mut rng),
                stack_spill: option(&mut rng),
                backfill: option(&mut rng),
            };
            let size = if rng.chance(70) {
                1 + rng.below(16) as i32
            } else {
                1 + rng.below(48) as i32
            };
            let align = rng.pick(&[1, 2, 4, 4, 8, 8, 16]);
            let config = configure(&f, &attributes);
            let before = status.clone();
            let expected = assign(&f, &config, &mut status, size, align);
            let before_state = (s.groups().to_vec(), held(&s));
            let result = s.assign_join(
                &r,
                &attributes,
                JoinRequest::new(size as u32, align as u32),
                Default::default(),
            );
            cov.comparisons += 1;
            let context = || format!("{f:#?}\n{attributes:?} size {size} align {align}");
            match (&expected, result) {
                (Expected::NoTiles, Err(JoinError::NoTiles { class })) => {
                    assert_eq!(class, config.class);
                    cov.no_tiles += 1;
                }
                (Expected::MissingStack, Err(JoinError::MissingStack)) => cov.missing_stack += 1,
                (
                    Expected::InvalidJustify,
                    Err(JoinError::Unsupported {
                        reason: "excess bytes cover the whole justified piece",
                        ..
                    }),
                ) => cov.invalid_justify += 1,
                (Expected::Fail { stack_attempted }, Ok(a)) => match (stack_attempted, a.outcome) {
                    (false, JoinOutcome::NoFit(JoinNoFit::StackSpillDisabled { .. })) => {
                        cov.no_fit_disabled += 1
                    }
                    (true, JoinOutcome::NoFit(JoinNoFit::Stack { .. })) => cov.no_fit_stack += 1,
                    (_, other) => panic!("{}\nexpected fail, got {other:?}", context()),
                },
                (Expected::Success { value, held: new }, Ok(a)) => {
                    let JoinOutcome::Assigned(allocation) = &a.outcome else {
                        panic!("{}\nexpected success, got {:?}", context(), a.outcome)
                    };
                    assert_eq!(&actual_value(allocation), value, "{}", context());
                    assert_eq!(
                        (
                            a.config.storage,
                            a.config.big_endian,
                            a.config.consume_from_stack,
                            a.config.consume_most_significant,
                            a.config.enforce_alignment,
                            a.config.justify_right,
                            a.config.backfill
                        ),
                        (
                            config.class,
                            config.big,
                            config.stack,
                            config.most_sig,
                            config.enforce,
                            config.right,
                            config.backfill
                        )
                    );
                    for &extent in new {
                        assert!(expected_held.insert(extent), "{}", context());
                    }
                    cov.assigned += 1;
                    let steps = &allocation.steps;
                    if steps
                        .iter()
                        .any(|s| matches!(s.kind, JoinStepKind::Stack { .. }))
                    {
                        cov.spilled += 1;
                        cov.stack_only += usize::from(steps.len() == 1);
                    }
                    if allocation.excess != 0 {
                        if matches!(value, Value::Float { .. }) {
                            cov.float_conversions += 1;
                        } else {
                            cov.cropped += 1;
                        }
                    }
                    if allocation.skipped_tiles != 0 {
                        cov.skipped += 1;
                        let tiles = extract_tiles(&f, config.class);
                        let skipped = &tiles[..allocation.skipped_tiles];
                        if config.backfill {
                            cov.backfilled_skips += 1;
                        }
                        if skipped.iter().any(|&t| before[f.entries[t].groups[0]] > 0) {
                            cov.positive_cursor_skips += 1;
                        }
                    }
                    let tiles: Vec<_> = steps
                        .iter()
                        .filter(|s| s.kind == JoinStepKind::Tile)
                        .map(|s| s.site)
                        .collect();
                    let all = extract_tiles(&f, config.class);
                    let positions: Vec<_> = tiles
                        .iter()
                        .map(|site| all.iter().position(|&t| f.site(t) == *site).unwrap())
                        .collect();
                    if positions.windows(2).any(|w| w[1] != w[0] + 1) {
                        cov.gap_spans += 1;
                    }
                }
                (expected, other) => {
                    panic!("{}\nexpected {expected:?}, got {other:?}", context())
                }
            }
            if !matches!(expected, Expected::Success { .. }) {
                assert_eq!(status, before);
                assert_eq!((s.groups().to_vec(), held(&s)), before_state);
            }
            assert_eq!(statuses(&s), status, "{}", context());
            assert_eq!(held(&s), expected_held, "{}", context());
        }
    }
    println!("{cov:#?}");
    assert!(cov.comparisons > 17_000, "{cov:?}");
    for (name, count) in [
        ("assigned", cov.assigned),
        ("spilled", cov.spilled),
        ("stack only", cov.stack_only),
        ("cropped", cov.cropped),
        ("float conversions", cov.float_conversions),
        ("skipped", cov.skipped),
        ("backfilled skips", cov.backfilled_skips),
        ("positive cursor skips", cov.positive_cursor_skips),
        ("gap spans", cov.gap_spans),
        ("no fit disabled", cov.no_fit_disabled),
        ("no fit stack", cov.no_fit_stack),
        ("invalid justify", cov.invalid_justify),
        ("no tiles", cov.no_tiles),
        ("missing stack", cov.missing_stack),
        ("big endian", cov.big_endian),
        ("output", cov.output),
        ("positive growth", cov.positive_growth),
    ] {
        assert!(count >= 50, "{name}: {cov:?}");
    }
}
