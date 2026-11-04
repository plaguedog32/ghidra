//! Independent references for the native datatype graph, extractor and
//! predicates. The reference decodes alignment maps into the dense native
//! vector (type.cc:5172/5200, lookup 3805, padding 3821/3943), converts each
//! type recursively from the Java transport facts, and runs a literal
//! recursive port of PrimitiveExtractor/commonRefinement/HomogeneousAggregate
//! (modelrules.cc:142-249, 471-490). It shares only the source `TypeLayouts`
//! (the Java side of the transport) with production; no production native
//! helper, alignment map or graph accessor is used to compute expectations.
mod native_common;

use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Arc;

use ghidra_abi::*;
use ghidra_languages::{
    Catalog, CompilerSpec, DataOrganization, DatatypeClass, DatatypeFilter, MetaType, SizeAlignment,
};
use ghidra_types::{
    Builtin, Composite, Endianness, Field, MinimumAlignment, Packing, ResolvedDataOrganization,
    TypeDefinition, TypeId, TypeKind, TypeLayouts,
};

const MAX: i64 = i32::MAX as i64;

// ---------------------------------------------------------------- alignment

struct Dense(Vec<i64>);

impl Dense {
    fn decode(declared: Option<&[SizeAlignment]>) -> Self {
        let Some(entries) = declared else {
            return Self(vec![1, 1, 2, 2, 4, 4, 4, 4, 8]);
        };
        let mut map: Vec<i64> = Vec::new();
        for entry in entries {
            while map.len() <= entry.size as usize {
                map.push(-1);
            }
            map[entry.size as usize] = i64::from(entry.alignment);
        }
        map[0] = 1;
        let mut current = 1;
        for slot in map.iter_mut().skip(1) {
            if *slot == -1 {
                *slot = current;
            } else {
                current = *slot;
            }
        }
        Self(map)
    }
    fn alignment(&self, size: i64) -> i64 {
        if size as usize >= self.0.len() {
            *self.0.last().unwrap()
        } else {
            self.0[size as usize]
        }
    }
    fn primitive(&self, size: i64) -> Option<(i64, i64, i64)> {
        let alignment = self.alignment(size);
        let rem = size % alignment;
        let padded = if rem == 0 {
            size
        } else {
            size + alignment - rem
        };
        (padded <= MAX).then(|| (size, padded, self.alignment(padded)))
    }
}

// ---------------------------------------------------------------- conversion

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
enum Key {
    Source(usize),
    Base(u32, u8),
    Bytes(u32),
    UnionBit(usize, usize),
}

fn code(meta: MetaType) -> u8 {
    match meta {
        MetaType::Int => 0,
        MetaType::Uint => 1,
        _ => 2,
    }
}

#[derive(Debug)]
struct R {
    key: Key,
    meta: MetaType,
    size: i64,
    align_size: i64,
    alignment: i64,
    enumeration: bool,
    kind: Rc<RKind>,
}

#[derive(Debug)]
enum RKind {
    Leaf,
    Array(Rc<R>, i64),
    Struct {
        fields: Vec<(i64, Rc<R>)>,
        bits: Vec<(i64, i64, i64, i64, Key)>,
    },
    Union(Vec<(i64, Rc<R>)>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Fail {
    root: usize,
    class: &'static str,
}

#[derive(Clone, Copy, Debug)]
struct Bits {
    offset: i64,
    size: i64,
    least: i64,
    bits: i64,
}

fn overlap_test(a: &Bits, b: &Bits, big: bool) -> i32 {
    let op2 = if big {
        b.least + 8 * ((a.offset + a.size) - (b.offset + b.size))
    } else {
        b.least + 8 * (b.offset - a.offset)
    };
    let this_most = a.least + a.bits;
    let op2_most = op2 + b.bits;
    if big {
        if a.least >= op2_most {
            return -1;
        }
        if op2 >= this_most {
            return 1;
        }
    } else {
        if this_most <= op2 {
            return -1;
        }
        if op2_most <= a.least {
            return 1;
        }
    }
    if a.least == op2 && this_most == op2_most {
        0
    } else if op2 <= a.least && op2_most >= this_most {
        2
    } else if a.least <= op2 && this_most >= op2_most {
        3
    } else {
        4
    }
}

struct Conv<'a> {
    layouts: &'a TypeLayouts,
    map: &'a Dense,
    big: bool,
    max_base: i64,
    memo: HashMap<usize, Result<Rc<R>, Fail>>,
    synthetic: HashMap<Key, Rc<R>>,
    dropped: BTreeSet<(usize, usize)>,
}

fn leaf(key: Key, meta: MetaType, g: (i64, i64, i64)) -> Rc<R> {
    Rc::new(R {
        key,
        meta,
        size: g.0,
        align_size: g.1,
        alignment: g.2,
        enumeration: false,
        kind: Rc::new(RKind::Leaf),
    })
}

impl Conv<'_> {
    fn fail(root: usize, class: &'static str) -> Fail {
        Fail { root, class }
    }
    fn dep(fail: Fail) -> Fail {
        Fail {
            root: fail.root,
            class: "dependency",
        }
    }
    fn prim(&self, id: usize, key: Key, meta: MetaType, size: i64) -> Result<Rc<R>, Fail> {
        if size > MAX {
            return Err(Self::fail(id, "size"));
        }
        let g = self.map.primitive(size).ok_or(Self::fail(id, "arith"))?;
        Ok(leaf(key, meta, g))
    }
    fn opaque(&self, id: usize, key: Key, bytes: i64) -> Result<Rc<R>, Fail> {
        if bytes < 16 {
            return self.prim(id, key, MetaType::Unknown, bytes);
        }
        if bytes > MAX {
            return Err(Self::fail(id, "size"));
        }
        Ok(Rc::new(R {
            key,
            meta: MetaType::Struct,
            size: bytes,
            align_size: bytes,
            alignment: 1,
            enumeration: false,
            kind: Rc::new(RKind::Struct {
                fields: vec![],
                bits: vec![],
            }),
        }))
    }
    fn base(&mut self, owner: usize, size: i64, meta: MetaType) -> Result<Rc<R>, Fail> {
        if size > self.max_base {
            let key = Key::Bytes(size as u32);
            if let Some(found) = self.synthetic.get(&key) {
                return Ok(found.clone());
            }
            let element = self.base(owner, 1, MetaType::Unknown)?;
            let total = size * element.align_size;
            if total > MAX {
                return Err(Self::fail(owner, "arith"));
            }
            let r = Rc::new(R {
                key,
                meta: MetaType::Array,
                size: total,
                align_size: total,
                alignment: element.alignment,
                enumeration: false,
                kind: Rc::new(RKind::Array(element, size)),
            });
            self.synthetic.insert(key, r.clone());
            return Ok(r);
        }
        let key = Key::Base(size as u32, code(meta));
        if let Some(found) = self.synthetic.get(&key) {
            return Ok(found.clone());
        }
        let g = self.map.primitive(size).ok_or(Self::fail(owner, "arith"))?;
        let r = leaf(key, meta, g);
        self.synthetic.insert(key, r.clone());
        Ok(r)
    }

    fn get(&mut self, id: usize) -> Result<Rc<R>, Fail> {
        if let Some(done) = self.memo.get(&id) {
            return done.clone();
        }
        let result = self.convert(id);
        self.memo.insert(id, result.clone());
        result
    }

    fn convert(&mut self, id: usize) -> Result<Rc<R>, Fail> {
        let layouts = self.layouts;
        let def = &layouts.definitions()[id];
        let layout = layouts.layout(TypeId(id)).unwrap();
        let key = Key::Source(id);
        let size = layout.geometry.size.map(|n| n as i64);
        let int = |signed: bool| {
            if signed {
                MetaType::Int
            } else {
                MetaType::Uint
            }
        };
        match &def.kind {
            TypeKind::Void => Ok(leaf(key, MetaType::Void, (0, 0, 1))),
            TypeKind::Incomplete => Err(Self::fail(id, "incomplete")),
            TypeKind::Function { .. } => Ok(leaf(key, MetaType::Code, (1, 1, 1))),
            TypeKind::Builtin(b) => {
                let meta = match b {
                    Builtin::Bool => MetaType::Bool,
                    Builtin::Float | Builtin::Double | Builtin::LongDouble => MetaType::Float,
                    Builtin::UnsignedChar
                    | Builtin::UnsignedShort
                    | Builtin::UnsignedInt
                    | Builtin::UnsignedLong
                    | Builtin::UnsignedLongLong => MetaType::Uint,
                    Builtin::Char => int(layouts.organization().char_signed),
                    _ => MetaType::Int,
                };
                self.prim(id, key, meta, size.unwrap())
            }
            TypeKind::Integer { signed, .. } => self.prim(id, key, int(*signed), size.unwrap()),
            TypeKind::Float { .. } => self.prim(id, key, MetaType::Float, size.unwrap()),
            TypeKind::Enum { signed, .. } => {
                let r = self.prim(id, key, int(*signed), size.unwrap())?;
                let r = Rc::try_unwrap(r).unwrap();
                Ok(Rc::new(R {
                    enumeration: true,
                    ..r
                }))
            }
            TypeKind::Pointer { .. } => self.prim(id, key, MetaType::Ptr, size.unwrap()),
            TypeKind::Opaque { bytes } => self.opaque(id, key, i64::from(*bytes)),
            TypeKind::Alias(target) => {
                let t = self.get(target.0).map_err(Self::dep)?;
                Ok(Rc::new(R {
                    key,
                    meta: t.meta,
                    size: t.size,
                    align_size: t.align_size,
                    alignment: t.alignment,
                    enumeration: t.enumeration,
                    kind: t.kind.clone(),
                }))
            }
            TypeKind::Array { element, count } => {
                let encoded = layout.geometry.length.unwrap() as i64;
                if *count == 0 {
                    return self.opaque(id, key, encoded);
                }
                if encoded > MAX {
                    return Err(Self::fail(id, "size"));
                }
                if *count as i64 > MAX {
                    return Err(Self::fail(id, "count"));
                }
                let e = self.get(element.0).map_err(Self::dep)?;
                let expected = *count as i64 * e.align_size;
                if expected > MAX {
                    return Err(Self::fail(id, "arith"));
                }
                if expected != encoded {
                    return Err(Self::fail(id, "mismatch"));
                }
                Ok(Rc::new(R {
                    key,
                    meta: MetaType::Array,
                    size: encoded,
                    align_size: encoded,
                    alignment: e.alignment,
                    enumeration: false,
                    kind: Rc::new(RKind::Array(e, *count as i64)),
                }))
            }
            TypeKind::Structure(c) => self.composite(id, c, false),
            TypeKind::Union(c) => self.composite(id, c, true),
        }
    }

    fn composite(&mut self, id: usize, c: &Composite, union: bool) -> Result<Rc<R>, Fail> {
        let layout = self.layouts.layout(TypeId(id)).unwrap().clone();
        let size = layout.geometry.length.unwrap() as i64;
        let alignment = i64::from(layout.geometry.alignment);
        if size > MAX {
            return Err(Self::fail(id, "size"));
        }
        if alignment == 0 || alignment > MAX {
            return Err(Self::fail(id, "alignment"));
        }
        let rem = size % alignment;
        let align_size = if rem == 0 {
            size
        } else {
            size + alignment - rem
        };
        if align_size > MAX {
            return Err(Self::fail(id, "arith"));
        }
        let mut fields = Vec::new();
        let mut bits: Vec<(i64, i64, i64, i64, Key)> = Vec::new();
        let mut kept: Vec<Bits> = Vec::new();
        let mut dropped = Vec::new();
        let mut calc = 0i64;
        let mut last = -1i64;
        for (index, (decl, fl)) in c.fields.iter().zip(&layout.fields).enumerate() {
            if fl.bytes == 0 {
                continue;
            }
            let offset = fl.offset as i64;
            if offset > MAX {
                return Err(Self::fail(id, "offset"));
            }
            if union {
                let t = if fl.bitfield.is_some() {
                    self.opaque(id, Key::UnionBit(id, index), fl.bytes as i64)
                        .map_err(|_| Self::fail(id, "arith"))?
                } else {
                    self.get(decl.ty.0).map_err(Self::dep)?
                };
                let end = offset + t.size;
                if end > MAX {
                    return Err(Self::fail(id, "arith"));
                }
                if end > size {
                    return Err(Self::fail(id, "fit"));
                }
                fields.push((offset, t));
                continue;
            }
            let t = self.get(decl.ty.0).map_err(Self::dep)?;
            if let Some(b) = fl.bitfield {
                if !matches!(t.meta, MetaType::Int | MetaType::Uint | MetaType::Bool) {
                    return Err(Self::fail(id, "nonint"));
                }
                let mut r = Bits {
                    offset,
                    least: i64::from(b.bit_offset),
                    bits: i64::from(b.effective_bits),
                    size: (i64::from(b.bit_offset) + i64::from(b.effective_bits) + 7) / 8,
                };
                if offset < last {
                    return Err(Self::fail(id, "order"));
                }
                if offset < calc
                    && (kept.is_empty() || overlap_test(kept.last().unwrap(), &r, self.big) != -1)
                {
                    dropped.push((id, index));
                    continue;
                }
                last = offset;
                calc = offset + r.size;
                if calc > MAX {
                    return Err(Self::fail(id, "arith"));
                }
                if calc > size {
                    return Err(Self::fail(id, "fit"));
                }
                if r.bits % 8 == 0 && r.least % 8 == 0 {
                    // BitRange::minimizeContainer (address.cc).
                    let trunc = r.least / 8;
                    if self.big {
                        r.size -= trunc;
                    } else {
                        r.offset += trunc;
                    }
                    r.least &= 7;
                    let num = r.size - (r.least + r.bits + 7) / 8;
                    if num > 0 {
                        if self.big {
                            r.offset += num;
                        }
                        r.size -= num;
                    }
                    let dt = if t.size == r.size {
                        t
                    } else {
                        let meta = if matches!(t.meta, MetaType::Int | MetaType::Uint) {
                            t.meta
                        } else {
                            MetaType::Unknown
                        };
                        self.base(id, r.size, meta)?
                    };
                    fields.push((r.offset, dt));
                } else {
                    bits.push((r.offset, r.size, r.least, r.bits, t.key));
                    kept.push(r);
                }
            } else {
                if t.meta == MetaType::Void {
                    return Err(Self::fail(id, "void"));
                }
                if offset < last {
                    return Err(Self::fail(id, "order"));
                }
                if offset < calc {
                    dropped.push((id, index));
                    continue;
                }
                last = offset;
                calc = offset + t.size;
                if calc > MAX {
                    return Err(Self::fail(id, "arith"));
                }
                if calc > size {
                    return Err(Self::fail(id, "fit"));
                }
                fields.push((offset, t));
            }
        }
        self.dropped.extend(dropped);
        Ok(Rc::new(R {
            key: Key::Source(id),
            meta: if union {
                MetaType::Union
            } else {
                MetaType::Struct
            },
            size,
            align_size,
            alignment,
            enumeration: false,
            kind: Rc::new(if union {
                RKind::Union(fields)
            } else {
                RKind::Struct { fields, bits }
            }),
        }))
    }
}

// ---------------------------------------------------------------- extraction

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct P {
    key: Key,
    offset: i64,
    meta: MetaType,
    size: i64,
    align_size: i64,
    alignment: i64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Reason {
    Max,
    UnionRejected(Key),
    EmptyUnion(Key),
    Incompatible(Key, i64, i64, i64, i64),
    Unsupported(Key, MetaType),
}

#[derive(Debug)]
struct Overflow;

struct Ex {
    prims: Vec<P>,
    unknown: bool,
    unaligned: bool,
    extra: bool,
    union_invalid: bool,
    array_primitive: bool,
    reason: Option<Reason>,
}

impl Ex {
    fn new(
        dt: &Rc<R>,
        union_illegal: bool,
        array_primitive: bool,
        offset: i64,
        max: i64,
    ) -> Result<Self, Overflow> {
        let mut ex = Self {
            prims: vec![],
            unknown: false,
            unaligned: false,
            extra: false,
            union_invalid: union_illegal,
            array_primitive,
            reason: None,
        };
        let valid = ex.extract(dt, max, offset, 0)?;
        assert_eq!(valid, ex.reason.is_none());
        Ok(ex)
    }

    fn primitive(&mut self, dt: &Rc<R>, max: i64, offset: i64) -> bool {
        if self.prims.len() as i64 >= max {
            self.reason = Some(Reason::Max);
            return false;
        }
        self.prims.push(P {
            key: dt.key,
            offset,
            meta: dt.meta,
            size: dt.size,
            align_size: dt.align_size,
            alignment: dt.alignment,
        });
        true
    }

    fn extract(&mut self, dt: &Rc<R>, max: i64, offset: i64, depth: i64) -> Result<bool, Overflow> {
        match dt.meta {
            MetaType::Unknown => {
                self.unknown = true;
                Ok(self.primitive(dt, max, offset))
            }
            MetaType::Int
            | MetaType::Uint
            | MetaType::Bool
            | MetaType::Code
            | MetaType::Float
            | MetaType::Ptr => Ok(self.primitive(dt, max, offset)),
            MetaType::Array => {
                if self.array_primitive && depth != 0 {
                    return Ok(self.primitive(dt, max, offset));
                }
                let RKind::Array(element, count) = &*dt.kind else {
                    unreachable!()
                };
                let mut at = offset;
                for _ in 0..*count {
                    if at > MAX {
                        return Err(Overflow);
                    }
                    if !self.extract(element, max, at, depth + 1)? {
                        return Ok(false);
                    }
                    at += element.align_size;
                }
                Ok(true)
            }
            MetaType::Union => self.union(dt, max, offset),
            MetaType::Struct => {
                let RKind::Struct { fields, .. } = &*dt.kind else {
                    unreachable!()
                };
                let mut expected = offset;
                for (field_offset, ty) in fields {
                    let current = field_offset + offset;
                    if current > MAX {
                        return Err(Overflow);
                    }
                    let align = ty.alignment;
                    if current % align != 0 {
                        self.unaligned = true;
                    }
                    if expected > MAX {
                        return Err(Overflow);
                    }
                    let rem = expected % align;
                    if rem != 0 {
                        expected += align - rem;
                        if expected > MAX {
                            return Err(Overflow);
                        }
                    }
                    if expected != current {
                        self.extra = true;
                    }
                    if !self.extract(ty, max, current, depth + 1)? {
                        return Ok(false);
                    }
                    expected = current + ty.align_size;
                }
                Ok(true)
            }
            meta => {
                self.reason = Some(Reason::Unsupported(dt.key, meta));
                Ok(false)
            }
        }
    }

    fn union(&mut self, dt: &Rc<R>, max: i64, offset: i64) -> Result<bool, Overflow> {
        if self.union_invalid {
            self.reason = Some(Reason::UnionRejected(dt.key));
            return Ok(false);
        }
        let RKind::Union(fields) = &*dt.kind else {
            unreachable!()
        };
        if fields.is_empty() {
            self.reason = Some(Reason::EmptyUnion(dt.key));
            return Ok(false);
        }
        let mut common: Option<Vec<P>> = None;
        for (field_offset, ty) in fields {
            let at = offset + field_offset;
            if at > MAX {
                return Err(Overflow);
            }
            let next = Ex::new(ty, false, self.array_primitive, at, max)?;
            if let Some(reason) = next.reason {
                self.reason = Some(reason);
                return Ok(false);
            }
            common = Some(match common {
                None => next.prims,
                Some(first) => match refine(&first, &next.prims)? {
                    Ok(list) => list,
                    Err((big, small)) => {
                        self.reason = Some(Reason::Incompatible(
                            dt.key,
                            big.offset,
                            big.align_size,
                            small.offset,
                            small.align_size,
                        ));
                        return Ok(false);
                    }
                },
            });
        }
        let common = common.unwrap();
        if (self.prims.len() + common.len()) as i64 > max {
            self.reason = Some(Reason::Max);
            return Ok(false);
        }
        self.prims.extend(common);
        Ok(true)
    }
}

fn end(p: &P) -> Result<i64, Overflow> {
    let e = p.offset + p.align_size;
    if e > MAX { Err(Overflow) } else { Ok(e) }
}

#[allow(clippy::type_complexity)]
fn refine(first: &[P], second: &[P]) -> Result<Result<Vec<P>, (P, P)>, Overflow> {
    let mut common = Vec::new();
    let (mut a, mut b) = (0, 0);
    while a < first.len() && b < second.len() {
        let (l, r) = (first[a], second[b]);
        if l.offset < r.offset && end(&l)? <= r.offset {
            common.push(l);
            a += 1;
            continue;
        }
        if r.offset < l.offset && end(&r)? <= l.offset {
            common.push(r);
            b += 1;
            continue;
        }
        if l.align_size >= r.align_size {
            match check_overlap(&mut common, second, b, l)? {
                Ok(next) => b = next,
                Err(pair) => return Ok(Err(pair)),
            }
            a += 1;
        } else {
            match check_overlap(&mut common, first, a, r)? {
                Ok(next) => a = next,
                Err(pair) => return Ok(Err(pair)),
            }
            b += 1;
        }
    }
    common.extend_from_slice(&first[a..]);
    common.extend_from_slice(&second[b..]);
    Ok(Ok(common))
}

fn check_overlap(
    res: &mut Vec<P>,
    small: &[P],
    mut point: usize,
    big: P,
) -> Result<Result<usize, (P, P)>, Overflow> {
    let end_off = end(&big)?;
    let use_small = big.meta == MetaType::Float;
    while point < small.len() {
        if small[point].offset >= end_off {
            break;
        }
        if end(&small[point])? > end_off {
            return Ok(Err((big, small[point])));
        }
        if use_small {
            res.push(small[point]);
        }
        point += 1;
    }
    if !use_small {
        res.push(big);
    }
    Ok(Ok(point))
}

fn hfa_ref(dt: &Rc<R>, max: i64) -> Result<&'static str, Overflow> {
    if !matches!(dt.meta, MetaType::Array | MetaType::Struct) {
        return Ok("aggregate");
    }
    let ex = Ex::new(dt, true, false, 0, max)?;
    Ok(if ex.reason.is_some() {
        "invalid"
    } else if ex.prims.is_empty() {
        "empty"
    } else if ex.unknown {
        "unknown"
    } else if ex.unaligned {
        "unaligned"
    } else if ex.extra {
        "holes"
    } else if ex.prims[0].meta != MetaType::Float {
        "float"
    } else if ex.prims.iter().any(|p| p.key != ex.prims[0].key) {
        "identity"
    } else {
        "match"
    })
}

fn filter_ref(filter: &DatatypeFilter, dt: &Rc<R>) -> Result<bool, Overflow> {
    let size_ok = |size: i64| {
        if !filter.sizes.is_empty() {
            return filter.sizes.iter().any(|n| i64::from(*n) == size);
        }
        let max = match filter.max_size {
            None | Some(0) => MAX,
            Some(n) => i64::from(n),
        };
        size >= i64::from(filter.min_size.unwrap_or(0)) && size <= max
    };
    Ok(match filter.class {
        DatatypeClass::Any => size_ok(dt.size),
        DatatypeClass::HomogeneousFloatAggregate => {
            let max = match filter.max_primitives {
                None | Some(0) => 4,
                Some(n) => i64::from(n),
            };
            hfa_ref(dt, max)? == "match"
        }
        DatatypeClass::Meta(MetaType::Array) => {
            let RKind::Array(_, count) = &*dt.kind else {
                return Ok(false);
            };
            dt.meta == MetaType::Array
                && size_ok(dt.size)
                && *count >= i64::from(filter.min_elements.unwrap_or(0))
                && match filter.max_elements {
                    None | Some(0) => true,
                    Some(n) => *count <= i64::from(n),
                }
        }
        DatatypeClass::Meta(meta) => dt.meta == meta && size_ok(dt.size),
    })
}

// ---------------------------------------------------------------- comparison

#[derive(Debug, Default)]
struct Counters {
    graphs: usize,
    skipped_graphs: usize,
    types: usize,
    converted: usize,
    failures: HashMap<&'static str, usize>,
    synthetic_fields: usize,
    nonbyte_bitfields: usize,
    union_bitfields: usize,
    dropped: usize,
    unloadable: usize,
    extractions: usize,
    valid: usize,
    invalid: HashMap<&'static str, usize>,
    overflows: usize,
    unaligned: usize,
    holes: usize,
    unknown: usize,
    primitives: usize,
    hfa: HashMap<&'static str, usize>,
    filters: usize,
    filter_matches: usize,
}

fn key_of(graph: &NativeTypeGraph, ty: NativeTypeId) -> Key {
    match graph.get(ty).unwrap().origin {
        NativeOrigin::Source(t) => Key::Source(t.0),
        NativeOrigin::SyntheticBase { size, meta } => Key::Base(size, code(meta)),
        NativeOrigin::SyntheticByteArray { count } => Key::Bytes(count),
        NativeOrigin::UnionBitfield { owner, field } => Key::UnionBit(owner.0, field),
    }
}

fn class(error: NativeConversionError) -> &'static str {
    use NativeConversionError::*;
    match error {
        Incomplete(_) => "incomplete",
        SizeRange { .. } => "size",
        AlignmentRange { .. } => "alignment",
        ArrayCount { .. } => "count",
        ArraySizeMismatch { .. } => "mismatch",
        Arithmetic { .. } => "arith",
        FieldOffset { .. } => "offset",
        FieldOutOfOrder { .. } => "order",
        FieldDoesNotFit { .. } => "fit",
        VoidField { .. } => "void",
        NonIntegerBitfieldBase { .. } => "nonint",
        MissingByteOrder { .. } => "byteorder",
        Dependency { .. } => "dependency",
    }
}

fn hfa_class(h: &NativeHfa) -> &'static str {
    match h.rejection {
        None => "match",
        Some(NativeHfaRejection::NotAggregate(_)) => "aggregate",
        Some(NativeHfaRejection::Invalid(_)) => "invalid",
        Some(NativeHfaRejection::Empty) => "empty",
        Some(NativeHfaRejection::ContainsUnknown) => "unknown",
        Some(NativeHfaRejection::Unaligned) => "unaligned",
        Some(NativeHfaRejection::ContainsHoles) => "holes",
        Some(NativeHfaRejection::NotFloat(_)) => "float",
        Some(NativeHfaRejection::MixedIdentity { .. }) => "identity",
    }
}

fn references(def: &TypeDefinition, layouts: &TypeLayouts, id: usize) -> Vec<usize> {
    let layout = layouts.layout(TypeId(id)).unwrap();
    match &def.kind {
        TypeKind::Alias(t) | TypeKind::Pointer { target: t, .. } => vec![t.0],
        TypeKind::Array { element, count } if *count != 0 => vec![element.0],
        TypeKind::Function {
            result, parameters, ..
        } => std::iter::once(result.0)
            .chain(parameters.iter().map(|p| p.0))
            .collect(),
        TypeKind::Structure(c) | TypeKind::Union(c) => {
            let union = matches!(def.kind, TypeKind::Union(_));
            c.fields
                .iter()
                .zip(&layout.fields)
                .filter(|(_, fl)| fl.bytes != 0 && !(union && fl.bitfield.is_some()))
                .map(|(f, _)| f.ty.0)
                .collect()
        }
        _ => vec![],
    }
}

fn filters() -> Vec<DatatypeFilter> {
    use native_common::filter;
    let mut list = vec![
        filter(DatatypeClass::Any),
        DatatypeFilter {
            min_size: Some(2),
            max_size: Some(8),
            ..filter(DatatypeClass::Any)
        },
        DatatypeFilter {
            sizes: vec![1, 4, 16],
            ..filter(DatatypeClass::Any)
        },
        native_common::hfa(),
        DatatypeFilter {
            max_primitives: Some(2),
            ..native_common::hfa()
        },
        DatatypeFilter {
            max_primitives: Some(8),
            max_size: Some(4),
            ..native_common::hfa()
        },
        DatatypeFilter {
            min_elements: Some(2),
            ..filter(DatatypeClass::Meta(MetaType::Array))
        },
        DatatypeFilter {
            max_elements: Some(2),
            min_size: Some(1),
            ..filter(DatatypeClass::Meta(MetaType::Array))
        },
    ];
    for meta in [
        MetaType::Void,
        MetaType::Spacebase,
        MetaType::Unknown,
        MetaType::Int,
        MetaType::Uint,
        MetaType::Bool,
        MetaType::Code,
        MetaType::Float,
        MetaType::Ptr,
        MetaType::PtrRel,
        MetaType::Array,
        MetaType::Struct,
        MetaType::Union,
        MetaType::PartUnion,
        MetaType::EnumInt,
        MetaType::EnumUint,
    ] {
        list.push(filter(DatatypeClass::Meta(meta)));
    }
    list
}

#[allow(clippy::too_many_arguments, clippy::needless_range_loop)]
fn compare(
    layouts: &Arc<TypeLayouts>,
    production_map: &NativeAlignmentMap,
    reference_map: &Dense,
    max_base: u32,
    offsets: &[u32],
    maxima: &[u32],
    filters: &[DatatypeFilter],
    counters: &mut Counters,
) {
    let options = NativeTypeOptions {
        max_basetype_size: max_base,
    };
    let graph = Arc::new(
        NativeTypeGraph::new(layouts.clone(), production_map, options, Default::default()).unwrap(),
    );
    let mut conv = Conv {
        layouts,
        map: reference_map,
        big: layouts.endianness() == Some(Endianness::Big),
        max_base: i64::from(max_base),
        memo: HashMap::new(),
        synthetic: HashMap::new(),
        dropped: BTreeSet::new(),
    };
    let count = layouts.definitions().len();
    let mut failed = vec![false; count];
    counters.graphs += 1;
    for index in 0..count {
        counters.types += 1;
        let reference = conv.get(index);
        match (graph.native(TypeId(index)), &reference) {
            (Err(NativeTypeError::Conversion(error)), Err(fail)) => {
                assert_eq!(
                    (error.root().0, class(error)),
                    (fail.root, fail.class),
                    "{index}"
                );
                *counters.failures.entry(fail.class).or_default() += 1;
                failed[index] = true;
            }
            (Ok(nid), Ok(r)) => {
                counters.converted += 1;
                let t = graph.get(nid).unwrap();
                assert_eq!(
                    (
                        t.meta,
                        i64::from(t.size),
                        i64::from(t.aligned_size),
                        i64::from(t.alignment),
                        t.enumeration
                    ),
                    (r.meta, r.size, r.align_size, r.alignment, r.enumeration),
                    "type {index}"
                );
                compare_shape(&graph, nid, r, counters);
                compare_queries(&graph, nid, index, r, offsets, maxima, filters, counters);
            }
            (production, _) => {
                panic!("type {index}: production {production:?}, reference {reference:?}")
            }
        }
    }
    // Drops are only committed for successful decodes in both models.
    let committed: BTreeSet<_> = conv
        .dropped
        .iter()
        .copied()
        .filter(|(owner, _)| !failed[*owner])
        .collect();
    let production: BTreeSet<_> = graph
        .dropped_fields()
        .iter()
        .map(|d| (d.owner.0, d.source_field))
        .collect();
    assert_eq!(production, committed);
    counters.dropped += production.len();
    // Loadability: any failure reachable through transported references.
    for index in 0..count {
        let mut seen = vec![false; count];
        let mut stack = vec![index];
        let mut blocked = false;
        while let Some(at) = stack.pop() {
            if seen[at] {
                continue;
            }
            seen[at] = true;
            blocked |= failed[at];
            stack.extend(references(&layouts.definitions()[at], layouts, at));
        }
        assert_eq!(
            graph.load_blocker(TypeId(index)).unwrap().is_some(),
            blocked
        );
        counters.unloadable += usize::from(blocked);
    }
}

fn compare_shape(graph: &NativeTypeGraph, nid: NativeTypeId, r: &R, counters: &mut Counters) {
    let fields: Vec<(i64, Key)> = graph
        .fields(nid)
        .unwrap()
        .iter()
        .map(|f| (i64::from(f.offset), key_of(graph, f.ty)))
        .collect();
    let bits: Vec<_> = graph
        .bitfields(nid)
        .unwrap()
        .iter()
        .map(|b| {
            (
                i64::from(b.byte_offset),
                i64::from(b.byte_size),
                i64::from(b.least_significant_bit),
                i64::from(b.bits),
                key_of(graph, b.base),
            )
        })
        .collect();
    match &*r.kind {
        RKind::Leaf => assert!(fields.is_empty() && graph.array(nid).unwrap().is_none()),
        RKind::Array(element, count) => {
            let array = graph.array(nid).unwrap().unwrap();
            assert_eq!(
                (key_of(graph, array.element), i64::from(array.count)),
                (element.key, *count)
            );
        }
        RKind::Struct {
            fields: expected,
            bits: expected_bits,
        } => {
            let expected: Vec<_> = expected.iter().map(|(o, t)| (*o, t.key)).collect();
            assert_eq!(fields, expected);
            assert_eq!(&bits, expected_bits);
            counters.nonbyte_bitfields += bits.len();
            counters.synthetic_fields += fields
                .iter()
                .filter(|(_, k)| matches!(k, Key::Base(..) | Key::Bytes(_)))
                .count();
        }
        RKind::Union(expected) => {
            let expected: Vec<_> = expected.iter().map(|(o, t)| (*o, t.key)).collect();
            assert_eq!(fields, expected);
            counters.union_bitfields += fields
                .iter()
                .filter(|(_, k)| matches!(k, Key::UnionBit(..)))
                .count();
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn compare_queries(
    graph: &Arc<NativeTypeGraph>,
    nid: NativeTypeId,
    index: usize,
    r: &Rc<R>,
    offsets: &[u32],
    maxima: &[u32],
    filters: &[DatatypeFilter],
    counters: &mut Counters,
) {
    for reject_unions in [false, true] {
        for nested_arrays_are_primitives in [false, true] {
            for &offset in offsets {
                for &max in maxima {
                    let options = NativeExtractionOptions {
                        offset,
                        reject_unions,
                        nested_arrays_are_primitives,
                        max_primitives: max,
                    };
                    let production = NativePrimitiveExtraction::new(
                        graph.clone(),
                        nid,
                        options,
                        Default::default(),
                    );
                    let reference = Ex::new(
                        r,
                        reject_unions,
                        nested_arrays_are_primitives,
                        i64::from(offset),
                        i64::from(max),
                    );
                    counters.extractions += 1;
                    let context = format!("type {index} {options:?}");
                    match (production, reference) {
                        (Err(NativeExtractionError::Overflow), Err(Overflow)) => {
                            counters.overflows += 1
                        }
                        (Ok(e), Ok(ex)) => compare_outcome(graph, &e, &ex, counters, &context),
                        (p, x) => panic!(
                            "{context}: production {p:?}, reference {:?}",
                            x.map(|e| e.reason)
                        ),
                    }
                }
            }
        }
    }
    for max in [None, Some(2), Some(6)] {
        let production = graph
            .homogeneous_float_aggregate(TypeId(index), max, Default::default())
            .unwrap();
        let reference = hfa_ref(r, i64::from(max.unwrap_or(4))).unwrap();
        assert_eq!(hfa_class(&production), reference, "hfa {index} {max:?}");
        *counters.hfa.entry(reference).or_default() += 1;
    }
    for filter in filters {
        let production = graph
            .matches_filter(filter, TypeId(index), Default::default())
            .unwrap()
            .matched;
        assert_eq!(
            production,
            filter_ref(filter, r).unwrap(),
            "{index} {filter:?}"
        );
        counters.filters += 1;
        counters.filter_matches += usize::from(production);
    }
}

fn compare_outcome(
    graph: &NativeTypeGraph,
    e: &NativePrimitiveExtraction,
    ex: &Ex,
    counters: &mut Counters,
    context: &str,
) {
    match (e.outcome(), ex.reason) {
        (
            NativeExtractionOutcome::Valid {
                primitives,
                contains_unknown,
                aligned,
                contains_holes,
            },
            None,
        ) => {
            let actual: Vec<P> = primitives
                .iter()
                .map(|p| P {
                    key: key_of(graph, p.ty),
                    offset: i64::from(p.offset),
                    meta: p.meta,
                    size: i64::from(p.size),
                    align_size: i64::from(p.aligned_size),
                    alignment: i64::from(p.alignment),
                })
                .collect();
            assert_eq!(actual, ex.prims, "{context}");
            assert_eq!(
                (*contains_unknown, *aligned, *contains_holes),
                (ex.unknown, !ex.unaligned, ex.extra),
                "{context}"
            );
            counters.valid += 1;
            counters.primitives += actual.len();
            counters.unaligned += usize::from(!aligned);
            counters.holes += usize::from(*contains_holes);
            counters.unknown += usize::from(*contains_unknown);
        }
        (NativeExtractionOutcome::Invalid(invalid), Some(reason)) => {
            let actual = match *invalid {
                NativeInvalidExtraction::MaxPrimitives { .. } => Reason::Max,
                NativeInvalidExtraction::UnionRejected(t) => {
                    Reason::UnionRejected(key_of(graph, t))
                }
                NativeInvalidExtraction::EmptyUnion(t) => Reason::EmptyUnion(key_of(graph, t)),
                NativeInvalidExtraction::IncompatibleUnion {
                    union,
                    big_offset,
                    big_aligned_size,
                    small_offset,
                    small_aligned_size,
                } => Reason::Incompatible(
                    key_of(graph, union),
                    i64::from(big_offset),
                    i64::from(big_aligned_size),
                    i64::from(small_offset),
                    i64::from(small_aligned_size),
                ),
                NativeInvalidExtraction::Unsupported { ty, meta } => {
                    Reason::Unsupported(key_of(graph, ty), meta)
                }
            };
            assert_eq!(actual, reason, "{context}");
            let name = match reason {
                Reason::Max => "max",
                Reason::UnionRejected(_) => "union rejected",
                Reason::EmptyUnion(_) => "empty union",
                Reason::Incompatible(..) => "incompatible",
                Reason::Unsupported(..) => "unsupported",
            };
            *counters.invalid.entry(name).or_default() += 1;
        }
        (actual, expected) => panic!("{context}: production {actual:?}, reference {expected:?}"),
    }
}

// ---------------------------------------------------------------- generation

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
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

const BUILTINS: [Builtin; 8] = [
    Builtin::Bool,
    Builtin::Char,
    Builtin::UnsignedChar,
    Builtin::WChar,
    Builtin::Short,
    Builtin::Int,
    Builtin::Double,
    Builtin::LongDouble,
];

/// Random small graphs over every source kind. Sized/integer-like facts are
/// tracked by the generator from its own choices.
fn random_graph(rng: &mut Rng) -> Vec<TypeDefinition> {
    let count = 6 + rng.below(28) as usize;
    let mut defs = Vec::new();
    let mut sized: Vec<usize> = Vec::new();
    let mut int_like: Vec<usize> = Vec::new();
    for index in 0..count {
        let roll = rng.below(100);
        let mut is_sized = true;
        let mut is_int = false;
        let kind = match roll {
            0..=2 => {
                is_sized = false;
                TypeKind::Void
            }
            3..=4 => {
                is_sized = false;
                TypeKind::Incomplete
            }
            5..=6 => {
                is_sized = false;
                TypeKind::Function {
                    result: TypeId(rng.below(count as u64) as usize),
                    parameters: (0..rng.below(3))
                        .map(|_| TypeId(rng.below(count as u64) as usize))
                        .collect(),
                    variadic: rng.chance(50),
                }
            }
            7..=19 => {
                is_int = true;
                TypeKind::Integer {
                    bytes: rng.pick(&[1, 2, 3, 4, 8, 16]),
                    signed: rng.chance(50),
                }
            }
            20..=27 => TypeKind::Float {
                bytes: rng.pick(&[4, 4, 8, 10, 16]),
            },
            28..=33 => {
                is_int = true;
                TypeKind::Enum {
                    bytes: 1 + rng.below(8) as u32,
                    signed: rng.chance(50),
                }
            }
            34..=39 => TypeKind::Pointer {
                target: TypeId(rng.below(count as u64) as usize),
                bytes: rng.pick(&[None, Some(2), Some(3), Some(4), Some(8)]),
            },
            40..=47 => TypeKind::Opaque {
                bytes: 1 + rng.below(20) as u32,
            },
            48..=52 => {
                let builtin = rng.pick(&BUILTINS);
                is_int = !matches!(
                    builtin,
                    Builtin::WChar | Builtin::Double | Builtin::LongDouble
                );
                TypeKind::Builtin(builtin)
            }
            53..=62 if index > 0 => {
                let target = rng.below(index as u64) as usize;
                is_sized = sized.contains(&target);
                is_int = int_like.contains(&target);
                TypeKind::Alias(TypeId(target))
            }
            63..=72 if !sized.is_empty() => TypeKind::Array {
                element: TypeId(rng.pick(&sized)),
                count: rng.pick(&[0, 1, 2, 3, 4]),
            },
            _ => {
                let union = roll >= 90;
                let mut fields = Vec::new();
                for field in 0..rng.below(6) {
                    if !int_like.is_empty() && rng.chance(40) {
                        fields.push(Field::bitfield(
                            format!("b{field}"),
                            TypeId(rng.pick(&int_like)),
                            rng.pick(&[0, 1, 3, 7, 8, 12, 16, 24, 32, 40, 64, 96, 128]),
                        ));
                    } else if !sized.is_empty() {
                        fields.push(Field::new(format!("f{field}"), TypeId(rng.pick(&sized))));
                    }
                }
                let composite = Composite {
                    fields,
                    packing: rng.pick(&[
                        Packing::Default,
                        Packing::Default,
                        Packing::Explicit(1),
                        Packing::Explicit(2),
                        Packing::Explicit(4),
                    ]),
                    minimum_alignment: rng.pick(&[
                        MinimumAlignment::Default,
                        MinimumAlignment::Default,
                        MinimumAlignment::Machine,
                        MinimumAlignment::Explicit(2),
                        MinimumAlignment::Explicit(8),
                        MinimumAlignment::Explicit(16),
                    ]),
                };
                if union {
                    TypeKind::Union(composite)
                } else {
                    TypeKind::Structure(composite)
                }
            }
        };
        if is_sized {
            sized.push(index);
        }
        if is_int {
            int_like.push(index);
        }
        defs.push(TypeDefinition::new(format!("t{index}"), kind));
    }
    defs
}

fn random_organization(rng: &mut Rng) -> ResolvedDataOrganization {
    let mut organization = DataOrganization::default().resolve(rng.pick(&[4, 8]));
    organization.char_signed = rng.chance(50);
    organization.use_ms_bitfield_convention = rng.chance(30);
    let extra: &[(u32, u32)] = rng.pick(&[
        &[][..],
        &[(16, 16)][..],
        &[(16, 1)][..],
        &[(3, 1), (12, 4)][..],
        &[(10, 2), (16, 8)][..],
    ]);
    for &(size, alignment) in extra {
        let map = &mut organization.size_alignment_map;
        match map.binary_search_by_key(&size, |e| e.size) {
            Ok(at) => map[at].alignment = alignment,
            Err(at) => map.insert(at, SizeAlignment { size, alignment }),
        }
    }
    organization
}

fn random_map(rng: &mut Rng) -> Vec<SizeAlignment> {
    (0..1 + rng.below(4))
        .map(|_| {
            let size = rng.below(25) as u32;
            SizeAlignment {
                size,
                alignment: if size == 0 {
                    0
                } else {
                    rng.pick(&[1, 2, 3, 4, 8, 16])
                },
            }
        })
        .collect()
}

#[test]
fn random_graphs_match_the_recursive_native_reference() {
    let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
    let mut counters = Counters::default();
    let filters = filters();
    let max = i32::MAX as u32;
    for _ in 0..400 {
        let defs = random_graph(&mut rng);
        let organization = random_organization(&mut rng);
        let endianness = rng.pick(&[Endianness::Little, Endianness::Big]);
        let Ok(layouts) = TypeLayouts::new_with_endianness(
            defs.into(),
            organization,
            endianness,
            Default::default(),
        ) else {
            counters.skipped_graphs += 1;
            continue;
        };
        let layouts = Arc::new(layouts);
        let bridge_entries = layouts.organization().size_alignment_map.clone();
        let declared = random_map(&mut rng);
        let maps: [(NativeAlignmentMap, Dense); 3] = [
            (
                NativeAlignmentMap::from_organization(layouts.organization(), Default::default())
                    .unwrap(),
                Dense::decode(Some(&bridge_entries)),
            ),
            (
                NativeAlignmentMap::new(None, Default::default()).unwrap(),
                Dense::decode(None),
            ),
            (
                NativeAlignmentMap::new(Some(&declared), Default::default()).unwrap(),
                Dense::decode(Some(&declared)),
            ),
        ];
        let max_base = rng.pick(&[8, 10, 10, 12]);
        for (production, reference) in &maps {
            compare(
                &layouts,
                production,
                reference,
                max_base,
                &[0, 3, max - 2],
                &[0, 1, 4, 16],
                &filters,
                &mut counters,
            );
        }
    }
    eprintln!("native random oracle: {counters:#?}");
    assert!(counters.skipped_graphs < 40, "{}", counters.skipped_graphs);
    assert!(counters.graphs >= 1_000);
    assert!(counters.converted > 10_000);
    assert!(counters.extractions > 500_000);
    assert!(counters.valid > 150_000 && counters.primitives > 400_000);
    assert!(counters.unaligned > 1_000 && counters.holes > 1_000 && counters.unknown > 5_000);
    assert!(counters.overflows > 1_000);
    for reason in [
        "max",
        "union rejected",
        "empty union",
        "incompatible",
        "unsupported",
    ] {
        assert!(
            counters.invalid.get(reason).copied().unwrap_or(0) > 50,
            "{reason}"
        );
    }
    for class in ["incomplete", "mismatch", "dependency"] {
        assert!(
            counters.failures.get(class).copied().unwrap_or(0) > 50,
            "{class}"
        );
    }
    for class in [
        "match",
        "identity",
        "holes",
        "unaligned",
        "unknown",
        "invalid",
        "aggregate",
        "empty",
        "float",
    ] {
        assert!(
            counters.hfa.get(class).copied().unwrap_or(0) > 20,
            "hfa {class}"
        );
    }
    assert!(counters.synthetic_fields > 200 && counters.nonbyte_bitfields > 500);
    assert!(counters.union_bitfields > 100 && counters.unloadable > 500);
    assert!(counters.filter_matches > 10_000);
}

/// A fixed graph exercising every kind, built against each organization.
fn fixed_graph() -> Vec<TypeDefinition> {
    let mut s = native_common::Source::default();
    let void = s.add(TypeKind::Void);
    let f4 = s.float(4);
    let f8 = s.float(8);
    let f10 = s.float(10);
    let alias = s.alias(f4);
    let alias2 = s.alias(alias);
    let i1 = s.int(1, false);
    let i2 = s.int(2, true);
    let i3 = s.int(3, true);
    let i4 = s.int(4, false);
    let i8 = s.int(8, true);
    let i16 = s.int(16, false);
    let e3 = s.add(TypeKind::Enum {
        bytes: 3,
        signed: true,
    });
    let e4 = s.add(TypeKind::Enum {
        bytes: 4,
        signed: false,
    });
    let pointer = s.add(TypeKind::Pointer {
        target: void,
        bytes: None,
    });
    let p3 = s.add(TypeKind::Pointer {
        target: f4,
        bytes: Some(3),
    });
    let function = s.add(TypeKind::Function {
        result: void,
        parameters: vec![f4],
        variadic: false,
    });
    let builtins: Vec<_> = BUILTINS
        .iter()
        .map(|b| s.add(TypeKind::Builtin(*b)))
        .collect();
    let opaques: Vec<_> = [1, 3, 5, 7, 12, 15, 16, 17, 20]
        .map(|n| s.opaque(n))
        .to_vec();
    let zero = s.array(f4, 0);
    let floats = s.array(f4, 4);
    let aliases = s.array(alias, 2);
    let enums = s.array(e3, 2);
    let pointers = s.array(p3, 2);
    let hfa = s.structure(&[f4, alias, alias2]);
    let hfa2 = s.structure(&[alias, alias]);
    let doubles = s.structure(&[f8, f8]);
    let natural = s.structure(&[i1, i4, f4]);
    let packed = s.packed(&[i1, i4, f8, opaques[6]]);
    let tail = s.packed(&[f4, opaques[7]]);
    let tails = s.array(tail, 2);
    let min16 = s.composite(
        &[f4],
        Packing::Default,
        MinimumAlignment::Explicit(16),
        false,
    );
    let min16s = s.array(min16, 2);
    let empty = s.structure(&[]);
    let empties = s.array(empty, 3);
    let union = s.union(&[f8, floats, i8]);
    let union2 = s.union(&[f4, i4, opaques[2]]);
    let with_union = s.structure(&[i2, union2, f4]);
    let bitfields = s.with_fields(
        vec![
            Field::bitfield("a", i4, 3),
            Field::bitfield("b", i4, 13),
            Field::bitfield("c", e4, 16),
            Field::bitfield("z", i4, 0),
            Field::bitfield("d", i8, 24),
            Field::bitfield("e", i16, 96),
            Field::new("f", f4),
            Field::bitfield("g", i2, 8),
        ],
        Packing::Default,
        MinimumAlignment::Default,
        false,
    );
    let bit_union = s.with_fields(
        vec![
            Field::bitfield("a", i4, 5),
            Field::bitfield("w", i16, 128),
            Field::new("f", f4),
        ],
        Packing::Default,
        MinimumAlignment::Default,
        true,
    );
    let code_pointer = s.add(TypeKind::Pointer {
        target: function,
        bytes: None,
    });
    let mixed = s.structure(&[
        bitfields,
        bit_union,
        with_union,
        tails,
        f10,
        i3,
        pointer,
        code_pointer,
    ]);
    let _ = (
        builtins, aliases, enums, pointers, hfa, hfa2, doubles, natural, packed, min16s, empties,
        union, mixed, zero,
    );
    s.defs
}

#[test]
fn retained_compiler_organizations_match_the_native_reference() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let catalog = Catalog::discover(&root).unwrap();
    let paths: BTreeSet<_> = catalog
        .languages
        .iter()
        .flat_map(|language| &language.compilers)
        .filter_map(|compiler| compiler.spec.available_path())
        .map(|path| std::fs::canonicalize(path).unwrap())
        .collect();
    assert_eq!(
        paths.len(),
        107,
        "distinct retained compiler specifications"
    );
    let defs: Arc<[TypeDefinition]> = fixed_graph().into();
    let filters = filters();
    let mut counters = Counters::default();
    let mut distinct_maps = BTreeSet::new();
    for (index, path) in paths.iter().enumerate() {
        let spec = CompilerSpec::from_path(path).unwrap();
        for pointer_size in [4, 8] {
            let organization = spec.resolved_data_organization(pointer_size);
            let endianness = if (index + pointer_size as usize).is_multiple_of(2) {
                Endianness::Little
            } else {
                Endianness::Big
            };
            let layouts = Arc::new(
                TypeLayouts::new_with_endianness(
                    defs.clone(),
                    organization,
                    endianness,
                    Default::default(),
                )
                .unwrap(),
            );
            let entries = layouts.organization().size_alignment_map.clone();
            distinct_maps.insert(
                entries
                    .iter()
                    .map(|e| (e.size, e.alignment))
                    .collect::<Vec<_>>(),
            );
            compare(
                &layouts,
                &NativeAlignmentMap::from_organization(layouts.organization(), Default::default())
                    .unwrap(),
                &Dense::decode(Some(&entries)),
                10,
                &[0, 1],
                &[4, 64],
                &filters,
                &mut counters,
            );
        }
    }
    eprintln!(
        "retained-organization native oracle ({} distinct resolved maps): {counters:#?}",
        distinct_maps.len()
    );
    assert_eq!(counters.graphs, 214);
    assert!(distinct_maps.len() > 3);
    assert!(counters.extractions > 100_000);
    assert!(counters.valid > 50_000);
    assert!(counters.hfa.get("match").copied().unwrap_or(0) > 500);
    assert!(counters.failures.get("mismatch").copied().unwrap_or(0) >= 214);
}
