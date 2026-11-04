//! General scalar-piece extraction and source-ordered union refinement.
//! Source behavior is derived from lang/protorules/PrimitiveExtractor.java.
use std::sync::Arc;

use ghidra_languages::MetaType;
use ghidra_types::{TypeId, TypeKind};

use crate::{DatatypePredicates, HomogeneousFloat, PredicateError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExtractionOptions {
    pub offset: u64,
    pub reject_unions: bool,
    /// A root array expands. An array nested within the current extraction
    /// context is one primitive. Each union member starts a fresh context.
    pub nested_arrays_are_primitives: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExtractionLimits {
    /// Source semantic maximum, separately applied to every extractor context.
    /// Intermediate union refinements may exceed this and later shrink.
    pub max_primitives: usize,
    /// Live records across all contexts and refinement scratch lists.
    pub max_live_primitives: usize,
    /// Active datatype nesting, including the root. Union contexts do not reset
    /// this resource depth even though their array-expansion depth resets.
    pub max_depth: usize,
    pub max_work: u64,
}

impl Default for ExtractionLimits {
    fn default() -> Self {
        Self {
            max_primitives: 65_536,
            max_live_primitives: 1_000_000,
            max_depth: 100_000,
            max_work: 64_000_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrimitiveSource {
    Type(TypeId),
    /// Wrapper identity must not collapse to its declared integer base. Normalized
    /// bit metadata is available at the owner's field index in the shared layout.
    BitField {
        owner: TypeId,
        field: usize,
        base: TypeId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Primitive {
    pub source: PrimitiveSource,
    pub offset: u64,
    pub meta_type: MetaType,
    /// Java getLength; code/function definitions have -1 and void has 0.
    pub length: i128,
    /// Java getAlignedLength; used for array stepping and union refinement.
    pub aligned_length: i128,
    pub alignment: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ExtractionStats {
    pub node_visits: u64,
    pub refinement_steps: u64,
    pub peak_live_primitives: usize,
    pub peak_depth: usize,
    pub work: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ExtractionError {
    #[error("primitive extraction limit exceeded: {0}")]
    Limit(&'static str),
    #[error(transparent)]
    Datatype(#[from] PredicateError),
    #[error("union {0:?} is rejected by the extraction policy")]
    UnionRejected(TypeId),
    #[error("union {0:?} has no members")]
    EmptyUnion(TypeId),
    #[error(
        "union {ty:?} has incompatible overlap: primitive at {big_offset:#x} length {big_length} and primitive at {small_offset:#x} length {small_length}"
    )]
    IncompatibleUnion {
        ty: TypeId,
        big_offset: u64,
        big_length: i128,
        small_offset: u64,
        small_length: i128,
    },
    #[error("primitive extraction offset/extent arithmetic overflow")]
    Overflow,
}

type Result<T> = std::result::Result<T, ExtractionError>;

/// An owned result from one immutable datatype snapshot. Unlike Java's invalid
/// extractor objects, errors expose no partially extracted prefix.
#[derive(Debug, Clone)]
pub struct PrimitiveExtraction {
    predicates: Arc<DatatypePredicates>,
    root: TypeId,
    options: ExtractionOptions,
    limits: ExtractionLimits,
    primitives: Vec<Primitive>,
    contains_unknown: bool,
    output_contains_unknown: bool,
    stats: ExtractionStats,
}

impl PrimitiveExtraction {
    pub fn new(
        predicates: Arc<DatatypePredicates>,
        root: TypeId,
        options: ExtractionOptions,
        limits: ExtractionLimits,
    ) -> Result<Self> {
        predicates.fact(root)?;
        if limits.max_depth == 0 {
            return Err(ExtractionError::Limit("depth"));
        }
        let mut budget = Budget {
            limits,
            stats: ExtractionStats::default(),
            live: 0,
        };
        let initial = enter(root, u128::from(options.offset), 0, 1, &mut budget)?;
        let mut contexts = vec![Context::new(initial)];
        let (primitives, contains_unknown) = loop {
            let task = contexts
                .last_mut()
                .expect("root context exists")
                .tasks
                .pop();
            let Some(task) = task else {
                let finished = contexts.pop().expect("completed context exists");
                if let Some(parent) = contexts.last_mut() {
                    // The retained handleUnion copies lists, not child flags.
                    let mut union = parent.pending.take().expect("union awaited member");
                    union.common = Some(if let Some(common) = union.common.take() {
                        refine(common, finished.primitives, union.ty, &mut budget)?
                    } else {
                        finished.primitives
                    });
                    parent.tasks.push(Task::Union(union));
                    continue;
                }
                break (finished.primitives, finished.contains_unknown);
            };
            budget.work(1)?;
            match task {
                Task::Enter {
                    ty,
                    offset,
                    depth,
                    nesting,
                } => {
                    budget.stats.node_visits = budget
                        .stats
                        .node_visits
                        .checked_add(1)
                        .ok_or(ExtractionError::Limit("work"))?;
                    let fact = *predicates.fact(ty)?;
                    let ty = fact.canonical;
                    let meta = fact.meta_type.ok_or(PredicateError::IncompleteType(ty))?;
                    let kind = &predicates.layouts().definitions()[ty.0].kind;
                    let context = contexts.last_mut().expect("current context");
                    match kind {
                        TypeKind::Array { element, count } => {
                            if options.nested_arrays_are_primitives && depth != 0 {
                                append_type(context, &predicates, ty, offset, meta, &mut budget)?;
                            } else if *count != 0 {
                                // Cached empty summaries are safe only when nested
                                // arrays are expanded, not hidden as primitives.
                                if !options.nested_arrays_are_primitives
                                    && fact.homogeneous_float == HomogeneousFloat::Empty
                                {
                                    continue;
                                }
                                let stride = predicates
                                    .layouts()
                                    .layout(ty)
                                    .expect("valid array")
                                    .array_stride
                                    .expect("direct array stride");
                                context.tasks.push(Task::Array {
                                    element: *element,
                                    count: *count,
                                    next: 0,
                                    offset,
                                    stride,
                                    depth,
                                    nesting,
                                });
                            }
                        }
                        TypeKind::Structure(_) => {
                            if !options.nested_arrays_are_primitives
                                && fact.homogeneous_float == HomogeneousFloat::Empty
                            {
                                continue;
                            }
                            context.tasks.push(Task::Structure {
                                ty,
                                next: 0,
                                offset,
                                depth,
                                nesting,
                            });
                        }
                        TypeKind::Union(c) => {
                            if options.reject_unions {
                                return Err(ExtractionError::UnionRejected(ty));
                            }
                            if c.fields.is_empty() {
                                return Err(ExtractionError::EmptyUnion(ty));
                            }
                            context.tasks.push(Task::Union(Union {
                                ty,
                                next: 0,
                                offset,
                                nesting,
                                common: None,
                            }));
                        }
                        _ => append_type(context, &predicates, ty, offset, meta, &mut budget)?,
                    }
                }
                Task::Array {
                    element,
                    count,
                    next,
                    offset,
                    stride,
                    depth,
                    nesting,
                } => {
                    if next >= count {
                        continue;
                    }
                    let at = offset
                        .checked_add(u128::from(next) * u128::from(stride))
                        .ok_or(ExtractionError::Overflow)?;
                    let child = enter(
                        element,
                        at,
                        depth.checked_add(1).ok_or(ExtractionError::Overflow)?,
                        nesting
                            .checked_add(1)
                            .ok_or(ExtractionError::Limit("depth"))?,
                        &mut budget,
                    )?;
                    let context = contexts.last_mut().expect("array context");
                    context.tasks.push(Task::Array {
                        element,
                        count,
                        next: next.checked_add(1).ok_or(ExtractionError::Overflow)?,
                        offset,
                        stride,
                        depth,
                        nesting,
                    });
                    context.tasks.push(child);
                }
                Task::Structure {
                    ty,
                    next,
                    offset,
                    depth,
                    nesting,
                } => {
                    let layout = predicates.layouts().layout(ty).expect("valid structure");
                    let Some(field) = layout.fields.get(next) else {
                        continue;
                    };
                    let at = offset
                        .checked_add(u128::from(field.offset))
                        .ok_or(ExtractionError::Overflow)?;
                    let child = enter_field(
                        &predicates,
                        ty,
                        next,
                        at,
                        depth.checked_add(1).ok_or(ExtractionError::Overflow)?,
                        nesting
                            .checked_add(1)
                            .ok_or(ExtractionError::Limit("depth"))?,
                        &mut budget,
                    )?;
                    let context = contexts.last_mut().expect("structure context");
                    context.tasks.push(Task::Structure {
                        ty,
                        next: next + 1,
                        offset,
                        depth,
                        nesting,
                    });
                    context.tasks.push(child);
                }
                Task::Union(mut union) => {
                    let layout = predicates.layouts().layout(union.ty).expect("valid union");
                    if let Some(field) = layout.fields.get(union.next) {
                        let at = union
                            .offset
                            .checked_add(u128::from(field.offset))
                            .ok_or(ExtractionError::Overflow)?;
                        let child = enter_field(
                            &predicates,
                            union.ty,
                            union.next,
                            at,
                            0,
                            union
                                .nesting
                                .checked_add(1)
                                .ok_or(ExtractionError::Limit("depth"))?,
                            &mut budget,
                        )?;
                        union.next += 1;
                        contexts.last_mut().expect("union parent").pending = Some(union);
                        contexts.push(Context::new(child));
                    } else {
                        let mut common = union.common.expect("nonempty union extracted a member");
                        let parent = contexts.last_mut().expect("union parent");
                        check_output(parent.primitives.len(), common.len(), limits.max_primitives)?;
                        budget.work(common.len() as u64)?;
                        parent.primitives.append(&mut common); // move; live count is unchanged
                    }
                }
                Task::BitField(primitive) => {
                    budget.stats.node_visits = budget
                        .stats
                        .node_visits
                        .checked_add(1)
                        .ok_or(ExtractionError::Limit("work"))?;
                    append_primitive(
                        contexts.last_mut().expect("bitfield context"),
                        primitive,
                        &mut budget,
                    )?;
                }
            }
        };
        budget.work(primitives.len() as u64)?;
        let output_contains_unknown = primitives.iter().any(|p| p.meta_type == MetaType::Unknown);
        debug_assert_eq!(budget.live, primitives.len());
        Ok(Self {
            predicates,
            root,
            options,
            limits,
            primitives,
            contains_unknown,
            output_contains_unknown,
            stats: budget.stats,
        })
    }

    pub fn predicates(&self) -> &Arc<DatatypePredicates> {
        &self.predicates
    }
    pub fn root(&self) -> TypeId {
        self.root
    }
    pub fn options(&self) -> ExtractionOptions {
        self.options
    }
    pub fn limits(&self) -> ExtractionLimits {
        self.limits
    }
    pub fn primitives(&self) -> &[Primitive] {
        &self.primitives
    }
    /// Retained context-local flag: unknown union-member flags are not propagated.
    pub fn contains_unknown(&self) -> bool {
        self.contains_unknown
    }
    /// Actual final-list metadata, separate from the retained context-local flag.
    pub fn output_contains_unknown(&self) -> bool {
        self.output_contains_unknown
    }
    /// Both supported automatic packing modes suppress Java's manual-layout checks.
    pub fn is_aligned(&self) -> bool {
        true
    }
    pub fn contains_holes(&self) -> bool {
        false
    }
    pub fn stats(&self) -> ExtractionStats {
        self.stats
    }
}

struct Context {
    tasks: Vec<Task>,
    primitives: Vec<Primitive>,
    pending: Option<Union>,
    contains_unknown: bool,
}
impl Context {
    fn new(task: Task) -> Self {
        Self {
            tasks: vec![task],
            primitives: vec![],
            pending: None,
            contains_unknown: false,
        }
    }
}

enum Task {
    // Traversal can reach an empty trailing member at the exclusive end 2^64.
    // Only emitted primitives need a representable u64 starting offset.
    BitField(Primitive),
    Enter {
        ty: TypeId,
        offset: u128,
        depth: usize,
        nesting: usize,
    },
    Array {
        element: TypeId,
        count: u64,
        next: u64,
        offset: u128,
        stride: u64,
        depth: usize,
        nesting: usize,
    },
    Structure {
        ty: TypeId,
        next: usize,
        offset: u128,
        depth: usize,
        nesting: usize,
    },
    Union(Union),
}
struct Union {
    ty: TypeId,
    next: usize,
    offset: u128,
    nesting: usize,
    common: Option<Vec<Primitive>>,
}

struct Budget {
    limits: ExtractionLimits,
    stats: ExtractionStats,
    live: usize,
}
impl Budget {
    fn work(&mut self, n: u64) -> Result<()> {
        self.stats.work = self
            .stats
            .work
            .checked_add(n)
            .filter(|n| *n <= self.limits.max_work)
            .ok_or(ExtractionError::Limit("work"))?;
        Ok(())
    }
    fn push(&mut self, list: &mut Vec<Primitive>, primitive: Primitive) -> Result<()> {
        self.work(1)?;
        let live = self
            .live
            .checked_add(1)
            .filter(|n| *n <= self.limits.max_live_primitives)
            .ok_or(ExtractionError::Limit("live primitives"))?;
        list.push(primitive);
        self.live = live;
        self.stats.peak_live_primitives = self.stats.peak_live_primitives.max(live);
        Ok(())
    }
}

fn enter(
    ty: TypeId,
    offset: u128,
    depth: usize,
    nesting: usize,
    budget: &mut Budget,
) -> Result<Task> {
    budget.work(1)?;
    if nesting > budget.limits.max_depth {
        return Err(ExtractionError::Limit("depth"));
    }
    budget.stats.peak_depth = budget.stats.peak_depth.max(nesting);
    Ok(Task::Enter {
        ty,
        offset,
        depth,
        nesting,
    })
}

fn enter_field(
    predicates: &DatatypePredicates,
    owner: TypeId,
    index: usize,
    offset: u128,
    depth: usize,
    nesting: usize,
    budget: &mut Budget,
) -> Result<Task> {
    let field = &predicates
        .layouts()
        .layout(owner)
        .expect("valid field owner")
        .fields[index];
    let ordinary = enter(field.ty, offset, depth, nesting, budget)?;
    if let Some(bits) = field.bitfield {
        let alignment = predicates
            .layouts()
            .layout(field.ty)
            .expect("valid declared base")
            .geometry
            .alignment;
        Ok(Task::BitField(Primitive {
            source: PrimitiveSource::BitField {
                owner,
                field: index,
                base: field.ty,
            },
            offset: u64::try_from(offset).map_err(|_| ExtractionError::Overflow)?,
            meta_type: MetaType::Unknown,
            length: i128::from(bits.storage_bytes),
            aligned_length: i128::from(bits.storage_bytes),
            alignment,
        }))
    } else {
        Ok(ordinary)
    }
}

fn check_output(current: usize, additional: usize, maximum: usize) -> Result<()> {
    current
        .checked_add(additional)
        .filter(|n| *n <= maximum)
        .ok_or(ExtractionError::Limit("primitives"))?;
    Ok(())
}

fn append_type(
    context: &mut Context,
    predicates: &DatatypePredicates,
    ty: TypeId,
    offset: u128,
    meta: MetaType,
    budget: &mut Budget,
) -> Result<()> {
    let fact = predicates.fact(ty)?;
    let geometry = predicates
        .layouts()
        .layout(ty)
        .expect("valid leaf type")
        .geometry;
    let length = fact.length.ok_or(PredicateError::IncompleteType(ty))?;
    let aligned_length = if meta == MetaType::Code {
        -1
    } else {
        geometry
            .aligned_length
            .map(i128::from)
            .ok_or(PredicateError::IncompleteType(ty))?
    };
    append_primitive(
        context,
        Primitive {
            source: PrimitiveSource::Type(ty),
            offset: u64::try_from(offset).map_err(|_| ExtractionError::Overflow)?,
            meta_type: meta,
            length,
            aligned_length,
            alignment: geometry.alignment,
        },
        budget,
    )
}

fn append_primitive(
    context: &mut Context,
    primitive: Primitive,
    budget: &mut Budget,
) -> Result<()> {
    if primitive.aligned_length >= 0
        && i128::from(primitive.offset) + primitive.aligned_length > 1_i128 << 64
    {
        return Err(ExtractionError::Overflow);
    }
    check_output(context.primitives.len(), 1, budget.limits.max_primitives)?;
    budget.push(&mut context.primitives, primitive)?;
    if primitive.meta_type == MetaType::Unknown {
        context.contains_unknown = true;
    }
    Ok(())
}

fn end(primitive: Primitive) -> i128 {
    i128::from(primitive.offset) + primitive.aligned_length
}

/// Source-ordered refinement, deliberately not interval-union normalization.
fn refine(
    first: Vec<Primitive>,
    second: Vec<Primitive>,
    ty: TypeId,
    budget: &mut Budget,
) -> Result<Vec<Primitive>> {
    let mut result = Vec::new();
    let mut a = 0;
    let mut b = 0;
    while a < first.len() && b < second.len() {
        budget.work(1)?;
        budget.stats.refinement_steps = budget
            .stats
            .refinement_steps
            .checked_add(1)
            .ok_or(ExtractionError::Limit("work"))?;
        let left = first[a];
        let right = second[b];
        if left.offset < right.offset && end(left) <= i128::from(right.offset) {
            budget.push(&mut result, left)?;
            a += 1;
            continue;
        }
        if right.offset < left.offset && end(right) <= i128::from(left.offset) {
            budget.push(&mut result, right)?;
            b += 1;
            continue;
        }
        if left.aligned_length >= right.aligned_length {
            b = overlap(&mut result, &second, b, left, ty, budget)?;
            a += 1;
        } else {
            a = overlap(&mut result, &first, a, right, ty, budget)?;
            b += 1;
        }
    }
    for primitive in first[a..].iter().chain(&second[b..]) {
        budget.push(&mut result, *primitive)?;
    }
    budget.live -= first.len() + second.len();
    Ok(result)
}

fn overlap(
    result: &mut Vec<Primitive>,
    small: &[Primitive],
    mut at: usize,
    big: Primitive,
    ty: TypeId,
    budget: &mut Budget,
) -> Result<usize> {
    while at < small.len() {
        budget.work(1)?;
        budget.stats.refinement_steps = budget
            .stats
            .refinement_steps
            .checked_add(1)
            .ok_or(ExtractionError::Limit("work"))?;
        let primitive = small[at];
        if i128::from(primitive.offset) >= end(big) {
            break;
        }
        if end(primitive) > end(big) {
            return Err(ExtractionError::IncompatibleUnion {
                ty,
                big_offset: big.offset,
                big_length: big.aligned_length,
                small_offset: primitive.offset,
                small_length: primitive.aligned_length,
            });
        }
        if big.meta_type == MetaType::Float {
            budget.push(result, primitive)?;
        }
        at += 1;
    }
    if big.meta_type != MetaType::Float {
        budget.push(result, big)?;
    }
    Ok(at)
}
