//! Native `PrimitiveExtractor` (modelrules.cc:142-249) over the converted graph.
//!
//! The source recursion is replaced by explicit task stacks, one per extractor
//! context (the root and each union member). Arrays expand lazily. Every
//! native `int4` offset, end and expected offset is checked when it is used,
//! instead of emulating signed overflow.
use std::sync::Arc;

use ghidra_languages::MetaType;

use crate::native_types::{
    NATIVE_INT_MAX, NativeOrigin, NativeRange, NativeShape, NativeTypeError, NativeTypeGraph,
    NativeTypeId,
};

/// Source extractor arguments. `max_primitives` is the semantic per-context
/// maximum (`max`), not a resource limit: exceeding it makes the extraction
/// invalid, as in the source, rather than returning an error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeExtractionOptions {
    /// Starting offset; must be a nonnegative native int.
    pub offset: u32,
    /// `unionIllegal`, applied only to the root context. Union-member contexts
    /// always permit nested unions, as the source constructs them.
    pub reject_unions: bool,
    /// `arrayPrimitive`: an array below the current context root is one
    /// primitive. Union members start a fresh context at depth zero.
    pub nested_arrays_are_primitives: bool,
    pub max_primitives: u32,
}

impl NativeExtractionOptions {
    pub fn new(max_primitives: u32) -> Self {
        Self {
            offset: 0,
            reject_unions: false,
            nested_arrays_are_primitives: false,
            max_primitives,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeExtractionLimits {
    /// Live records across all contexts and refinement scratch lists.
    pub max_live_primitives: usize,
    /// Active datatype nesting including the root; union members add a level.
    pub max_depth: usize,
    pub max_work: u64,
}

impl Default for NativeExtractionLimits {
    fn default() -> Self {
        Self {
            max_live_primitives: 1_000_000,
            max_depth: 100_000,
            max_work: 64_000_000,
        }
    }
}

/// One extracted piece. `ty` is the exact native object reached (aliases keep
/// their own identity); `origin` records whether it is converted or synthetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativePrimitive {
    pub ty: NativeTypeId,
    pub origin: NativeOrigin,
    pub offset: u32,
    pub meta: MetaType,
    pub size: u32,
    pub aligned_size: u32,
    pub alignment: u32,
}

/// Why the source extractor would be invalid. These are semantic outcomes,
/// distinct from resource or arithmetic errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeInvalidExtraction {
    /// A context reached `max_primitives`, or a union's refinement would exceed
    /// it when appended to its parent.
    MaxPrimitives {
        maximum: u32,
    },
    UnionRejected(NativeTypeId),
    EmptyUnion(NativeTypeId),
    /// `commonRefinement` found a smaller piece ending past the larger one.
    IncompatibleUnion {
        union: NativeTypeId,
        big_offset: u32,
        big_aligned_size: u32,
        small_offset: u32,
        small_aligned_size: u32,
    },
    /// Void, or any other meta-type outside the extractor's switch.
    Unsupported {
        ty: NativeTypeId,
        meta: MetaType,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NativeExtractionOutcome {
    /// Flags are the root context's: union members' flags are dropped.
    Valid {
        primitives: Vec<NativePrimitive>,
        contains_unknown: bool,
        aligned: bool,
        contains_holes: bool,
    },
    Invalid(NativeInvalidExtraction),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NativeExtractionStats {
    pub node_visits: u64,
    pub refinement_steps: u64,
    pub union_contexts: u64,
    /// Array elements not entered because each is an inert subtree
    /// (fieldless structures), whose entry has no effect at any offset.
    pub skipped_inert_elements: u64,
    pub peak_live_primitives: usize,
    pub peak_depth: usize,
    pub work: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NativeExtractionError {
    #[error("native primitive extraction limit exceeded: {0}")]
    Limit(&'static str),
    #[error("invalid native extraction options: {0}")]
    InvalidOptions(&'static str),
    #[error(transparent)]
    Type(#[from] NativeTypeError),
    #[error("native extraction offset arithmetic exceeds the signed-int range")]
    Overflow,
}

type Result<T> = std::result::Result<T, NativeExtractionError>;

/// An owned extraction over one immutable native graph. Invalid extractions
/// expose only their reason; errors expose no partial prefix.
#[derive(Debug, Clone)]
pub struct NativePrimitiveExtraction {
    graph: Arc<NativeTypeGraph>,
    root: NativeTypeId,
    options: NativeExtractionOptions,
    limits: NativeExtractionLimits,
    outcome: NativeExtractionOutcome,
    stats: NativeExtractionStats,
}

impl NativePrimitiveExtraction {
    pub fn new(
        graph: Arc<NativeTypeGraph>,
        root: NativeTypeId,
        options: NativeExtractionOptions,
        limits: NativeExtractionLimits,
    ) -> Result<Self> {
        let (outcome, stats) = extract(&graph, root, options, limits)?;
        Ok(Self {
            graph,
            root,
            options,
            limits,
            outcome,
            stats,
        })
    }

    pub fn graph(&self) -> &Arc<NativeTypeGraph> {
        &self.graph
    }
    pub fn root(&self) -> NativeTypeId {
        self.root
    }
    pub fn options(&self) -> NativeExtractionOptions {
        self.options
    }
    pub fn limits(&self) -> NativeExtractionLimits {
        self.limits
    }
    pub fn outcome(&self) -> &NativeExtractionOutcome {
        &self.outcome
    }
    pub fn is_valid(&self) -> bool {
        matches!(self.outcome, NativeExtractionOutcome::Valid { .. })
    }
    /// Empty for an invalid extraction.
    pub fn primitives(&self) -> &[NativePrimitive] {
        match &self.outcome {
            NativeExtractionOutcome::Valid { primitives, .. } => primitives,
            NativeExtractionOutcome::Invalid(_) => &[],
        }
    }
    pub fn stats(&self) -> NativeExtractionStats {
        self.stats
    }
}

/// The borrowed engine shared by the owned extraction and native HFA queries.
pub(crate) fn extract(
    graph: &NativeTypeGraph,
    root: NativeTypeId,
    options: NativeExtractionOptions,
    limits: NativeExtractionLimits,
) -> Result<(NativeExtractionOutcome, NativeExtractionStats)> {
    if options.offset > NATIVE_INT_MAX {
        return Err(NativeExtractionError::InvalidOptions(
            "start offset exceeds the native signed-int range",
        ));
    }
    if options.max_primitives > NATIVE_INT_MAX {
        return Err(NativeExtractionError::InvalidOptions(
            "primitive maximum exceeds the native signed-int range",
        ));
    }
    graph.get(root)?;
    let mut engine = Engine {
        graph,
        options,
        limits,
        stats: NativeExtractionStats::default(),
        live: 0,
    };
    let outcome = engine.run(root)?;
    Ok((outcome, engine.stats))
}

struct Engine<'g> {
    graph: &'g NativeTypeGraph,
    options: NativeExtractionOptions,
    limits: NativeExtractionLimits,
    stats: NativeExtractionStats,
    live: usize,
}

struct Context {
    tasks: Vec<Task>,
    primitives: Vec<NativePrimitive>,
    unknown: bool,
    unaligned: bool,
    holes: bool,
    reject_unions: bool,
    pending: Option<UnionTask>,
}

impl Context {
    fn new(task: Task, reject_unions: bool) -> Self {
        Self {
            tasks: vec![task],
            primitives: Vec::new(),
            unknown: false,
            unaligned: false,
            holes: false,
            reject_unions,
            pending: None,
        }
    }
}

enum Task {
    Enter {
        ty: NativeTypeId,
        offset: u32,
        /// The source `depth != 0` test, reset by union members.
        nested: bool,
        nesting: usize,
    },
    Array {
        element: NativeTypeId,
        count: u32,
        next: u32,
        offset: u32,
        stride: u32,
        nesting: usize,
    },
    Structure {
        fields: NativeRange,
        next: usize,
        offset: u32,
        /// `expectedOff`, kept wide and checked when the next field uses it.
        expected: u64,
        nesting: usize,
    },
    Union(UnionTask),
}

struct UnionTask {
    ty: NativeTypeId,
    fields: NativeRange,
    next: usize,
    offset: u32,
    nesting: usize,
    common: Option<Vec<NativePrimitive>>,
}

fn int4(value: u64) -> Result<u32> {
    if value > u64::from(NATIVE_INT_MAX) {
        return Err(NativeExtractionError::Overflow);
    }
    Ok(value as u32)
}

fn end(primitive: &NativePrimitive) -> Result<u32> {
    int4(u64::from(primitive.offset) + u64::from(primitive.aligned_size))
}

impl Engine<'_> {
    fn work(&mut self, amount: u64) -> Result<()> {
        self.stats.work = self
            .stats
            .work
            .checked_add(amount)
            .filter(|n| *n <= self.limits.max_work)
            .ok_or(NativeExtractionError::Limit("work"))?;
        Ok(())
    }

    fn step(counter: &mut u64) -> Result<()> {
        *counter = counter
            .checked_add(1)
            .ok_or(NativeExtractionError::Limit("work"))?;
        Ok(())
    }

    fn push(&mut self, list: &mut Vec<NativePrimitive>, primitive: NativePrimitive) -> Result<()> {
        self.work(1)?;
        let live = self
            .live
            .checked_add(1)
            .filter(|n| *n <= self.limits.max_live_primitives)
            .ok_or(NativeExtractionError::Limit("live primitives"))?;
        list.push(primitive);
        self.live = live;
        self.stats.peak_live_primitives = self.stats.peak_live_primitives.max(live);
        Ok(())
    }

    fn enter(
        &mut self,
        ty: NativeTypeId,
        offset: u32,
        nested: bool,
        nesting: usize,
    ) -> Result<Task> {
        self.work(1)?;
        if nesting > self.limits.max_depth {
            return Err(NativeExtractionError::Limit("depth"));
        }
        self.stats.peak_depth = self.stats.peak_depth.max(nesting);
        Ok(Task::Enter {
            ty,
            offset,
            nested,
            nesting,
        })
    }

    fn run(&mut self, root: NativeTypeId) -> Result<NativeExtractionOutcome> {
        let first = self
            .depth_checked_root()
            .and_then(|()| self.enter(root, self.options.offset, false, 1))?;
        let mut contexts = vec![Context::new(first, self.options.reject_unions)];
        loop {
            let task = contexts.last_mut().expect("context").tasks.pop();
            let Some(task) = task else {
                let finished = contexts.pop().expect("finished context");
                let Some(parent) = contexts.last_mut() else {
                    return Ok(NativeExtractionOutcome::Valid {
                        primitives: finished.primitives,
                        contains_unknown: finished.unknown,
                        aligned: !finished.unaligned,
                        contains_holes: finished.holes,
                    });
                };
                // handleUnion copies member lists; member flags are dropped.
                let mut union = parent.pending.take().expect("union awaited a member");
                let merged = match union.common.take() {
                    None => finished.primitives,
                    Some(common) => match self.refine(common, finished.primitives, union.ty)? {
                        Ok(merged) => merged,
                        Err(invalid) => return Ok(NativeExtractionOutcome::Invalid(invalid)),
                    },
                };
                union.common = Some(merged);
                contexts
                    .last_mut()
                    .expect("union parent")
                    .tasks
                    .push(Task::Union(union));
                continue;
            };
            self.work(1)?;
            let invalid = match task {
                Task::Enter {
                    ty,
                    offset,
                    nested,
                    nesting,
                } => {
                    let context = contexts.last_mut().expect("context");
                    self.visit(context, ty, offset, nested, nesting)?
                }
                Task::Array {
                    element,
                    count,
                    next,
                    offset,
                    stride,
                    nesting,
                } => {
                    if next < count {
                        let at = int4(u64::from(offset) + u64::from(next) * u64::from(stride))?;
                        let child = self.enter(element, at, true, nesting + 1)?;
                        let context = contexts.last_mut().expect("array context");
                        context.tasks.push(Task::Array {
                            element,
                            count,
                            next: next + 1,
                            offset,
                            stride,
                            nesting,
                        });
                        context.tasks.push(child);
                    }
                    None
                }
                Task::Structure {
                    fields,
                    next,
                    offset,
                    expected,
                    nesting,
                } => {
                    if next < fields.end {
                        let field = self.graph.field_slice(NativeRange {
                            start: next,
                            end: next + 1,
                        })[0];
                        let current = int4(u64::from(offset) + u64::from(field.offset))?;
                        let child = *self.graph.get(field.ty)?;
                        let alignment = u64::from(child.alignment);
                        let mut expected = u64::from(int4(expected)?);
                        let remainder = expected % alignment;
                        if remainder != 0 {
                            expected = u64::from(int4(expected + (alignment - remainder))?);
                        }
                        let task = self.enter(field.ty, current, true, nesting + 1)?;
                        let context = contexts.last_mut().expect("structure context");
                        if u64::from(current) % alignment != 0 {
                            context.unaligned = true;
                        }
                        if expected != u64::from(current) {
                            context.holes = true;
                        }
                        context.tasks.push(Task::Structure {
                            fields,
                            next: next + 1,
                            offset,
                            expected: u64::from(current) + u64::from(child.aligned_size),
                            nesting,
                        });
                        context.tasks.push(task);
                    }
                    None
                }
                Task::Union(mut union) => {
                    if union.next < union.fields.end {
                        let field = self.graph.field_slice(NativeRange {
                            start: union.next,
                            end: union.next + 1,
                        })[0];
                        let at = int4(u64::from(union.offset) + u64::from(field.offset))?;
                        let child = self.enter(field.ty, at, false, union.nesting + 1)?;
                        Self::step(&mut self.stats.union_contexts)?;
                        union.next += 1;
                        contexts.last_mut().expect("union parent").pending = Some(union);
                        contexts.push(Context::new(child, false));
                        None
                    } else {
                        let mut common = union.common.take().expect("nonempty union");
                        let parent = contexts.last_mut().expect("union parent");
                        if parent.primitives.len() + common.len()
                            > self.options.max_primitives as usize
                        {
                            Some(NativeInvalidExtraction::MaxPrimitives {
                                maximum: self.options.max_primitives,
                            })
                        } else {
                            self.work(common.len() as u64)?;
                            parent.primitives.append(&mut common); // Moves; live count unchanged.
                            None
                        }
                    }
                }
            };
            if let Some(invalid) = invalid {
                return Ok(NativeExtractionOutcome::Invalid(invalid));
            }
        }
    }

    fn depth_checked_root(&self) -> Result<()> {
        if self.limits.max_depth == 0 {
            return Err(NativeExtractionError::Limit("depth"));
        }
        Ok(())
    }

    /// `PrimitiveExtractor::extract`'s switch for one entered datatype.
    fn visit(
        &mut self,
        context: &mut Context,
        ty: NativeTypeId,
        offset: u32,
        nested: bool,
        nesting: usize,
    ) -> Result<Option<NativeInvalidExtraction>> {
        Self::step(&mut self.stats.node_visits)?;
        let native = *self.graph.get(ty)?;
        match native.meta {
            MetaType::Unknown
            | MetaType::Int
            | MetaType::Uint
            | MetaType::Bool
            | MetaType::Code
            | MetaType::Float
            | MetaType::Ptr => {
                if native.meta == MetaType::Unknown {
                    context.unknown = true;
                }
                self.emit(context, ty, offset)
            }
            MetaType::Array => {
                if self.options.nested_arrays_are_primitives && nested {
                    return self.emit(context, ty, offset);
                }
                let NativeShape::Array { element, count } = self.graph.shape(ty)? else {
                    unreachable!("array meta-type has an array shape");
                };
                let stride = self.graph.get(element)?.aligned_size;
                let inert = self
                    .graph
                    .inert(element)
                    .filter(|inert| !self.options.nested_arrays_are_primitives || inert.depth == 0);
                if let Some(inert) = inert {
                    // Skip only if the exact traversal could not have failed.
                    let deepest = nesting.checked_add(1 + inert.depth);
                    let reach = u64::from(offset)
                        + u64::from(count.saturating_sub(1)) * u64::from(stride)
                        + inert.reach;
                    if count == 0
                        || deepest.is_some_and(|n| n <= self.limits.max_depth)
                            && reach <= u64::from(NATIVE_INT_MAX)
                    {
                        if count != 0 {
                            self.stats.peak_depth =
                                self.stats.peak_depth.max(deepest.expect("checked"));
                        }
                        self.stats.skipped_inert_elements = self
                            .stats
                            .skipped_inert_elements
                            .checked_add(u64::from(count))
                            .ok_or(NativeExtractionError::Limit("work"))?;
                        return Ok(None);
                    }
                }
                context.tasks.push(Task::Array {
                    element,
                    count,
                    next: 0,
                    offset,
                    stride,
                    nesting,
                });
                Ok(None)
            }
            MetaType::Struct => {
                let NativeShape::Structure { fields, .. } = self.graph.shape(ty)? else {
                    unreachable!("struct meta-type has a structure shape");
                };
                context.tasks.push(Task::Structure {
                    fields,
                    next: fields.start,
                    offset,
                    expected: u64::from(offset),
                    nesting,
                });
                Ok(None)
            }
            MetaType::Union => {
                if context.reject_unions {
                    return Ok(Some(NativeInvalidExtraction::UnionRejected(ty)));
                }
                let NativeShape::Union { fields } = self.graph.shape(ty)? else {
                    unreachable!("union meta-type has a union shape");
                };
                if fields.is_empty() {
                    return Ok(Some(NativeInvalidExtraction::EmptyUnion(ty)));
                }
                context.tasks.push(Task::Union(UnionTask {
                    ty,
                    fields,
                    next: fields.start,
                    offset,
                    nesting,
                    common: None,
                }));
                Ok(None)
            }
            meta => Ok(Some(NativeInvalidExtraction::Unsupported { ty, meta })),
        }
    }

    fn emit(
        &mut self,
        context: &mut Context,
        ty: NativeTypeId,
        offset: u32,
    ) -> Result<Option<NativeInvalidExtraction>> {
        if context.primitives.len() >= self.options.max_primitives as usize {
            return Ok(Some(NativeInvalidExtraction::MaxPrimitives {
                maximum: self.options.max_primitives,
            }));
        }
        let native = *self.graph.get(ty)?;
        self.push(
            &mut context.primitives,
            NativePrimitive {
                ty,
                origin: native.origin,
                offset,
                meta: native.meta,
                size: native.size,
                aligned_size: native.aligned_size,
                alignment: native.alignment,
            },
        )?;
        Ok(None)
    }

    /// `commonRefinement`: source order, aligned sizes, float preference.
    fn refine(
        &mut self,
        first: Vec<NativePrimitive>,
        second: Vec<NativePrimitive>,
        union: NativeTypeId,
    ) -> Result<std::result::Result<Vec<NativePrimitive>, NativeInvalidExtraction>> {
        let mut result = Vec::new();
        let mut a = 0;
        let mut b = 0;
        while a < first.len() && b < second.len() {
            self.work(1)?;
            Self::step(&mut self.stats.refinement_steps)?;
            let left = first[a];
            let right = second[b];
            if left.offset < right.offset && end(&left)? <= right.offset {
                self.push(&mut result, left)?;
                a += 1;
                continue;
            }
            if right.offset < left.offset && end(&right)? <= left.offset {
                self.push(&mut result, right)?;
                b += 1;
                continue;
            }
            if left.aligned_size >= right.aligned_size {
                match self.overlap(&mut result, &second, b, left, union)? {
                    Ok(next) => b = next,
                    Err(invalid) => return Ok(Err(invalid)),
                }
                a += 1;
            } else {
                match self.overlap(&mut result, &first, a, right, union)? {
                    Ok(next) => a = next,
                    Err(invalid) => return Ok(Err(invalid)),
                }
                b += 1;
            }
        }
        for primitive in first[a..].iter().chain(&second[b..]) {
            self.push(&mut result, *primitive)?;
        }
        self.live -= first.len() + second.len();
        Ok(Ok(result))
    }

    /// `checkOverlap`: a nonfloat big piece is kept; a float yields to the
    /// overlapped smaller pieces. Only a small piece ending past `big` fails.
    fn overlap(
        &mut self,
        result: &mut Vec<NativePrimitive>,
        small: &[NativePrimitive],
        mut at: usize,
        big: NativePrimitive,
        union: NativeTypeId,
    ) -> Result<std::result::Result<usize, NativeInvalidExtraction>> {
        let big_end = end(&big)?;
        let use_small = big.meta == MetaType::Float;
        while at < small.len() {
            self.work(1)?;
            Self::step(&mut self.stats.refinement_steps)?;
            let piece = small[at];
            if piece.offset >= big_end {
                break;
            }
            if end(&piece)? > big_end {
                return Ok(Err(NativeInvalidExtraction::IncompatibleUnion {
                    union,
                    big_offset: big.offset,
                    big_aligned_size: big.aligned_size,
                    small_offset: piece.offset,
                    small_aligned_size: piece.aligned_size,
                }));
            }
            if use_small {
                self.push(result, piece)?;
            }
            at += 1;
        }
        if !use_small {
            self.push(result, big)?;
        }
        Ok(Ok(at))
    }
}
