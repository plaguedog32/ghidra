//! Native `MultiSlotDualAssign` (`<join_dual_class>`, modelrules.cc:1213-1470):
//! one value tiled over two register classes, chosen per fixed-size window of
//! the datatype's native primitives, optionally spilling the remaining suffix
//! onto the stack. This is one rule action, not rule dispatch or signature
//! allocation. Every failure, including `NoFit`, is transactional.
use std::sync::Arc;

use ghidra_languages::{Endianness, MetaType, RuleAction};

use crate::native_extract::{
    NativeExtractionError, NativeExtractionLimits, NativeExtractionOptions,
    NativeExtractionOutcome, NativeExtractionStats, NativeInvalidExtraction, NativePrimitive,
    extract,
};
use crate::native_types::{NativeTypeError, NativeTypeGraph, NativeTypeId};
use crate::{JoinPiece, JoinStorage};

use super::join::{consumed_stack_rejection, crop};
use super::*;

/// The source extractor's per-context maximum (`PrimitiveExtractor(dt,false,
/// false,0,1024)`). It is semantic: exceeding it is an invalid extraction.
const MAX_PRIMITIVES: u32 = 1024;

/// Declared `<join_dual_class>` attributes (`MultiSlotDualAssign::decode`).
/// `None` keeps the constructor default; the reverse flags toggle only when
/// declared `true`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DualJoinAttributes {
    /// `storage` or `a`: the base class (`baseType`).
    pub storage_a: Option<StorageClass>,
    /// `b`: the alternate class (`altType`).
    pub storage_b: Option<StorageClass>,
    pub reverse_justify: Option<bool>,
    pub reverse_significance: Option<bool>,
    pub stack_spill: Option<bool>,
    pub fill_alternate: Option<bool>,
}

impl DualJoinAttributes {
    /// The attributes of a parsed `RuleAction::JoinDualClass`; `None` for
    /// other actions.
    pub fn from_action(action: &RuleAction) -> Option<Self> {
        match *action {
            RuleAction::JoinDualClass {
                storage_a,
                storage_b,
                reverse_justify,
                reverse_significance,
                stack_spill,
                fill_alternate,
            } => Some(Self {
                storage_a,
                storage_b,
                reverse_justify,
                reverse_significance,
                stack_spill,
                fill_alternate,
            }),
            _ => None,
        }
    }
}

/// The resolved `MultiSlotDualAssign` fields after defaults, toggles and
/// `initializeEntries`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DualJoinConfig {
    /// `baseType`; `General` by default.
    pub base: StorageClass,
    /// `altType`; `Float` by default.
    pub alternate: StorageClass,
    /// `ParamListStandard::isBigEndian`: the byte order of the list's first
    /// entry's space, as for `<join>`.
    pub big_endian: bool,
    /// `consumeFromStack`: false by default for input and output lists.
    pub consume_from_stack: bool,
    /// `consumeMostSig`: the first consumed piece is most significant.
    pub consume_most_significant: bool,
    /// `justifyRight`: excess bytes are padding at the value's start.
    pub justify_right: bool,
    /// `fillAlternate`: an alternate window must be one primitive of exactly
    /// the tile size.
    pub fill_alternate: bool,
    /// `tileSize`: the first base tile's width, equal to the first alternate
    /// tile's. Later tiles may differ; windows always use this width.
    pub tile_size: u32,
}

/// One of the action's two tile lists.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DualClass {
    Base,
    Alternate,
}

/// One budget per call. Nested extraction and placements receive only the
/// remaining work (and piece) budget; their work is part of the total.
#[derive(Clone, Copy, Debug)]
pub struct DualJoinLimits {
    /// Tiles collected into the base and alternate lists together.
    pub max_tiles: usize,
    /// List entries scanned at initialization plus `getFirstUnused` visits.
    pub max_examined_entries: u64,
    /// `getTileClass` primitive reads, including the read that ends a window.
    pub max_primitive_visits: u64,
    pub max_group_references: u64,
    /// Journaled status writes.
    pub max_group_updates: u64,
    /// Nested placement queries: chosen tiles plus the stack spill.
    pub max_placements: usize,
    /// Output pieces; a floating conversion counts once.
    pub max_pieces: usize,
    /// Occupied extents held by the state after the call.
    pub max_occupied_extents: usize,
    /// Per-placement structural cap passed to each nested query.
    pub max_source_pieces: usize,
    /// Nested extraction: live primitive records across its contexts.
    pub max_extraction_live_primitives: usize,
    /// Nested extraction: datatype nesting including the root.
    pub max_extraction_depth: usize,
    pub max_work: u64,
}

impl Default for DualJoinLimits {
    fn default() -> Self {
        Self {
            max_tiles: 100_000,
            max_examined_entries: 4_000_000,
            max_primitive_visits: 4_000_000,
            max_group_references: 8_000_000,
            max_group_updates: 1_000_000,
            max_placements: 65_536,
            max_pieces: 65_536,
            max_occupied_extents: 65_536,
            max_source_pieces: 1024,
            max_extraction_live_primitives: 1_000_000,
            max_extraction_depth: 100_000,
            max_work: 64_000_000,
        }
    }
}

/// Why `getTileClass` returned -1 for one window.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DualTileRejection {
    /// Every primitive was already classified (`index >= primitives.size()`).
    NoPrimitiveLeft,
    /// The next primitive starts before the window. This happens after a
    /// later tile wider than `tile_size`.
    StartsBeforeWindow { primitive: usize },
    /// A primitive's raw extent crosses the window end.
    CrossesWindow { primitive: usize },
    /// No primitive starts inside the window.
    EmptyWindow,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DualJoinNoFit {
    /// The root extraction is invalid.
    InvalidExtraction(NativeInvalidExtraction),
    /// The extraction is valid but has no primitives.
    NoPrimitives,
    /// The extraction has holes.
    Holes,
    /// A window at this value offset could not be classified.
    Window {
        offset: u32,
        rejection: DualTileRejection,
    },
    /// The class chosen for the window at `offset` has no unused tile and the
    /// action does not spill.
    Exhausted {
        class: DualClass,
        offset: u32,
        uncovered: u32,
    },
    /// The stack pool rejected the remaining suffix.
    Stack { uncovered: u32, reason: NoFit },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DualJoinStepKind {
    /// A register tile consumed at its full declared width. `tile` indexes
    /// the class's tile list.
    Tile { class: DualClass, tile: usize },
    /// The whole remaining suffix in the final stack pool, after `exhausted`
    /// had no unused tile.
    Stack {
        exhausted: DualClass,
        slots: SlotRange,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DualJoinStep {
    pub site: BindingSite,
    /// The tile's group, or the stack pool's first group.
    pub group: ResourceId,
    pub kind: DualJoinStepKind,
    /// `typeSize - sizeLeft` when the step was chosen: the window start for
    /// a tile, the suffix start for the stack.
    pub offset: u32,
    /// Value bytes in this step: the tile width less any excess removed from
    /// it, or the spilled bytes. A floating conversion keeps the full tile.
    pub bytes: u32,
    /// Classification provenance into [`DualJoinAssignment::primitives`]:
    /// the primitives a tile's window classified, or for the stack those from
    /// the exhausted window to the end. With later tiles of another width
    /// this is not physical containment (windows use `tile_size`).
    pub first_primitive: usize,
    pub primitive_end: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DualJoinAllocation {
    /// Native `getSize`: the raw, not aligned, size.
    pub size: u32,
    /// Native `getAlignment`, used only for the stack spill.
    pub alignment: u32,
    /// Most significant first; join-pool tiles contribute their own physical
    /// pieces in place.
    pub storage: JoinStorage,
    /// Consumption order, not significance order.
    pub steps: Vec<DualJoinStep>,
    /// Bytes of the final register tile beyond the value (zero when the
    /// tiles matched exactly or the value spilled).
    pub excess: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DualJoinOutcome {
    Assigned(DualJoinAllocation),
    /// Upstream `fail`: no status change is committed.
    NoFit(DualJoinNoFit),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DualJoinUsage {
    pub base_tiles: usize,
    pub alternate_tiles: usize,
    pub examined_entries: u64,
    /// The nested root extraction (zero when it did not run).
    pub extraction: NativeExtractionStats,
    /// Primitives of a valid root extraction.
    pub primitives: usize,
    pub primitive_visits: u64,
    pub group_references: u64,
    pub group_updates: u64,
    pub placements: usize,
    pub pieces: usize,
    /// Held by the state after the call (unchanged by `NoFit`).
    pub occupied_extents: usize,
    pub source_pieces: usize,
    /// Includes extraction and nested placement work.
    pub work: u64,
}

/// The action's result. It retains the source graph so that the native IDs
/// in `primitives` and in an invalid-extraction reason stay interpretable.
#[derive(Clone, Debug)]
pub struct DualJoinAssignment {
    pub graph: Arc<NativeTypeGraph>,
    pub ty: NativeTypeId,
    pub config: DualJoinConfig,
    /// The valid root extraction in source order; empty when it is invalid.
    pub primitives: Vec<NativePrimitive>,
    pub outcome: DualJoinOutcome,
    pub usage: DualJoinUsage,
}

/// Graphs compare by identity (`Arc::ptr_eq`), everything else by value.
impl PartialEq for DualJoinAssignment {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.graph, &other.graph)
            && self.ty == other.ty
            && self.config == other.config
            && self.primitives == other.primitives
            && self.outcome == other.outcome
            && self.usage == other.usage
    }
}

impl Eq for DualJoinAssignment {}

#[derive(Debug, thiserror::Error)]
pub enum DualJoinError {
    #[error("dual-class join limit exceeded: {0}")]
    Limit(&'static str),
    #[error("allocation state belongs to another compiler overlay or list")]
    StateMismatch,
    /// An unknown native ID, or a datatype whose conversion failed.
    #[error("dual-class join datatype: {0}")]
    Type(NativeTypeError),
    /// The graph's layouts declare a byte order other than the language's
    /// default space; byte-range bitfield offsets would then be wrong.
    #[error("datatype byte order {graph:?} differs from the language default space {language:?}")]
    ByteOrderMismatch {
        graph: Endianness,
        language: Endianness,
    },
    /// A nested extraction error other than a limit or a datatype error.
    #[error("dual-class join extraction: {0}")]
    Extraction(NativeExtractionError),
    /// Initialization error (`Could not find matching resources`).
    #[error("no exclusion, single-group {class:?} tiles for the dual-class join action")]
    NoTiles { class: StorageClass },
    /// Initialization error (`Storage class register sizes do not match`).
    #[error("first base tile has {base} bytes but first alternate tile has {alternate}")]
    TileSizeMismatch { base: u32, alternate: u32 },
    /// Initialization error: stack spill needs `getStackEntry`.
    #[error("dual-class join stack spill requires the last entry to be an aligned stack pool")]
    MissingStack,
    /// Native `int4` arithmetic the source would overflow.
    #[error("dual-class join arithmetic exceeds the native int range: {0}")]
    NativeIntRange(&'static str),
    #[error("invalid dual-class join declaration at {site:?}: {reason}")]
    InvalidDeclaration {
        site: BindingSite,
        reason: &'static str,
    },
    #[error("dual-class join storage at {site:?} overlaps storage held by {previous:?}")]
    Overlap {
        site: BindingSite,
        previous: BindingSite,
    },
    #[error("dual-class join entry {site:?}: resource group {group:?} is already in use")]
    GroupInUse {
        site: BindingSite,
        group: ResourceId,
    },
    /// A layout the source would build invalidly, or one not modeled here.
    #[error("unsupported dual-class join layout at {site:?}: {reason}")]
    Unsupported {
        site: BindingSite,
        reason: &'static str,
    },
    #[error("dual-class join placement at {site:?}: {source}")]
    Placement {
        site: BindingSite,
        source: PlacementError,
    },
    #[error(transparent)]
    Allocation(FallbackError),
}

impl From<FallbackError> for DualJoinError {
    fn from(error: FallbackError) -> Self {
        match error {
            FallbackError::Limit(resource) => Self::Limit(resource),
            FallbackError::StateMismatch => Self::StateMismatch,
            FallbackError::Overlap { site, previous, .. } => Self::Overlap { site, previous },
            FallbackError::GroupInUse { site, group, .. } => Self::GroupInUse { site, group },
            FallbackError::Unsupported { site, reason, .. } => Self::Unsupported { site, reason },
            other => Self::Allocation(other),
        }
    }
}

fn placement_error(site: BindingSite) -> impl FnOnce(PlacementError) -> DualJoinError {
    move |error| match error {
        PlacementError::Limit("output pieces") => DualJoinError::Limit("pieces"),
        PlacementError::Limit(resource) => DualJoinError::Limit(resource),
        source => DualJoinError::Placement { site, source },
    }
}

fn extraction_error(error: NativeExtractionError) -> DualJoinError {
    match error {
        NativeExtractionError::Limit("live primitives") => {
            DualJoinError::Limit("extraction live primitives")
        }
        NativeExtractionError::Limit("depth") => DualJoinError::Limit("extraction depth"),
        NativeExtractionError::Limit(resource) => DualJoinError::Limit(resource),
        NativeExtractionError::Type(error) => DualJoinError::Type(error),
        other => DualJoinError::Extraction(other),
    }
}

/// `metatype2typeclass` (type.cc:304): float and pointer meta-types have
/// their own class; every other meta-type, Unknown and Code included, is
/// general.
fn type_class(meta: MetaType) -> StorageClass {
    match meta {
        MetaType::Float => StorageClass::Float,
        MetaType::Ptr => StorageClass::Ptr,
        _ => StorageClass::General,
    }
}

/// Native getAddrBySlot's arithmetic before its capacity check. Keep floor
/// division for alignment waste and refuse int4 overflow even when wide
/// placement arithmetic would subsequently report SlotsExhausted. Shared with
/// the native fallback kernel; these are this action's established reasons.
fn native_spill_cursor(
    cursor: u64,
    alignment: u32,
    type_align: u32,
    size: u32,
) -> Result<u64, &'static str> {
    super::native::native_slot_cursor(cursor, alignment, type_align, size)
        .map(|(cursor, _)| cursor)
        .map_err(|operation| match operation {
            NativeSlotOverflow::Cursor => "stack cursor exceeds the native int range",
            NativeSlotOverflow::CursorBytes => "stack cursor bytes exceed the native int range",
            NativeSlotOverflow::AlignedCursor => {
                "aligned stack cursor exceeds the native int range"
            }
            NativeSlotOverflow::CursorPlusSlots => {
                "stack cursor plus value slots exceeds the native int range"
            }
        })
}

#[derive(Clone, Copy)]
struct Tile {
    entry: usize,
    site: BindingSite,
    group: ResourceId,
    size: u32,
}

struct Spill {
    entry: usize,
    group: ResourceId,
    uncovered: u32,
    next_slot: u64,
    value: PlacedValue,
    exhausted: DualClass,
    offset: u32,
    first_primitive: usize,
}

#[derive(Clone, Copy)]
struct Chosen {
    tile: Tile,
    class: DualClass,
    index: usize,
    offset: u32,
    first_primitive: usize,
    primitive_end: usize,
}

/// Per-call counters the shared fallback budget does not have.
struct Counters {
    visits: u64,
    max_visits: u64,
}

impl Counters {
    fn visit(&mut self, budget: &mut Budget) -> Result<(), DualJoinError> {
        self.visits = self
            .visits
            .checked_add(1)
            .filter(|n| *n <= self.max_visits)
            .ok_or(DualJoinError::Limit("primitive visits"))?;
        budget.work(1)?;
        Ok(())
    }
}

/// `getTileClass` for the window `[offset, offset + tile_size)`. The outer
/// `Err` is a resource or native-int error; the inner one a source -1.
fn tile_class(
    primitives: &[NativePrimitive],
    offset: u32,
    index: &mut usize,
    config: &DualJoinConfig,
    counters: &mut Counters,
    budget: &mut Budget,
) -> Result<Result<DualClass, DualTileRejection>, DualJoinError> {
    budget.work(1)?;
    let end = u64::from(offset) + u64::from(config.tile_size);
    if end > u64::from(i32::MAX as u32) {
        return Err(DualJoinError::NativeIntRange(
            "tile window end exceeds the native int range",
        ));
    }
    if *index >= primitives.len() {
        return Ok(Err(DualTileRejection::NoPrimitiveLeft));
    }
    let first_size = primitives[*index].size;
    let mut class = DualClass::Alternate;
    let mut count = 0_usize;
    while *index < primitives.len() {
        counters.visit(budget)?;
        let primitive = primitives[*index];
        if primitive.offset < offset {
            return Ok(Err(DualTileRejection::StartsBeforeWindow {
                primitive: *index,
            }));
        }
        if u64::from(primitive.offset) >= end {
            break;
        }
        // Raw size (`dt->getSize()`), not the aligned size.
        let last = u64::from(primitive.offset) + u64::from(primitive.size);
        if last > u64::from(i32::MAX as u32) {
            return Err(DualJoinError::NativeIntRange(
                "primitive end exceeds the native int range",
            ));
        }
        if last > end {
            return Ok(Err(DualTileRejection::CrossesWindow { primitive: *index }));
        }
        count += 1;
        *index += 1;
        if type_class(primitive.meta) != config.alternate {
            class = DualClass::Base;
        }
    }
    if count == 0 {
        return Ok(Err(DualTileRejection::EmptyWindow));
    }
    if config.fill_alternate && (count > 1 || first_size != config.tile_size) {
        class = DualClass::Base;
    }
    Ok(Ok(class))
}

impl AllocationState {
    /// Run one `<join_dual_class>` action for the native datatype `ty` of
    /// `graph`. Raw size, alignment and primitives come from the graph.
    /// Success commits the consumed tiles and the stack cursor; `NoFit` and
    /// every error leave the state exactly unchanged.
    pub fn assign_dual_join(
        &mut self,
        resources: &CompilerResources,
        attributes: &DualJoinAttributes,
        graph: Arc<NativeTypeGraph>,
        ty: NativeTypeId,
        limits: DualJoinLimits,
    ) -> Result<DualJoinAssignment, DualJoinError> {
        let mut journal = Vec::new();
        let result = self.run_dual_join(resources, attributes, graph, ty, limits, &mut journal);
        if !matches!(
            result,
            Ok(DualJoinAssignment {
                outcome: DualJoinOutcome::Assigned(_),
                ..
            })
        ) {
            self.rollback(journal);
        }
        result
    }

    fn run_dual_join(
        &mut self,
        resources: &CompilerResources,
        attributes: &DualJoinAttributes,
        graph: Arc<NativeTypeGraph>,
        ty: NativeTypeId,
        limits: DualJoinLimits,
        journal: &mut Vec<Undo>,
    ) -> Result<DualJoinAssignment, DualJoinError> {
        let (list, source) = self.source_list(resources)?;
        if self.occupied.len() > limits.max_occupied_extents {
            return Err(DualJoinError::Limit("occupied extents"));
        }
        let storage = self.storage.clone();
        let mut budget = Budget {
            limits: FallbackLimits {
                max_requests: 1,
                max_groups: usize::MAX,
                max_examined_entries: limits.max_examined_entries,
                max_group_references: limits.max_group_references,
                max_group_updates: limits.max_group_updates,
                max_placements: limits.max_placements,
                max_pieces: limits.max_pieces,
                max_occupied_extents: limits.max_occupied_extents,
                max_source_pieces: limits.max_source_pieces,
                max_work: limits.max_work,
            },
            usage: FallbackUsage {
                requests: 1,
                occupied_extents: self.occupied.len(),
                ..Default::default()
            },
        };
        budget.work(1)?;

        // The datatype: native getSize/getAlignment from the graph.
        budget.work(1)?;
        let native = *graph.get(ty).map_err(DualJoinError::Type)?;
        if let Some(order) = graph.layouts().endianness() {
            let file = storage.register_file();
            budget.lookup(file.spaces().len())?;
            let language = file
                .space(file.default_space())
                .ok_or(DualJoinError::StateMismatch)?
                .endianness;
            if order != language {
                return Err(DualJoinError::ByteOrderMismatch {
                    graph: order,
                    language,
                });
            }
        }

        // Constructor defaults (modelrules.cc:1301-1318), then decode toggles.
        let base_class = attributes.storage_a.unwrap_or(StorageClass::General);
        let alternate_class = attributes.storage_b.unwrap_or(StorageClass::Float);
        let first = list
            .entries
            .first()
            .ok_or(DualJoinError::NoTiles { class: base_class })?;
        let big_endian = self.list_big_endian(&storage, first.site, &mut budget)?;
        let toggled = |flag: Option<bool>, value: bool| value ^ (flag == Some(true));
        let mut config = DualJoinConfig {
            base: base_class,
            alternate: alternate_class,
            big_endian,
            consume_from_stack: attributes.stack_spill.unwrap_or(false),
            consume_most_significant: toggled(attributes.reverse_significance, big_endian),
            justify_right: toggled(attributes.reverse_justify, big_endian),
            fill_alternate: attributes.fill_alternate.unwrap_or(false),
            tile_size: 0,
        };

        // initializeEntries: extractTiles for each class (one scan), then
        // getStackEntry and the three initialization checks in source order.
        let mut base = Vec::new();
        let mut alternate = Vec::new();
        for (index, (entry, declared)) in list.entries.iter().zip(&source.entries).enumerate() {
            budget.examine()?;
            if !entry.exclusion || entry.groups.len() != 1 {
                continue;
            }
            let class = declared.storage_class;
            let lists = usize::from(class == config.base) + usize::from(class == config.alternate);
            if lists == 0 {
                continue;
            }
            if base.len() + alternate.len() + lists > limits.max_tiles {
                return Err(DualJoinError::Limit("tiles"));
            }
            if declared.max_size == 0 || declared.max_size > i32::MAX as u32 {
                return Err(DualJoinError::InvalidDeclaration {
                    site: entry.site,
                    reason: "tile width must be a positive native int",
                });
            }
            budget.work(lists)?;
            let tile = Tile {
                entry: index,
                site: entry.site,
                group: entry.groups[0],
                size: declared.max_size,
            };
            if class == config.base {
                base.push(tile);
            }
            if class == config.alternate {
                alternate.push(tile);
            }
        }
        if base.is_empty() {
            return Err(DualJoinError::NoTiles { class: config.base });
        }
        if alternate.is_empty() {
            return Err(DualJoinError::NoTiles {
                class: config.alternate,
            });
        }
        config.tile_size = base[0].size;
        if alternate[0].size != config.tile_size {
            return Err(DualJoinError::TileSizeMismatch {
                base: config.tile_size,
                alternate: alternate[0].size,
            });
        }
        let stack = if config.consume_from_stack {
            let index = list.entries.len() - 1;
            let entry = &list.entries[index];
            budget.lookup(storage.bindings().len())?;
            let binding = storage
                .binding(entry.site)
                .ok_or(DualJoinError::StateMismatch)?;
            if entry.exclusion
                || !matches!(&binding.storage, ResolvedStorage::Single(range) if range.address.space == AbiSpace::Stack)
            {
                return Err(DualJoinError::MissingStack);
            }
            Some(index)
        } else {
            None
        };

        // assignAddress: PrimitiveExtractor(dt, false, false, 0, 1024).
        let mut counters = Counters {
            visits: 0,
            max_visits: limits.max_primitive_visits,
        };
        let (extracted, stats) = extract(
            &graph,
            ty,
            NativeExtractionOptions {
                offset: 0,
                reject_unions: false,
                nested_arrays_are_primitives: false,
                max_primitives: MAX_PRIMITIVES,
            },
            NativeExtractionLimits {
                max_live_primitives: limits.max_extraction_live_primitives,
                max_depth: limits.max_extraction_depth,
                max_work: limits.max_work - budget.usage.work,
            },
        )
        .map_err(extraction_error)?;
        budget.work_u64(stats.work)?;
        let (base_tiles, alternate_tiles) = (base.len(), alternate.len());
        let finish = |outcome,
                      primitives: Vec<NativePrimitive>,
                      budget: &Budget,
                      counters: &Counters,
                      occupied_extents|
         -> Result<DualJoinAssignment, DualJoinError> {
            let usage = DualJoinUsage {
                base_tiles,
                alternate_tiles,
                examined_entries: budget.usage.examined_entries,
                extraction: stats,
                primitives: primitives.len(),
                primitive_visits: counters.visits,
                group_references: budget.usage.group_references,
                group_updates: budget.usage.group_updates,
                placements: budget.usage.placements,
                pieces: budget.usage.pieces,
                occupied_extents,
                source_pieces: budget.usage.source_pieces,
                work: budget.usage.work,
            };
            Ok(DualJoinAssignment {
                graph: graph.clone(),
                ty,
                config,
                primitives,
                outcome,
                usage,
            })
        };
        let primitives = match extracted {
            NativeExtractionOutcome::Invalid(reason) => {
                let held = self.occupied.len();
                return finish(
                    DualJoinOutcome::NoFit(DualJoinNoFit::InvalidExtraction(reason)),
                    Vec::new(),
                    &budget,
                    &counters,
                    held,
                );
            }
            // containsUnknown and aligned are intentionally not tested.
            NativeExtractionOutcome::Valid {
                primitives,
                contains_holes,
                ..
            } => {
                let reason = if primitives.is_empty() {
                    Some(DualJoinNoFit::NoPrimitives)
                } else if contains_holes {
                    Some(DualJoinNoFit::Holes)
                } else {
                    None
                };
                if let Some(reason) = reason {
                    let held = self.occupied.len();
                    return finish(
                        DualJoinOutcome::NoFit(reason),
                        primitives,
                        &budget,
                        &counters,
                        held,
                    );
                }
                primitives
            }
        };

        // The tiling loop over native int sizes. Windows always span
        // `tile_size`; the offset advances by each chosen tile's own width.
        let type_size = native.size;
        let align = native.alignment;
        let untouched = GroupState::Available { used_slots: 0 };
        let mut size_left = i64::from(type_size);
        let mut index = 0;
        let mut cursors = [0_usize; 2];
        let mut chosen: Vec<Chosen> = Vec::new();
        let mut exhausted = None;
        while size_left > 0 {
            let offset = (i64::from(type_size) - size_left) as u32;
            let first_primitive = index;
            let class = match tile_class(
                &primitives,
                offset,
                &mut index,
                &config,
                &mut counters,
                &mut budget,
            )? {
                Ok(class) => class,
                Err(rejection) => {
                    let held = self.occupied.len();
                    return finish(
                        DualJoinOutcome::NoFit(DualJoinNoFit::Window { offset, rejection }),
                        primitives,
                        &budget,
                        &counters,
                        held,
                    );
                }
            };
            let (tiles, cursor) = match class {
                DualClass::Base => (&base, &mut cursors[0]),
                DualClass::Alternate => (&alternate, &mut cursors[1]),
            };
            // getFirstUnused: any nonzero status, positive cursors included,
            // is skipped. The cursor stays on the returned tile.
            while *cursor < tiles.len() {
                budget.examine()?;
                budget.references(1)?;
                let status = *self
                    .groups
                    .get(tiles[*cursor].group.0)
                    .ok_or(DualJoinError::StateMismatch)?;
                if status == untouched {
                    break;
                }
                *cursor += 1;
            }
            if *cursor == tiles.len() {
                if !config.consume_from_stack {
                    let held = self.occupied.len();
                    return finish(
                        DualJoinOutcome::NoFit(DualJoinNoFit::Exhausted {
                            class,
                            offset,
                            uncovered: size_left as u32,
                        }),
                        primitives,
                        &budget,
                        &counters,
                        held,
                    );
                }
                exhausted = Some((class, offset, first_primitive));
                break;
            }
            let tile = tiles[*cursor];
            self.set(tile.group.0, GroupState::Consumed, &mut budget, journal)?;
            chosen.push(Chosen {
                tile,
                class,
                index: *cursor,
                offset,
                first_primitive,
                primitive_end: index,
            });
            size_left -= i64::from(tile.size);
        }

        // The whole remaining suffix goes to the stack with the datatype's
        // own alignment and the action's justification.
        let mut spill = None;
        if size_left > 0 {
            let uncovered = size_left as u32;
            let (Some(stack_index), Some((exhausted, offset, first_primitive))) =
                (stack, exhausted)
            else {
                return Err(DualJoinError::StateMismatch);
            };
            let entry = &list.entries[stack_index];
            let declared = &source.entries[stack_index];
            let unsupported = |reason| DualJoinError::Unsupported {
                site: entry.site,
                reason,
            };
            budget.references(1)?;
            let group = *entry.groups.first().ok_or(DualJoinError::StateMismatch)?;
            // getAddrBySlot rejects a value below the minimum before any slot
            // arithmetic, then wastes slots with native floor division.
            let cursor = match self.groups.get(group.0) {
                Some(GroupState::Available { used_slots }) => {
                    budget.work(1)?;
                    if uncovered < declared.min_size {
                        Err(NoFit::BelowMinimum)
                    } else {
                        Ok(
                            native_spill_cursor(
                                *used_slots,
                                declared.alignment(),
                                align,
                                uncovered,
                            )
                            .map_err(DualJoinError::NativeIntRange)?,
                        )
                    }
                }
                Some(GroupState::Consumed) => {
                    budget.work(1)?;
                    match consumed_stack_rejection(declared, uncovered, align)
                        .map_err(unsupported)?
                    {
                        Some(reason) => Err(reason),
                        None => {
                            return Err(unsupported("the stack pool's resource group is consumed"));
                        }
                    }
                }
                None => return Err(DualJoinError::StateMismatch),
            };
            let cursor = match cursor {
                Ok(cursor) => cursor,
                Err(reason) => {
                    let held = self.occupied.len();
                    return finish(
                        DualJoinOutcome::NoFit(DualJoinNoFit::Stack { uncovered, reason }),
                        primitives,
                        &budget,
                        &counters,
                        held,
                    );
                }
            };
            bump_count(
                &mut budget.usage.placements,
                1,
                limits.max_placements,
                "placements",
            )?;
            let placement = place_parameter(
                &storage,
                entry.site,
                PlacementRequest {
                    size: uncovered,
                    used_slots: cursor,
                    // The native alignment waste is already in the cursor.
                    type_alignment: 1,
                    justification: if config.justify_right {
                        Justification::Right
                    } else {
                        Justification::Left
                    },
                },
                budget.nested_limits(),
            )
            .map_err(placement_error(entry.site))?;
            budget.work_u64(placement.work)?;
            budget.usage.source_pieces = budget.usage.source_pieces.max(placement.source_pieces);
            let value = match placement.outcome {
                PlacementOutcome::NoFit(NoFit::AddressDomain) => {
                    return Err(unsupported(
                        "spilled stack storage leaves its address domain",
                    ));
                }
                PlacementOutcome::NoFit(reason) => {
                    let held = self.occupied.len();
                    return finish(
                        DualJoinOutcome::NoFit(DualJoinNoFit::Stack { uncovered, reason }),
                        primitives,
                        &budget,
                        &counters,
                        held,
                    );
                }
                PlacementOutcome::Placed(value) => value,
            };
            self.set(
                group.0,
                GroupState::Available {
                    used_slots: placement.next_slot,
                },
                &mut budget,
                journal,
            )?;
            spill = Some(Spill {
                entry: stack_index,
                group,
                uncovered,
                next_slot: placement.next_slot,
                value,
                exhausted,
                offset,
                first_primitive,
            });
        }

        // Materialize the selection. Excess comes only from the final tile;
        // there is no floating-extension shortcut in this action.
        let excess = if size_left < 0 {
            (-size_left) as u32
        } else {
            0
        };
        let crop_step = (excess != 0).then(|| {
            if config.justify_right {
                0
            } else {
                chosen.len() - 1
            }
        });
        let from_start = config.big_endian ^ config.consume_most_significant ^ config.justify_right;
        let step_count = chosen.len() + usize::from(spill.is_some());
        let mut steps = Vec::with_capacity(step_count);
        let mut bounds = Vec::with_capacity(step_count);
        let mut pieces: Vec<JoinPiece> = Vec::new();
        let mut converted = None;
        for (step, choice) in chosen.iter().enumerate() {
            let tile = choice.tile;
            let declared = &source.entries[tile.entry];
            let unsupported = |reason| DualJoinError::Unsupported {
                site: tile.site,
                reason,
            };
            bump_count(
                &mut budget.usage.placements,
                1,
                limits.max_placements,
                "placements",
            )?;
            // getAddrBySlot(status, trialSize, 1): a full untouched tile.
            let placement = place_parameter(
                &storage,
                tile.site,
                PlacementRequest {
                    size: tile.size,
                    used_slots: 0,
                    type_alignment: 1,
                    justification: Justification::Default,
                },
                budget.nested_limits(),
            )
            .map_err(placement_error(tile.site))?;
            budget.work_u64(placement.work)?;
            budget.usage.source_pieces = budget.usage.source_pieces.max(placement.source_pieces);
            let value = match placement.outcome {
                PlacementOutcome::Placed(value) => value,
                PlacementOutcome::NoFit(NoFit::AddressDomain) => {
                    return Err(unsupported("tile storage leaves its address domain"));
                }
                PlacementOutcome::NoFit(_) => {
                    return Err(unsupported("tile cannot hold its declared width"));
                }
            };
            budget.lookup(storage.bindings().len())?;
            let binding = storage
                .binding(tile.site)
                .ok_or(DualJoinError::StateMismatch)?;
            let join_tile = matches!(&binding.storage, ResolvedStorage::Join { .. });
            if let (ResolvedStorage::Join { pieces, .. }, PlacedStorage::Bits { .. }) =
                (&binding.storage, &value.storage)
            {
                budget.work(pieces.len())?;
                let total = pieces
                    .iter()
                    .try_fold(0_u64, |n, p| n.checked_add(u64::from(p.storage.size?)));
                if total != Some(u64::from(tile.size)) {
                    // Upstream would nest a partial join-space varnode.
                    return Err(unsupported("join tile narrower than its join storage"));
                }
            }
            let mut bytes = tile.size;
            match value.storage {
                PlacedStorage::FloatConversion { .. } if step_count != 1 || excess != 0 => {
                    return Err(unsupported(
                        "floating-extension tile inside a compound or truncated join",
                    ));
                }
                PlacedStorage::FloatConversion {
                    container,
                    logical_size,
                } => {
                    bump_count(&mut budget.usage.pieces, 1, limits.max_pieces, "pieces")?;
                    converted = Some((container, logical_size));
                }
                PlacedStorage::Bits {
                    pieces: mut tile_pieces,
                } => {
                    if crop_step == Some(step) {
                        if join_tile || tile_pieces.len() != 1 {
                            return Err(unsupported("justification would truncate a join tile"));
                        }
                        crop(&mut tile_pieces[0], excess, from_start).map_err(unsupported)?;
                        bytes -= excess;
                    }
                    bump_count(
                        &mut budget.usage.pieces,
                        tile_pieces.len(),
                        limits.max_pieces,
                        "pieces",
                    )?;
                    let start = pieces.len();
                    pieces.reserve(tile_pieces.len());
                    pieces.extend(tile_pieces.into_iter().map(|piece| JoinPiece {
                        site: tile.site,
                        step,
                        piece,
                    }));
                    bounds.push((start, pieces.len()));
                }
            }
            let (spans, _) = self
                .binding_spans(&binding.storage, declared, tile.size, 0, &mut budget)
                .map_err(|error| match error {
                    SpanError::Budget(error) => error.into(),
                    SpanError::Unsupported(reason) => unsupported(reason),
                })?;
            for span in spans {
                self.occupy(span, 0, tile.site, &mut budget, journal)?;
            }
            steps.push(DualJoinStep {
                site: tile.site,
                group: tile.group,
                kind: DualJoinStepKind::Tile {
                    class: choice.class,
                    tile: choice.index,
                },
                offset: choice.offset,
                bytes,
                first_primitive: choice.first_primitive,
                primitive_end: choice.primitive_end,
            });
        }
        if let Some(spill) = spill {
            let entry = &list.entries[spill.entry];
            let declared = &source.entries[spill.entry];
            let site = entry.site;
            let group = spill.group;
            budget.references(entry.groups.len())?;
            for &other in &entry.groups {
                let state = self
                    .groups
                    .get(other.0)
                    .ok_or(DualJoinError::StateMismatch)?;
                if other != group && *state != untouched {
                    return Err(DualJoinError::GroupInUse { site, group: other });
                }
            }
            let (spans, slots) = self
                .spans(
                    entry,
                    declared,
                    spill.uncovered,
                    spill.next_slot,
                    &mut budget,
                )
                .map_err(|error| match error {
                    SpanError::Budget(error) => error.into(),
                    SpanError::Unsupported(reason) => DualJoinError::Unsupported { site, reason },
                })?;
            for span in spans {
                self.occupy(span, 0, site, &mut budget, journal)?;
            }
            let PlacedStorage::Bits {
                pieces: stack_pieces,
            } = spill.value.storage
            else {
                return Err(DualJoinError::Unsupported {
                    site,
                    reason: "stack spill is not a bit slice",
                });
            };
            bump_count(
                &mut budget.usage.pieces,
                stack_pieces.len(),
                limits.max_pieces,
                "pieces",
            )?;
            let step = steps.len();
            let start = pieces.len();
            pieces.reserve(stack_pieces.len());
            pieces.extend(
                stack_pieces
                    .into_iter()
                    .map(|piece| JoinPiece { site, step, piece }),
            );
            bounds.push((start, pieces.len()));
            steps.push(DualJoinStep {
                site,
                group,
                kind: DualJoinStepKind::Stack {
                    exhausted: spill.exhausted,
                    slots: slots.ok_or(DualJoinError::StateMismatch)?,
                },
                offset: spill.offset,
                bytes: spill.uncovered,
                first_primitive: spill.first_primitive,
                primitive_end: primitives.len(),
            });
        }

        // assignAddressFromPieces: reverse consumption order unless the first
        // consumed step is most significant. Each step keeps its own order.
        let storage_recipe = if let Some((container, logical_size)) = converted {
            JoinStorage::FloatConversion {
                container,
                logical_size,
            }
        } else {
            budget.work(pieces.len())?;
            if !config.consume_most_significant && bounds.len() > 1 {
                let total = pieces.len();
                pieces.reverse();
                for &(start, end) in &bounds {
                    pieces[total - end..total - start].reverse();
                }
            }
            let mut significance = 0_u32;
            for piece in pieces.iter_mut().rev() {
                piece.piece.lsb_byte = significance;
                significance = piece
                    .piece
                    .storage
                    .size
                    .and_then(|size| significance.checked_add(size))
                    .ok_or(DualJoinError::StateMismatch)?;
            }
            if significance != type_size {
                return Err(DualJoinError::StateMismatch);
            }
            JoinStorage::Pieces(pieces)
        };
        let held = self.occupied.len();
        finish(
            DualJoinOutcome::Assigned(DualJoinAllocation {
                size: type_size,
                alignment: align,
                storage: storage_recipe,
                steps,
                excess,
            }),
            primitives,
            &budget,
            &counters,
            held,
        )
    }
}
