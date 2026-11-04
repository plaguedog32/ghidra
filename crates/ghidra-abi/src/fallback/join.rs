//! Native `MultiSlotAssign` (`<join>`, modelrules.cc:856-1072): one compound
//! value over the register tiles of one storage class, optionally spilling the
//! uncovered bytes onto the stack. This is one rule action, not rule dispatch
//! or signature allocation. Every failure, including `NoFit`, is transactional.
use ghidra_languages::RuleAction;
use ghidra_pcode::Endianness;

use crate::{PieceRole, PlacedPiece};

use super::*;

/// Declared `<join>` attributes (`MultiSlotAssign::decode`). `None` keeps the
/// constructor default; the reverse flags toggle only when declared `true`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct JoinAttributes {
    pub storage: Option<StorageClass>,
    pub reverse_justify: Option<bool>,
    pub reverse_significance: Option<bool>,
    pub align: Option<bool>,
    pub stack_spill: Option<bool>,
    pub backfill: Option<bool>,
}

impl JoinAttributes {
    /// The attributes of a parsed `RuleAction::Join`; `None` for other actions.
    pub fn from_action(action: &RuleAction) -> Option<Self> {
        match *action {
            RuleAction::Join {
                storage,
                reverse_justify,
                reverse_significance,
                align,
                stack_spill,
                backfill,
            } => Some(Self {
                storage,
                reverse_justify,
                reverse_significance,
                align,
                stack_spill,
                backfill,
            }),
            _ => None,
        }
    }
}

/// The resolved `MultiSlotAssign` fields after defaults and toggles.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct JoinConfig {
    /// `resourceType`; `General` by default.
    pub storage: StorageClass,
    /// `ParamListStandard::isBigEndian`: the byte order of the list's first
    /// entry's space (a join or `OTHER` first entry uses the default space,
    /// a stack entry its backing space, as placement does).
    pub big_endian: bool,
    /// `consumeFromStack`: true for input lists, false for output lists.
    pub consume_from_stack: bool,
    /// `consumeMostSig`: the first consumed tile is most significant.
    pub consume_most_significant: bool,
    /// `enforceAlignment`.
    pub enforce_alignment: bool,
    /// `justifyRight`: excess bytes are padding at the value's start.
    pub justify_right: bool,
    /// `allowBackfill`: tiles passed over by the start search stay available.
    pub backfill: bool,
}

/// The datatype geometry the action reads. No datatype graph is consulted.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct JoinRequest {
    /// Native `Datatype::getSize`: raw, not aligned, size in `1..=i32::MAX`.
    pub raw_size: u32,
    /// Native `Datatype::getAlignment` in `1..=i32::MAX`.
    pub alignment: u32,
}

impl JoinRequest {
    pub fn new(raw_size: u32, alignment: u32) -> Self {
        Self {
            raw_size,
            alignment,
        }
    }
}

/// One budget per call. Nested placements receive only the remaining work
/// and piece budget; their work is part of the total.
#[derive(Clone, Copy, Debug)]
pub struct JoinLimits {
    /// Eligible tiles collected from the list.
    pub max_tiles: usize,
    /// List entries scanned at initialization plus tile visits.
    pub max_examined_entries: u64,
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
    pub max_work: u64,
}

impl Default for JoinLimits {
    fn default() -> Self {
        Self {
            max_tiles: 100_000,
            max_examined_entries: 4_000_000,
            max_group_references: 8_000_000,
            max_group_updates: 1_000_000,
            max_placements: 65_536,
            max_pieces: 65_536,
            max_occupied_extents: 65_536,
            max_source_pieces: 1024,
            max_work: 64_000_000,
        }
    }
}

/// One physical or padding piece of the joined value.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JoinPiece {
    /// The tile or stack entry that supplied this piece.
    pub site: BindingSite,
    /// Index into [`JoinAllocation::steps`] (consumption order).
    pub step: usize,
    /// `lsb_byte` is significance in the whole joined value. `source_piece`
    /// and `source_byte_offset` locate the slice in that entry's storage.
    pub piece: PlacedPiece,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum JoinStorage {
    /// Most significant first, as `assignAddressFromPieces` orders them.
    /// A join-pool tile contributes its own physical pieces in place.
    /// Contiguous pieces are not merged (`JoinRecord::mergeSequence` only
    /// changes representation, not bytes or significance).
    Pieces(Vec<JoinPiece>),
    /// A `float` join that used exactly one tile and had excess bytes:
    /// `constructFloatExtensionAddress` over that tile's full container.
    /// The conversion is recorded, not executed.
    FloatConversion {
        container: StorageRange,
        logical_size: u32,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum JoinStepKind {
    /// A register tile consumed at its full declared width.
    Tile,
    /// The remaining bytes in the final stack pool.
    Stack { slots: SlotRange },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct JoinStep {
    pub site: BindingSite,
    /// The tile's group, or the stack pool's first group.
    pub group: ResourceId,
    pub kind: JoinStepKind,
    /// Value bytes in this step: the tile width less any excess removed from
    /// it, or the spilled bytes. A floating conversion keeps the full tile.
    pub bytes: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JoinAllocation {
    /// Logical width: the raw request size.
    pub size: u32,
    pub storage: JoinStorage,
    /// Consumption order, not significance order.
    pub steps: Vec<JoinStep>,
    /// Tiles passed over by the start search. They are consumed unless
    /// backfill is enabled, even when they previously had a slot cursor.
    pub skipped_tiles: usize,
    /// Bytes of the final register tile beyond the value (zero when the
    /// tiles matched exactly or the value spilled).
    pub excess: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum JoinNoFit {
    /// Tiles did not cover the value and the action does not spill.
    StackSpillDisabled { uncovered: u32 },
    /// The stack pool rejected the uncovered bytes.
    Stack { uncovered: u32, reason: NoFit },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub enum JoinOutcome {
    Assigned(JoinAllocation),
    /// Upstream `fail`: no status change is committed.
    NoFit(JoinNoFit),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct JoinUsage {
    /// Eligible tiles found at initialization.
    pub tiles: usize,
    pub examined_entries: u64,
    pub group_references: u64,
    pub group_updates: u64,
    pub placements: usize,
    pub pieces: usize,
    /// Held by the state after the call (unchanged by `NoFit`).
    pub occupied_extents: usize,
    pub source_pieces: usize,
    /// Includes nested placement work.
    pub work: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JoinAssignment {
    pub config: JoinConfig,
    pub outcome: JoinOutcome,
    pub usage: JoinUsage,
}

#[derive(Debug, thiserror::Error)]
pub enum JoinError {
    #[error("join allocation limit exceeded: {0}")]
    Limit(&'static str),
    #[error("allocation state belongs to another compiler overlay or list")]
    StateMismatch,
    #[error("invalid join request: {0}")]
    InvalidRequest(&'static str),
    /// Initialization error (`Could not find matching resources`).
    #[error("no exclusion, single-group {class:?} tiles for the join action")]
    NoTiles { class: StorageClass },
    /// Initialization error: stack spill needs `getStackEntry`.
    #[error("join stack spill requires the last entry to be an aligned stack pool")]
    MissingStack,
    #[error("invalid join declaration at {site:?}: {reason}")]
    InvalidDeclaration {
        site: BindingSite,
        reason: &'static str,
    },
    #[error("join storage at {site:?} overlaps storage held by {previous:?}")]
    Overlap {
        site: BindingSite,
        previous: BindingSite,
    },
    #[error("join entry {site:?}: resource group {group:?} is already in use")]
    GroupInUse {
        site: BindingSite,
        group: ResourceId,
    },
    /// A layout the source would build invalidly, or one not modeled here.
    #[error("unsupported join layout at {site:?}: {reason}")]
    Unsupported {
        site: BindingSite,
        reason: &'static str,
    },
    #[error("join placement at {site:?}: {source}")]
    Placement {
        site: BindingSite,
        source: PlacementError,
    },
    #[error(transparent)]
    Allocation(FallbackError),
}

impl From<FallbackError> for JoinError {
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

fn placement_error(site: BindingSite) -> impl FnOnce(PlacementError) -> JoinError {
    move |error| match error {
        PlacementError::Limit("output pieces") => JoinError::Limit("pieces"),
        PlacementError::Limit(resource) => JoinError::Limit(resource),
        source => JoinError::Placement { site, source },
    }
}

#[derive(Clone, Copy)]
struct Tile {
    entry: usize,
    site: BindingSite,
    group: ResourceId,
    size: u32,
}

/// Remove `excess` bytes from one placed single-range piece
/// (`AssignAction::justifyPieces`). The result stays inside the placed range,
/// which already fits its address domain.
fn crop(piece: &mut PlacedPiece, excess: u32, from_start: bool) -> Result<(), &'static str> {
    if piece.role == PieceRole::Padding {
        return Err("justification would truncate constant padding");
    }
    let size = piece.storage.size.ok_or("unsized placed piece")?;
    if excess >= size {
        // Upstream would build a zero or negative piece width here.
        return Err("excess bytes cover the whole justified piece");
    }
    if from_start {
        let first = coordinate(&piece.storage) + i128::from(excess);
        piece.storage.address.offset = if piece.storage.address.space == AbiSpace::Stack {
            i64::try_from(first).map_err(|_| "cropped stack offset")? as u64
        } else {
            u64::try_from(first).map_err(|_| "cropped offset")?
        };
        piece.source_byte_offset += excess;
    }
    piece.storage.size = Some(size - excess);
    Ok(())
}

impl AllocationState {
    /// Run one `<join>` action for a value of the given raw size/alignment.
    /// Success commits the consumed tiles, skipped tiles and the stack cursor.
    /// `NoFit` and every error leave the state exactly unchanged, unlike the
    /// bare fallback primitive.
    pub fn assign_join(
        &mut self,
        resources: &CompilerResources,
        attributes: &JoinAttributes,
        request: JoinRequest,
        limits: JoinLimits,
    ) -> Result<JoinAssignment, JoinError> {
        let mut journal = Vec::new();
        let result = self.run_join(resources, attributes, request, limits, &mut journal);
        if !matches!(
            result,
            Ok(JoinAssignment {
                outcome: JoinOutcome::Assigned(_),
                ..
            })
        ) {
            self.rollback(journal);
        }
        result
    }

    fn run_join(
        &mut self,
        resources: &CompilerResources,
        attributes: &JoinAttributes,
        request: JoinRequest,
        limits: JoinLimits,
        journal: &mut Vec<Undo>,
    ) -> Result<JoinAssignment, JoinError> {
        let (list, source) = self.source_list(resources)?;
        if request.raw_size == 0 || request.raw_size > i32::MAX as u32 {
            return Err(JoinError::InvalidRequest(
                "raw size must be a positive native int",
            ));
        }
        if request.alignment == 0 || request.alignment > i32::MAX as u32 {
            return Err(JoinError::InvalidRequest(
                "alignment must be a positive native int",
            ));
        }
        if self.occupied.len() > limits.max_occupied_extents {
            return Err(JoinError::Limit("occupied extents"));
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
        let class = attributes.storage.unwrap_or(StorageClass::General);

        // Constructor defaults (modelrules.cc:897-916), then decode toggles.
        let first = list.entries.first().ok_or(JoinError::NoTiles { class })?;
        let big_endian = self.list_big_endian(&storage, first.site, &mut budget)?;
        let toggled = |flag: Option<bool>, value: bool| value ^ (flag == Some(true));
        let config = JoinConfig {
            storage: class,
            big_endian,
            consume_from_stack: attributes
                .stack_spill
                .unwrap_or(self.direction == ParameterDirection::Input),
            consume_most_significant: toggled(attributes.reverse_significance, big_endian),
            enforce_alignment: attributes.align.unwrap_or(false),
            justify_right: toggled(attributes.reverse_justify, big_endian),
            backfill: attributes.backfill.unwrap_or(false),
        };

        // initializeEntries: extractTiles, then getStackEntry.
        let mut tiles = Vec::new();
        for (index, (entry, declared)) in list.entries.iter().zip(&source.entries).enumerate() {
            budget.examine()?;
            if !entry.exclusion || entry.groups.len() != 1 || declared.storage_class != class {
                continue;
            }
            if tiles.len() >= limits.max_tiles {
                return Err(JoinError::Limit("tiles"));
            }
            if declared.max_size == 0 || declared.max_size > i32::MAX as u32 {
                // A zero-width tile would never finish the source fit loop.
                return Err(JoinError::InvalidDeclaration {
                    site: entry.site,
                    reason: "tile width must be a positive native int",
                });
            }
            budget.work(1)?;
            tiles.push(Tile {
                entry: index,
                site: entry.site,
                group: entry.groups[0],
                size: declared.max_size,
            });
        }
        if tiles.is_empty() {
            return Err(JoinError::NoTiles { class });
        }
        let stack = if config.consume_from_stack {
            let index = list.entries.len() - 1;
            let entry = &list.entries[index];
            budget.lookup(storage.bindings().len())?;
            let binding = storage
                .binding(entry.site)
                .ok_or(JoinError::StateMismatch)?;
            if entry.exclusion
                || !matches!(&binding.storage, ResolvedStorage::Single(range) if range.address.space == AbiSpace::Stack)
            {
                return Err(JoinError::MissingStack);
            }
            Some(index)
        } else {
            None
        };
        let usage = |budget: &Budget, tiles: usize, held: usize| JoinUsage {
            tiles,
            examined_entries: budget.usage.examined_entries,
            group_references: budget.usage.group_references,
            group_updates: budget.usage.group_updates,
            placements: budget.usage.placements,
            pieces: budget.usage.pieces,
            occupied_extents: held,
            source_pieces: budget.usage.source_pieces,
            work: budget.usage.work,
        };
        let untouched = GroupState::Available { used_slots: 0 };

        // Start search (checkFit). Its adjacency loop never advances `iter`,
        // so for a positive tile width it repeats the start tile's status test
        // and succeeds: only the start tile's status and alignment matter.
        let mut size_left = i64::from(request.raw_size);
        let mut align = i64::from(request.alignment);
        let mut consumed = 0_i64;
        let mut iter = 0;
        while iter < tiles.len() {
            let tile = tiles[iter];
            budget.examine()?;
            budget.references(1)?;
            let status = *self
                .groups
                .get(tile.group.0)
                .ok_or(JoinError::StateMismatch)?;
            let mut fit = status == untouched;
            if fit && config.enforce_alignment && align > i64::from(tile.size) {
                if consumed > i64::from(i32::MAX) {
                    return Err(JoinError::Unsupported {
                        site: tile.site,
                        reason: "skipped tile bytes exceed the native int range",
                    });
                }
                fit = consumed % align == 0;
            }
            if fit {
                break;
            }
            if !config.backfill && status != GroupState::Consumed {
                self.set(tile.group.0, GroupState::Consumed, &mut budget, journal)?;
            }
            consumed = consumed.saturating_add(i64::from(tile.size));
            iter += 1;
        }
        let skipped_tiles = iter;

        // Consume every later untouched tile at full width until covered.
        let mut chosen = Vec::new();
        while size_left > 0 && iter < tiles.len() {
            let tile = tiles[iter];
            iter += 1;
            budget.examine()?;
            budget.references(1)?;
            if *self
                .groups
                .get(tile.group.0)
                .ok_or(JoinError::StateMismatch)?
                != untouched
            {
                continue;
            }
            self.set(tile.group.0, GroupState::Consumed, &mut budget, journal)?;
            chosen.push(tile);
            size_left -= i64::from(tile.size);
            align = 1;
        }

        // Stack spill with the action's justification.
        let mut spill = None;
        if size_left > 0 {
            let uncovered = size_left as u32;
            let Some(index) = stack else {
                let held = self.occupied.len();
                return Ok(JoinAssignment {
                    config,
                    outcome: JoinOutcome::NoFit(JoinNoFit::StackSpillDisabled { uncovered }),
                    usage: usage(&budget, tiles.len(), held),
                });
            };
            let entry = &list.entries[index];
            budget.references(1)?;
            let group = *entry.groups.first().ok_or(JoinError::StateMismatch)?;
            let cursor = match self.groups.get(group.0) {
                Some(GroupState::Available { used_slots }) => *used_slots,
                Some(GroupState::Consumed) => {
                    return Err(JoinError::Unsupported {
                        site: entry.site,
                        reason: "the stack pool's resource group is consumed",
                    });
                }
                None => return Err(JoinError::StateMismatch),
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
                    type_alignment: align as u32,
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
                    return Err(JoinError::Unsupported {
                        site: entry.site,
                        reason: "spilled stack storage leaves its address domain",
                    });
                }
                PlacementOutcome::NoFit(reason) => {
                    let held = self.occupied.len();
                    return Ok(JoinAssignment {
                        config,
                        outcome: JoinOutcome::NoFit(JoinNoFit::Stack { uncovered, reason }),
                        usage: usage(&budget, tiles.len(), held),
                    });
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
            spill = Some((index, group, uncovered, placement.next_slot, value));
        }

        // Materialize the selection. Excess comes only from the final tile.
        let excess = if size_left < 0 {
            (-size_left) as u32
        } else {
            0
        };
        let float_conversion = excess != 0 && class == StorageClass::Float && chosen.len() == 1;
        let crop_step = (excess != 0 && !float_conversion).then(|| {
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
        for (step, tile) in chosen.iter().enumerate() {
            let declared = &source.entries[tile.entry];
            let unsupported = |reason| JoinError::Unsupported {
                site: tile.site,
                reason,
            };
            bump_count(
                &mut budget.usage.placements,
                1,
                limits.max_placements,
                "placements",
            )?;
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
            let binding = storage.binding(tile.site).ok_or(JoinError::StateMismatch)?;
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
                    let single = !join_tile
                        && tile_pieces.len() == 1
                        && tile_pieces[0].role == PieceRole::Storage;
                    if float_conversion {
                        if !single {
                            return Err(unsupported(
                                "floating conversion of a join or padding tile",
                            ));
                        }
                        bump_count(&mut budget.usage.pieces, 1, limits.max_pieces, "pieces")?;
                        converted = Some((tile_pieces[0].storage.clone(), request.raw_size));
                    } else {
                        if crop_step == Some(step) {
                            if join_tile || tile_pieces.len() != 1 {
                                return Err(unsupported(
                                    "justification would truncate a join tile",
                                ));
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
            steps.push(JoinStep {
                site: tile.site,
                group: tile.group,
                kind: JoinStepKind::Tile,
                bytes,
            });
        }
        if let Some((index, group, uncovered, next_slot, value)) = spill {
            let entry = &list.entries[index];
            let declared = &source.entries[index];
            let site = entry.site;
            budget.references(entry.groups.len())?;
            for &other in &entry.groups {
                let state = self.groups.get(other.0).ok_or(JoinError::StateMismatch)?;
                if other != group && *state != untouched {
                    return Err(JoinError::GroupInUse { site, group: other });
                }
            }
            let (spans, slots) = self
                .spans(entry, declared, uncovered, next_slot, &mut budget)
                .map_err(|error| match error {
                    SpanError::Budget(error) => error.into(),
                    SpanError::Unsupported(reason) => JoinError::Unsupported { site, reason },
                })?;
            for span in spans {
                self.occupy(span, 0, site, &mut budget, journal)?;
            }
            let PlacedStorage::Bits {
                pieces: stack_pieces,
            } = value.storage
            else {
                return Err(JoinError::Unsupported {
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
            steps.push(JoinStep {
                site,
                group,
                kind: JoinStepKind::Stack {
                    slots: slots.ok_or(JoinError::StateMismatch)?,
                },
                bytes: uncovered,
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
                    .ok_or(JoinError::StateMismatch)?;
            }
            if significance != request.raw_size {
                return Err(JoinError::StateMismatch);
            }
            JoinStorage::Pieces(pieces)
        };
        let held = self.occupied.len();
        Ok(JoinAssignment {
            config,
            outcome: JoinOutcome::Assigned(JoinAllocation {
                size: request.raw_size,
                storage: storage_recipe,
                steps,
                skipped_tiles,
                excess,
            }),
            usage: usage(&budget, tiles.len(), held),
        })
    }

    /// `entry.front().getSpace()->isBigEndian()` over the per-space model.
    fn list_big_endian(
        &self,
        storage: &CompilerStorage,
        first: BindingSite,
        budget: &mut Budget,
    ) -> Result<bool, JoinError> {
        budget.lookup(storage.bindings().len())?;
        let binding = storage.binding(first).ok_or(JoinError::StateMismatch)?;
        let file = storage.register_file();
        let id = match &binding.storage {
            ResolvedStorage::Single(range) => match range.address.space {
                AbiSpace::Language(id) => id,
                AbiSpace::Stack => match storage.stack().backing_space {
                    AbiSpace::Language(id) => id,
                    _ => file.default_space(),
                },
                AbiSpace::Other => file.default_space(),
            },
            ResolvedStorage::Join { .. } => file.default_space(),
        };
        budget.lookup(file.spaces().len())?;
        let space = file.space(id).ok_or(JoinError::Unsupported {
            site: first,
            reason: "unknown address space",
        })?;
        Ok(space.endianness == Endianness::Big)
    }
}
