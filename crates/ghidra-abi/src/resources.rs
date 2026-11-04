//! Declaration-ordered parameter resources. This pass does not place values.
use std::sync::Arc;

use ghidra_languages::{ParamList, StorageClass};
use ghidra_pcode::SpaceKind;
use serde::Serialize;
use thiserror::Error;

use crate::{AbiAddress, AbiSpace, BindingSite, CompilerStorage, ResolvedStorage};

#[derive(Clone, Copy, Debug)]
pub struct ResourceLimits {
    pub max_models: usize,
    pub max_entries: usize,
    pub max_regions: usize,
    pub max_groups: usize,
    pub max_group_references: usize,
    pub max_work: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_models: 16_384,
            max_entries: 100_000,
            max_regions: 1_000_000,
            max_groups: 100_000,
            max_group_references: 1_000_000,
            max_work: 16_000_000,
        }
    }
}

#[derive(Debug, Error)]
pub enum ResourceError {
    #[error("parameter resource limit exceeded: {0}")]
    Limit(&'static str),
    #[error("invalid parameter resource at {site:?}: {reason}")]
    Invalid {
        site: BindingSite,
        reason: &'static str,
    },
    #[error("parameter resource at {site:?} illegally overlaps earlier {previous:?}")]
    IllegalOverlap {
        site: BindingSite,
        previous: BindingSite,
    },
    #[error("prototype {0} has incomplete declarations")]
    IncompleteModel(usize),
}

/// IDs are local to one model's input or output list, never global registers.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct ResourceId(pub usize);

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum ParameterDirection {
    Input,
    Output,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct EntryResources {
    pub site: BindingSite,
    /// Sorted, retaining repetitions as the retained ParamEntry implementations do.
    pub groups: Vec<ResourceId>,
    pub overlapping: bool,
    pub declared_group: Option<usize>,
    pub exclusion: bool,
    /// Aligned pools have this many slots; exclusion pools have one.
    pub slot_capacity: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ListResources {
    pub entries: Vec<EntryResources>,
    pub group_count: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ModelResources {
    pub input: ListResources,
    pub output: ListResources,
}

#[derive(Debug, Serialize)]
pub struct CompilerResources {
    #[serde(skip)]
    storage: Arc<CompilerStorage>,
    models: Vec<ModelResources>,
    entry_count: usize,
    region_count: usize,
    group_count: usize,
    group_references: usize,
    work: u64,
}

impl CompilerResources {
    pub fn new(
        storage: Arc<CompilerStorage>,
        limits: ResourceLimits,
    ) -> Result<Self, ResourceError> {
        let prototypes = &storage.source().prototypes;
        if prototypes.len() > limits.max_models {
            return Err(ResourceError::Limit("models"));
        }
        let mut budget = Budget::new(limits);
        let mut entry_count = 0;
        for (model, prototype) in prototypes.iter().enumerate() {
            budget.charge(1)?;
            if !prototype.is_complete() {
                return Err(ResourceError::IncompleteModel(model));
            }
            add(
                &mut entry_count,
                prototype.input.entries.len(),
                limits.max_entries,
                "entries",
            )?;
            add(
                &mut entry_count,
                prototype.output.entries.len(),
                limits.max_entries,
                "entries",
            )?;
        }
        // Preflight allocation slots, including empty model/list records.
        budget.charge(prototypes.len())?;
        budget.charge(entry_count)?;
        let mut models = Vec::with_capacity(prototypes.len());
        for (model, prototype) in prototypes.iter().enumerate() {
            let input = build_list(
                &storage,
                model,
                ParameterDirection::Input,
                &prototype.input,
                &mut budget,
            )?;
            let output = build_list(
                &storage,
                model,
                ParameterDirection::Output,
                &prototype.output,
                &mut budget,
            )?;
            models.push(ModelResources { input, output });
        }
        Ok(Self {
            storage,
            models,
            entry_count,
            region_count: budget.regions,
            group_count: budget.groups,
            group_references: budget.references,
            work: budget.work,
        })
    }
    pub fn storage(&self) -> &Arc<CompilerStorage> {
        &self.storage
    }
    pub fn models(&self) -> &[ModelResources] {
        &self.models
    }
    pub fn list(&self, model: usize, direction: ParameterDirection) -> Option<&ListResources> {
        self.models.get(model).map(|m| match direction {
            ParameterDirection::Input => &m.input,
            ParameterDirection::Output => &m.output,
        })
    }
    pub fn entry_count(&self) -> usize {
        self.entry_count
    }
    pub fn region_count(&self) -> usize {
        self.region_count
    }
    pub fn group_count(&self) -> usize {
        self.group_count
    }
    pub fn group_references(&self) -> usize {
        self.group_references
    }
    pub fn build_work(&self) -> u64 {
        self.work
    }
}

fn add(
    count: &mut usize,
    amount: usize,
    maximum: usize,
    resource: &'static str,
) -> Result<(), ResourceError> {
    *count = count
        .checked_add(amount)
        .filter(|n| *n <= maximum)
        .ok_or(ResourceError::Limit(resource))?;
    Ok(())
}

struct Budget {
    limits: ResourceLimits,
    regions: usize,
    groups: usize,
    references: usize,
    work: u64,
}
impl Budget {
    fn new(limits: ResourceLimits) -> Self {
        Self {
            limits,
            regions: 0,
            groups: 0,
            references: 0,
            work: 0,
        }
    }
    fn charge(&mut self, amount: usize) -> Result<(), ResourceError> {
        self.work = self
            .work
            .checked_add(u64::try_from(amount).map_err(|_| ResourceError::Limit("work"))?)
            .filter(|n| *n <= self.limits.max_work)
            .ok_or(ResourceError::Limit("work"))?;
        Ok(())
    }
    fn regions(&mut self, amount: usize) -> Result<(), ResourceError> {
        add(
            &mut self.regions,
            amount,
            self.limits.max_regions,
            "regions",
        )?;
        self.charge(amount)
    }
    fn copy_groups(
        &mut self,
        to: &mut Vec<ResourceId>,
        from: &[ResourceId],
    ) -> Result<(), ResourceError> {
        add(
            &mut self.references,
            from.len(),
            self.limits.max_group_references,
            "group references",
        )?;
        self.charge(from.len())?;
        to.extend_from_slice(from);
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct Region {
    space: AbiSpace,
    first: i128,
    last: i128,
    size: u32,
    constant: bool,
}
impl Region {
    fn new(
        storage: &CompilerStorage,
        address: AbiAddress,
        size: u32,
        site: BindingSite,
        budget: &mut Budget,
    ) -> Result<Self, ResourceError> {
        let invalid = |reason| ResourceError::Invalid { site, reason };
        let constant = match address.space {
            AbiSpace::Stack | AbiSpace::Other => false,
            AbiSpace::Language(id) => {
                budget.charge(
                    (usize::BITS - storage.register_file().spaces().len().leading_zeros()) as usize
                        + 1,
                )?;
                let space = storage
                    .register_file()
                    .space(id)
                    .ok_or_else(|| invalid("unknown address space"))?;
                space.kind == SpaceKind::Constant
            }
        };
        let signed = address.space == AbiSpace::Stack;
        let first = if signed {
            i128::from(address.offset as i64)
        } else {
            i128::from(address.offset)
        };
        let last = first + i128::from(size) - 1;
        // A pool's capacity is not an allocated memory extent. It can exceed
        // the address domain; keep its mathematical end without masking or
        // wrapping. Actual value placement must validate the chosen slice.
        if size == 0 {
            return Err(invalid("zero parameter resource size"));
        }
        Ok(Self {
            space: address.space,
            first,
            last,
            size,
            constant,
        })
    }
    fn intersects(self, other: Self) -> bool {
        self.space == other.space && self.first <= other.last && other.first <= self.last
    }
    fn contains(self, other: Self) -> bool {
        self.space == other.space && self.first <= other.first && self.last >= other.last
    }
    fn exact(self, other: Self) -> bool {
        self.space == other.space && self.first == other.first && self.size == other.size
    }
}

enum Shape {
    Single(Region),
    Join(Vec<Region>),
}

fn site(model: usize, direction: ParameterDirection, entry: usize) -> BindingSite {
    match direction {
        ParameterDirection::Input => BindingSite::Input { model, entry },
        ParameterDirection::Output => BindingSite::Output { model, entry },
    }
}

fn build_list(
    storage: &CompilerStorage,
    model: usize,
    direction: ParameterDirection,
    source: &ParamList,
    budget: &mut Budget,
) -> Result<ListResources, ResourceError> {
    budget.charge(source.entries.len())?;
    let mut shapes = Vec::with_capacity(source.entries.len());
    let mut output = ListResources {
        entries: Vec::with_capacity(source.entries.len()),
        group_count: 0,
    };
    let mut active_group = None;
    let mut last_group = None;
    let mut base_group = 0;
    for (index, entry) in source.entries.iter().enumerate() {
        let site = site(model, direction, index);
        let invalid = |reason| ResourceError::Invalid { site, reason };
        budget.charge(1)?;
        if entry.min_size == 0
            || entry.max_size < entry.min_size
            || entry.max_size > i32::MAX as u32
            || entry.align.is_some_and(|a| a > i32::MAX as u32)
        {
            return Err(invalid("invalid parameter size/alignment"));
        }
        if let Some(group) = entry.group {
            if group >= source.group_count {
                return Err(invalid("unknown declared group"));
            }
            if active_group != Some(group) {
                if last_group.is_some_and(|last| group <= last) {
                    return Err(invalid("declared groups must be contiguous and ordered"));
                }
                active_group = Some(group);
                last_group = Some(group);
                base_group = output.group_count;
            }
        } else {
            active_group = None;
            base_group = output.group_count;
        }
        if index > 0 && source.separate_float {
            let previous = &source.entries[index - 1];
            let previous = if previous.group.is_some() {
                StorageClass::General
            } else {
                previous.storage_class
            };
            let current = if entry.group.is_some() {
                StorageClass::General
            } else {
                entry.storage_class
            };
            if previous.rank() < current.rank() {
                return Err(invalid("entries are not ordered by storage class"));
            }
        }
        budget.charge((usize::BITS - storage.bindings().len().leading_zeros()) as usize + 1)?;
        let binding = storage
            .binding(site)
            .ok_or_else(|| invalid("missing resolved binding"))?;
        let shape = match &binding.storage {
            ResolvedStorage::Single(range) => {
                budget.regions(1)?;
                Shape::Single(Region::new(
                    storage,
                    range.address,
                    entry.max_size,
                    site,
                    budget,
                )?)
            }
            ResolvedStorage::Join { pieces, .. } => {
                if entry.group.is_some() {
                    return Err(invalid("join in an explicit group"));
                }
                budget.regions(pieces.len())?;
                let mut regions = Vec::with_capacity(pieces.len());
                for piece in pieces {
                    regions.push(Region::new(
                        storage,
                        piece.storage.address,
                        piece
                            .storage
                            .size
                            .ok_or_else(|| invalid("unsized join piece"))?,
                        site,
                        budget,
                    )?);
                }
                Shape::Join(regions)
            }
        };
        let mut groups = Vec::new();
        match &shape {
            Shape::Join(pieces) => {
                for piece in pieces {
                    if piece.constant {
                        continue;
                    }
                    // Exact physical matching chooses the most recent earlier
                    // non-join pool, exactly as findEntryByStorage does.
                    for previous in (0..shapes.len()).rev() {
                        budget.charge(1)?;
                        if let Shape::Single(region) = shapes[previous]
                            && region.exact(*piece)
                        {
                            budget.copy_groups(&mut groups, &output.entries[previous].groups)?;
                            break;
                        }
                    }
                }
                if groups.is_empty() {
                    return Err(invalid("join must match an earlier parameter pool"));
                }
            }
            Shape::Single(current) => {
                for (previous, previous_shape) in shapes.iter().enumerate() {
                    budget.charge(1)?;
                    if let Some(group) = entry.group
                        && source.entries[previous].group == Some(group)
                    {
                        let a = &source.entries[previous];
                        if a.min_size <= entry.max_size
                            && entry.min_size <= a.max_size
                            && (a.storage_class == entry.storage_class
                                || a.storage_class == StorageClass::General)
                        {
                            return Err(invalid(
                                "group members are not distinguished by size/class order",
                            ));
                        }
                    }
                    let intersects = match previous_shape {
                        Shape::Single(region) => region.intersects(*current),
                        Shape::Join(pieces) => {
                            let mut found = false;
                            for piece in pieces {
                                budget.charge(1)?;
                                if piece.intersects(*current) {
                                    found = true;
                                    break;
                                }
                            }
                            found
                        }
                    };
                    if !intersects {
                        continue;
                    }
                    if !matches!(previous_shape, Shape::Single(region) if current.contains(*region))
                    {
                        return Err(ResourceError::IllegalOverlap {
                            site,
                            previous: output.entries[previous].site,
                        });
                    }
                    if !output.entries[previous].overlapping {
                        budget.copy_groups(&mut groups, &output.entries[previous].groups)?;
                    }
                }
            }
        }
        let overlapping = !groups.is_empty();
        if !overlapping {
            budget.copy_groups(&mut groups, &[ResourceId(base_group)])?;
        }
        let sort_cost = groups
            .len()
            .checked_mul((usize::BITS - groups.len().leading_zeros()) as usize)
            .ok_or(ResourceError::Limit("work"))?;
        budget.charge(sort_cost)?;
        groups.sort_unstable();
        let count = groups
            .last()
            .expect("nonempty groups")
            .0
            .checked_add(1)
            .ok_or(ResourceError::Limit("groups"))?;
        if count > output.group_count {
            add(
                &mut budget.groups,
                count - output.group_count,
                budget.limits.max_groups,
                "groups",
            )?;
            output.group_count = count;
        }
        output.entries.push(EntryResources {
            site,
            groups,
            overlapping,
            declared_group: entry.group,
            exclusion: entry.alignment() == 0,
            slot_capacity: entry.slots(),
        });
        shapes.push(shape);
    }
    Ok(output)
}
