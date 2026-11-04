use std::collections::BTreeMap;
use std::sync::Arc;

use ghidra_languages::{CompilerSpec, Extension, MemoryTag, ParamEntry, Storage, StorageClass};
use serde::Serialize;

use crate::error::add;
use crate::storage::Resolver;
use crate::{
    AbiAddress, AbiError, AbiLimits, AbiResult, AbiSpace, RegisterFile, RegisterId,
    ResolvedStorage, StackProperties,
};

/// Stable source positions; source models and list order are never renamed.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub enum BindingSite {
    SpecReturnAddress,
    PreferSplit(usize),
    Input { model: usize, entry: usize },
    Output { model: usize, entry: usize },
    Unaffected { model: usize, index: usize },
    KilledByCall { model: usize, index: usize },
    ReturnAddress { model: usize, index: usize },
    LikelyTrash { model: usize, index: usize },
    InternalStorage { model: usize, index: usize },
    Global(usize),
    NoHighPointer(usize),
    ReadOnly(usize),
    InferPointerBounds(usize),
    LocalRange { model: usize, index: usize },
    ParameterRange { model: usize, index: usize },
    SpaceBase(usize),
    DeadCodeDelay(usize),
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ParameterConstraints {
    pub min_size: u32,
    pub max_size: u32,
    pub alignment: u32,
    pub storage_class: StorageClass,
    pub extension: Extension,
    pub group: Option<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolvedBinding {
    pub site: BindingSite,
    pub storage: ResolvedStorage,
    /// A parameter's pool capacity is not an allocated value width. Unsized
    /// stack addresses remain unsized even when max_size is large.
    pub parameter: Option<ParameterConstraints>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolvedMemoryRange {
    pub site: BindingSite,
    pub first: AbiAddress,
    pub last: AbiAddress,
    pub register: Option<RegisterId>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolvedSpaceBase {
    pub source_index: usize,
    pub register: RegisterId,
    pub space: AbiSpace,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolvedDeadCodeDelay {
    pub source_index: usize,
    pub space: AbiSpace,
    pub delay: i32,
}

/// An address-resolution overlay. The original compiler declarations and
/// register file stay shared; this does not execute a calling convention.
#[derive(Debug, Serialize)]
pub struct CompilerStorage {
    #[serde(skip)]
    source: Arc<CompilerSpec>,
    #[serde(skip)]
    file: Arc<RegisterFile>,
    stack: StackProperties,
    bindings: Vec<ResolvedBinding>,
    ranges: Vec<ResolvedMemoryRange>,
    space_bases: Vec<ResolvedSpaceBase>,
    dead_code_delays: Vec<ResolvedDeadCodeDelay>,
    #[serde(skip)]
    binding_index: BTreeMap<BindingSite, usize>,
    #[serde(skip)]
    range_index: BTreeMap<BindingSite, usize>,
    total_pieces: usize,
    name_bytes: usize,
    work: u64,
}

impl CompilerStorage {
    pub fn new(
        source: Arc<CompilerSpec>,
        file: Arc<RegisterFile>,
        limits: AbiLimits,
    ) -> AbiResult<Self> {
        if source.prototypes.len() > limits.max_models {
            return Err(AbiError::Limit("models"));
        }
        if source.space_bases.len() > limits.max_space_bases {
            return Err(AbiError::Limit("space bases"));
        }
        let mut resolver = Resolver::new(&file, source.stack_pointer.as_ref(), limits)?;
        let mut storage_count = source.prefer_split.len();
        add(
            &mut storage_count,
            usize::from(source.return_address.is_some()),
            limits.max_bindings,
            "bindings",
        )?;
        let mut range_count = source.global.len();
        for amount in [
            source.no_high_ptr.as_ref().map_or(0, Vec::len),
            source.read_only.as_ref().map_or(0, Vec::len),
            source.infer_pointer_bounds.len(),
        ] {
            add(&mut range_count, amount, limits.max_bindings, "bindings")?;
        }
        for model in &source.prototypes {
            resolver.budget.work(1)?;
            for amount in [
                model.input.entries.len(),
                model.output.entries.len(),
                model.unaffected.len(),
                model.killed_by_call.len(),
                model.return_address.as_ref().map_or(0, Vec::len),
                model.likely_trash.len(),
                model.internal_storage.len(),
            ] {
                add(&mut storage_count, amount, limits.max_bindings, "bindings")?;
            }
            for amount in [
                model.local_range.as_ref().map_or(0, Vec::len),
                model.param_range.as_ref().map_or(0, Vec::len),
            ] {
                add(&mut range_count, amount, limits.max_bindings, "bindings")?;
            }
        }
        let mut records = storage_count;
        for amount in [
            range_count,
            source.space_bases.len(),
            source.dead_code_delays.len(),
        ] {
            add(&mut records, amount, limits.max_bindings, "bindings")?;
        }
        resolver.budget.work(records)?;
        let mut output = Output {
            bindings: Vec::with_capacity(storage_count),
            ranges: Vec::with_capacity(range_count),
            binding_index: BTreeMap::new(),
            range_index: BTreeMap::new(),
        };
        if let Some(storage) = &source.return_address {
            output.storage(&mut resolver, BindingSite::SpecReturnAddress, storage, None)?;
        }
        for (index, storage) in source.prefer_split.iter().enumerate() {
            output.storage(
                &mut resolver,
                BindingSite::PreferSplit(index),
                storage,
                None,
            )?;
        }
        output.tags(&mut resolver, &source.global, BindingSite::Global)?;
        if let Some(tags) = &source.no_high_ptr {
            output.tags(&mut resolver, tags, BindingSite::NoHighPointer)?;
        }
        if let Some(tags) = &source.read_only {
            output.tags(&mut resolver, tags, BindingSite::ReadOnly)?;
        }
        for (index, range) in source.infer_pointer_bounds.iter().enumerate() {
            output.range(&mut resolver, BindingSite::InferPointerBounds(index), range)?;
        }
        for (model, prototype) in source.prototypes.iter().enumerate() {
            resolver.budget.work(1)?;
            for (entry, parameter) in prototype.input.entries.iter().enumerate() {
                output.storage(
                    &mut resolver,
                    BindingSite::Input { model, entry },
                    &parameter.storage,
                    Some(parameter),
                )?;
            }
            for (entry, parameter) in prototype.output.entries.iter().enumerate() {
                output.storage(
                    &mut resolver,
                    BindingSite::Output { model, entry },
                    &parameter.storage,
                    Some(parameter),
                )?;
            }
            for (index, storage) in prototype.unaffected.iter().enumerate() {
                output.storage(
                    &mut resolver,
                    BindingSite::Unaffected { model, index },
                    storage,
                    None,
                )?;
            }
            for (index, storage) in prototype.killed_by_call.iter().enumerate() {
                output.storage(
                    &mut resolver,
                    BindingSite::KilledByCall { model, index },
                    storage,
                    None,
                )?;
            }
            if let Some(addresses) = &prototype.return_address {
                for (index, storage) in addresses.iter().enumerate() {
                    output.storage(
                        &mut resolver,
                        BindingSite::ReturnAddress { model, index },
                        storage,
                        None,
                    )?;
                }
            }
            for (index, storage) in prototype.likely_trash.iter().enumerate() {
                output.storage(
                    &mut resolver,
                    BindingSite::LikelyTrash { model, index },
                    storage,
                    None,
                )?;
            }
            for (index, storage) in prototype.internal_storage.iter().enumerate() {
                output.storage(
                    &mut resolver,
                    BindingSite::InternalStorage { model, index },
                    storage,
                    None,
                )?;
            }
            if let Some(tags) = &prototype.local_range {
                output.tags(&mut resolver, tags, |index| BindingSite::LocalRange {
                    model,
                    index,
                })?;
            }
            if let Some(tags) = &prototype.param_range {
                output.tags(&mut resolver, tags, |index| BindingSite::ParameterRange {
                    model,
                    index,
                })?;
            }
        }
        resolver.budget.work(source.space_bases.len())?;
        let mut space_bases = Vec::with_capacity(source.space_bases.len());
        for (index, base) in source.space_bases.iter().enumerate() {
            let resolved = (|| {
                resolver.budget.name(&base.name)?;
                resolver
                    .budget
                    .lookup(file.spaces().len(), base.name.len())?;
                if file.space_named(&base.name).is_some() {
                    return Err(AbiError::InvalidStorage(
                        "compiler spacebase name duplicates a language address space",
                    ));
                }
                if matches!(base.name.as_str(), "stack" | "join" | "OTHER") {
                    return Err(AbiError::InvalidStorage(
                        "compiler frames shadowing synthetic spaces are not modeled",
                    ));
                }
                let register = file.find_register(&base.register, &mut resolver.budget)?;
                let space = resolver.space(&base.space)?.space;
                Ok(ResolvedSpaceBase {
                    source_index: index,
                    register,
                    space,
                })
            })()
            .map_err(|source| AbiError::At {
                site: BindingSite::SpaceBase(index),
                source: Box::new(source),
            })?;
            space_bases.push(resolved);
        }
        resolver.budget.work(source.dead_code_delays.len())?;
        let mut delays = Vec::with_capacity(source.dead_code_delays.len());
        for (index, delay) in source.dead_code_delays.iter().enumerate() {
            let space = resolver
                .space(&delay.space)
                .map_err(|source| AbiError::At {
                    site: BindingSite::DeadCodeDelay(index),
                    source: Box::new(source),
                })?
                .space;
            delays.push(ResolvedDeadCodeDelay {
                source_index: index,
                space,
                delay: delay.delay,
            });
        }
        let total_pieces = resolver.budget.pieces;
        let name_bytes = resolver.budget.name_bytes;
        let work = resolver.budget.work;
        let stack = resolver.stack;
        Ok(Self {
            source,
            file,
            stack,
            bindings: output.bindings,
            ranges: output.ranges,
            space_bases,
            dead_code_delays: delays,
            binding_index: output.binding_index,
            range_index: output.range_index,
            total_pieces,
            name_bytes,
            work,
        })
    }

    pub fn source(&self) -> &Arc<CompilerSpec> {
        &self.source
    }

    /// Explicit per-model return locations, or the spec-level fallback. An
    /// explicit empty list suppresses the fallback. The slice is borrowed and
    /// lookup does not allocate or scan other prototype models.
    pub fn return_addresses(&self, model: usize) -> AbiResult<&[ResolvedBinding]> {
        let prototype = self
            .source
            .prototypes
            .get(model)
            .ok_or(AbiError::InvalidStorage("unknown prototype index"))?;
        let (site, count) = match &prototype.return_address {
            Some(addresses) if addresses.is_empty() => return Ok(&[]),
            Some(addresses) => (
                BindingSite::ReturnAddress { model, index: 0 },
                addresses.len(),
            ),
            None if self.source.return_address.is_none() => return Ok(&[]),
            None => (BindingSite::SpecReturnAddress, 1),
        };
        let start = *self
            .binding_index
            .get(&site)
            .ok_or(AbiError::InvalidStorage("missing return binding"))?;
        let end = start
            .checked_add(count)
            .ok_or(AbiError::Limit("return addresses"))?;
        self.bindings
            .get(start..end)
            .ok_or(AbiError::InvalidStorage("return binding range"))
    }
    pub fn register_file(&self) -> &Arc<RegisterFile> {
        &self.file
    }
    pub fn stack(&self) -> &StackProperties {
        &self.stack
    }
    pub fn bindings(&self) -> &[ResolvedBinding] {
        &self.bindings
    }
    pub fn ranges(&self) -> &[ResolvedMemoryRange] {
        &self.ranges
    }
    pub fn space_bases(&self) -> &[ResolvedSpaceBase] {
        &self.space_bases
    }
    pub fn dead_code_delays(&self) -> &[ResolvedDeadCodeDelay] {
        &self.dead_code_delays
    }
    pub fn binding(&self, site: BindingSite) -> Option<&ResolvedBinding> {
        self.binding_index.get(&site).map(|&i| &self.bindings[i])
    }
    pub fn range(&self, site: BindingSite) -> Option<&ResolvedMemoryRange> {
        self.range_index.get(&site).map(|&i| &self.ranges[i])
    }
    pub fn total_pieces(&self) -> usize {
        self.total_pieces
    }
    pub fn name_bytes(&self) -> usize {
        self.name_bytes
    }
    pub fn build_work(&self) -> u64 {
        self.work
    }
}

struct Output {
    bindings: Vec<ResolvedBinding>,
    ranges: Vec<ResolvedMemoryRange>,
    binding_index: BTreeMap<BindingSite, usize>,
    range_index: BTreeMap<BindingSite, usize>,
}

impl Output {
    fn storage(
        &mut self,
        resolver: &mut Resolver<'_>,
        site: BindingSite,
        source: &Storage,
        parameter: Option<&ParamEntry>,
    ) -> AbiResult<()> {
        let result = (|| {
            let storage = resolver.resolve(source, None)?;
            let parameter = if let Some(entry) = parameter {
                if entry.min_size == 0 || entry.max_size < entry.min_size {
                    return Err(AbiError::InvalidStorage("parameter size bounds"));
                }
                if let Some(actual) = storage.size()
                    && entry.max_size > actual
                {
                    return Err(AbiError::TooSmall {
                        actual,
                        required: entry.max_size,
                    });
                }
                Some(ParameterConstraints {
                    min_size: entry.min_size,
                    max_size: entry.max_size,
                    alignment: entry.alignment(),
                    storage_class: entry.storage_class,
                    extension: entry.extension,
                    group: entry.group,
                })
            } else {
                None
            };
            resolver.budget.lookup(self.binding_index.len(), 1)?;
            self.binding_index.insert(site, self.bindings.len());
            self.bindings.push(ResolvedBinding {
                site,
                storage,
                parameter,
            });
            Ok(())
        })();
        result.map_err(|source| AbiError::At {
            site,
            source: Box::new(source),
        })
    }

    fn tags(
        &mut self,
        resolver: &mut Resolver<'_>,
        tags: &[MemoryTag],
        site: impl Fn(usize) -> BindingSite,
    ) -> AbiResult<()> {
        for (index, tag) in tags.iter().enumerate() {
            let site = site(index);
            match tag {
                MemoryTag::Range(range) => self.range(resolver, site, range)?,
                MemoryTag::Register { name } => {
                    let result = (|| {
                        resolver.budget.pieces(1)?;
                        let range = resolver.register(name)?;
                        let size = range
                            .size
                            .ok_or(AbiError::InvalidStorage("unsized register"))?;
                        let last = range
                            .address
                            .offset
                            .checked_add(u64::from(size) - 1)
                            .ok_or(AbiError::InvalidStorage("register range overflow"))?;
                        self.push_range(
                            resolver,
                            ResolvedMemoryRange {
                                site,
                                first: range.address,
                                last: AbiAddress {
                                    offset: last,
                                    ..range.address
                                },
                                register: range.register,
                            },
                        )
                    })();
                    result.map_err(|source| AbiError::At {
                        site,
                        source: Box::new(source),
                    })?;
                }
            }
        }
        Ok(())
    }

    fn range(
        &mut self,
        resolver: &mut Resolver<'_>,
        site: BindingSite,
        range: &ghidra_languages::AddressRange,
    ) -> AbiResult<()> {
        let result = (|| {
            resolver.budget.work(1)?;
            let properties = resolver.space(&range.space)?;
            let capacity = ((1_u128 << (8 * u32::from(properties.address_size)))
                * u128::from(properties.word_size))
            .min(1_u128 << 64);
            let default_last = if properties.signed {
                (capacity / 2 - 1) as u64
            } else {
                (capacity - 1) as u64
            };
            let mut first = properties.normalize(range.first.unwrap_or(0), None)?;
            let mut last = properties.normalize(range.last.unwrap_or(default_last), None)?;
            let reversed = if properties.signed {
                (first.offset as i64) > last.offset as i64
            } else {
                first.offset > last.offset
            };
            if reversed {
                if matches!(
                    site,
                    BindingSite::Global(_)
                        | BindingSite::NoHighPointer(_)
                        | BindingSite::ReadOnly(_)
                        | BindingSite::InferPointerBounds(_)
                ) {
                    std::mem::swap(&mut first, &mut last);
                } else {
                    return Err(AbiError::InvalidStorage("reversed address range"));
                }
            }
            self.push_range(
                resolver,
                ResolvedMemoryRange {
                    site,
                    first,
                    last,
                    register: None,
                },
            )
        })();
        result.map_err(|source| AbiError::At {
            site,
            source: Box::new(source),
        })
    }

    fn push_range(
        &mut self,
        resolver: &mut Resolver<'_>,
        range: ResolvedMemoryRange,
    ) -> AbiResult<()> {
        resolver.budget.lookup(self.range_index.len(), 1)?;
        self.range_index.insert(range.site, self.ranges.len());
        self.ranges.push(range);
        Ok(())
    }
}
