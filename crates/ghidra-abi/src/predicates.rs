//! Retained compiler-rule datatype predicates. This module executes no action
//! or side effect and never assigns an argument to a storage pool.
use std::sync::Arc;

use ghidra_languages::{DatatypeClass, DatatypeFilter, MetaType, ModelRule, RuleQualifier};
use ghidra_types::{Builtin, TypeId, TypeKind, TypeLayouts};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PredicateLimits {
    /// Construction only, before the node-indexed fact/visit arrays.
    pub max_types: usize,
    /// Construction only: references recorded by the immutable layout snapshot.
    pub max_references: usize,
    /// Construction only: active by-value dependency stack.
    pub max_depth: usize,
    /// Per query, across all evaluated filters; includes duplicate list entries.
    pub max_size_items: usize,
    /// Per rule query, checked before reading qualifier contents.
    pub max_qualifiers: usize,
    /// Per rule query, checked before reading prototype parameter IDs.
    pub max_parameters: usize,
    /// Fresh budget for each construction or query. There are no nested graph calls.
    pub max_work: u64,
}

impl Default for PredicateLimits {
    fn default() -> Self {
        Self {
            max_types: 100_000,
            max_references: 1_000_000,
            max_depth: 100_000,
            max_size_items: 100_000,
            max_qualifiers: 10_000,
            max_parameters: 100_000,
            max_work: 32_000_000,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PredicateError {
    #[error("datatype predicate limit exceeded: {0}")]
    Limit(&'static str),
    #[error("unknown predicate datatype {0:?}")]
    UnknownType(TypeId),
    #[error("incomplete datatype {0:?} has no concrete classification or length")]
    IncompleteType(TypeId),
    #[error("invalid datatype filter: {0}")]
    InvalidFilter(&'static str),
    #[error("invalid prototype context: {0}")]
    InvalidPrototype(&'static str),
    #[error("varargs position subtraction exceeds the modeled signed-int range")]
    PositionOverflow,
    #[error("datatype predicate arithmetic overflow")]
    Overflow,
}

type Result<T> = std::result::Result<T, PredicateError>;

/// Identity is the canonical alias-target TypeId, not a floating byte width.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HomogeneousFloat {
    Empty,
    Float {
        primitive: TypeId,
        count: u64,
    },
    No,
    /// The snapshot permits pointers to incomplete types. These do not poison
    /// unrelated facts, but a predicate that needs the incomplete type errors.
    Incomplete(TypeId),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DatatypeFact {
    pub canonical: TypeId,
    /// Java MetaDataType.get mapping, including void -> Unknown and enum -> Int/Uint.
    /// Opaque fixed storage uses the generic unrecognized-type Unknown fallback.
    pub meta_type: Option<MetaType>,
    /// Java getLength, including -1 for function definitions. None for incomplete.
    pub length: Option<i128>,
    /// Structural summary; the HFA predicate separately requires an outer array/struct.
    pub homogeneous_float: HomogeneousFloat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PredicateStats {
    pub types: usize,
    pub references: usize,
    pub depth: usize,
    pub work: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PredicateUsage {
    pub size_items: usize,
    pub qualifiers: usize,
    pub parameters: usize,
    pub work: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PredicateRejection {
    Datatype,
    Qualifier(usize),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PredicateMatch {
    pub matched: bool,
    pub rejection: Option<PredicateRejection>,
    pub usage: PredicateUsage,
}

#[derive(Debug, Clone, Copy)]
pub struct PrototypeTypes<'a> {
    pub result: TypeId,
    pub parameters: &'a [TypeId],
    /// None models firstVarArgSlot=-1. Some(n) is the first variable parameter
    /// slot; n==parameters.len() is legal, including an empty variadic prototype.
    pub first_vararg: Option<usize>,
}

/// Bounded facts shared by all datatype predicates over one immutable snapshot.
/// Arrays/aggregates use cached summaries, never expanded element lists.
#[derive(Debug, Clone)]
pub struct DatatypePredicates {
    layouts: Arc<TypeLayouts>,
    facts: Vec<DatatypeFact>,
    stats: PredicateStats,
    limits: PredicateLimits,
}

impl DatatypePredicates {
    pub fn new(layouts: Arc<TypeLayouts>, limits: PredicateLimits) -> Result<Self> {
        let count = layouts.definitions().len();
        let references = layouts.stats().references;
        if count > limits.max_types {
            return Err(PredicateError::Limit("types"));
        }
        if references > limits.max_references {
            return Err(PredicateError::Limit("references"));
        }
        let mut budget = QueryBudget::new(limits);
        let mut facts = vec![None; count];
        let mut visited = vec![false; count];
        let mut stack = Vec::new();
        let mut depth = 0;
        for root in 0..count {
            budget.work(1)?;
            if visited[root] {
                continue;
            }
            push(
                TypeId(root),
                &mut stack,
                &mut visited,
                &mut depth,
                &mut budget,
            )?;
            while let Some((id, next)) = stack.last_mut() {
                budget.work(1)?;
                if let Some(child) = dependency(&layouts.definitions()[id.0].kind, *next) {
                    *next += 1;
                    // TypeLayouts has already validated the DAG and every ID.
                    if !visited[child.0] {
                        push(child, &mut stack, &mut visited, &mut depth, &mut budget)?;
                    }
                } else {
                    let id = *id;
                    facts[id.0] = Some(compute(id, &layouts, &facts, &mut budget)?);
                    stack.pop();
                }
            }
        }
        budget.work(count as u64)?;
        let facts = facts
            .into_iter()
            .map(|f| f.expect("all validated DAG nodes visited"))
            .collect();
        Ok(Self {
            layouts,
            facts,
            stats: PredicateStats {
                types: count,
                references,
                depth,
                work: budget.usage.work,
            },
            limits,
        })
    }

    pub fn layouts(&self) -> &Arc<TypeLayouts> {
        &self.layouts
    }
    pub fn facts(&self) -> &[DatatypeFact] {
        &self.facts
    }
    pub fn fact(&self, ty: TypeId) -> Result<&DatatypeFact> {
        self.facts.get(ty.0).ok_or(PredicateError::UnknownType(ty))
    }
    pub fn stats(&self) -> PredicateStats {
        self.stats
    }
    pub fn limits(&self) -> PredicateLimits {
        self.limits
    }

    pub fn matches_filter(
        &self,
        filter: &DatatypeFilter,
        ty: TypeId,
        limits: PredicateLimits,
    ) -> Result<PredicateMatch> {
        let mut budget = QueryBudget::new(limits);
        let matched = self.evaluate(filter, ty, &mut budget)?;
        Ok(PredicateMatch {
            matched,
            rejection: (!matched).then_some(PredicateRejection::Datatype),
            usage: budget.usage,
        })
    }

    /// Match the datatype first, then qualifiers in declaration order, with
    /// short-circuit AND. The action, preconditions and side effects are not run.
    /// `ty` and `position` are explicit, like ModelRule.assignAddress's arguments.
    pub fn matches_rule(
        &self,
        rule: &ModelRule,
        ty: TypeId,
        prototype: PrototypeTypes<'_>,
        position: i32,
        limits: PredicateLimits,
    ) -> Result<PredicateMatch> {
        if rule.qualifiers.len() > limits.max_qualifiers {
            return Err(PredicateError::Limit("qualifiers"));
        }
        if prototype.parameters.len() > limits.max_parameters {
            return Err(PredicateError::Limit("parameters"));
        }
        if prototype
            .first_vararg
            .is_some_and(|n| n > prototype.parameters.len() || n > i32::MAX as usize)
        {
            return Err(PredicateError::InvalidPrototype(
                "first vararg slot exceeds the input list or signed-int range",
            ));
        }
        let mut budget = QueryBudget::new(limits);
        budget.usage.parameters = prototype.parameters.len();
        budget.work(1)?;
        self.fact(prototype.result)?;
        self.fact(ty)?;
        for parameter in prototype.parameters {
            budget.work(1)?;
            self.fact(*parameter)?;
        }
        if !self.evaluate(&rule.datatype, ty, &mut budget)? {
            return Ok(PredicateMatch {
                matched: false,
                rejection: Some(PredicateRejection::Datatype),
                usage: budget.usage,
            });
        }
        for (index, qualifier) in rule.qualifiers.iter().enumerate() {
            budget.work(1)?;
            budget.usage.qualifiers += 1; // Preflight bounded this list.
            let matches = match qualifier {
                RuleQualifier::Position { index } => position == *index,
                RuleQualifier::Varargs { first, last } => {
                    if let Some(slot) = prototype.first_vararg {
                        let delta = i64::from(position) - slot as i64;
                        let delta =
                            i32::try_from(delta).map_err(|_| PredicateError::PositionOverflow)?;
                        delta >= first.unwrap_or(i32::MIN) && delta <= last.unwrap_or(i32::MAX)
                    } else {
                        false
                    }
                }
                RuleQualifier::DatatypeAt { index, datatype } => {
                    let target = if *index < 0 {
                        Some(prototype.result)
                    } else {
                        prototype.parameters.get(*index as usize).copied()
                    };
                    if let Some(target) = target {
                        self.evaluate(datatype, target, &mut budget)?
                    } else {
                        false
                    }
                }
            };
            if !matches {
                return Ok(PredicateMatch {
                    matched: false,
                    rejection: Some(PredicateRejection::Qualifier(index)),
                    usage: budget.usage,
                });
            }
        }
        Ok(PredicateMatch {
            matched: true,
            rejection: None,
            usage: budget.usage,
        })
    }

    fn evaluate(
        &self,
        filter: &DatatypeFilter,
        ty: TypeId,
        budget: &mut QueryBudget,
    ) -> Result<bool> {
        budget.work(1)?;
        let fact = self.fact(ty)?;
        validate_filter(filter, budget)?;
        let meta = fact
            .meta_type
            .ok_or(PredicateError::IncompleteType(fact.canonical))?;
        match filter.class {
            DatatypeClass::HomogeneousFloatAggregate => {
                // HomogeneousAggregate.filter does not call inherited filterOnSize.
                if !matches!(meta, MetaType::Array | MetaType::Struct) {
                    return Ok(false);
                }
                let maximum = filter.max_primitives.filter(|n| *n != 0).unwrap_or(4);
                return match fact.homogeneous_float {
                    HomogeneousFloat::Float { count, .. } => Ok(count <= u64::from(maximum)),
                    HomogeneousFloat::Incomplete(id) => Err(PredicateError::IncompleteType(id)),
                    _ => Ok(false),
                };
            }
            DatatypeClass::Meta(MetaType::Array) => {
                // restoreFilterXml selects ArrayFilter, whose instanceof check
                // does not strip typedefs, unlike MetaDataType.get.
                let TypeKind::Array { count, .. } = self.layouts.definitions()[ty.0].kind else {
                    return Ok(false);
                };
                if count < u64::from(filter.min_elements.unwrap_or(0))
                    || filter
                        .max_elements
                        .is_some_and(|n| n != 0 && count > u64::from(n))
                {
                    return Ok(false);
                }
            }
            DatatypeClass::Meta(expected) if expected != meta => return Ok(false),
            _ => (),
        }
        let length = fact
            .length
            .ok_or(PredicateError::IncompleteType(fact.canonical))?;
        if !filter.sizes.is_empty() {
            return Ok(filter.sizes.iter().any(|n| i128::from(*n) == length));
        }
        let minimum = i128::from(filter.min_size.unwrap_or(0));
        let maximum = i128::from(
            filter
                .max_size
                .filter(|n| *n != 0)
                .unwrap_or(i32::MAX as u32),
        );
        Ok(length >= minimum && length <= maximum)
    }
}

struct QueryBudget {
    limits: PredicateLimits,
    usage: PredicateUsage,
}
impl QueryBudget {
    fn new(limits: PredicateLimits) -> Self {
        Self {
            limits,
            usage: PredicateUsage::default(),
        }
    }
    fn work(&mut self, n: u64) -> Result<()> {
        self.usage.work = self
            .usage
            .work
            .checked_add(n)
            .filter(|n| *n <= self.limits.max_work)
            .ok_or(PredicateError::Limit("work"))?;
        Ok(())
    }
}

fn validate_filter(filter: &DatatypeFilter, budget: &mut QueryBudget) -> Result<()> {
    budget.usage.size_items = budget
        .usage
        .size_items
        .checked_add(filter.sizes.len())
        .filter(|n| *n <= budget.limits.max_size_items)
        .ok_or(PredicateError::Limit("size items"))?;
    // This bounds both validation and the later membership scan, even if the
    // type's class fails before that scan is needed.
    budget.work(
        (filter.sizes.len() as u64)
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .ok_or(PredicateError::Limit("work"))?,
    )?;
    if !filter.sizes.is_empty() && (filter.min_size.is_some() || filter.max_size.is_some()) {
        return Err(PredicateError::InvalidFilter(
            "enumerated sizes mixed with range bounds",
        ));
    }
    if filter.sizes.iter().any(|n| *n == 0 || *n > i32::MAX as u32) {
        return Err(PredicateError::InvalidFilter(
            "sizes must be positive signed ints",
        ));
    }
    for n in [filter.min_size, filter.max_size].into_iter().flatten() {
        if n > i32::MAX as u32 {
            return Err(PredicateError::InvalidFilter(
                "size bound exceeds signed int",
            ));
        }
    }
    if matches!(filter.class, DatatypeClass::HomogeneousFloatAggregate)
        && filter.max_primitives.is_some_and(|n| n > i32::MAX as u32)
    {
        return Err(PredicateError::InvalidFilter(
            "primitive bound exceeds signed int",
        ));
    }
    if matches!(filter.class, DatatypeClass::Meta(MetaType::Array))
        && [filter.min_elements, filter.max_elements]
            .into_iter()
            .flatten()
            .any(|n| n > i32::MAX as u32)
    {
        return Err(PredicateError::InvalidFilter(
            "element bound exceeds signed int",
        ));
    }
    Ok(())
}

fn push(
    id: TypeId,
    stack: &mut Vec<(TypeId, usize)>,
    visited: &mut [bool],
    depth: &mut usize,
    budget: &mut QueryBudget,
) -> Result<()> {
    budget.work(1)?;
    if stack.len() >= budget.limits.max_depth {
        return Err(PredicateError::Limit("depth"));
    }
    visited[id.0] = true;
    stack.push((id, 0));
    *depth = (*depth).max(stack.len());
    Ok(())
}

fn dependency(kind: &TypeKind, index: usize) -> Option<TypeId> {
    match kind {
        TypeKind::Alias(target) if index == 0 => Some(*target),
        TypeKind::Array { element, .. } if index == 0 => Some(*element),
        TypeKind::Structure(c) => c.fields.get(index).map(|f| f.ty),
        _ => None,
    }
}

fn combine(a: HomogeneousFloat, b: HomogeneousFloat) -> Result<HomogeneousFloat> {
    use HomogeneousFloat::*;
    Ok(match (a, b) {
        (No, _) | (_, No) => No,
        (Incomplete(id), _) | (_, Incomplete(id)) => Incomplete(id),
        (Empty, other) | (other, Empty) => other,
        (
            Float {
                primitive: a,
                count: n,
            },
            Float {
                primitive: b,
                count: m,
            },
        ) if a == b => Float {
            primitive: a,
            count: n.checked_add(m).ok_or(PredicateError::Overflow)?,
        },
        _ => No,
    })
}

fn compute(
    id: TypeId,
    layouts: &TypeLayouts,
    facts: &[Option<DatatypeFact>],
    budget: &mut QueryBudget,
) -> Result<DatatypeFact> {
    budget.work(1)?;
    let kind = &layouts.definitions()[id.0].kind;
    let get = |id: TypeId| facts[id.0].expect("computed validated dependency");
    if let TypeKind::Alias(target) = kind {
        return Ok(get(*target));
    }
    let meta = match kind {
        TypeKind::Void | TypeKind::Opaque { .. } => MetaType::Unknown,
        TypeKind::Incomplete => {
            return Ok(DatatypeFact {
                canonical: id,
                meta_type: None,
                length: None,
                homogeneous_float: HomogeneousFloat::Incomplete(id),
            });
        }
        TypeKind::Builtin(b) => match b {
            Builtin::Bool => MetaType::Bool,
            Builtin::Float | Builtin::Double | Builtin::LongDouble => MetaType::Float,
            Builtin::UnsignedChar
            | Builtin::UnsignedShort
            | Builtin::UnsignedInt
            | Builtin::UnsignedLong
            | Builtin::UnsignedLongLong => MetaType::Uint,
            Builtin::Char if !layouts.organization().char_signed => MetaType::Uint,
            _ => MetaType::Int,
        },
        TypeKind::Integer { signed, .. } | TypeKind::Enum { signed, .. } => {
            if *signed {
                MetaType::Int
            } else {
                MetaType::Uint
            }
        }
        TypeKind::Float { .. } => MetaType::Float,
        TypeKind::Pointer { .. } => MetaType::Ptr,
        TypeKind::Array { .. } => MetaType::Array,
        TypeKind::Structure(_) => MetaType::Struct,
        TypeKind::Union(_) => MetaType::Union,
        TypeKind::Function { .. } => MetaType::Code,
        TypeKind::Alias(_) => unreachable!("alias handled above"),
    };
    let homogeneous_float = match kind {
        TypeKind::Array { element, count } => {
            if *count == 0 {
                HomogeneousFloat::Empty
            } else {
                match get(*element).homogeneous_float {
                    HomogeneousFloat::Float {
                        primitive,
                        count: n,
                    } => HomogeneousFloat::Float {
                        primitive,
                        count: n.checked_mul(*count).ok_or(PredicateError::Overflow)?,
                    },
                    other => other,
                }
            }
        }
        TypeKind::Structure(c) => {
            let mut summary = HomogeneousFloat::Empty;
            for field in &c.fields {
                budget.work(1)?;
                summary = combine(summary, get(field.ty).homogeneous_float)?;
            }
            summary
        }
        _ if meta == MetaType::Float => HomogeneousFloat::Float {
            primitive: id,
            count: 1,
        },
        _ => HomogeneousFloat::No,
    };
    let length = if matches!(kind, TypeKind::Function { .. }) {
        Some(-1)
    } else {
        layouts
            .layout(id)
            .expect("valid snapshot ID")
            .geometry
            .length
            .map(i128::from)
    };
    Ok(DatatypeFact {
        canonical: id,
        meta_type: Some(meta),
        length,
        homogeneous_float,
    })
}
