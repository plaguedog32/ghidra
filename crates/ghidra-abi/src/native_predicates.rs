//! Native compiler-rule datatype filters and qualifiers (modelrules.cc) over
//! the converted graph. No action, precondition or side effect is executed.
use ghidra_languages::{DatatypeClass, DatatypeFilter, MetaType, ModelRule, RuleQualifier};
use ghidra_types::TypeId;

use crate::native_extract::{
    NativeExtractionError, NativeExtractionLimits, NativeExtractionOptions,
    NativeExtractionOutcome, NativeInvalidExtraction, extract,
};
use crate::native_types::{NativeConversionError, NativeTypeError, NativeTypeGraph, NativeTypeId};
use crate::{PredicateRejection, PrototypeTypes};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativePredicateLimits {
    /// Per query, across all evaluated filters; includes duplicate list entries.
    pub max_size_items: usize,
    /// Per rule query, checked before reading qualifier contents.
    pub max_qualifiers: usize,
    /// Per rule query, checked before reading prototype parameter IDs.
    pub max_parameters: usize,
    /// Per evaluated HFA filter: live primitive records of its extraction.
    pub max_live_primitives: usize,
    /// Per evaluated HFA filter: extraction nesting including the root.
    pub max_depth: usize,
    /// One work budget per query. Each nested HFA extraction runs with the
    /// remaining budget, and its work is added to the query's work.
    pub max_work: u64,
}

impl Default for NativePredicateLimits {
    fn default() -> Self {
        Self {
            max_size_items: 100_000,
            max_qualifiers: 10_000,
            max_parameters: 100_000,
            max_live_primitives: 1_000_000,
            max_depth: 100_000,
            max_work: 64_000_000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NativePredicateUsage {
    pub size_items: usize,
    pub qualifiers: usize,
    pub parameters: usize,
    /// Nested HFA extractions run by this query.
    pub extractions: usize,
    pub work: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativePredicateMatch {
    pub matched: bool,
    pub rejection: Option<PredicateRejection>,
    pub usage: NativePredicateUsage,
}

/// The first failed `HomogeneousAggregate::filter` condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeHfaRejection {
    /// Native meta-type is neither Array nor Struct (aliases keep theirs).
    NotAggregate(MetaType),
    /// The bounded extraction was invalid, including the primitive maximum.
    Invalid(NativeInvalidExtraction),
    Empty,
    ContainsUnknown,
    Unaligned,
    ContainsHoles,
    NotFloat(MetaType),
    /// A later leaf is a different native object than the first.
    MixedIdentity {
        index: usize,
        first: NativeTypeId,
        other: NativeTypeId,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NativeHfa {
    pub matched: bool,
    pub rejection: Option<NativeHfaRejection>,
    /// The shared float object when matched.
    pub primitive: Option<NativeTypeId>,
    pub count: usize,
    pub usage: NativePredicateUsage,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NativePredicateError {
    #[error("native datatype predicate limit exceeded: {0}")]
    Limit(&'static str),
    #[error("unknown predicate datatype {0:?}")]
    UnknownType(TypeId),
    #[error(transparent)]
    Conversion(#[from] NativeConversionError),
    #[error("invalid native datatype filter: {0}")]
    InvalidFilter(&'static str),
    #[error("invalid prototype context: {0}")]
    InvalidPrototype(&'static str),
    #[error("varargs position subtraction exceeds the modeled signed-int range")]
    PositionOverflow,
    #[error("native datatype predicate arithmetic exceeds the signed-int range")]
    Overflow,
    #[error(transparent)]
    Graph(NativeTypeError),
}

type Result<T> = std::result::Result<T, NativePredicateError>;

impl From<NativeTypeError> for NativePredicateError {
    fn from(error: NativeTypeError) -> Self {
        match error {
            NativeTypeError::Conversion(error) => Self::Conversion(error),
            NativeTypeError::UnknownSource(ty) => Self::UnknownType(ty),
            // Not produced by queries on IDs this graph returned.
            other => Self::Graph(other),
        }
    }
}

impl NativeTypeGraph {
    /// Test a parsed datatype filter against the decoded native type of `ty`.
    pub fn matches_filter(
        &self,
        filter: &DatatypeFilter,
        ty: TypeId,
        limits: NativePredicateLimits,
    ) -> Result<NativePredicateMatch> {
        let mut budget = Budget::new(limits);
        let matched = self.evaluate(filter, ty, &mut budget)?;
        Ok(NativePredicateMatch {
            matched,
            rejection: (!matched).then_some(PredicateRejection::Datatype),
            usage: budget.usage,
        })
    }

    /// `ModelRule::assignAddress`'s filter then qualifier checks, in declaration
    /// order with short-circuit AND. IDs are validated first; a conversion
    /// failure is reported only when a reached filter evaluates that type.
    pub fn matches_rule(
        &self,
        rule: &ModelRule,
        ty: TypeId,
        prototype: PrototypeTypes<'_>,
        position: i32,
        limits: NativePredicateLimits,
    ) -> Result<NativePredicateMatch> {
        if rule.qualifiers.len() > limits.max_qualifiers {
            return Err(NativePredicateError::Limit("qualifiers"));
        }
        if prototype.parameters.len() > limits.max_parameters {
            return Err(NativePredicateError::Limit("parameters"));
        }
        if prototype
            .first_vararg
            .is_some_and(|n| n > prototype.parameters.len() || n > i32::MAX as usize)
        {
            return Err(NativePredicateError::InvalidPrototype(
                "first vararg slot exceeds the input list or signed-int range",
            ));
        }
        let mut budget = Budget::new(limits);
        budget.usage.parameters = prototype.parameters.len();
        budget.work(1)?;
        self.known(prototype.result)?;
        self.known(ty)?;
        for parameter in prototype.parameters {
            budget.work(1)?;
            self.known(*parameter)?;
        }
        if !self.evaluate(&rule.datatype, ty, &mut budget)? {
            return Ok(NativePredicateMatch {
                matched: false,
                rejection: Some(PredicateRejection::Datatype),
                usage: budget.usage,
            });
        }
        for (index, qualifier) in rule.qualifiers.iter().enumerate() {
            budget.work(1)?;
            budget.usage.qualifiers += 1;
            let matches = match qualifier {
                RuleQualifier::Position { index } => position == *index,
                RuleQualifier::Varargs { first, last } => match prototype.first_vararg {
                    Some(slot) => {
                        let delta = i32::try_from(i64::from(position) - slot as i64)
                            .map_err(|_| NativePredicateError::PositionOverflow)?;
                        delta >= first.unwrap_or(i32::MIN) && delta <= last.unwrap_or(i32::MAX)
                    }
                    None => false,
                },
                RuleQualifier::DatatypeAt { index, datatype } => {
                    let target = if *index < 0 {
                        Some(prototype.result)
                    } else {
                        prototype.parameters.get(*index as usize).copied()
                    };
                    match target {
                        Some(target) => self.evaluate(datatype, target, &mut budget)?,
                        None => false,
                    }
                }
            };
            if !matches {
                return Ok(NativePredicateMatch {
                    matched: false,
                    rejection: Some(PredicateRejection::Qualifier(index)),
                    usage: budget.usage,
                });
            }
        }
        Ok(NativePredicateMatch {
            matched: true,
            rejection: None,
            usage: budget.usage,
        })
    }

    /// `HomogeneousAggregate::filter` with explicit details. A `None`, zero or
    /// absent maximum uses the source default of four. Size bounds are ignored.
    pub fn homogeneous_float_aggregate(
        &self,
        ty: TypeId,
        max_primitives: Option<u32>,
        limits: NativePredicateLimits,
    ) -> Result<NativeHfa> {
        if max_primitives.is_some_and(|n| n > i32::MAX as u32) {
            return Err(NativePredicateError::InvalidFilter(
                "primitive bound exceeds signed int",
            ));
        }
        let mut budget = Budget::new(limits);
        budget.work(1)?;
        let id = self.native(ty)?;
        let maximum = max_primitives.filter(|n| *n != 0).unwrap_or(4);
        let mut result = self.hfa(id, maximum, &mut budget)?;
        result.usage = budget.usage;
        Ok(result)
    }

    fn known(&self, ty: TypeId) -> Result<()> {
        if ty.0 < self.source_count() {
            Ok(())
        } else {
            Err(NativePredicateError::UnknownType(ty))
        }
    }

    fn evaluate(&self, filter: &DatatypeFilter, ty: TypeId, budget: &mut Budget) -> Result<bool> {
        budget.work(1)?;
        self.known(ty)?;
        validate_filter(filter, budget)?;
        let id = self.native(ty)?;
        let native = *self.get(id)?;
        match filter.class {
            DatatypeClass::HomogeneousFloatAggregate => {
                let maximum = filter.max_primitives.filter(|n| *n != 0).unwrap_or(4);
                return Ok(self.hfa(id, maximum, budget)?.matched);
            }
            DatatypeClass::Meta(MetaType::Array) => {
                // ArrayFilter tests the native meta-type, which an alias of an
                // array keeps, then size, then element bounds.
                let Some(array) = self.array(id)? else {
                    return Ok(false);
                };
                if !size_matches(filter, native.size) {
                    return Ok(false);
                }
                return Ok(array.count >= filter.min_elements.unwrap_or(0)
                    && filter
                        .max_elements
                        .is_none_or(|n| n == 0 || array.count <= n));
            }
            DatatypeClass::Meta(expected) if expected != native.meta => return Ok(false),
            _ => (),
        }
        Ok(size_matches(filter, native.size))
    }

    fn hfa(&self, id: NativeTypeId, maximum: u32, budget: &mut Budget) -> Result<NativeHfa> {
        let native = *self.get(id)?;
        let reject = |rejection, budget: &Budget| NativeHfa {
            matched: false,
            rejection: Some(rejection),
            primitive: None,
            count: 0,
            usage: budget.usage,
        };
        if !matches!(native.meta, MetaType::Array | MetaType::Struct) {
            return Ok(reject(
                NativeHfaRejection::NotAggregate(native.meta),
                budget,
            ));
        }
        budget.usage.extractions = budget
            .usage
            .extractions
            .checked_add(1)
            .ok_or(NativePredicateError::Limit("work"))?;
        let limits = NativeExtractionLimits {
            max_live_primitives: budget.limits.max_live_primitives,
            max_depth: budget.limits.max_depth,
            max_work: budget.limits.max_work - budget.usage.work,
        };
        let options = NativeExtractionOptions {
            offset: 0,
            reject_unions: true,
            nested_arrays_are_primitives: false,
            max_primitives: maximum,
        };
        let (outcome, stats) = extract(self, id, options, limits).map_err(|error| match error {
            NativeExtractionError::Limit(name) => NativePredicateError::Limit(name),
            NativeExtractionError::Overflow => NativePredicateError::Overflow,
            NativeExtractionError::Type(error) => error.into(),
            NativeExtractionError::InvalidOptions(name) => {
                NativePredicateError::InvalidFilter(name)
            }
        })?;
        budget.usage.work += stats.work; // Bounded by the remaining budget.
        let (primitives, contains_unknown, aligned, contains_holes) = match outcome {
            NativeExtractionOutcome::Invalid(invalid) => {
                return Ok(reject(NativeHfaRejection::Invalid(invalid), budget));
            }
            NativeExtractionOutcome::Valid {
                primitives,
                contains_unknown,
                aligned,
                contains_holes,
            } => (primitives, contains_unknown, aligned, contains_holes),
        };
        let Some(first) = primitives.first() else {
            return Ok(reject(NativeHfaRejection::Empty, budget));
        };
        if contains_unknown {
            return Ok(reject(NativeHfaRejection::ContainsUnknown, budget));
        }
        if !aligned {
            return Ok(reject(NativeHfaRejection::Unaligned, budget));
        }
        if contains_holes {
            return Ok(reject(NativeHfaRejection::ContainsHoles, budget));
        }
        if first.meta != MetaType::Float {
            return Ok(reject(NativeHfaRejection::NotFloat(first.meta), budget));
        }
        for (index, primitive) in primitives.iter().enumerate().skip(1) {
            budget.work(1)?;
            if primitive.ty != first.ty {
                return Ok(reject(
                    NativeHfaRejection::MixedIdentity {
                        index,
                        first: first.ty,
                        other: primitive.ty,
                    },
                    budget,
                ));
            }
        }
        Ok(NativeHfa {
            matched: true,
            rejection: None,
            primitive: Some(first.ty),
            count: primitives.len(),
            usage: budget.usage,
        })
    }
}

/// `SizeRestrictedFilter::filterOnSize` on the native raw size (`getSize`).
fn size_matches(filter: &DatatypeFilter, size: u32) -> bool {
    if !filter.sizes.is_empty() {
        return filter.sizes.contains(&size);
    }
    let maximum = filter
        .max_size
        .filter(|n| *n != 0)
        .unwrap_or(i32::MAX as u32);
    size >= filter.min_size.unwrap_or(0) && size <= maximum
}

struct Budget {
    limits: NativePredicateLimits,
    usage: NativePredicateUsage,
}

impl Budget {
    fn new(limits: NativePredicateLimits) -> Self {
        Self {
            limits,
            usage: NativePredicateUsage::default(),
        }
    }
    fn work(&mut self, amount: u64) -> Result<()> {
        self.usage.work = self
            .usage
            .work
            .checked_add(amount)
            .filter(|n| *n <= self.limits.max_work)
            .ok_or(NativePredicateError::Limit("work"))?;
        Ok(())
    }
}

/// Decoder-equivalent validation of a parsed filter, checked when reached.
fn validate_filter(filter: &DatatypeFilter, budget: &mut Budget) -> Result<()> {
    budget.usage.size_items = budget
        .usage
        .size_items
        .checked_add(filter.sizes.len())
        .filter(|n| *n <= budget.limits.max_size_items)
        .ok_or(NativePredicateError::Limit("size items"))?;
    budget.work(
        (filter.sizes.len() as u64)
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .ok_or(NativePredicateError::Limit("work"))?,
    )?;
    if !filter.sizes.is_empty() && (filter.min_size.is_some() || filter.max_size.is_some()) {
        return Err(NativePredicateError::InvalidFilter(
            "enumerated sizes mixed with range bounds",
        ));
    }
    if filter.sizes.iter().any(|n| *n == 0 || *n > i32::MAX as u32) {
        return Err(NativePredicateError::InvalidFilter(
            "sizes must be positive signed ints",
        ));
    }
    if [filter.min_size, filter.max_size]
        .into_iter()
        .flatten()
        .any(|n| n > i32::MAX as u32)
    {
        return Err(NativePredicateError::InvalidFilter(
            "size bound exceeds signed int",
        ));
    }
    match filter.class {
        DatatypeClass::HomogeneousFloatAggregate
            if filter.max_primitives.is_some_and(|n| n > i32::MAX as u32) =>
        {
            Err(NativePredicateError::InvalidFilter(
                "primitive bound exceeds signed int",
            ))
        }
        DatatypeClass::Meta(MetaType::Array)
            if [filter.min_elements, filter.max_elements]
                .into_iter()
                .flatten()
                .any(|n| n > i32::MAX as u32) =>
        {
            Err(NativePredicateError::InvalidFilter(
                "element bound exceeds signed int",
            ))
        }
        // string2metatype (metatype.cc) has no "partenum" name.
        DatatypeClass::Meta(MetaType::PartEnum) => Err(NativePredicateError::InvalidFilter(
            "partenum is not a native meta-type name",
        )),
        _ => Ok(()),
    }
}
