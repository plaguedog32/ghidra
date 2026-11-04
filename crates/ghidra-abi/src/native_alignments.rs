//! The native decompiler TypeFactory alignment map, separate from Java layouts.
use std::collections::BTreeMap;

use ghidra_languages::{ResolvedDataOrganization, SizeAlignment};
use serde::Serialize;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeAlignmentLimits {
    /// Declared records, including duplicate sizes, checked before reading them.
    /// The absent-map default is a fixed five-record representation.
    pub max_entries: usize,
    pub max_work: u64,
}

impl Default for NativeAlignmentLimits {
    fn default() -> Self {
        Self {
            max_entries: 100_000,
            max_work: 4_000_000,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum NativeAlignmentOrigin {
    Default,
    Declared,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize)]
pub struct NativeAlignmentUsage {
    pub declarations: usize,
    /// Includes size zero, whose alignment is always one.
    pub stored_entries: usize,
    pub work: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct NativePrimitiveGeometry {
    pub size: u32,
    pub aligned_size: u32,
    pub alignment: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum NativeAlignmentError {
    #[error("native alignment limit exceeded: {0}")]
    Limit(&'static str),
    #[error("an explicitly declared native alignment map is empty")]
    EmptyMap,
    #[error("invalid native alignment entry {index}: {reason}")]
    InvalidEntry { index: usize, reason: &'static str },
    #[error("native primitive size {0} exceeds the modeled signed-int range")]
    InvalidSize(u64),
    #[error(
        "native primitive size {size} padded to alignment {alignment} exceeds the signed-int range"
    )]
    Overflow { size: u32, alignment: u32 },
}

/// Sparse equivalent of TypeFactory::decodeAlignmentMap/setDefaultAlignmentMap.
/// A far-away size key never causes allocation proportional to the key value.
#[derive(Clone, Debug)]
pub struct NativeAlignmentMap {
    entries: Vec<SizeAlignment>,
    origin: NativeAlignmentOrigin,
    limits: NativeAlignmentLimits,
    usage: NativeAlignmentUsage,
}

impl NativeAlignmentMap {
    /// The compiler-organization bridge encodes the resolved map, including
    /// Java's seeded entries. An empty organization map is omitted by encode,
    /// which selects native defaults. Other organization fields do not affect
    /// TypeFactory's alignment map or primitive padding.
    pub fn from_organization(
        organization: &ResolvedDataOrganization,
        limits: NativeAlignmentLimits,
    ) -> Result<Self, NativeAlignmentError> {
        let entries = &organization.size_alignment_map;
        Self::new((!entries.is_empty()).then_some(entries.as_slice()), limits)
    }

    /// None uses the native default; Some imports exactly the given declarations,
    /// without adding Java's seeded 1/2/4/8 entries. Duplicate sizes are last-wins.
    /// An explicit empty map is an error, unlike an absent map.
    pub fn new(
        declared: Option<&[SizeAlignment]>,
        limits: NativeAlignmentLimits,
    ) -> Result<Self, NativeAlignmentError> {
        let mut usage = NativeAlignmentUsage::default();
        if let Some(declared) = declared {
            if declared.len() > limits.max_entries {
                return Err(NativeAlignmentError::Limit("entries"));
            }
            usage.declarations = declared.len();
            if declared.is_empty() {
                return Err(NativeAlignmentError::EmptyMap);
            }
            charge(&mut usage, limits, 1)?;
            let mut map = BTreeMap::new();
            map.insert(0, 1);
            for (index, entry) in declared.iter().enumerate() {
                // Visit plus a conservative logarithmic insertion charge.
                charge(
                    &mut usage,
                    limits,
                    2 + u64::from(usize::BITS - map.len().leading_zeros()),
                )?;
                if entry.size > i32::MAX as u32 || entry.alignment > i32::MAX as u32 {
                    return Err(NativeAlignmentError::InvalidEntry {
                        index,
                        reason: "size/alignment exceeds signed int",
                    });
                }
                if entry.size != 0 && entry.alignment == 0 {
                    return Err(NativeAlignmentError::InvalidEntry {
                        index,
                        reason: "positive sizes require positive alignment",
                    });
                }
                if entry.size != 0 {
                    map.insert(entry.size, entry.alignment);
                }
                // Source decode overwrites alignMap[0] with 1 after all entries.
            }
            charge(&mut usage, limits, map.len() as u64)?;
            usage.stored_entries = map.len();
            let entries = map
                .into_iter()
                .map(|(size, alignment)| SizeAlignment { size, alignment })
                .collect();
            Ok(Self {
                entries,
                origin: NativeAlignmentOrigin::Declared,
                limits,
                usage,
            })
        } else {
            // Fixed storage, charged before allocation. This reproduces the
            // native nine-element dense map with five floor-lookup breakpoints.
            charge(&mut usage, limits, 6)?;
            let entries = [0, 1, 2, 4, 8]
                .into_iter()
                .map(|size| SizeAlignment {
                    size,
                    alignment: size.max(1),
                })
                .collect();
            usage.stored_entries = 5;
            Ok(Self {
                entries,
                origin: NativeAlignmentOrigin::Default,
                limits,
                usage,
            })
        }
    }

    pub fn entries(&self) -> &[SizeAlignment] {
        &self.entries
    }
    pub fn origin(&self) -> NativeAlignmentOrigin {
        self.origin
    }
    pub fn limits(&self) -> NativeAlignmentLimits {
        self.limits
    }
    pub fn usage(&self) -> NativeAlignmentUsage {
        self.usage
    }

    /// getAlignment: floor lookup, one below the first positive key, and the
    /// final value above the last key. No absolute/default/pointer cap applies.
    /// The query allocates nothing and takes O(log stored_entries) time.
    pub fn alignment(&self, size: u64) -> u32 {
        let after = self
            .entries
            .partition_point(|entry| u64::from(entry.size) <= size);
        self.entries[after - 1].alignment // The invariant size-zero entry exists.
    }

    /// Primitive findAdd geometry: round using alignment(raw size), then query
    /// alignment again at the rounded size. Applies to native scalar and pointer
    /// objects; it does not turn this record into a native datatype graph.
    /// Size zero yields (0,0,1), useful for void geometry. No bytes are allocated.
    pub fn primitive_geometry(
        &self,
        size: u64,
    ) -> Result<NativePrimitiveGeometry, NativeAlignmentError> {
        let size = u32::try_from(size)
            .ok()
            .filter(|n| *n <= i32::MAX as u32)
            .ok_or(NativeAlignmentError::InvalidSize(size))?;
        let alignment = self.alignment(u64::from(size));
        let padded = u64::from(size).div_ceil(u64::from(alignment)) * u64::from(alignment);
        if padded > i32::MAX as u64 {
            return Err(NativeAlignmentError::Overflow { size, alignment });
        }
        Ok(NativePrimitiveGeometry {
            size,
            aligned_size: padded as u32,
            alignment: self.alignment(padded),
        })
    }
}

fn charge(
    usage: &mut NativeAlignmentUsage,
    limits: NativeAlignmentLimits,
    amount: u64,
) -> Result<(), NativeAlignmentError> {
    usage.work = usage
        .work
        .checked_add(amount)
        .filter(|n| *n <= limits.max_work)
        .ok_or(NativeAlignmentError::Limit("work"))?;
    Ok(())
}
