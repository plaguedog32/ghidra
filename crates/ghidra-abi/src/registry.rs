use std::collections::{BTreeMap, BTreeSet};

use ghidra_pcode::{AddressSpace, SpaceId, SpaceKind};
use serde::Serialize;

use crate::error::{Budget, label};
use crate::{AbiError, AbiLimits, AbiResult};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
pub struct RegisterId(pub usize);

/// A byte-addressed physical register alias. Large declarative registers are
/// permitted; this does not assert that the P-code Value type can execute them.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RegisterDefinition {
    pub name: String,
    pub space: SpaceId,
    pub offset: u64,
    pub size: u32,
}

#[derive(Debug, Serialize)]
pub struct RegisterFile {
    spaces: Vec<AddressSpace>,
    default_space: SpaceId,
    registers: Vec<RegisterDefinition>,
    #[serde(skip)]
    space_ids: BTreeMap<SpaceId, usize>,
    #[serde(skip)]
    space_names: BTreeMap<String, usize>,
    #[serde(skip)]
    names: BTreeMap<String, RegisterId>,
    #[serde(skip)]
    max_name_length: usize,
    work: u64,
    name_bytes: usize,
}

pub(crate) fn capacity(space: &AddressSpace) -> u128 {
    ((1_u128 << (u32::from(space.address_size) * 8)) * u128::from(space.word_size))
        .min(u128::from(u64::MAX) + 1)
}

impl RegisterFile {
    pub fn new(
        spaces: Vec<AddressSpace>,
        default_space: SpaceId,
        registers: Vec<RegisterDefinition>,
        limits: AbiLimits,
    ) -> AbiResult<Self> {
        if spaces.is_empty() || spaces.len() > limits.max_spaces {
            return Err(AbiError::Limit("spaces"));
        }
        if registers.len() > limits.max_registers {
            return Err(AbiError::Limit("registers"));
        }
        let mut budget = Budget::new(limits);
        let mut space_ids = BTreeMap::new();
        let mut space_names = BTreeMap::new();
        for (index, space) in spaces.iter().enumerate() {
            budget.name(&space.name)?;
            budget.lookup(spaces.len(), space.name.len())?;
            budget.lookup(spaces.len(), 1)?;
            space
                .validate()
                .map_err(|_| AbiError::InvalidLayout("invalid address space"))?;
            if space_ids.insert(space.id, index).is_some() {
                return Err(AbiError::InvalidLayout("duplicate space ID"));
            }
            budget.name(&space.name)?;
            if space_names.insert(space.name.clone(), index).is_some() {
                return Err(AbiError::InvalidLayout("duplicate space name"));
            }
        }
        let default = space_ids
            .get(&default_space)
            .map(|&i| &spaces[i])
            .ok_or(AbiError::InvalidLayout("unknown default space"))?;
        if !matches!(default.kind, SpaceKind::Ram | SpaceKind::Other) {
            return Err(AbiError::InvalidLayout("default space must be memory"));
        }
        let mut names = BTreeMap::new();
        let mut originals = BTreeSet::new();
        for (index, register) in registers.iter().enumerate() {
            budget.name(&register.name)?;
            budget.lookup(registers.len(), register.name.len())?;
            if !originals.insert(register.name.as_str()) {
                return Err(AbiError::InvalidLayout("duplicate register name"));
            }
            let space = space_ids
                .get(&register.space)
                .map(|&i| &spaces[i])
                .ok_or(AbiError::InvalidLayout("register names unknown space"))?;
            if space.kind != SpaceKind::Register {
                return Err(AbiError::InvalidLayout("register is not in register space"));
            }
            if register.size == 0
                || u128::from(register.offset) + u128::from(register.size) > capacity(space)
            {
                return Err(AbiError::InvalidLayout("register extent outside space"));
            }
            // Match RegisterBuilder's exact/lower/upper spellings for ASCII
            // language identifiers. Later case-variation collisions win.
            for form in 0..3 {
                budget.name(&register.name)?;
                budget.lookup(registers.len().saturating_mul(3), register.name.len())?;
                let name = match form {
                    0 => register.name.clone(),
                    1 => register.name.to_ascii_lowercase(),
                    _ => register.name.to_ascii_uppercase(),
                };
                names.insert(name, RegisterId(index));
            }
        }
        drop(originals);
        Ok(Self {
            spaces,
            default_space,
            registers,
            space_ids,
            space_names,
            names,
            max_name_length: limits.max_name_length,
            work: budget.work,
            name_bytes: budget.name_bytes,
        })
    }

    pub fn spaces(&self) -> &[AddressSpace] {
        &self.spaces
    }
    pub fn registers(&self) -> &[RegisterDefinition] {
        &self.registers
    }
    pub fn default_space(&self) -> SpaceId {
        self.default_space
    }
    pub fn build_work(&self) -> u64 {
        self.work
    }
    pub fn name_bytes(&self) -> usize {
        self.name_bytes
    }
    pub fn space(&self, id: SpaceId) -> Option<&AddressSpace> {
        self.space_ids.get(&id).map(|&i| &self.spaces[i])
    }
    pub fn space_named(&self, name: &str) -> Option<&AddressSpace> {
        if name.len() > self.max_name_length {
            return None;
        }
        self.space_names.get(name).map(|&i| &self.spaces[i])
    }
    pub fn register_id(&self, name: &str) -> Option<RegisterId> {
        if name.len() > self.max_name_length {
            return None;
        }
        self.names.get(name).copied()
    }
    pub fn register(&self, id: RegisterId) -> AbiResult<&RegisterDefinition> {
        self.registers
            .get(id.0)
            .ok_or(AbiError::UnknownRegisterId(id))
    }
    pub fn registers_overlap(&self, left: RegisterId, right: RegisterId) -> AbiResult<bool> {
        let a = self.register(left)?;
        let b = self.register(right)?;
        Ok(a.space == b.space
            && u128::from(a.offset) < u128::from(b.offset) + u128::from(b.size)
            && u128::from(b.offset) < u128::from(a.offset) + u128::from(a.size))
    }
    pub(crate) fn find_register(&self, name: &str, budget: &mut Budget) -> AbiResult<RegisterId> {
        budget.name(name)?;
        budget.lookup(self.names.len(), name.len())?;
        self.register_id(name)
            .ok_or_else(|| AbiError::UnknownRegister(label(name)))
    }
    pub(crate) fn find_space(&self, name: &str, budget: &mut Budget) -> AbiResult<&AddressSpace> {
        budget.name(name)?;
        budget.lookup(self.space_names.len(), name.len())?;
        self.space_named(name)
            .ok_or_else(|| AbiError::UnknownSpace(label(name)))
    }
}
