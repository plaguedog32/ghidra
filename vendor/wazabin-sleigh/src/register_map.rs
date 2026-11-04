//! Register geometry: which register encloses a location, and which overlap
//! it.
//!
//! An architecture names overlapping registers: on x86-64 `AL`, `AH`, `AX`,
//! `EAX` and `RAX` are five names over the same eight bytes. P-code reads and
//! writes whichever name the semantics use, so a consumer tracking "what is
//! in `RAX`" must know that a store to `AL` writes byte 0 of it and a load of
//! `AH` reads byte 1. The map answers that from the geometry the
//! specification declared, and is built once when the specification is
//! compiled, so a precompiled specification carries it.
//!
//! Whether a partial write clears the rest of the register is not a question
//! for this table. Semantics that zero-extend say so in p-code — x86-64's
//! `MOV EAX, EDI` is a 4-byte store to `EAX` followed by
//! `RAX = zext(EAX)` — and semantics that keep the other bytes emit nothing.
//! A consumer that models the register file byte-precisely with these slices
//! therefore gets either behaviour right without an architecture rule.

use jstd::registry::Registry;
use pcode_types::{Register, RegisterId, SpaceId, Varnode};
use serde::{Deserialize, Serialize};
use std::cmp::Reverse;

/// A location expressed inside the widest register enclosing it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RegisterSlice {
    /// The enclosing register.
    pub register: RegisterId,
    /// Byte offset of the location from the start of `register`.
    pub offset: usize,
    /// Size of the location in bytes.
    pub size: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct Entry {
    offset: u64,
    size: usize,
    register: RegisterId,
}

impl Entry {
    fn end(&self) -> u64 {
        self.offset.saturating_add(self.size as u64)
    }
}

/// The registers of one space, sorted by offset, widest first among equals.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct SpaceRegisters {
    entries: Vec<Entry>,
    /// `first[o]` is the index of the first entry at or past offset `o`, for
    /// every offset up to the space's last register byte. Register spaces are
    /// small and dense, so a table answers a lookup in one load where a
    /// binary search costs a chain of them.
    first: Vec<u32>,
    /// The widest register of the space, bounding how far back a query looks.
    max_size: usize,
}

impl SpaceRegisters {
    fn new(mut entries: Vec<Entry>) -> Self {
        entries.sort_by_key(|e| (e.offset, Reverse(e.size)));
        let extent = entries.iter().map(Entry::end).max().unwrap_or(0) as usize;
        let first = (0..=extent as u64)
            .map(|o| entries.partition_point(|e| e.offset < o) as u32)
            .collect();
        let max_size = entries.iter().map(|e| e.size).max().unwrap_or(0);
        Self {
            entries,
            first,
            max_size,
        }
    }

    /// The index of the first entry at or past `offset`.
    fn first_at(&self, offset: u64) -> usize {
        usize::try_from(offset)
            .ok()
            .and_then(|o| self.first.get(o))
            .map_or(self.entries.len(), |&i| i as usize)
    }

    /// Entries starting exactly at `offset`, widest first.
    fn starting_at(&self, offset: u64) -> impl Iterator<Item = &Entry> {
        self.entries[self.first_at(offset)..]
            .iter()
            .take_while(move |e| e.offset == offset)
    }

    /// Entries starting at or before `offset` that can still reach it,
    /// nearest first.
    fn starting_before(&self, offset: u64) -> impl Iterator<Item = &Entry> {
        let end = self.first_at(offset.saturating_add(1));
        let start = self.first_at(offset.saturating_sub(self.max_size as u64));
        self.entries[start..end].iter().rev()
    }

    fn overlapping(&self, offset: u64, size: usize) -> impl Iterator<Item = &Entry> {
        let end = offset.saturating_add(size as u64);
        let before = self
            .starting_before(offset)
            .filter(move |e| e.end() > offset);
        let after = self.entries[self.first_at(offset.saturating_add(1))..]
            .iter()
            .take_while(move |e| e.offset < end);
        before.chain(after)
    }
}

/// Every register of a specification, indexed by location.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub(crate) struct RegisterMap {
    /// Indexed by space id; spaces without registers hold an empty entry.
    by_space: Vec<SpaceRegisters>,
}

impl RegisterMap {
    pub(crate) fn new(registers: &Registry<RegisterId, Register>) -> Self {
        let mut by_space: Vec<Vec<Entry>> = Vec::new();
        for register in registers.iter() {
            let space = usize::from(register.inner.space);
            if by_space.len() <= space {
                by_space.resize_with(space + 1, Default::default);
            }
            by_space[space].push(Entry {
                offset: register.inner.offset as u64,
                size: register.inner.size,
                register: register.id,
            });
        }
        Self {
            by_space: by_space.into_iter().map(SpaceRegisters::new).collect(),
        }
    }

    fn space(&self, space: SpaceId) -> Option<&SpaceRegisters> {
        self.by_space.get(usize::from(space))
    }

    /// The register declared at exactly `varnode`.
    pub(crate) fn at(&self, varnode: Varnode) -> Option<RegisterId> {
        self.space(varnode.space)?
            .starting_at(varnode.offset)
            .find(|e| e.size == varnode.size)
            .map(|e| e.register)
    }

    /// `varnode` as a slice of the widest register that wholly contains it.
    pub(crate) fn enclosing(&self, varnode: Varnode) -> Option<RegisterSlice> {
        let end = varnode.offset.checked_add(varnode.size as u64)?;
        self.space(varnode.space)?
            .starting_before(varnode.offset)
            .filter(|e| e.end() >= end)
            .max_by_key(|e| (e.size, Reverse(e.offset)))
            .map(|e| RegisterSlice {
                register: e.register,
                offset: (varnode.offset - e.offset) as usize,
                size: varnode.size,
            })
    }

    /// Every register sharing a byte with `varnode`, in offset order, widest
    /// first among registers at the same offset.
    pub(crate) fn overlapping(&self, varnode: Varnode) -> impl Iterator<Item = RegisterId> + '_ {
        self.space(varnode.space).into_iter().flat_map(move |regs| {
            let mut found: Vec<&Entry> = regs.overlapping(varnode.offset, varnode.size).collect();
            found.sort_by_key(|e| (e.offset, Reverse(e.size)));
            found.into_iter().map(|e| e.register)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CompiledSpec, Compiler, SourceDb};

    /// x86-64's `RAX` family and `RCX` at 8, plus a register in another
    /// space so a space's index is its own.
    const SPEC: &str = "define endian=little;
        define space ram type=ram_space size=8 default;
        define space register type=register_space size=4;
        define space other type=register_space size=4;
        define register offset=0 size=8 [ RAX RCX ];
        define register offset=0 size=4 [ EAX ];
        define register offset=0 size=2 [ AX ];
        define register offset=0 size=1 [ AL AH ];
        define register offset=8 size=4 [ ECX ];
        define register offset=8 size=1 [ CL ];
        define other offset=0 size=8 [ o0 ];
        define token instr(8) op=(0,7);
        :nop is op=0 { }";

    fn spec() -> CompiledSpec {
        let mut sources = SourceDb::new();
        let root = sources.add_file("regs.slaspec", SPEC);
        Compiler::new(&mut sources)
            .compile(root)
            .expect("the specification compiles")
    }

    fn reg(spec: &CompiledSpec, name: &str) -> RegisterId {
        spec.register(name)
            .unwrap_or_else(|| panic!("{name} is defined"))
            .id
    }

    fn at(spec: &CompiledSpec, offset: u64, size: usize) -> Varnode {
        let space = spec
            .space("register")
            .expect("the register space exists")
            .id;
        Varnode::new(space, offset, size)
    }

    #[test]
    fn a_partial_register_is_a_slice_of_the_widest_one() {
        let spec = spec();
        assert_eq!(
            spec.enclosing_register(at(&spec, 1, 1)),
            Some(RegisterSlice {
                register: reg(&spec, "RAX"),
                offset: 1,
                size: 1
            })
        );
        assert_eq!(
            spec.enclosing_register(at(&spec, 8, 4)),
            Some(RegisterSlice {
                register: reg(&spec, "RCX"),
                offset: 0,
                size: 4
            })
        );
        assert_eq!(
            spec.enclosing_register(at(&spec, 0, 8)).map(|s| s.register),
            Some(reg(&spec, "RAX"))
        );
    }

    #[test]
    fn a_location_spanning_registers_or_outside_them_has_no_enclosing_register() {
        let spec = spec();
        assert_eq!(spec.enclosing_register(at(&spec, 6, 4)), None);
        assert_eq!(spec.enclosing_register(at(&spec, 16, 1)), None);
        assert_eq!(
            spec.enclosing_register(Varnode::new(spec.default_space(), 0, 1)),
            None
        );
        assert_eq!(spec.enclosing_register(Varnode::constant(0, 1)), None);
    }

    #[test]
    fn a_register_space_is_indexed_on_its_own() {
        let spec = spec();
        let other = spec.space("other").expect("the other space exists").id;
        assert_eq!(
            spec.enclosing_register(Varnode::new(other, 2, 2))
                .map(|s| s.register),
            Some(reg(&spec, "o0"))
        );
        assert_eq!(
            spec.overlapping_registers(Varnode::new(other, 8, 1))
                .count(),
            0
        );
    }

    #[test]
    fn overlaps_are_every_register_sharing_a_byte() {
        let spec = spec();
        let names = |v: Varnode| -> Vec<String> {
            spec.overlapping_registers(v)
                .map(|id| {
                    spec.registers()
                        .nth(usize::from(id))
                        .unwrap()
                        .name()
                        .to_owned()
                })
                .collect()
        };
        assert_eq!(names(at(&spec, 1, 1)), ["RAX", "EAX", "AX", "AH"]);
        assert_eq!(names(at(&spec, 7, 2)), ["RAX", "RCX", "ECX", "CL"]);
        assert_eq!(names(at(&spec, 16, 8)), [] as [&str; 0]);
    }

    #[test]
    fn exact_lookup_needs_the_declared_extent() {
        let spec = spec();
        assert_eq!(spec.register_at(at(&spec, 0, 2)), Some(reg(&spec, "AX")));
        assert_eq!(spec.register_at(at(&spec, 0, 3)), None);
        assert_eq!(spec.register_at(at(&spec, 8, 1)), Some(reg(&spec, "CL")));
    }
}
