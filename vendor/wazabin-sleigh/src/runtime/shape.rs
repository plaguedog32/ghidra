//! The shape of a decoded instruction: which of its bits chose the
//! constructors, and which are plain operand values.
//!
//! A decode reads the instruction's bits for two purposes. Some decide what
//! the instruction *is*: the bits the decision trees dispatch on, the bits
//! the tried constructors' patterns test, and the bits of fields whose value
//! picks a register, an attached value or a context assignment. The rest are
//! read only to become integers in the p-code — immediates, displacements,
//! branch offsets. Two encodings that agree on the first kind decode to the
//! same constructors, in the same order, with the same operand layout; they
//! differ only in the values of the second kind.
//!
//! [`Decoder::decode_one_shaped`](super::Decoder::decode_one_shaped) records
//! that split as a [`Shape`]: a bit mask over the instruction's bytes (set
//! where the bit was decisive), the patterns of the more specific
//! candidates the decode passed over — an encoding matching one of them
//! decodes differently, whatever its masked bits say — and the list of
//! parameter fields. A caller memoizing per-encoding work can key it on the
//! masked bytes, check the exclusions, and parameterize it on the fields,
//! and serve every encoding of the shape from one entry.
//!
//! A field read as an index into an `attach variables` table is a
//! [`RegisterField`]: its bits are not in the mask either, since the
//! constructors and their operand layout are the same whichever register
//! the value names, and a caller can parameterize on the register as it
//! does on an integer.

use std::cell::{Cell, RefCell};

use crate::{bitrange::BitRange, objects::field::FieldTableId};

use super::walker::{extract_bytes, signed};

/// One parameter field of a [`Shape`]: a run of instruction bits read only
/// for its integer value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ParamField {
    /// The field's lowest bit, LSB-numbered from the instruction's first
    /// byte: bit `n` is bit `n % 8` of byte `n / 8`.
    pub bit: u32,
    /// The field's width in bits.
    pub width: u8,
    /// Whether the field's value is sign-extended.
    pub signed: bool,
}

impl ParamField {
    fn range(self) -> BitRange {
        let start = self.bit as usize;
        BitRange::new(start, start + usize::from(self.width) - 1)
    }

    /// The field's value in `bytes`, an instruction of the shape.
    pub fn value(self, bytes: &[u8]) -> i64 {
        let range = self.range();
        let raw = extract_bytes(bytes, &range);
        if self.signed {
            signed(raw, &range)
        } else {
            raw as i64
        }
    }
}

/// One register field of a [`Shape`]: a run of instruction bits read as an
/// index into an `attach variables` table, so that its value names which
/// register an operand is. Only a field whose table holds distinct
/// registers of one size, read for the register alone, is one; a value the
/// table has no register for is an [exclusion](Shape::exclusions) of the
/// shape.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct RegisterField {
    /// The field's lowest bit, numbered as a [`ParamField`]'s.
    pub bit: u32,
    /// The field's width in bits, at most 8.
    pub width: u8,
    /// The table the value indexes; see
    /// [`CompiledSpec::attached_registers`](super::CompiledSpec::attached_registers).
    pub table: FieldTableId,
}

impl RegisterField {
    fn range(self) -> BitRange {
        let start = self.bit as usize;
        BitRange::new(start, start + usize::from(self.width) - 1)
    }

    /// The field's value in `bytes`, an instruction of the shape: the index
    /// into the table.
    pub fn value(self, bytes: &[u8]) -> u64 {
        extract_bytes(bytes, &self.range())
    }
}

/// A candidate pattern the decode passed over: it would have been taken had
/// it matched, so no encoding of the shape matches it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Exclusion {
    /// The instruction byte the pattern starts at.
    pub offset: usize,
    /// Per-byte masks from `offset`.
    pub mask: Box<[u8]>,
    /// What the masked bits would have to equal.
    pub value: Box<[u8]>,
}

impl Exclusion {
    /// Whether `bytes`, an instruction, matches the pattern.
    pub fn matches(&self, bytes: &[u8]) -> bool {
        bytes
            .get(self.offset..self.offset + self.mask.len())
            .is_some_and(|bytes| {
                bytes
                    .iter()
                    .zip(self.mask.iter().zip(self.value.iter()))
                    .all(|(byte, (mask, value))| byte & mask == *value)
            })
    }
}

/// Which bits of an instruction chose its constructors, which patterns it
/// escaped, and which fields are its parameters. See the [module
/// documentation](self).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Shape {
    len: usize,
    mask: Box<[u8]>,
    exclusions: Box<[Exclusion]>,
    params: Box<[ParamField]>,
    registers: Box<[RegisterField]>,
    overrun: bool,
}

impl Shape {
    /// The instruction's length in bytes.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the instruction is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// One byte per instruction byte; a set bit chose the constructors.
    pub fn mask(&self) -> &[u8] {
        &self.mask
    }

    /// The patterns of more specific candidates the decode passed over, in
    /// the order it tried them. No encoding of the shape matches any. A
    /// pattern may reach past the instruction's own bytes — the decoder
    /// tested it against what followed — so they are tested against the
    /// stream, not the instruction.
    pub fn exclusions(&self) -> &[Exclusion] {
        &self.exclusions
    }

    /// The parameter fields, in the order the decoder read them. A field
    /// may overlap the mask — a decision tree can dispatch on one bit of an
    /// immediate — and those bits are then the same in every instruction of
    /// the shape.
    pub fn params(&self) -> &[ParamField] {
        &self.params
    }

    /// The register fields, in the order the decoder read them. Two may
    /// cover the same bits — one constructor reads a field as a 32-bit
    /// register, another the same bits as its 64-bit one — and, like a
    /// parameter, a field may overlap the mask.
    pub fn registers(&self) -> &[RegisterField] {
        &self.registers
    }

    /// Whether `bytes`, a stream whose first [`len`](Self::len) bytes agree
    /// with an instruction of this shape on the mask, start an instruction
    /// of this shape: they match no exclusion. A stream too short for an
    /// exclusion to be tested does not match it, as it would not for the
    /// decoder.
    pub fn admits(&self, bytes: &[u8]) -> bool {
        bytes.len() >= self.len && !self.exclusions.iter().any(|e| e.matches(bytes))
    }

    /// Whether the decode depended on instructions past this one — a delay
    /// slot was filled, or `inst_next2` measured. The shape then does not
    /// describe what chose the constructors.
    pub fn overruns(&self) -> bool {
        self.overrun
    }

    /// `bytes` with every bit outside the mask cleared, into `out`, which
    /// must hold [`len`](Self::len) bytes.
    pub fn masked(&self, bytes: &[u8], out: &mut [u8]) {
        for ((out, byte), mask) in out.iter_mut().zip(bytes).zip(&self.mask) {
            *out = byte & mask;
        }
    }
}

/// Accumulates a [`Shape`] while a walker decodes.
#[derive(Default)]
pub(crate) struct ShapeRecorder {
    /// Bits chosen so far, growing as the walker reads further.
    mask: RefCell<Vec<u8>>,
    exclusions: RefCell<Vec<Exclusion>>,
    params: RefCell<Vec<ParamField>>,
    registers: RefCell<Vec<RegisterField>>,
    overrun: Cell<bool>,
}

impl ShapeRecorder {
    /// Marks the bits of `range`, numbered from the instruction's first byte.
    pub(crate) fn note_bits(&self, range: &BitRange) {
        let mut mask = self.mask.borrow_mut();
        let last = range.end() / 8;
        if mask.len() <= last {
            mask.resize(last + 1, 0);
        }
        for bit in range.iter() {
            mask[bit / 8] |= 1 << (bit % 8);
        }
    }

    /// Marks the bits of `bytes`, a per-byte mask starting at byte `offset`
    /// of the instruction.
    pub(crate) fn note_mask(&self, offset: usize, bytes: &[u8]) {
        let mut mask = self.mask.borrow_mut();
        if mask.len() < offset + bytes.len() {
            mask.resize(offset + bytes.len(), 0);
        }
        for (slot, byte) in mask[offset..].iter_mut().zip(bytes) {
            *slot |= byte;
        }
    }

    /// Records a candidate pattern at `offset` of the instruction that was
    /// not taken: it failed at `byte` of `mask`, or the bytes ran out
    /// before it could be tested. When the mask so far already fixes the
    /// bits it failed on, every encoding of the shape fails it the same way
    /// and nothing is kept.
    pub(crate) fn note_exclusion(
        &self,
        offset: usize,
        byte: Option<usize>,
        mask: &[u8],
        value: &[u8],
    ) {
        let fixed = byte.is_some_and(|byte| {
            self.mask
                .borrow()
                .get(offset + byte)
                .is_some_and(|fixed| fixed & mask[byte] == mask[byte])
        });
        if fixed {
            return;
        }
        let exclusion = Exclusion {
            offset,
            mask: mask.into(),
            value: value.into(),
        };
        let mut exclusions = self.exclusions.borrow_mut();
        if !exclusions.contains(&exclusion) {
            exclusions.push(exclusion);
        }
    }

    /// Records a field read for its value alone.
    pub(crate) fn note_param(&self, range: &BitRange, signed: bool) {
        let width = range.size();
        // A field wider than a `u8` counts or a `u64` holds is not a
        // parameter a caller can carry; keep it in the mask instead.
        if width == 0 || width > 64 {
            self.note_bits(range);
            return;
        }
        self.params.borrow_mut().push(ParamField {
            bit: range.start() as u32,
            width: width as u8,
            signed,
        });
    }

    /// Records a field read as an index into register table `table`, and
    /// excludes every value in `holes` — those the table has no register
    /// for — from the shape.
    pub(crate) fn note_register(
        &self,
        range: &BitRange,
        table: FieldTableId,
        holes: impl Iterator<Item = u64>,
    ) {
        let width = range.size();
        debug_assert!((1..=8).contains(&width));
        let field = RegisterField {
            bit: range.start() as u32,
            width: width as u8,
            table,
        };
        let mut registers = self.registers.borrow_mut();
        if registers.contains(&field) {
            return;
        }
        registers.push(field);
        let offset = range.start() / 8;
        let len = range.end() / 8 - offset + 1;
        for hole in holes {
            let mut mask = vec![0u8; len];
            let mut value = vec![0u8; len];
            for (i, bit) in range.iter().enumerate() {
                mask[bit / 8 - offset] |= 1 << (bit % 8);
                if hole >> i & 1 != 0 {
                    value[bit / 8 - offset] |= 1 << (bit % 8);
                }
            }
            let exclusion = Exclusion {
                offset,
                mask: mask.into(),
                value: value.into(),
            };
            let mut exclusions = self.exclusions.borrow_mut();
            if !exclusions.contains(&exclusion) {
                exclusions.push(exclusion);
            }
        }
    }

    /// Records that the decode depended on bytes past the instruction.
    pub(crate) fn note_overrun(&self) {
        self.overrun.set(true);
    }

    /// The shape of the instruction of `len` bytes the walker decoded.
    pub(crate) fn finish(self, len: usize) -> Shape {
        let mut mask = self.mask.into_inner();
        let mut overrun = self.overrun.get();
        if mask.len() > len {
            overrun |= mask[len..].iter().any(|byte| *byte != 0);
            mask.truncate(len);
        }
        mask.resize(len, 0);
        let mut params = self.params.into_inner();
        // A parameter past the end is a decode the walker abandoned; it
        // decides nothing.
        params.retain(|param| (param.bit as usize + usize::from(param.width)).div_ceil(8) <= len);
        let mut registers = self.registers.into_inner();
        registers
            .retain(|field| (field.bit as usize + usize::from(field.width)).div_ceil(8) <= len);
        let exclusions = self.exclusions.into_inner();
        Shape {
            len,
            mask: mask.into_boxed_slice(),
            exclusions: exclusions.into_boxed_slice(),
            params: params.into_boxed_slice(),
            registers: registers.into_boxed_slice(),
            overrun,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{Compiler, Decoder, SourceDb};

    /// A two-byte instruction set: an opcode byte, then a byte whose low
    /// three bits pick a register from a full table, whose next three pick
    /// one from a table with a hole, and whose top two bits are an
    /// immediate. `add` reads a register field; `set` reads an immediate;
    /// `mix` reads one of each; `pick` dispatches on the register bits.
    fn spec() -> crate::CompiledSpec {
        let mut sources = SourceDb::new();
        let root = sources.add_file(
            "regs.slaspec",
            "define endian=little;
             define space ram type=ram_space size=4 default;
             define space register type=register_space size=4;
             define register offset=0 size=4 [ r0 r1 r2 r3 r4 r5 r6 r7 ];
             define token op(8) opcode=(0,7);
             define token arg(8) ra=(0,2) rb=(3,5) rraw=(0,2) imm=(6,7);
             attach variables [ ra ] [ r0 r1 r2 r3 r4 r5 r6 r7 ];
             attach variables [ rb ] [ r0 r1 r2 r3 _ r5 r6 r7 ];
             :add ra is opcode=0; ra { ra = ra + 1; }
             :set imm is opcode=1; imm { r0 = imm; }
             :mix ra, rb is opcode=2; ra & rb { ra = rb; }
             :pick ra is opcode=3; ra & rraw=1 { ra = 1; }
             :pick ra is opcode=3; ra { ra = 2; }",
        );
        Compiler::new(&mut sources)
            .compile(root)
            .expect("the register spec compiles")
    }

    #[test]
    fn a_register_field_is_a_parameter_out_of_the_mask() {
        let spec = spec();
        let decoder = Decoder::new(&spec);
        let context = spec.new_context();
        let (_, shape) = decoder
            .decode_one_shaped(0, &[0x00, 0x05], &context)
            .expect("add r5 decodes");
        assert_eq!(shape.mask(), &[0xff, 0x00]);
        assert!(shape.params().is_empty());
        let [field] = shape.registers() else {
            panic!("one register field, not {:?}", shape.registers());
        };
        assert_eq!((field.bit, field.width), (8, 3));
        assert_eq!(field.value(&[0x00, 0x05]), 5);
        assert_eq!(
            spec.attached_registers(field.table)
                .iter()
                .map(|r| r.map(|r| spec
                    .registers()
                    .nth(usize::from(r))
                    .unwrap()
                    .name()
                    .to_owned()))
                .collect::<Vec<_>>(),
            (0..8).map(|i| Some(format!("r{i}"))).collect::<Vec<_>>()
        );
        assert!(shape.exclusions().is_empty());
    }

    #[test]
    fn a_hole_in_the_table_excludes_its_value() {
        let spec = spec();
        let decoder = Decoder::new(&spec);
        let context = spec.new_context();
        let (_, shape) = decoder
            .decode_one_shaped(0, &[0x02, 0x0a], &context)
            .expect("mix r2, r1 decodes");
        assert_eq!(shape.mask(), &[0xff, 0x00]);
        assert_eq!(shape.registers().len(), 2);
        let [hole] = shape.exclusions() else {
            panic!("one exclusion, for rb=4: {:?}", shape.exclusions());
        };
        assert_eq!(
            (hole.offset, &*hole.mask, &*hole.value),
            (1, &[0x38][..], &[0x20][..])
        );
        assert!(!shape.admits(&[0x02, 0x22]), "rb = 4 binds no register");
        assert!(shape.admits(&[0x02, 0x2a]));
        assert!(
            decoder.decode_one(0, &[0x02, 0x22], &context).is_err()
                || spec.attached_registers(shape.registers()[1].table)[4].is_none()
        );
    }

    #[test]
    fn a_register_field_a_pattern_tests_is_in_the_mask_or_excluded() {
        let spec = spec();
        let decoder = Decoder::new(&spec);
        let context = spec.new_context();
        // `pick r1` matched the constructor testing the bits: they chose.
        let (_, shape) = decoder
            .decode_one_shaped(0, &[0x03, 0x01], &context)
            .expect("pick r1 decodes");
        assert_eq!(shape.mask()[1] & 0x07, 0x07, "the bits chose a constructor");
        // `pick r2` passed that constructor over: its pattern is excluded,
        // and the field is a parameter of the other constructor's shape.
        let (_, shape) = decoder
            .decode_one_shaped(0, &[0x03, 0x02], &context)
            .expect("pick r2 decodes");
        assert_eq!(shape.mask()[1] & 0x07, 0);
        assert_eq!(shape.registers().len(), 1);
        assert!(!shape.admits(&[0x03, 0x01]));
        assert!(shape.admits(&[0x03, 0x07]));
        // An immediate is a parameter, not a register field.
        let (_, shape) = decoder
            .decode_one_shaped(0, &[0x01, 0x80], &context)
            .expect("set 2 decodes");
        assert!(shape.registers().is_empty());
        assert_eq!(shape.params().len(), 1);
    }
}
