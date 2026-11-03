//! Structural p-code model, with raw and analysis-context operations preserved.
//!
//! Validation checks local bounds, arity, output presence, and documented width
//! relationships. Resolving spaces, checking constant-operand roles, memory
//! mapping, SSA edges, and call context requires an execution/analysis context.

use std::fmt;

use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{Error, Opcode, validate_size};

pub const MAX_INPUTS: usize = 1024;
pub const MAX_OPS_PER_INSTRUCTION: usize = 16_384;
pub const MAX_SPACE_NAME_BYTES: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SpaceId(pub u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SpaceKind {
    Constant,
    Ram,
    Register,
    Unique,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AddressSpace {
    pub id: SpaceId,
    pub name: String,
    pub kind: SpaceKind,
    /// Address width in bytes. Offsets in this model are at most 64 bits.
    pub address_size: u8,
    /// Number of bytes per addressable unit.
    pub word_size: u32,
    pub endianness: Endianness,
}

impl AddressSpace {
    pub fn validate(&self) -> Result<(), Error> {
        let invalid = |message: &str| Error::InvalidOperands {
            opcode: Opcode::Unimplemented,
            message: message.into(),
        };
        if self.name.is_empty() || self.name.len() > MAX_SPACE_NAME_BYTES {
            return Err(invalid(
                "address-space name must contain 1..=256 UTF-8 bytes",
            ));
        }
        if !(1..=8).contains(&self.address_size) {
            return Err(invalid("address-space width must be 1..=8 bytes"));
        }
        if self.word_size == 0 {
            return Err(invalid("address-space word size must be nonzero"));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Varnode {
    pub space: SpaceId,
    pub offset: u64,
    pub size: u32,
}

impl Varnode {
    pub fn validate(&self) -> Result<(), Error> {
        // Constant offsets are literal bit patterns, so offset+size need not be
        // a valid address range without knowing the address-space kind.
        validate_size(self.size)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeOperation {
    pub opcode: Opcode,
    pub output: Option<Varnode>,
    #[serde(deserialize_with = "deserialize_inputs")]
    pub inputs: Vec<Varnode>,
}

impl PcodeOperation {
    pub fn validate(&self) -> Result<(), Error> {
        use Opcode::*;
        let invalid = |message: &str| Error::InvalidOperands {
            opcode: self.opcode,
            message: message.into(),
        };
        if self.inputs.len() > MAX_INPUTS {
            return Err(Error::InvalidArity {
                opcode: self.opcode,
                expected: "at most 1024".into(),
                actual: self.inputs.len(),
            });
        }
        for input in &self.inputs {
            input.validate()?;
        }
        if let Some(output) = &self.output {
            output.validate()?;
        }
        let (minimum, maximum) = match self.opcode {
            Unimplemented => (0, 0),
            Copy | Branch | Branchind | IntZext | IntSext | Int2Comp | IntNegate | BoolNegate
            | FloatNan | FloatNeg | FloatAbs | FloatSqrt | FloatInt2Float | FloatFloat2Float
            | FloatTrunc | FloatCeil | FloatFloor | FloatRound | Cast | Popcount | Lzcount => {
                (1, 1)
            }
            Store | Ptradd | Segmentop | Zpull | Spull => (3, 3),
            Insert => (4, 4),
            Call | Callind | Callother | Return | Multiequal => (1, MAX_INPUTS),
            Cpoolref => (2, MAX_INPUTS),
            New => (1, 2),
            _ => (2, 2),
        };
        if !(minimum..=maximum).contains(&self.inputs.len()) {
            return Err(Error::InvalidArity {
                opcode: self.opcode,
                expected: if minimum == maximum {
                    minimum.to_string()
                } else {
                    format!("{minimum}..={maximum}")
                },
                actual: self.inputs.len(),
            });
        }
        match self.opcode {
            Unimplemented | Store | Branch | Cbranch | Branchind | Return => {
                if self.output.is_some() {
                    return Err(invalid("this operation has no output"));
                }
            }
            // Analysis-context calls may have return values. User-defined ops
            // may have outputs even in raw p-code.
            Call | Callind | Callother => {}
            _ if self.output.is_none() => return Err(invalid("an output varnode is required")),
            _ => {}
        }
        let output_size = self.output.map_or(0, |output| output.size);
        match self.opcode {
            Copy | Cast | Int2Comp | IntNegate | Indirect | FloatNeg | FloatAbs | FloatSqrt
            | FloatCeil | FloatFloor | FloatRound => {
                if output_size != self.inputs[0].size {
                    return Err(invalid("input0 and output must have equal widths"));
                }
            }
            IntZext | IntSext => {
                if output_size <= self.inputs[0].size {
                    return Err(invalid(
                        "extension output must be strictly wider than input0",
                    ));
                }
            }
            IntEqual | IntNotequal | IntSless | IntSlessequal | IntLess | IntLessequal
            | IntCarry | IntScarry | IntSborrow | FloatEqual | FloatNotequal | FloatLess
            | FloatLessequal => {
                if self.inputs[0].size != self.inputs[1].size || output_size != 1 {
                    return Err(invalid(
                        "comparison inputs must have equal widths and output must be one byte",
                    ));
                }
            }
            IntAdd | IntSub | IntXor | IntAnd | IntOr | IntMult | IntDiv | IntSdiv | IntRem
            | IntSrem | FloatAdd | FloatDiv | FloatMult | FloatSub => {
                if self.inputs.iter().any(|input| input.size != output_size) {
                    return Err(invalid(
                        "arithmetic inputs and output must have equal widths",
                    ));
                }
            }
            IntLeft | IntRight | IntSright | Ptradd | Ptrsub | Insert => {
                if output_size != self.inputs[0].size {
                    return Err(invalid("input0 and output must have equal widths"));
                }
            }
            BoolNegate | BoolXor | BoolAnd | BoolOr => {
                if output_size != 1 || self.inputs.iter().any(|input| input.size != 1) {
                    return Err(invalid("boolean inputs and output must be one byte"));
                }
            }
            FloatNan => {
                if output_size != 1 {
                    return Err(invalid("FLOAT_NAN output must be one byte"));
                }
            }
            Cbranch => {
                if self.inputs[1].size != 1 {
                    return Err(invalid("CBRANCH condition must be one byte"));
                }
            }
            Piece => {
                if self.inputs[0].size + self.inputs[1].size != output_size {
                    return Err(invalid("PIECE input widths must sum to the output width"));
                }
            }
            Subpiece => {
                if output_size > self.inputs[0].size {
                    return Err(invalid("SUBPIECE output cannot be wider than input0"));
                }
            }
            Multiequal if self.inputs.iter().any(|input| input.size != output_size) => {
                return Err(invalid(
                    "MULTIEQUAL inputs and output must have equal widths",
                ));
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PcodeInstruction {
    pub address: u64,
    pub length: u32,
    #[serde(deserialize_with = "deserialize_ops")]
    pub ops: Vec<PcodeOperation>,
}

impl PcodeInstruction {
    pub fn validate(&self) -> Result<(), Error> {
        let invalid = |message: &str| Error::InvalidOperands {
            opcode: Opcode::Unimplemented,
            message: message.into(),
        };
        if self.length == 0
            || self
                .address
                .checked_add(u64::from(self.length) - 1)
                .is_none()
        {
            return Err(invalid(
                "instruction length must be nonzero and its final address must not overflow",
            ));
        }
        if self.ops.len() > MAX_OPS_PER_INSTRUCTION {
            return Err(invalid(
                "instruction contains more than 16384 p-code operations",
            ));
        }
        for operation in &self.ops {
            operation.validate()?;
        }
        Ok(())
    }
}

fn deserialize_inputs<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<Varnode>, D::Error> {
    deserialize_bounded_vec::<D, Varnode, MAX_INPUTS>(deserializer)
}

fn deserialize_ops<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<PcodeOperation>, D::Error> {
    deserialize_bounded_vec::<D, PcodeOperation, MAX_OPS_PER_INSTRUCTION>(deserializer)
}

fn deserialize_bounded_vec<'de, D, T, const LIMIT: usize>(
    deserializer: D,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVisitor<T, const LIMIT: usize>(std::marker::PhantomData<T>);
    impl<'de, T: Deserialize<'de>, const LIMIT: usize> Visitor<'de> for BoundedVisitor<T, LIMIT> {
        type Value = Vec<T>;
        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(formatter, "at most {LIMIT} items")
        }
        fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
            if access.size_hint().is_some_and(|size| size > LIMIT) {
                return Err(de::Error::custom("p-code sequence exceeds its item limit"));
            }
            let mut values = Vec::new();
            while let Some(value) = access.next_element()? {
                if values.len() == LIMIT {
                    return Err(de::Error::custom("p-code sequence exceeds its item limit"));
                }
                values.push(value);
            }
            Ok(values)
        }
    }
    deserializer.deserialize_seq(BoundedVisitor::<T, LIMIT>(std::marker::PhantomData))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn varnode(size: u32) -> Varnode {
        Varnode {
            space: SpaceId(2),
            offset: 0x100,
            size,
        }
    }
    fn operation(opcode: Opcode, input_sizes: &[u32], output_size: Option<u32>) -> PcodeOperation {
        PcodeOperation {
            opcode,
            output: output_size.map(varnode),
            inputs: input_sizes.iter().copied().map(varnode).collect(),
        }
    }

    #[test]
    fn arity_and_output_shapes_cover_raw_and_high_pcode() {
        for valid in [
            operation(Opcode::Copy, &[8], Some(8)),
            operation(Opcode::Store, &[4, 8, 4], None),
            operation(Opcode::Call, &[8], None),
            operation(Opcode::Call, &[8, 4, 4], Some(8)),
            operation(Opcode::Callother, &[4], None),
            operation(Opcode::Callother, &[4, 8], Some(4)),
            operation(Opcode::Return, &[8, 4, 4], None),
            operation(Opcode::Multiequal, &[8, 8, 8], Some(8)),
            operation(Opcode::Insert, &[8, 1, 4, 4], Some(8)),
            operation(Opcode::Zpull, &[8, 4, 4], Some(1)),
            operation(Opcode::Spull, &[8, 4, 4], Some(1)),
            operation(Opcode::New, &[4], Some(8)),
            operation(Opcode::New, &[4, 4], Some(8)),
            operation(Opcode::IntZext, &[1], Some(8)),
            operation(Opcode::Unimplemented, &[], None),
        ] {
            valid.validate().unwrap();
        }
        for invalid in [
            operation(Opcode::Copy, &[], Some(8)),
            operation(Opcode::Store, &[4, 8, 4], Some(4)),
            operation(Opcode::Branch, &[8], Some(8)),
            operation(Opcode::Copy, &[8], None),
            operation(Opcode::Copy, &[1], Some(8)),
            operation(Opcode::IntZext, &[8], Some(8)),
            operation(Opcode::IntSext, &[8], Some(4)),
            operation(Opcode::BoolAnd, &[8, 8], Some(1)),
            operation(Opcode::IntEqual, &[4, 4], Some(4)),
            operation(Opcode::Multiequal, &[4, 8], Some(8)),
            operation(Opcode::Insert, &[8, 4, 4], Some(8)),
            operation(Opcode::Cbranch, &[8, 8], None),
            operation(Opcode::Piece, &[4, 4], Some(4)),
            operation(Opcode::New, &[4, 4, 4], Some(8)),
        ] {
            assert!(invalid.validate().is_err(), "accepted {invalid:?}");
        }
    }

    #[test]
    fn space_varnode_and_instruction_bounds_are_explicit() {
        let mut space = AddressSpace {
            id: SpaceId(1),
            name: "ram".into(),
            kind: SpaceKind::Ram,
            address_size: 8,
            word_size: 1,
            endianness: Endianness::Little,
        };
        space.validate().unwrap();
        space.word_size = 0;
        assert!(space.validate().is_err());
        space.word_size = 1;
        space.address_size = 9;
        assert!(space.validate().is_err());
        assert!(varnode(0).validate().is_err());
        assert!(varnode(513).validate().is_err());
        Varnode {
            space: SpaceId(0),
            offset: u64::MAX,
            size: 8,
        }
        .validate()
        .unwrap();
        let mut instruction = PcodeInstruction {
            address: u64::MAX,
            length: 1,
            ops: vec![],
        };
        instruction.validate().unwrap();
        instruction.length = 2;
        assert!(instruction.validate().is_err());
        instruction.length = 0;
        assert!(instruction.validate().is_err());
    }

    #[test]
    fn serde_sequence_budgets_are_enforced_before_growing_unbounded_vectors() {
        let too_many_inputs = PcodeOperation {
            opcode: Opcode::Call,
            output: None,
            inputs: vec![varnode(8); MAX_INPUTS + 1],
        };
        assert!(too_many_inputs.validate().is_err());
        let json = serde_json::to_vec(&too_many_inputs).unwrap();
        assert!(serde_json::from_slice::<PcodeOperation>(&json).is_err());
        let too_many_ops = PcodeInstruction {
            address: 0,
            length: 1,
            ops: vec![operation(Opcode::Unimplemented, &[], None); MAX_OPS_PER_INSTRUCTION + 1],
        };
        assert!(too_many_ops.validate().is_err());
        let json = serde_json::to_vec(&too_many_ops).unwrap();
        assert!(serde_json::from_slice::<PcodeInstruction>(&json).is_err());
    }
}
