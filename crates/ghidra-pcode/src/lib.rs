//! Native p-code building blocks ported from the retained Ghidra sources.
//!
//! Opcode numbers and mnemonics match `PcodeOp.java`. This crate supplies a
//! bounded value model and structural operation validation; it is not a SLEIGH
//! compiler, instruction lifter, or complete decompiler. Validated structure is
//! not proof of a well-formed control-flow graph or correct processor semantics.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub mod eval;
mod eval_float;
pub mod machine;
pub mod model;
pub mod value;

pub use eval::evaluate_pure;
pub use model::{
    AddressSpace, Endianness, PcodeInstruction, PcodeOperation, SpaceId, SpaceKind, Varnode,
};
pub use value::Value;

/// Largest supported value or varnode width, in bytes.
pub const MAX_VALUE_SIZE: u32 = 512;

macro_rules! opcodes {
    ($( $variant:ident = $number:literal => $mnemonic:literal ),+ $(,)?) => {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[repr(u8)]
        pub enum Opcode {
            $(#[serde(rename = $mnemonic)] $variant = $number),+
        }

        impl Opcode {
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            pub const fn mnemonic(self) -> &'static str {
                match self { $(Self::$variant => $mnemonic),+ }
            }
        }

        impl TryFrom<u8> for Opcode {
            type Error = Error;

            fn try_from(value: u8) -> Result<Self, Self::Error> {
                match value {
                    $($number => Ok(Self::$variant),)+
                    _ => Err(Error::InvalidOpcode(u32::from(value))),
                }
            }
        }

        impl FromStr for Opcode {
            type Err = Error;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                match value {
                    $($mnemonic => Ok(Self::$variant),)+
                    _ => Err(Error::InvalidOpcode(u32::MAX)),
                }
            }
        }
    };
}

opcodes! {
    Unimplemented = 0 => "UNIMPLEMENTED",
    Copy = 1 => "COPY",
    Load = 2 => "LOAD",
    Store = 3 => "STORE",
    Branch = 4 => "BRANCH",
    Cbranch = 5 => "CBRANCH",
    Branchind = 6 => "BRANCHIND",
    Call = 7 => "CALL",
    Callind = 8 => "CALLIND",
    Callother = 9 => "CALLOTHER",
    Return = 10 => "RETURN",
    IntEqual = 11 => "INT_EQUAL",
    IntNotequal = 12 => "INT_NOTEQUAL",
    IntSless = 13 => "INT_SLESS",
    IntSlessequal = 14 => "INT_SLESSEQUAL",
    IntLess = 15 => "INT_LESS",
    IntLessequal = 16 => "INT_LESSEQUAL",
    IntZext = 17 => "INT_ZEXT",
    IntSext = 18 => "INT_SEXT",
    IntAdd = 19 => "INT_ADD",
    IntSub = 20 => "INT_SUB",
    IntCarry = 21 => "INT_CARRY",
    IntScarry = 22 => "INT_SCARRY",
    IntSborrow = 23 => "INT_SBORROW",
    Int2Comp = 24 => "INT_2COMP",
    IntNegate = 25 => "INT_NEGATE",
    IntXor = 26 => "INT_XOR",
    IntAnd = 27 => "INT_AND",
    IntOr = 28 => "INT_OR",
    IntLeft = 29 => "INT_LEFT",
    IntRight = 30 => "INT_RIGHT",
    IntSright = 31 => "INT_SRIGHT",
    IntMult = 32 => "INT_MULT",
    IntDiv = 33 => "INT_DIV",
    IntSdiv = 34 => "INT_SDIV",
    IntRem = 35 => "INT_REM",
    IntSrem = 36 => "INT_SREM",
    BoolNegate = 37 => "BOOL_NEGATE",
    BoolXor = 38 => "BOOL_XOR",
    BoolAnd = 39 => "BOOL_AND",
    BoolOr = 40 => "BOOL_OR",
    FloatEqual = 41 => "FLOAT_EQUAL",
    FloatNotequal = 42 => "FLOAT_NOTEQUAL",
    FloatLess = 43 => "FLOAT_LESS",
    FloatLessequal = 44 => "FLOAT_LESSEQUAL",
    FloatNan = 46 => "FLOAT_NAN",
    FloatAdd = 47 => "FLOAT_ADD",
    FloatDiv = 48 => "FLOAT_DIV",
    FloatMult = 49 => "FLOAT_MULT",
    FloatSub = 50 => "FLOAT_SUB",
    FloatNeg = 51 => "FLOAT_NEG",
    FloatAbs = 52 => "FLOAT_ABS",
    FloatSqrt = 53 => "FLOAT_SQRT",
    FloatInt2Float = 54 => "INT2FLOAT",
    FloatFloat2Float = 55 => "FLOAT2FLOAT",
    FloatTrunc = 56 => "TRUNC",
    FloatCeil = 57 => "CEIL",
    FloatFloor = 58 => "FLOOR",
    FloatRound = 59 => "ROUND",
    Multiequal = 60 => "MULTIEQUAL",
    Indirect = 61 => "INDIRECT",
    Piece = 62 => "PIECE",
    Subpiece = 63 => "SUBPIECE",
    Cast = 64 => "CAST",
    Ptradd = 65 => "PTRADD",
    Ptrsub = 66 => "PTRSUB",
    Segmentop = 67 => "SEGMENTOP",
    Cpoolref = 68 => "CPOOLREF",
    New = 69 => "NEW",
    Insert = 70 => "INSERT",
    Zpull = 71 => "ZPULL",
    Popcount = 72 => "POPCOUNT",
    Lzcount = 73 => "LZCOUNT",
    Spull = 74 => "SPULL",
}

impl TryFrom<u32> for Opcode {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self, Self::Error> {
        u8::try_from(value)
            .map_err(|_| Error::InvalidOpcode(value))
            .and_then(Self::try_from)
    }
}

impl fmt::Display for Opcode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.mnemonic())
    }
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid p-code value size {0}; expected 1..=512 bytes")]
    InvalidSize(u32),
    #[error("invalid p-code opcode {0}; slot 45 is reserved and valid codes end at 74")]
    InvalidOpcode(u32),
    #[error("{opcode} expects {expected} inputs, received {actual}")]
    InvalidArity {
        opcode: Opcode,
        expected: String,
        actual: usize,
    },
    #[error("invalid {opcode} operands: {message}")]
    InvalidOperands { opcode: Opcode, message: String },
    #[error("p-code division by zero")]
    DivisionByZero,
    #[error("p-code opcode {0} requires unsupported semantics or execution context")]
    UnsupportedOpcode(Opcode),
}

pub(crate) fn validate_size(size: u32) -> Result<(), Error> {
    if (1..=MAX_VALUE_SIZE).contains(&size) {
        Ok(())
    } else {
        Err(Error::InvalidSize(size))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_opcode_and_mnemonic_matches_retained_upstream_java() {
        let java = include_str!(
            "../../../Ghidra/Framework/SoftwareModeling/src/main/java/ghidra/program/model/pcode/PcodeOp.java"
        );
        let mut constants = 0;
        for line in java.lines() {
            let Some(declaration) = line.trim().strip_prefix("public static final int ") else {
                continue;
            };
            let (name, right) = declaration.split_once('=').unwrap();
            let number: u32 = right.split(';').next().unwrap().trim().parse().unwrap();
            if name.trim() == "PCODE_MAX" {
                continue;
            }
            let opcode = Opcode::try_from(number).unwrap();
            let case = format!("case {}:", name.trim());
            let after = java.split_once(&case).unwrap().1.trim_start();
            let expected = after
                .strip_prefix("return \"")
                .unwrap()
                .split('"')
                .next()
                .unwrap();
            assert_eq!(opcode.mnemonic(), expected);
            assert_eq!(expected.parse::<Opcode>().unwrap(), opcode);
            assert_eq!(Opcode::try_from(number as u8).unwrap(), opcode);
            constants += 1;
        }
        assert_eq!(constants, 74);
        assert_eq!(Opcode::ALL.len(), constants);
    }

    #[test]
    fn invalid_and_reserved_opcodes_cannot_be_constructed() {
        for code in [45_u32, 75, 255, 256, u32::MAX] {
            assert!(matches!(
                Opcode::try_from(code),
                Err(Error::InvalidOpcode(_))
            ));
        }
        assert!("INVALID_OP".parse::<Opcode>().is_err());
        assert!("copy".parse::<Opcode>().is_err());
        assert!(serde_json::from_str::<Opcode>("45").is_err());
        assert_eq!(
            serde_json::to_string(&Opcode::Int2Comp).unwrap(),
            "\"INT_2COMP\""
        );
    }
}
