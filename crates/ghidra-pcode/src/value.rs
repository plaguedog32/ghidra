//! Bounded, fixed-width unsigned storage with two's-complement signed views.

use std::fmt;

use num_bigint::{BigInt, BigUint};
use num_traits::{One, ToPrimitive};
use serde::de::{self, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{Error, MAX_VALUE_SIZE, validate_size};

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Value {
    pub(crate) size: u32,
    pub(crate) bits: BigUint,
}

impl Value {
    /// Wraps `bits` modulo the requested width. Width is checked before shifting.
    pub fn new(size: u32, bits: BigUint) -> Result<Self, Error> {
        validate_size(size)?;
        let mask = (BigUint::one() << (size * 8) as usize) - BigUint::one();
        Ok(Self {
            size,
            bits: bits & mask,
        })
    }

    pub fn from_u64(size: u32, value: u64) -> Result<Self, Error> {
        Self::new(size, BigUint::from(value))
    }

    pub fn from_le_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let size = u32::try_from(bytes.len()).map_err(|_| Error::InvalidSize(u32::MAX))?;
        validate_size(size)?;
        Ok(Self {
            size,
            bits: BigUint::from_bytes_le(bytes),
        })
    }

    pub fn from_be_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let size = u32::try_from(bytes.len()).map_err(|_| Error::InvalidSize(u32::MAX))?;
        validate_size(size)?;
        Ok(Self {
            size,
            bits: BigUint::from_bytes_be(bytes),
        })
    }

    pub fn size(&self) -> u32 {
        self.size
    }

    pub fn bits(&self) -> &BigUint {
        &self.bits
    }

    pub fn to_le_bytes(&self) -> Vec<u8> {
        let mut bytes = self.bits.to_bytes_le();
        bytes.resize(self.size as usize, 0);
        bytes
    }

    pub fn to_be_bytes(&self) -> Vec<u8> {
        let mut bytes = self.to_le_bytes();
        bytes.reverse();
        bytes
    }

    pub fn to_u64(&self) -> Option<u64> {
        self.bits.to_u64()
    }

    pub fn signed(&self) -> BigInt {
        let bits = BigInt::from(self.bits.clone());
        if self.bits.bit(u64::from(self.size) * 8 - 1) {
            bits - (BigInt::one() << (self.size * 8) as usize)
        } else {
            bits
        }
    }
}

// BigUint's serde representation is a sequence of little-endian u32 digits.
// Deserializing it directly would allocate an unbounded attacker-provided Vec.
struct BoundedBits(BigUint);

impl<'de> Deserialize<'de> for BoundedBits {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct BitsVisitor;
        impl<'de> Visitor<'de> for BitsVisitor {
            type Value = BoundedBits;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("at most 128 canonical little-endian u32 digits")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut access: A) -> Result<Self::Value, A::Error> {
                let limit = (MAX_VALUE_SIZE / 4) as usize;
                if access.size_hint().is_some_and(|size| size > limit) {
                    return Err(de::Error::custom("p-code value exceeds 512 bytes"));
                }
                let mut digits = Vec::new();
                while let Some(digit) = access.next_element::<u32>()? {
                    if digits.len() == limit {
                        return Err(de::Error::custom("p-code value exceeds 512 bytes"));
                    }
                    digits.push(digit);
                }
                if digits.last() == Some(&0) {
                    return Err(de::Error::custom("noncanonical high zero digit"));
                }
                Ok(BoundedBits(BigUint::new(digits)))
            }
        }
        deserializer.deserialize_seq(BitsVisitor)
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct EncodedValue {
            size: u32,
            bits: BoundedBits,
        }
        let encoded = EncodedValue::deserialize(deserializer)?;
        validate_size(encoded.size).map_err(de::Error::custom)?;
        if encoded.bits.0.bits() > u64::from(encoded.size) * 8 {
            return Err(de::Error::custom("value bits exceed the declared width"));
        }
        Ok(Self {
            size: encoded.size,
            bits: encoded.bits.0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_wrap_and_signed_views_cover_width_extremes() {
        assert_eq!(Value::from_u64(1, 256).unwrap().to_u64(), Some(0));
        assert_eq!(Value::from_u64(1, 255).unwrap().signed(), BigInt::from(-1));
        assert_eq!(
            Value::from_u64(1, 128).unwrap().signed(),
            BigInt::from(-128)
        );
        assert_eq!(Value::from_u64(1, 127).unwrap().signed(), BigInt::from(127));
        let big = Value::from_le_bytes(&[0xff; 512]).unwrap();
        assert_eq!(big.signed(), BigInt::from(-1));
        assert!(big.to_u64().is_none());
        assert_eq!(big.to_le_bytes(), [0xff; 512]);
        let minimum = Value::new(512, BigUint::one() << 4095_usize).unwrap();
        assert_eq!(minimum.signed(), -(BigInt::one() << 4095_usize));
        let wrapped = Value::new(512, BigUint::one() << 4096_usize).unwrap();
        assert_eq!(wrapped.to_u64(), Some(0));
    }

    #[test]
    fn endian_conversions_preserve_width_including_zero_padding() {
        let value = Value::from_le_bytes(&[0x78, 0x56, 0x34, 0x12, 0, 0]).unwrap();
        assert_eq!(value.to_u64(), Some(0x12345678));
        assert_eq!(value.to_le_bytes(), [0x78, 0x56, 0x34, 0x12, 0, 0]);
        assert_eq!(value.to_be_bytes(), [0, 0, 0x12, 0x34, 0x56, 0x78]);
        assert_eq!(Value::from_be_bytes(&value.to_be_bytes()).unwrap(), value);
        assert_eq!(Value::from_u64(8, 0).unwrap().to_le_bytes(), [0; 8]);
    }

    #[test]
    fn invalid_widths_and_oversized_input_are_rejected_before_conversion() {
        for size in [0, MAX_VALUE_SIZE + 1, u32::MAX] {
            assert!(matches!(
                Value::from_u64(size, 1),
                Err(Error::InvalidSize(_))
            ));
        }
        assert!(Value::from_le_bytes(&[]).is_err());
        assert!(Value::from_le_bytes(&[0; 513]).is_err());
        assert!(Value::from_be_bytes(&[0; 513]).is_err());
    }

    #[test]
    fn serde_enforces_width_canonical_bits_and_allocation_bound() {
        for value in [
            Value::from_u64(1, 0).unwrap(),
            Value::from_u64(8, u64::MAX).unwrap(),
            Value::from_le_bytes(&[0xab; 512]).unwrap(),
        ] {
            let serialized = serde_json::to_string(&value).unwrap();
            assert_eq!(serde_json::from_str::<Value>(&serialized).unwrap(), value);
        }
        for json in [
            r#"{"size":0,"bits":[]}"#,
            r#"{"size":513,"bits":[]}"#,
            r#"{"size":1,"bits":[256]}"#,
            r#"{"size":1,"bits":[1,0]}"#,
            r#"{"size":1,"bits":[1],"extra":0}"#,
            r#"{"size":1,"size":2,"bits":[1]}"#,
        ] {
            assert!(
                serde_json::from_str::<Value>(json).is_err(),
                "accepted {json}"
            );
        }
        let digits = std::iter::repeat_n("1", 129).collect::<Vec<_>>().join(",");
        assert!(
            serde_json::from_str::<Value>(&format!(r#"{{"size":512,"bits":[{digits}]}}"#)).is_err()
        );
    }
}
