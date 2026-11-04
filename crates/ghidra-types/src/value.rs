//! Value reads for normalized bitfield components. The selected byte order is
//! the memory buffer's order; a base integer's endian display setting does not
//! override it (BitFieldDataType.getSettingsDefinitions/getBigIntegerValue).
use std::fmt;

use crate::{BitfieldLayout, Endianness, FieldLayout, MAX_BITFIELD_BITS};

const VALUE_BYTES: usize = MAX_BITFIELD_BITS.div_ceil(8) as usize;

/// Numeric choices of AbstractIntegerDataType.getRepresentation. Character
/// encodings and enum-name lookup belong to datatype/settings consumers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum IntegerFormat {
    #[default]
    Hexadecimal,
    Decimal,
    Binary,
    Octal,
}

/// No missing memory is converted into a value. Caller-built public layout
/// records are validated, including the declared/effective width relation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum BitfieldValueError {
    #[error("invalid bitfield value layout: {0}")]
    InvalidLayout(&'static str),
    #[error("the selected field is not a bitfield")]
    NotBitfield,
    #[error("bitfield read needs {required} bytes, buffer has {available}")]
    BufferTooShort { required: u128, available: usize },
}

type Result<T> = std::result::Result<T, BitfieldValueError>;

/// An exact bit pattern and an explicit integer interpretation, up to 255 bits.
///
/// Bytes are least-significant first and unused high bits are always zero.
/// Signedness never changes these bits. Decimal formatting and `to_i64` apply
/// two's-complement interpretation; other numeric formats show the raw bits.
/// Unlike Java's Scalar/BigInteger split at 64 bits, one representation covers
/// all widths. A read allocates no heap memory and examines at most 33 bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BitfieldValue {
    bytes: [u8; VALUE_BYTES],
    bits: u8,
    signed: bool,
}

impl BitfieldLayout {
    /// Read from the beginning of this component's minimal storage, in the
    /// memory buffer's byte order, then shift and mask by this layout.
    ///
    /// The caller supplies the base's integer signedness. Ghidra's bitfield
    /// primitive-base rule uses unsigned interpretation for enums and bool,
    /// including through aliases; plain char follows the data organization.
    /// Zero-width fields produce zero without reading any buffer bytes.
    pub fn read_value(
        self,
        component: &[u8],
        endianness: Endianness,
        signed: bool,
    ) -> Result<BitfieldValue> {
        self.validate_value_layout()?;
        let mut value = BitfieldValue {
            bytes: [0; VALUE_BYTES],
            bits: self.effective_bits as u8,
            // The retained zero-width path returns Scalar(0, 0), whose
            // default signedness is true before consulting the base type.
            signed: signed || self.is_zero_width(),
        };
        if self.is_zero_width() {
            return Ok(value);
        }
        // Validation caps minimal storage at ceil((255 + 7) / 8) = 33.
        let size = self.storage_bytes as usize;
        if component.len() < size {
            return Err(BitfieldValueError::BufferTooShort {
                required: u128::from(self.storage_bytes),
                available: component.len(),
            });
        }
        for bit in 0..usize::from(value.bits) {
            let source = bit + usize::from(self.bit_offset);
            let byte = match endianness {
                Endianness::Little => source / 8,
                Endianness::Big => size - 1 - source / 8,
            };
            let set = (component[byte] >> (source % 8)) & 1;
            value.bytes[bit / 8] |= set << (bit % 8);
        }
        Ok(value)
    }

    fn validate_value_layout(self) -> Result<()> {
        let invalid = |message| BitfieldValueError::InvalidLayout(message);
        if self.declared_bits > MAX_BITFIELD_BITS {
            return Err(invalid("declared width exceeds 255 bits"));
        }
        if self.base_bytes == 0 {
            return Err(invalid("base size is zero"));
        }
        let effective = u128::from(self.declared_bits).min(8 * u128::from(self.base_bytes));
        if u128::from(self.effective_bits) != effective {
            return Err(invalid("effective width does not match the declared base"));
        }
        if self.bit_offset > 7 {
            return Err(invalid("minimal bit offset exceeds seven"));
        }
        let storage =
            u64::from((self.effective_bits + u32::from(self.bit_offset)).div_ceil(8)).max(1);
        if self.storage_bytes != storage {
            return Err(invalid("storage size is not minimal"));
        }
        Ok(())
    }
}

impl FieldLayout {
    /// Read this bitfield from a buffer beginning at its containing aggregate.
    /// The byte offset is checked before indexing; padding and other members
    /// are never read. This also works for unaligned packed components.
    ///
    /// A zero-width field reads no bytes, including when its offset lies at or
    /// beyond the buffer's end. Signedness follows `BitfieldLayout::read_value`.
    pub fn read_bitfield_value(
        self,
        aggregate: &[u8],
        endianness: Endianness,
        signed: bool,
    ) -> Result<BitfieldValue> {
        let layout = self.bitfield.ok_or(BitfieldValueError::NotBitfield)?;
        layout.validate_value_layout()?;
        let bytes = if layout.is_zero_width() {
            0
        } else {
            layout.storage_bytes
        };
        if self.bytes != bytes {
            return Err(BitfieldValueError::InvalidLayout(
                "field byte extent disagrees with bitfield storage",
            ));
        }
        if layout.is_zero_width() {
            return layout.read_value(&[], endianness, signed);
        }
        let required = u128::from(self.offset) + u128::from(layout.storage_bytes);
        let short = || BitfieldValueError::BufferTooShort {
            required,
            available: aggregate.len(),
        };
        if required > aggregate.len() as u128 {
            return Err(short());
        }
        // Each bound fits usize because the end fits the actual slice.
        let start = usize::try_from(self.offset).map_err(|_| short())?;
        let end = usize::try_from(required).map_err(|_| short())?;
        layout.read_value(&aggregate[start..end], endianness, signed)
    }
}

impl BitfieldValue {
    pub fn bit_width(self) -> u32 {
        u32::from(self.bits)
    }

    /// The requested base interpretation. Zero-width values are signed, as in
    /// the retained Scalar(0, 0) path, but have no sign bit and are never negative.
    pub fn is_signed(self) -> bool {
        self.signed
    }

    pub fn is_zero(self) -> bool {
        self.bytes.iter().all(|byte| *byte == 0)
    }

    pub fn is_negative(self) -> bool {
        self.signed && self.bits != 0 && self.bit(usize::from(self.bits) - 1)
    }

    /// The exact unsigned pattern. The slice is ceil(bit_width / 8) bytes,
    /// least-significant first, and is empty at width zero.
    pub fn unsigned_bytes_le(&self) -> &[u8] {
        &self.bytes[..usize::from(self.bits).div_ceil(8)]
    }

    /// The raw unsigned pattern if it fits, independent of signedness.
    pub fn to_u64(self) -> Option<u64> {
        as_u64(&self.bytes)
    }

    /// The interpreted integer if it fits a signed 64-bit value. Wide fields
    /// are supported too: a signed 255-bit -1 still fits i64.
    pub fn to_i64(self) -> Option<i64> {
        let magnitude = as_u64(&self.magnitude())?;
        if self.is_negative() {
            if magnitude == 1_u64 << 63 {
                Some(i64::MIN)
            } else {
                i64::try_from(magnitude).ok().map(|n| -n)
            }
        } else {
            i64::try_from(magnitude).ok()
        }
    }

    /// Numeric representation following the retained integer formatter:
    /// uppercase hex with `h`, binary with `b`, octal with `o`; decimal has no
    /// suffix. Padding applies only to nondecimal formats and uses field bits,
    /// not whole storage bytes. Negative nondecimal values show their raw bits.
    /// A zero-width field has an empty representation, as in BitFieldDataType.
    ///
    /// The result has at most 256 ASCII bytes. Padding remains defined above
    /// 64 bits rather than inheriting Java StringFormat's fixed zero-string.
    pub fn representation(self, format: IntegerFormat, padded: bool) -> String {
        if self.bits == 0 {
            return String::new();
        }
        let (radix, nominal, suffix) = match format {
            IntegerFormat::Decimal => return self.decimal(),
            IntegerFormat::Hexadecimal => (16, usize::from(self.bits).div_ceil(4), 'h'),
            IntegerFormat::Binary => (2, usize::from(self.bits), 'b'),
            IntegerFormat::Octal => (8, usize::from(self.bits).div_ceil(3), 'o'),
        };
        let digits = digits(self.bytes, radix);
        let padding = if padded {
            nominal.saturating_sub(digits.len())
        } else {
            0
        };
        let mut result = String::with_capacity(padding + digits.len() + 1);
        for _ in 0..padding {
            result.push('0');
        }
        result.push_str(&digits);
        result.push(suffix);
        result
    }

    /// BooleanDataType's nonzero test, when the caller selected a bool base.
    /// This does not infer the datatype. Zero-width fields display nothing.
    pub fn boolean_representation(self) -> &'static str {
        if self.bits == 0 {
            ""
        } else if self.is_zero() {
            "FALSE"
        } else {
            "TRUE"
        }
    }

    fn bit(self, bit: usize) -> bool {
        self.bytes[bit / 8] & (1 << (bit % 8)) != 0
    }

    fn magnitude(self) -> [u8; VALUE_BYTES] {
        let mut bytes = self.bytes;
        if self.is_negative() {
            let mut carry = 1_u16;
            for byte in &mut bytes {
                let next = u16::from(!*byte) + carry;
                *byte = next as u8;
                carry = next >> 8;
            }
            // Negation above is modulo 2^256. Keep only the declared bits.
            for bit in usize::from(self.bits)..VALUE_BYTES * 8 {
                bytes[bit / 8] &= !(1 << (bit % 8));
            }
        }
        bytes
    }

    fn decimal(self) -> String {
        let digits = digits(self.magnitude(), 10);
        if self.is_negative() {
            format!("-{digits}")
        } else {
            digits
        }
    }
}

impl fmt::Display for BitfieldValue {
    /// Decimal integer, including `0` for a zero-width field's value.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.decimal())
    }
}

fn as_u64(bytes: &[u8; VALUE_BYTES]) -> Option<u64> {
    if bytes[8..].iter().any(|byte| *byte != 0) {
        return None;
    }
    let mut low = [0; 8];
    low.copy_from_slice(&bytes[..8]);
    Some(u64::from_le_bytes(low))
}

/// Repeated base conversion on at most 32 bytes. No bigint dependency, no
/// allocation per input byte, and at most 255 * 32 small division steps.
fn digits(mut bytes: [u8; VALUE_BYTES], radix: u16) -> String {
    let mut reversed = [0; MAX_BITFIELD_BITS as usize];
    let mut count = 0;
    loop {
        let mut remainder = 0_u16;
        let mut nonzero = false;
        for byte in bytes.iter_mut().rev() {
            let next = (remainder << 8) | u16::from(*byte);
            *byte = (next / radix) as u8;
            remainder = next % radix;
            nonzero |= *byte != 0;
        }
        reversed[count] = b"0123456789ABCDEF"[usize::from(remainder)];
        count += 1;
        if !nonzero {
            break;
        }
    }
    reversed[..count]
        .iter()
        .rev()
        .map(|byte| char::from(*byte))
        .collect()
}
