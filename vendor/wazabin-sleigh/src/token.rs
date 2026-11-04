use crate::builder::Endian;
use jstd::{Identifier, registry::Identified};
use pcode_types::RegisterId;
use serde::{Deserialize, Serialize};

/// Identifies a token — one `define token` declaration in a SLEIGH
/// specification, a fixed-width slice of the instruction stream that fields
/// are carved out of.
#[derive(Identifier)]
pub struct TokenId(usize);

/// A mutable reference to a [`Token`] with its id
pub(crate) type TokenMutRef<'b> = Identified<TokenId, &'b mut Token>;

/// A method able to provide information
/// for a token based on its id
pub(crate) trait TokenContext {
    /// The size of the token
    fn token_size(&self, id: TokenId) -> usize;

    /// The endianness of the token
    fn token_endian(&self, id: TokenId) -> Endian;

    /// The name of the token
    fn token_name(&self, id: TokenId) -> &str;
}

/// Maps a bit position within a token's *value* to its position in the
/// instruction byte stream.
///
/// A field's `(low, high)` range numbers the bits of the integer the token
/// decodes to. For a little-endian token that integer is a little-endian read
/// of its bytes, so bit *n* of the value is bit *n* of the stream and the
/// mapping is the identity.
///
/// For a big-endian token the integer is a big-endian read, which reverses
/// which byte each bit lands in while leaving the bits within a byte alone. So
/// the mapping is a **byte permutation**, not a bit reversal — for a two-byte
/// token, value bits 0..=7 live in the *second* stream byte, unreversed.
///
/// Both pattern construction and field extraction go through here so that they
/// cannot drift apart.
///
/// Positions are relative to the start of the token; callers add the token's
/// own offset within the instruction afterwards.
pub(crate) fn token_stream_bit(token_bits: usize, endian: Endian, token_bit: usize) -> usize {
    match endian {
        Endian::Little => token_bit,
        Endian::Big => {
            let bytes = token_bits / 8;
            let byte = token_bit / 8;
            // A field wider than its token is a malformed spec; leave such a
            // bit where it is rather than wrapping around.
            match bytes.checked_sub(byte + 1) {
                Some(flipped) => flipped * 8 + token_bit % 8,
                None => token_bit,
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub(crate) struct Token {
    /// Size of this token in bits
    size: crate::Size,

    /// Endianness of this token
    pub endian: Endian,

    /// The name of this token
    pub name: Box<str>,
}

impl Token {
    pub(crate) fn new(size: usize, endian: Endian, name: impl Into<Box<str>>) -> Self {
        Self {
            size: size as crate::Size,
            endian,
            name: name.into(),
        }
    }

    pub(crate) fn size(&self) -> usize {
        self.size as usize
    }
}

/// Identifies a bit-range field — one entry of a `define bitrange`
/// declaration, which names a run of bits inside a register (for instance a
/// single flag within a status register) so that semantics can read and write
/// it by name.
pub use pcode_types::BitRangeFieldId;

#[derive(Serialize, Deserialize)]
pub(crate) struct BitRangeField {
    /// The name this bit range is declared under
    pub name: Box<str>,

    /// The name of the register this bit is a part of
    pub register: RegisterId,

    /// The offset of this bit in the register
    offset: crate::Size,

    /// The size of this register in bits
    size: crate::Size,
}

impl BitRangeField {
    pub(crate) fn new(
        name: impl Into<Box<str>>,
        register: RegisterId,
        offset: usize,
        size: usize,
    ) -> Self {
        Self {
            name: name.into(),
            register,
            offset: offset as crate::Size,
            size: size as crate::Size,
        }
    }

    pub(crate) fn offset(&self) -> usize {
        self.offset as usize
    }

    pub(crate) fn size(&self) -> usize {
        self.size as usize
    }
}
