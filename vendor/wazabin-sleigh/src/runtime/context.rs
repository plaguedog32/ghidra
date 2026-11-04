use std::{error::Error, fmt};

use serde::{Deserialize, Serialize};

use crate::objects::field::FieldId;

/// Error returned when constructing or updating runtime context bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContextError {
    /// The context byte buffer has the wrong length for this specification.
    InvalidLength {
        /// Size of the specification's context register, in bytes.
        expected: usize,
        /// Size of the buffer the caller supplied, in bytes.
        actual: usize,
    },

    /// The field id does not exist in this compiled specification.
    UnknownField {
        /// The id that has no field behind it.
        field: FieldId,
    },

    /// The field exists, but it is not a context field.
    NotContextField {
        /// The offending field; it lives in a token or is a global
        /// pseudo-field such as `inst_start`, neither of which is stored in
        /// the context register.
        field: FieldId,
    },

    /// The value cannot fit in the field's bit width.
    ValueOutOfRange {
        /// The context field that was being written.
        field: FieldId,
        /// Width of that field in bits, so it holds values below `2^width`.
        width: usize,
        /// The value the caller tried to write.
        value: u64,
    },
}

impl fmt::Display for ContextError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::InvalidLength { expected, actual } => {
                write!(
                    f,
                    "invalid context length: expected {expected} bytes, got {actual}"
                )
            }
            Self::UnknownField { field } => write!(f, "unknown context field {field:?}"),

            Self::NotContextField { field } => write!(f, "field {field:?} is not a context field"),

            Self::ValueOutOfRange {
                field,
                width,
                value,
            } => write!(
                f,
                "value {value} does not fit in {width}-bit context field {field:?}"
            ),
        }
    }
}

impl Error for ContextError {}

/// Mutable decode context bytes.
///
/// Context bytes are owned so the runtime can validate their length against the
/// compiled specification before decoding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextBytes {
    pub(super) bytes: Vec<u8>,
}

impl ContextBytes {
    /// Creates a context buffer from raw bytes.
    ///
    /// Prefer [`crate::CompiledSpec::new_context`] when possible. Raw buffers
    /// are validated by [`crate::CompiledSpec::set_context_field`] and
    /// [`crate::Decoder::decode_one`].
    pub fn from_raw(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Returns the raw context bytes used by the runtime matcher.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns mutable raw context bytes for callers that need direct setup.
    pub fn as_mut_bytes(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Returns the context length in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns true when this context has no bytes.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Backward-compatible name for [`ContextBytes`].
pub type Context = ContextBytes;
