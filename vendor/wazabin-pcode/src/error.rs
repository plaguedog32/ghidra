//! Errors raised while lowering and expanding SLEIGH p-code semantics.
//!
//! These are SLEIGH-language errors — a malformed `macro` body, an unresolvable
//! expression size — as distinct from errors about the IR a consumer builds
//! afterwards. They carry an optional byte span into the preprocessed source.

use std::{fmt::Display, ops::Range};

/// The kind of a [`PcodeError`].
#[derive(Debug, PartialEq, Eq)]
pub enum PcodeErrorTy {
    /// A bit range extends past the end of the value it indexes.
    RangeOutOfBounds {
        /// The bit range that was asked for.
        range: Range<usize>,
        /// How many bits the indexed value actually has.
        ///
        /// [`PcodeError::range_out_of_bounds`] has no size to hand and leaves
        /// this zero.
        available: usize,
    },

    /// A macro was invoked with the wrong number of arguments.
    ArgumentCountMismatch {
        /// Number of parameters in the macro's definition.
        expected: usize,
        /// Number of arguments at the call site.
        actual: usize,
    },

    /// Could not determine the size of an expression.
    UnknownSize,

    /// A macro was invoked but never defined.
    UnknownMacro(Box<str>),

    /// A macro definition contains more than one `export`.
    MultipleExports,

    /// The `export` statement is not the last statement in a macro definition.
    ExportNotLast,

    /// A statement-only construct was used where an expression was expected.
    FunctionStatement,

    /// Valid SLEIGH that this crate does not implement.
    Unsupported(Box<str>),
}

/// An error raised while lowering SLEIGH p-code, with an optional source span.
#[derive(Debug)]
pub struct PcodeError {
    /// What went wrong.
    pub ty: PcodeErrorTy,
    /// Byte range `(start, end)` into the prepared source, if available.
    pub span: Option<(usize, usize)>,
}

/// Shorthand for a result carrying a [`PcodeError`].
pub type PcodeResult<T> = std::result::Result<T, PcodeError>;

impl std::error::Error for PcodeError {}

/// Spans are diagnostic detail, not identity: two errors of the same kind
/// compare equal regardless of where they were raised.
impl PartialEq for PcodeError {
    fn eq(&self, other: &Self) -> bool {
        self.ty == other.ty
    }
}

impl Eq for PcodeError {}

impl PcodeError {
    /// Creates an error carrying a source span.
    pub fn new(ty: PcodeErrorTy, span: (usize, usize)) -> Self {
        Self {
            ty,
            span: Some(span),
        }
    }

    /// Creates an error with no source span.
    pub fn spanless(ty: PcodeErrorTy) -> Self {
        Self { ty, span: None }
    }

    /// Attaches a source span, replacing any existing one.
    pub fn with_span(mut self, span: (usize, usize)) -> Self {
        self.span = Some(span);
        self
    }

    /// A bit range that extends past the end of its subject.
    pub fn range_out_of_bounds(range: Range<usize>, span: (usize, usize)) -> Self {
        Self::new(
            PcodeErrorTy::RangeOutOfBounds {
                range,
                available: 0,
            },
            span,
        )
    }

    /// A macro invoked with the wrong number of arguments.
    pub fn argument_count_mismatch(expected: usize, actual: usize, span: (usize, usize)) -> Self {
        Self::new(
            PcodeErrorTy::ArgumentCountMismatch { expected, actual },
            span,
        )
    }

    /// An expression whose size could not be determined.
    pub fn unknown_size(span: (usize, usize)) -> Self {
        Self::new(PcodeErrorTy::UnknownSize, span)
    }

    /// A macro invoked but never defined.
    pub fn unknown_macro(name: &str, span: (usize, usize)) -> Self {
        Self::new(PcodeErrorTy::UnknownMacro(name.into()), span)
    }

    /// A macro definition containing more than one `export`.
    pub fn multiple_exports(span: (usize, usize)) -> Self {
        Self::new(PcodeErrorTy::MultipleExports, span)
    }

    /// An `export` that is not the last statement in its macro definition.
    pub fn export_not_last(span: (usize, usize)) -> Self {
        Self::new(PcodeErrorTy::ExportNotLast, span)
    }

    /// A statement-only construct used where an expression was expected.
    pub fn function_is_a_statement(span: (usize, usize)) -> Self {
        Self::new(PcodeErrorTy::FunctionStatement, span)
    }
}

impl Display for PcodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let message = match &self.ty {
            PcodeErrorTy::RangeOutOfBounds { range, available } => {
                format!("Range {range:?} is out of bounds for available size {available}")
            }

            PcodeErrorTy::ArgumentCountMismatch { expected, actual } => {
                format!("Expected {expected} arguments but got {actual}")
            }

            PcodeErrorTy::UnknownSize => {
                "Could not determine the size of this expression".to_string()
            }

            PcodeErrorTy::UnknownMacro(name) => format!("Unknown macro: {name}"),

            PcodeErrorTy::MultipleExports => {
                "A macro definition contains multiple exports".to_string()
            }

            PcodeErrorTy::ExportNotLast => {
                "The export statement is not the last statement in a macro definition".to_string()
            }

            PcodeErrorTy::FunctionStatement => {
                "Attempted to use a function as an expression, but it is a statement".to_string()
            }

            PcodeErrorTy::Unsupported(what) => what.to_string(),
        };

        if let Some((start, end)) = self.span {
            write!(f, "{message} (bytes {start}..{end})")
        } else {
            write!(f, "{message}")
        }
    }
}
