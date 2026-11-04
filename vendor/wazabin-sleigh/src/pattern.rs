use crate::token::TokenId;
use std::fmt::Display;

mod block;
mod combined;
mod token;

#[cfg(feature = "unstable-introspect")]
pub(crate) use block::CompiledPatternBlock;
pub(crate) use block::PatternBlock;
pub(crate) use combined::{CombinedPattern, CombinedRange};
pub(crate) use combined::{CompiledCombinedPattern, PatternOutcome};
pub(crate) use token::{Alignment, OperandId, OperandType, TokenPattern};

#[derive(Debug, Clone, Copy)]
pub(crate) enum Error {
    LRellipsis,
    RLellipsis,
    MismatchedSizes(usize, usize),
    MismatchedTokens(TokenId, TokenId),
    InteriorEllipsis,
    CommonSubPattern,
}

impl std::error::Error for Error {}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::CommonSubPattern => write!(f, "Differing alignments in the same table"),
            Error::InteriorEllipsis => write!(f, "Interior ellipsis"),
            Error::LRellipsis => write!(f, "Right/Left ellipsis"),
            Error::RLellipsis => write!(f, "Left/Right ellipsis"),
            &Error::MismatchedSizes(s1, s2) => write!(f, "Mismatched pattern sizes {s1} {s2}"),
            Error::MismatchedTokens(t1, t2) => write!(
                f,
                "Mismatched tokens when combining patterns {t1:?} != {t2:?}"
            ),
        }
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
