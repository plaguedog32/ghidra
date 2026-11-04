//! Pest parser for raw, physical SLEIGH source files.
//!
//! This parser intentionally does not share the main SLEIGH grammar's implicit
//! `WHITESPACE`/`COMMENT` rules. Source tooling needs trivia as real syntax so
//! formatting and future linting can preserve the original file byte-for-byte.

use pest_derive::Parser;

#[derive(Parser)]
#[grammar = "grammar/sleigh_raw.pest"]
pub(crate) struct PestRawSleighParser;

/// Marks a Pest rule as unreachable in hand-written lowering code.
macro_rules! unreachable_rule {
    ($pair: expr) => {
        unreachable!("Met rule {:?}: \"{}\"", $pair.as_rule(), $pair.as_str())
    };
}

pub(crate) use unreachable_rule;
