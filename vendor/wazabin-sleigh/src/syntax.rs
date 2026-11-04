//! Syntax-oriented analysis entry points.
//!
//! This module exposes a typed SLEIGH AST over preprocessed SLEIGH text plus
//! source provenance resolved through preprocessing metadata.

// Without `unstable-syntax` this module is crate-internal, so its public items
// are unreachable from outside by construction rather than by mistake.
#![cfg_attr(not(feature = "unstable-syntax"), allow(unreachable_pub))]

mod ast;
mod index;
pub(crate) mod lower;
pub(crate) mod parser;

// The AST is only nameable with `unstable-syntax`; without it these are the
// compiler's own front end and nothing outside the crate can reach them.
#[allow(unused_imports)]
pub use ast::{
    AlignmentDef, AttachStrDef, AttachValDef, AttachVarDef, BitRangeDef, BitRangeItem,
    ConstructorDef, ContextDef, EndiannessDef, FieldDef, MacroDef, PcodeOpDef, RegisterDef,
    SleighFile, SleighItem, SpaceDef, TokenDef, TriviaToken, UnresolvedAction,
    UnresolvedDisplayToken, UnresolvedExpr, WithBlockDef,
};
#[allow(unused_imports)]
pub use index::{IncludeDirective, SourceIndex};

use crate::raw_parsing::{PestRawSleighParser, Rule};
use crate::{
    diagnostic::{CompileError, Diagnostic, DiagnosticCode},
    resolve::resolve,
    source::{FileId, PreparedSourceId, PreprocessOptions, SourceDb, prepared_span_from_line_cols},
};
use parser::build_sleigh_ast;
use pest::Parser;

/// Shared pipeline: preprocess → Pest parse → typed AST.
///
/// Both the analysis path ([`parse`]) and the compilation path ([`crate::compile`])
/// funnel through here. All errors are returned as [`Vec<Diagnostic>`]; callers
/// that expose a different error type (e.g. [`crate::compile::CompileError`]) wrap
/// at their own boundary.
pub(crate) fn parse_to_ast(
    sources: &mut SourceDb,
    root: FileId,
    options: &PreprocessOptions,
) -> Result<(SleighFile, PreparedSourceId), Vec<Diagnostic>> {
    let prepared = sources.preprocess(root, options)?;
    let text = sources
        .prepared_text(prepared)
        .unwrap_or_default()
        .to_owned();

    let mut pairs = PestRawSleighParser::parse(Rule::sleigh_program, &text).map_err(|e| {
        let (start, end) = match &e.line_col {
            pest::error::LineColLocation::Pos(lc) => (*lc, *lc),
            pest::error::LineColLocation::Span(s, e) => (*s, *e),
        };
        vec![Diagnostic::error(
            DiagnosticCode::Parse,
            e.to_string(),
            prepared_span_from_line_cols(root, start, end),
        )]
    })?;

    let program = pairs.next().ok_or_else(|| {
        vec![Diagnostic::error(
            DiagnosticCode::Parse,
            "empty parse result",
            crate::source::Span::file_level(root),
        )]
    })?;

    let file = build_sleigh_ast(program, sources, prepared)?;
    Ok((file, prepared))
}

/// Result of analyzing a SLEIGH source file.
#[derive(Debug, Clone, Default)]
pub struct AnalysisResult {
    /// Diagnostics produced while preprocessing, parsing, and validating the file.
    pub diagnostics: Vec<Diagnostic>,

    /// Syntax index produced for source tooling.
    pub index: Option<SourceIndex>,
}

impl AnalysisResult {
    /// Returns `true` when no error diagnostics were produced.
    pub fn is_ok(&self) -> bool {
        self.diagnostics.is_empty()
    }
}

/// Result of parsing a SLEIGH source file for source tooling.
#[derive(Debug, Clone)]
pub struct ParseResult {
    /// Typed SLEIGH AST for the preprocessed root.
    pub file: SleighFile,

    /// Prepared source id used to build this result.
    pub prepared: PreparedSourceId,
}

/// Parses a source file and returns a reusable typed AST.
///
/// # Errors
///
/// Returns a [`CompileError`] if preprocessing or parsing fails. Name
/// resolution is not attempted, so unresolved references are not reported
/// here — use [`analyze`] or [`crate::Compiler::compile`] for those.
pub fn parse(sources: &mut SourceDb, root: FileId) -> Result<ParseResult, CompileError> {
    parse_with_options(sources, root, &PreprocessOptions::default())
}

/// Parses a source file with explicit preprocessing options.
pub fn parse_with_options(
    sources: &mut SourceDb,
    root: FileId,
    options: &PreprocessOptions,
) -> Result<ParseResult, CompileError> {
    let (file, prepared) = parse_to_ast(sources, root, options).map_err(CompileError::new)?;
    Ok(ParseResult { file, prepared })
}

/// Analyzes a source file and returns diagnostics without building a runtime spec.
///
/// This runs preprocess → parse → resolve → concretize, but intentionally stops
/// before the builder's p-code finalization step. That means macro
/// expansion errors will not appear here. The intended use case is source
/// tooling (hover, go-to-definition) where a partial result is more useful than
/// a hard stop on p-code expansion failures.
///
/// Use [`crate::Compiler::compile`] when you need the full error set.
pub fn analyze(sources: &mut SourceDb, root: FileId) -> AnalysisResult {
    let parsed = match parse(sources, root) {
        Ok(parsed) => parsed,
        Err(e) => {
            return AnalysisResult {
                diagnostics: e.diagnostics,
                index: None,
            };
        }
    };

    let mut index = SourceIndex::new(root);
    index.merge_preprocessed(sources, parsed.prepared);

    match resolve(&parsed.file) {
        Ok((mut builder, mut diagnostics)) => {
            match builder.concretize() {
                Ok(()) => diagnostics.extend(crate::lint::run_lints(&builder, &parsed.file)),
                Err(d) => diagnostics.push(*d),
            }
            AnalysisResult {
                diagnostics,
                index: Some(index),
            }
        }
        Err(resolve_diags) => {
            // resolve() emits diagnostics with physical-file spans — do not remap.
            AnalysisResult {
                diagnostics: resolve_diags,
                index: Some(index),
            }
        }
    }
}
