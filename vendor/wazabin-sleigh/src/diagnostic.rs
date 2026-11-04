//! Shared diagnostics for SLEIGH analysis, compilation, linting, and runtime setup.

use crate::source::{SourceDb, Span};
use std::{error::Error, fmt};

/// Severity of a diagnostic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// The operation cannot continue without correction.
    Error,
    /// The input is accepted, but likely contains a mistake.
    Warning,
    /// Informational note.
    Info,
}

/// Stable diagnostic category.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiagnosticCode {
    /// Preprocessor failure.
    Preprocess,
    /// Syntax or parse failure.
    Parse,
    /// Compile-time semantic failure.
    Compile,
    /// Lint finding.
    Lint(String),
    /// Runtime setup failure.
    Runtime,
}

/// Secondary diagnostic label for source-aware consumers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiagnosticLabel {
    /// Label span.
    pub span: Span,
    /// Label text.
    pub message: String,
}

/// Public diagnostic model used by all facade APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    /// Diagnostic severity.
    pub severity: Severity,
    /// Stable category/code.
    pub code: DiagnosticCode,
    /// Primary human-readable message.
    pub message: String,
    /// Primary source span.
    pub primary: Span,
    /// Additional source labels.
    pub labels: Vec<DiagnosticLabel>,
}

impl Diagnostic {
    /// Creates an error diagnostic.
    pub fn error(code: DiagnosticCode, message: impl Into<String>, primary: Span) -> Self {
        Self {
            severity: Severity::Error,
            code,
            message: message.into(),
            primary,
            labels: Vec::new(),
        }
    }

    /// Creates a warning diagnostic: the input is accepted, but something
    /// about it is worth saying out loud.
    pub fn warning(code: DiagnosticCode, message: impl Into<String>, primary: Span) -> Self {
        Self {
            severity: Severity::Warning,
            code,
            message: message.into(),
            primary,
            labels: Vec::new(),
        }
    }

    /// Returns the primary span for this diagnostic.
    pub fn span(&self) -> Span {
        self.primary
    }

    /// Renders this diagnostic as an annotated source snippet.
    ///
    /// Falls back to `path:line:col: message` when `sources` cannot supply the
    /// text — a diagnostic may outlive the [`SourceDb`] it came from, and one
    /// carried over from prepared text has no byte offsets to quote.
    ///
    /// ```
    /// # use sleigh::{Compiler, SourceDb};
    /// let mut sources = SourceDb::new();
    /// let root = sources.add_file("broken.slaspec", "define endian=little;\nnonsense\n");
    /// let error = Compiler::new(&mut sources).compile(root).unwrap_err();
    ///
    /// for diagnostic in error.diagnostics() {
    ///     println!("{}", diagnostic.render(&sources));
    /// }
    /// ```
    pub fn render(&self, sources: &SourceDb) -> String {
        let severity = match self.severity {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "note",
        };
        let path = sources
            .path(self.primary.file)
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| "<unknown>".to_string());
        let location = format!(
            "{path}:{}:{}",
            self.primary.start_line, self.primary.start_col
        );

        // A parse error arrives with pest's own annotated snippet already in
        // the message; quoting the line again would print it twice.
        let already_annotated = self.message.contains('\n');
        let mut out = if already_annotated {
            format!("{severity}: {location}\n{}", self.message.trim_end())
        } else {
            format!("{severity}: {}\n  --> {location}", self.message)
        };

        if let Some(line) = self.source_line(sources).filter(|_| !already_annotated) {
            let number = self.primary.start_line.to_string();
            let gutter = " ".repeat(number.len());
            let column = self.primary.start_col.saturating_sub(1);
            // A span may run past the end of its line; underline what is there.
            let width = self
                .primary
                .end_line
                .eq(&self.primary.start_line)
                .then(|| self.primary.end_col.saturating_sub(self.primary.start_col))
                .filter(|width| *width > 0)
                .unwrap_or(1)
                .min(line.len().saturating_sub(column).max(1));

            out.push_str(&format!(
                "\n{gutter} |\n{number} | {line}\n{gutter} | {}{}",
                " ".repeat(column),
                "^".repeat(width)
            ));
        }

        for label in &self.labels {
            out.push_str(&format!("\n  = {}", label.message));
        }

        out
    }

    /// The single source line the primary span starts on, if it can be found.
    fn source_line<'a>(&self, sources: &'a SourceDb) -> Option<&'a str> {
        sources
            .text(self.primary.file)?
            .lines()
            .nth(self.primary.start_line.checked_sub(1)?)
    }
}

/// Convenience alias used internally by builder, resolver, and parser functions.
pub(crate) type BuildResult<T> = Result<T, Box<Diagnostic>>;

/// Compile-time error wrapping one or more diagnostics.
#[derive(Debug, Clone)]
pub struct CompileError {
    /// Diagnostics that explain why compilation failed.
    pub diagnostics: Vec<Diagnostic>,
}

impl CompileError {
    /// Creates a compile error from a list of diagnostics.
    pub fn new(diagnostics: Vec<Diagnostic>) -> Self {
        Self { diagnostics }
    }

    /// Diagnostics that explain why compilation failed.
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    pub(crate) fn one(diagnostic: Diagnostic) -> Self {
        Self {
            diagnostics: vec![diagnostic],
        }
    }
}

impl fmt::Display for CompileError {
    /// Every diagnostic, one per line — not just the first.
    ///
    /// Messages only: `Display` has no [`SourceDb`] to quote source from. Use
    /// [`Diagnostic::render`] over [`Self::diagnostics`] for annotated
    /// snippets.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut diagnostics = self.diagnostics.iter();
        let Some(first) = diagnostics.next() else {
            return write!(f, "SLEIGH compilation failed");
        };

        write!(f, "{}", first.message)?;
        for diagnostic in diagnostics {
            write!(f, "\n{}", diagnostic.message)?;
        }
        Ok(())
    }
}

impl Error for CompileError {}
