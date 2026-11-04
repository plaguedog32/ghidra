//! Source index derived from preprocessed data.
//!
//! The index carries data that can only be sourced from the preprocessor:
//! includes, inactive ranges, and macro expansions.

#![cfg_attr(not(feature = "unstable-syntax"), allow(unreachable_pub))]

use crate::source::{FileId, MacroExpansion, PreparedSourceId, SourceDb, Span};

/// Include directive recorded from a physical file or preprocessing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncludeDirective {
    /// File containing the include directive.
    pub from: FileId,
    /// Resolved target file when known through preprocessing.
    pub to: Option<FileId>,
    /// Span of the directive or include path.
    pub span: Span,
}

/// Source index for source tooling.
#[derive(Debug, Clone)]
pub struct SourceIndex {
    /// Root physical file.
    pub root: FileId,
    /// Include directives, optionally resolved to target files.
    pub includes: Vec<IncludeDirective>,
    /// Source ranges disabled by current conditional preprocessing.
    pub inactive_ranges: Vec<Span>,
    /// Preprocessor `$(NAME)` substitutions with their resolved replacement text.
    pub macro_expansions: Vec<MacroExpansion>,
}

impl SourceIndex {
    /// Creates an empty index for `root`.
    pub fn new(root: FileId) -> Self {
        Self {
            root,
            includes: Vec::new(),
            inactive_ranges: Vec::new(),
            macro_expansions: Vec::new(),
        }
    }

    pub(crate) fn merge_preprocessed(&mut self, sources: &SourceDb, prepared: PreparedSourceId) {
        if let Some(edges) = sources.include_edges(prepared) {
            for edge in edges {
                let include = IncludeDirective {
                    from: edge.from,
                    to: Some(edge.to),
                    span: edge.span,
                };
                if let Some(existing) = self.includes.iter_mut().find(|existing| {
                    existing.from == include.from
                        && existing.to.is_none()
                        && span_contains(existing.span, include.span)
                }) {
                    existing.to = include.to;
                    existing.span = include.span;
                    continue;
                }

                if !self.includes.iter().any(|existing| {
                    existing.from == include.from
                        && existing.to == include.to
                        && existing.span == include.span
                }) {
                    self.includes.push(include);
                }
            }
        }

        self.inactive_ranges = sources
            .inactive_ranges(prepared)
            .unwrap_or_default()
            .to_vec();

        if let Some(expansions) = sources.macro_expansions(prepared) {
            self.macro_expansions = expansions.iter().map(|item| item.inner.clone()).collect();
        }
    }
}

fn span_contains(outer: Span, inner: Span) -> bool {
    outer.file == inner.file && outer.start <= inner.start && outer.end >= inner.end
}
