//! Source ownership and stable source locations for SLEIGH tooling.
//!
//! [`SourceDb`] is the public owner for SLEIGH source text.  Library entry
//! points take [`FileId`] handles instead of borrowed source strings so callers
//! do not need to leak or otherwise pin source text to compile a specification.

mod preprocess;

use std::{
    collections::{BTreeMap, HashMap},
    error::Error,
    fmt, fs, io,
    ops::Range,
    path::{Path, PathBuf},
    sync::Arc,
};

use crate::diagnostic::Diagnostic;
use jstd::{Identifier, registry::Registry};

/// Stable identifier for a file stored in a [`SourceDb`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FileId(usize);

impl FileId {
    pub(crate) fn index(self) -> usize {
        self.0
    }

    pub(crate) fn from_index(index: usize) -> Self {
        Self(index)
    }
}

/// Zero-based byte offset within a source file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BytePos(pub usize);

/// A concrete physical source-file location.
///
/// `Span` is the public source-location type. It always names a physical
/// [`FileId`], carries zero-based byte bounds for slicing, and carries
/// one-based line/column endpoints for diagnostics and editor integrations.
/// Internal preprocessing coordinates are mapped into `Span` before crossing
/// public source APIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    /// File that contains this span.
    pub file: FileId,
    /// Zero-based start byte.
    pub start: BytePos,
    /// Zero-based exclusive end byte.
    pub end: BytePos,
    /// One-based start line.
    pub start_line: usize,
    /// One-based start column.
    pub start_col: usize,
    /// One-based end line.
    pub end_line: usize,
    /// One-based end column.
    pub end_col: usize,
}

impl Span {
    /// Creates a span from line/column endpoints when byte offsets are not
    /// available in the same coordinate space.
    ///
    /// This is used only as a temporary carrier for diagnostics produced
    /// against prepared text before they are mapped back to physical source.
    pub(crate) fn from_line_cols(file: FileId, start: (usize, usize), end: (usize, usize)) -> Self {
        Self {
            file,
            start: BytePos(0),
            end: BytePos(0),
            start_line: start.0,
            start_col: start.1,
            end_line: end.0,
            end_col: end.1,
        }
    }

    /// Creates a placeholder span with no meaningful source location.
    ///
    /// Used inside builder methods that produce diagnostics before the caller
    /// has a chance to attach a real span. Callers in the resolver always
    /// overwrite `diagnostic.primary` with a real span immediately after.
    pub(crate) fn sentinel() -> Self {
        Self {
            file: FileId(0),
            start: BytePos(0),
            end: BytePos(0),
            start_line: 0,
            start_col: 0,
            end_line: 0,
            end_col: 0,
        }
    }

    /// Creates a file-level span pointing at byte 0 of `file`.
    ///
    /// Used as a last-resort span when no finer location is available (e.g.
    /// catastrophic parse failure before any tokens are produced).
    pub fn file_level(file: FileId) -> Self {
        Self {
            file,
            start: BytePos(0),
            end: BytePos(0),
            start_line: 1,
            start_col: 1,
            end_line: 1,
            end_col: 1,
        }
    }

    /// Creates a physical source span from byte coordinates and line/column
    /// endpoints.
    pub fn from_parts(
        file: FileId,
        start: BytePos,
        end: BytePos,
        start_line_col: (usize, usize),
        end_line_col: (usize, usize),
    ) -> Self {
        Self {
            file,
            start,
            end,
            start_line: start_line_col.0,
            start_col: start_line_col.1,
            end_line: end_line_col.0,
            end_col: end_line_col.1,
        }
    }
}

#[derive(Debug, Clone)]
struct SourceFile {
    path: PathBuf,
    text: Box<str>,
    line_starts: Vec<usize>,
}

impl SourceFile {
    fn new(path: PathBuf, text: String) -> Self {
        let line_starts = line_starts(&text);
        Self {
            path,
            text: text.into_boxed_str(),
            line_starts,
        }
    }
}

/// Stable identifier for a preprocessed source owned by [`SourceDb`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PreparedSourceId(usize);

impl PreparedSourceId {
    fn index(self) -> usize {
        self.0
    }
}

/// An include edge resolved by the source database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncludeEdge {
    /// File containing the include directive.
    pub from: FileId,
    /// File included by the directive.
    pub to: FileId,
    /// Span of the include path in the including file.
    pub span: Span,
}

/// Mapping from one line of preprocessed output to the original source line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LineMapping {
    /// One-based line in the preprocessed output.
    pub generated_line: usize,
    /// Original file.
    pub source_file: FileId,
    /// One-based line in the original file.
    pub source_line: usize,
}

/// Stable identifier for a macro substitution emitted during preprocessing.
#[derive(Identifier)]
pub struct MacroExpansionId(pub(crate) usize);

/// Stable identifier for a macro definition seen during preprocessing.
#[derive(Identifier)]
pub struct MacroDefinitionId(pub(crate) usize);

/// Provenance class for generated preprocessed bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceOrigin {
    /// Bytes copied directly from active source text.
    Source,
    /// Bytes were produced by a `$(NAME)` substitution.
    MacroExpansion(MacroExpansionId),
}

/// Provenance for an active `@define` directive seen during preprocessing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroDefinition {
    /// Macro name without directive syntax.
    pub name: String,
    /// Replacement text after preprocessing directive parsing.
    pub value: String,
    /// Span of the physical `@define` line.
    pub span: Span,
}

/// Mapping from generated preprocessed bytes back to original source.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SourceMapSegment {
    /// Byte range in the generated preprocessed buffer.
    pub generated: Range<usize>,
    /// Original source span that caused these generated bytes.
    pub source: Span,
    /// Provenance class for this segment.
    pub origin: SourceOrigin,
}

/// Provenance for a `$(NAME)` substitution inside an active source line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroExpansion {
    /// Macro name without `$(` and `)`.
    pub name: String,
    /// Span of the macro use in the original physical file.
    pub use_span: Span,
    /// Replacement text inserted into the generated line.
    pub replacement: String,
    /// Byte range in the complete generated preprocessed buffer.
    pub(crate) generated_range: Range<usize>,
    /// Span of the active `@define`, if known.
    pub definition: Option<Span>,
    /// Id of the active `@define`, if it came from source text.
    pub definition_id: Option<MacroDefinitionId>,
}

/// Error returned when a physical source file cannot be formatted from
/// preprocessing metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FormatError {
    /// No prepared source contains reconstruction records for this file.
    MissingMetadata {
        /// The file that could not be reconstructed.
        file: FileId,
    },
    /// Reconstruction records exist but cannot form one coherent file.
    IncompleteMetadata {
        /// The file that could not be reconstructed.
        file: FileId,
    },
}

impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingMetadata { file } => {
                write!(f, "missing preprocessing metadata for {file}")
            }
            Self::IncompleteMetadata { file } => {
                write!(f, "incomplete preprocessing metadata for {file}")
            }
        }
    }
}

impl Error for FormatError {}

/// Role of one physical source line during preprocessing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatLineKind {
    /// A non-directive line emitted into the prepared source.
    ActiveSource,
    /// A preprocessing directive line.
    Directive,
    /// A non-directive line skipped by an inactive conditional branch.
    InactiveBranch,
}

/// Role of one line chunk in the prepared output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FormatChunkKind {
    /// Text copied directly from a physical source line.
    Direct,
    /// Text produced by a macro substitution at the original source span.
    MacroUse(MacroExpansionId),
}

/// Lossless formatting chunk for one physical line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatChunk {
    /// Original source span for this chunk.
    pub source: Span,
    /// Exact original text for this chunk.
    pub text: String,
    /// Generated byte range when the chunk contributes to prepared text.
    pub(crate) generated: Option<Range<usize>>,
    /// Chunk role.
    pub kind: FormatChunkKind,
}

/// Lossless formatting record for one physical source line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatLine {
    /// Physical file containing this line.
    pub file: FileId,
    /// One-based physical line number.
    pub line: usize,
    /// Exact original line span, including the trailing newline if present.
    pub span: Span,
    /// Exact original line text, including the trailing newline if present.
    pub text: String,
    /// How preprocessing handled this line.
    pub kind: FormatLineKind,
    /// Generated byte range when this line contributes to prepared text.
    pub(crate) generated: Option<Range<usize>>,
    /// Chunk-level source/generation metadata for active source text.
    pub chunks: Vec<FormatChunk>,
}

/// Preprocessor options.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PreprocessOptions {
    /// Macro definitions available before the root file is processed.
    pub defines: HashMap<String, String>,
}

#[derive(Debug, Clone)]
struct PreparedSource {
    root: FileId,
    text: Arc<str>,
    line_map: Vec<LineMapping>,
    line_start_bytes: Vec<usize>,
    source_map: Vec<SourceMapSegment>,
    format_lines: Vec<FormatLine>,
    include_edges: Vec<IncludeEdge>,
    inactive_ranges: Vec<Span>,
    macro_definitions: Registry<MacroDefinitionId, MacroDefinition>,
    macro_expansions: Registry<MacroExpansionId, MacroExpansion>,
}

/// Owned collection of SLEIGH source files.
///
/// The database assigns stable [`FileId`] handles for the lifetime of the
/// database.  Compile and analysis entry points use those handles to keep
/// public APIs owned and source-aware.
#[derive(Debug, Default, Clone)]
pub struct SourceDb {
    files: Vec<SourceFile>,
    prepared: Vec<PreparedSource>,
}

impl SourceDb {
    /// Creates an empty source database.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a source file and returns its stable id.
    pub fn add_file(&mut self, path: impl Into<PathBuf>, text: impl Into<String>) -> FileId {
        let id = FileId(self.files.len());
        self.files.push(SourceFile::new(path.into(), text.into()));
        id
    }

    /// Reads one file from disk into the database.
    pub fn add_file_from_path(&mut self, path: impl Into<PathBuf>) -> io::Result<FileId> {
        let path = path.into();
        if let Some(id) = self.file_by_path(&path) {
            return Ok(id);
        }

        let text = fs::read_to_string(&path)?;
        Ok(self.add_file(path, text))
    }

    /// Returns the path recorded for `file`.
    pub fn path(&self, file: FileId) -> Option<&Path> {
        self.files.get(file.index()).map(|file| file.path.as_path())
    }

    /// Returns the source text recorded for `file`.
    pub fn text(&self, file: FileId) -> Option<&str> {
        self.files.get(file.index()).map(|file| file.text.as_ref())
    }

    /// Returns both path and source text for `file`.
    pub(crate) fn file(&self, file: FileId) -> Option<(&Path, &str)> {
        self.files
            .get(file.index())
            .map(|file| (file.path.as_path(), file.text.as_ref()))
    }

    /// Returns a byte-based span for `file`.
    pub fn span(&self, file: FileId, start: BytePos, end: BytePos) -> Option<Span> {
        let source = self.files.get(file.index())?;
        Some(Span::from_parts(
            file,
            start,
            end,
            line_col(source, start.0),
            line_col(source, end.0),
        ))
    }

    /// Returns the span covering one complete one-based line.
    pub fn line_span(&self, file: FileId, line: usize) -> Option<Span> {
        let source = self.files.get(file.index())?;
        if line == 0 || line > source.line_starts.len() {
            return None;
        }

        let start = source.line_starts[line - 1];
        let end = if line < source.line_starts.len() {
            source.line_starts[line] - 1
        } else {
            source.text.len()
        };
        self.span(file, BytePos(start), BytePos(end))
    }

    /// Converts one-based line/column endpoints to a physical source span.
    pub fn span_from_line_cols(
        &self,
        file: FileId,
        start_line_col: (usize, usize),
        end_line_col: (usize, usize),
    ) -> Option<Span> {
        let start = byte_for_line_col(
            self.files.get(file.index())?,
            start_line_col.0,
            start_line_col.1,
        )?;
        let end = byte_for_line_col(
            self.files.get(file.index())?,
            end_line_col.0,
            end_line_col.1,
        )?;
        Some(Span::from_parts(
            file,
            BytePos(start),
            BytePos(end),
            start_line_col,
            end_line_col,
        ))
    }

    /// Finds a file by display path.
    pub fn file_by_path(&self, path: &Path) -> Option<FileId> {
        self.files
            .iter()
            .position(|file| file.path == path)
            .map(FileId)
    }

    /// Preprocesses `root` through source-database include resolution.
    pub fn preprocess(
        &mut self,
        root: FileId,
        options: &PreprocessOptions,
    ) -> Result<PreparedSourceId, Vec<Diagnostic>> {
        let mut preprocessor = preprocess::Preprocessor::new(self, options);
        preprocessor.preprocess_file(root);
        let preprocess::Preprocessor {
            output,
            line_map,
            source_map,
            format_lines,
            include_edges,
            inactive_ranges,
            macro_definitions,
            macro_expansions,
            diagnostics,
            ..
        } = preprocessor;

        if !diagnostics.is_empty() {
            return Err(diagnostics);
        }

        let line_start_bytes = line_starts(&output);
        let id = PreparedSourceId(self.prepared.len());
        self.prepared.push(PreparedSource {
            root,
            text: Arc::from(output.as_str()),
            line_map,
            line_start_bytes,
            source_map,
            format_lines,
            include_edges,
            inactive_ranges,
            macro_definitions,
            macro_expansions,
        });
        Ok(id)
    }

    /// Returns preprocessed text by id.
    pub(crate) fn prepared_text(&self, id: PreparedSourceId) -> Option<&str> {
        self.prepared
            .get(id.index())
            .map(|source| source.text.as_ref())
    }

    /// Returns the root file for a preprocessed source.
    pub fn prepared_root(&self, id: PreparedSourceId) -> Option<FileId> {
        self.prepared.get(id.index()).map(|source| source.root)
    }

    /// Returns include edges for a preprocessed source.
    pub fn include_edges(&self, id: PreparedSourceId) -> Option<&[IncludeEdge]> {
        self.prepared
            .get(id.index())
            .map(|source| source.include_edges.as_slice())
    }

    /// Returns inactive conditional ranges for a preprocessed source.
    pub fn inactive_ranges(&self, id: PreparedSourceId) -> Option<&[Span]> {
        self.prepared
            .get(id.index())
            .map(|source| source.inactive_ranges.as_slice())
    }

    /// Returns line mappings for a preprocessed source.
    #[cfg(test)]
    pub(crate) fn line_map(&self, id: PreparedSourceId) -> Option<&[LineMapping]> {
        self.prepared
            .get(id.index())
            .map(|source| source.line_map.as_slice())
    }

    #[cfg(test)]
    pub(crate) fn source_map(&self, id: PreparedSourceId) -> Option<&[SourceMapSegment]> {
        self.prepared
            .get(id.index())
            .map(|source| source.source_map.as_slice())
    }

    /// Returns macro substitutions emitted into a preprocessed source.
    pub fn macro_expansions(
        &self,
        id: PreparedSourceId,
    ) -> Option<&Registry<MacroExpansionId, MacroExpansion>> {
        self.prepared
            .get(id.index())
            .map(|source| &source.macro_expansions)
    }

    /// Returns macro definitions seen during preprocessing.
    pub fn macro_definitions(
        &self,
        id: PreparedSourceId,
    ) -> Option<&Registry<MacroDefinitionId, MacroDefinition>> {
        self.prepared
            .get(id.index())
            .map(|source| &source.macro_definitions)
    }

    /// Returns physical-line reconstruction metadata for a preprocessed source.
    pub fn format_lines(&self, id: PreparedSourceId) -> Option<&[FormatLine]> {
        self.prepared
            .get(id.index())
            .map(|source| source.format_lines.as_slice())
    }

    /// Formats one physical source file from preprocessing metadata.
    ///
    /// This initial formatter is intentionally identity-only: it reconstructs
    /// the original physical file from recorded line/chunk metadata. It never
    /// falls back to returning the owned source text directly.
    ///
    /// # Errors
    ///
    /// Returns a [`FormatError`] if `file` has no recorded formatting metadata
    /// — it was never preprocessed, or was skipped by an inactive `@if`.
    pub fn format(&self, file: FileId) -> Result<String, FormatError> {
        let Some(records) = self.prepared.iter().rev().find_map(|prepared| {
            let records = prepared
                .format_lines
                .iter()
                .filter(|line| line.file == file)
                .collect::<Vec<_>>();
            (!records.is_empty()).then_some(records)
        }) else {
            return Err(FormatError::MissingMetadata { file });
        };

        let mut by_line: BTreeMap<usize, &FormatLine> = BTreeMap::new();
        for record in records {
            if let Some(existing) = by_line.insert(record.line, record)
                && existing.text != record.text
            {
                return Err(FormatError::IncompleteMetadata { file });
            }
        }

        let mut formatted = String::new();
        for (expected_line, (line, record)) in (1..).zip(by_line) {
            if line != expected_line {
                return Err(FormatError::IncompleteMetadata { file });
            }
            formatted.push_str(&record.text);
        }

        Ok(formatted)
    }

    /// Maps a preprocessed byte range back to the original source.
    ///
    /// # Panics
    ///
    /// Panics if the byte range cannot be mapped. This indicates a bug in the
    /// preprocessor — for example a token straddling a macro expansion
    /// boundary — rather than bad input. Use
    /// [`Self::try_map_preprocessed_bytes`] when `None` is a legitimate
    /// outcome.
    pub fn map_preprocessed_bytes(
        &self,
        id: PreparedSourceId,
        start_byte: usize,
        end_byte: usize,
    ) -> Span {
        self.try_map_preprocessed_bytes(id, start_byte, end_byte)
            .unwrap_or_else(|| {
                panic!(
                    "failed to map prepared-source bytes {start_byte}..{end_byte} back to \
                     physical source — preprocessor produced an unmappable token boundary"
                )
            })
    }

    /// Maps a preprocessed byte range back to the original source, returning
    /// `None` when the range cannot be mapped (e.g. macro expansion boundary).
    pub fn try_map_preprocessed_bytes(
        &self,
        id: PreparedSourceId,
        start_byte: usize,
        end_byte: usize,
    ) -> Option<Span> {
        let prepared = self.prepared.get(id.index())?;
        if let Some(span) = self.map_preprocessed_bytes_via_segments(prepared, start_byte, end_byte)
        {
            return Some(span);
        }
        let lsb = &prepared.line_start_bytes;

        let start_li = lsb.partition_point(|&s| s <= start_byte).saturating_sub(1);
        let end_search = if end_byte > start_byte {
            end_byte - 1
        } else {
            start_byte
        };
        let end_li = lsb.partition_point(|&s| s <= end_search).saturating_sub(1);

        let start_col = start_byte - lsb[start_li] + 1;
        let mut end_col = end_byte - lsb[end_li] + 1;
        if start_li == end_li && end_col == start_col {
            end_col += 1;
        }

        let start_m = prepared.line_map.get(start_li)?;
        let end_m = prepared.line_map.get(end_li).unwrap_or(start_m);

        self.span_from_line_cols(
            start_m.source_file,
            (start_m.source_line, start_col),
            (end_m.source_line, end_col),
        )
    }

    fn map_preprocessed_bytes_via_segments(
        &self,
        prepared: &PreparedSource,
        start_byte: usize,
        end_byte: usize,
    ) -> Option<Span> {
        let end_search = if end_byte > start_byte {
            end_byte - 1
        } else {
            start_byte
        };

        let start_segment = segment_containing(&prepared.source_map, start_byte)?;
        let end_segment = segment_containing(&prepared.source_map, end_search)?;

        if start_segment.source.file != end_segment.source.file {
            return Some(start_segment.source);
        }

        if start_segment.generated == end_segment.generated
            && matches!(start_segment.origin, SourceOrigin::MacroExpansion(_))
        {
            return Some(start_segment.source);
        }

        let source_start = mapped_source_byte(start_segment, start_byte);
        let source_end = if end_byte > start_byte {
            mapped_source_byte(end_segment, end_byte).max(source_start + 1)
        } else {
            source_start + 1
        };

        self.span(
            start_segment.source.file,
            BytePos(source_start),
            BytePos(source_end),
        )
        .or(Some(start_segment.source))
    }

    /// Iterates over files in insertion order.
    pub fn files(&self) -> impl Iterator<Item = (FileId, &Path, &str)> {
        self.files
            .iter()
            .enumerate()
            .map(|(idx, file)| (FileId(idx), file.path.as_path(), file.text.as_ref()))
    }
}

/// Builds a temporary prepared-text span from Pest line/column endpoints.
///
/// The returned span carries zero byte offsets and must be remapped to a
/// physical source span via [`SourceDb::map_preprocessed_span`] before
/// crossing any public API boundary.
pub(crate) fn prepared_span_from_line_cols(
    file: FileId,
    start: (usize, usize),
    end: (usize, usize),
) -> Span {
    let (start_line, start_col) = start;
    let (mut end_line, mut end_col) = end;

    if (start_line, start_col) == (end_line, end_col) {
        end_col += 1;
    }

    if end_line == 0 {
        end_line = start_line;
    }

    Span::from_line_cols(file, (start_line, start_col), (end_line, end_col))
}

impl fmt::Display for FileId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "file#{}", self.0)
    }
}

fn line_starts(text: &str) -> Vec<usize> {
    let mut starts = vec![0];
    for (idx, byte) in text.bytes().enumerate() {
        if byte == b'\n' && idx + 1 < text.len() {
            starts.push(idx + 1);
        }
    }
    starts
}

fn line_col(source: &SourceFile, byte: usize) -> (usize, usize) {
    let line_idx = match source.line_starts.binary_search(&byte) {
        Ok(idx) => idx,
        Err(idx) => idx.saturating_sub(1),
    };
    let line_start = source.line_starts[line_idx];
    (line_idx + 1, byte.saturating_sub(line_start) + 1)
}

fn byte_for_line_col(source: &SourceFile, line: usize, col: usize) -> Option<usize> {
    let line_start = *source.line_starts.get(line.checked_sub(1)?)?;
    Some((line_start + col.saturating_sub(1)).min(source.text.len()))
}

fn mapped_source_byte(segment: &SourceMapSegment, generated_byte: usize) -> usize {
    match segment.origin {
        SourceOrigin::MacroExpansion(_) => segment.source.start.0,
        SourceOrigin::Source => {
            let generated_offset = generated_byte.saturating_sub(segment.generated.start);
            (segment.source.start.0 + generated_offset).min(segment.source.end.0)
        }
    }
}

fn segment_containing(
    segments: &[SourceMapSegment],
    generated_byte: usize,
) -> Option<&SourceMapSegment> {
    let idx = segments.partition_point(|segment| segment.generated.end <= generated_byte);
    let segment = segments.get(idx)?;
    (segment.generated.start <= generated_byte && generated_byte < segment.generated.end)
        .then_some(segment)
}

/// Resolves the span of the include path string within a source line.
/// Used by the preprocessor to build include edges with accurate spans.
fn include_path_span(
    db: &SourceDb,
    file: FileId,
    line_no: usize,
    raw: &str,
    include: &str,
) -> Option<Span> {
    let line_start = db.files.get(file.index())?.line_starts[line_no - 1];
    let start_in_line = raw.find(include)?;
    db.span(
        file,
        BytePos(line_start + start_in_line),
        BytePos(line_start + start_in_line + include.len()),
    )
}
