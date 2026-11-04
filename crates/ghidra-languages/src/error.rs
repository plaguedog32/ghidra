use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::AssetStatus;

/// Hard failures. Recoverable problems are reported as [`Diagnostic`]s instead.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("catalog root {path} is not a readable directory: {reason}")]
    InvalidRoot { path: PathBuf, reason: String },
    #[error("I/O error reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("{path}:{line}: malformed XML: {message}")]
    Xml {
        path: PathBuf,
        line: u32,
        message: String,
    },
    #[error("{path}: limit exceeded: {message}")]
    Limit { path: PathBuf, message: String },
    #[error("{path}:{line}: {message}")]
    Schema {
        path: PathBuf,
        line: u32,
        message: String,
    },
    #[error("language {language_id}: {asset} `{declared}` is unavailable ({status:?})")]
    AssetUnavailable {
        language_id: String,
        asset: AssetKind,
        declared: String,
        status: AssetStatus,
    },
    /// A compiler's `.cspec` asset is missing, ambiguous or rejected.
    #[error("compiler {compiler_id}: compiler spec `{declared}` is unavailable ({status:?})")]
    CompilerSpecUnavailable {
        compiler_id: String,
        declared: String,
        status: AssetStatus,
    },
    #[error("language {language_id} declares no compiler `{compiler_id}`")]
    UnknownCompiler {
        language_id: String,
        compiler_id: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Severity {
    Info,
    Warning,
    Error,
}

/// Which declared language asset a diagnostic or error refers to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssetKind {
    SleighSource,
    ProcessorSpec,
    CompilerSpec,
    ManualIndex,
}

impl std::fmt::Display for AssetKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            AssetKind::SleighSource => "SLEIGH source",
            AssetKind::ProcessorSpec => "processor spec",
            AssetKind::CompilerSpec => "compiler spec",
            AssetKind::ManualIndex => "manual index",
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum DiagnosticKind {
    /// The XML file could not be parsed; the whole file was skipped.
    MalformedXml,
    /// A required attribute is absent; the element was skipped.
    MissingAttribute,
    /// An attribute value could not be decoded.
    InvalidAttribute,
    /// Attribute not part of the upstream schema; ignored like Ghidra does.
    UnknownAttribute,
    /// Element not expected at this position. As a warning Ghidra ignores it too; as an
    /// error Ghidra rejects it (for example a nested element inside a leaf tag).
    UnknownElement,
    /// A schema form this crate reads but does not model (reported, not guessed).
    UnsupportedForm,
    /// A required child element is absent.
    MissingElement,
    /// A name refers to a prototype model (or other declaration) that does not exist.
    UnresolvedReference,
    /// The file breaks a consistency rule Ghidra enforces when loading it (for example
    /// parameter entries out of storage-class order). Ghidra rejects such files.
    InconsistentSpec,
    /// A recognised element whose content is recorded but not turned into a typed model.
    UnmodeledElement,
    DuplicateLanguageId,
    DuplicateCompilerId,
    DuplicateEntry,
    /// The declared asset does not exist in the catalog tree.
    MissingAsset(AssetKind),
    /// Asset was not at its declared relative path but was found by unique file name,
    /// matching Ghidra's application-wide fallback search.
    AssetFoundBySearch(AssetKind),
    /// Several files match the asset name and none is at the declared location.
    AmbiguousAsset(AssetKind),
    /// Asset path is absolute or escapes the catalog root.
    RejectedAssetPath(AssetKind),
    SymlinkSkipped,
    LimitExceeded,
    Io,
}

/// A recoverable problem found while reading the catalog or a spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub severity: Severity,
    pub kind: DiagnosticKind,
    pub path: Option<PathBuf>,
    pub line: Option<u32>,
    pub language_id: Option<String>,
    pub message: String,
}

impl std::fmt::Display for Diagnostic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.severity)?;
        if let Some(path) = &self.path {
            write!(f, " {}", path.display())?;
            if let Some(line) = self.line {
                write!(f, ":{line}")?;
            }
        }
        if let Some(id) = &self.language_id {
            write!(f, " [{id}]")?;
        }
        write!(f, ": {}", self.message)
    }
}
