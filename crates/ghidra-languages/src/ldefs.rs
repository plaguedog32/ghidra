//! `.ldefs` language definition catalog.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use ghidra_pcode::Endianness;
use serde::{Deserialize, Serialize};

use crate::paths::{self, DiscoveryOptions, FileIndex, Resolution};
use crate::xml::{self, Element};
use crate::{AssetKind, Diagnostic, DiagnosticKind, Error, Limits, ProcessorSpec, Severity};

/// Where a declared asset was found.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AssetStatus {
    /// At the declared path.
    Present,
    /// Not at the declared path, but a unique file of that name exists in the catalog
    /// (Ghidra's application-wide fallback search). `path` is that file.
    FoundBySearch,
    /// Not found. `path` is the expected declared location.
    Missing,
    /// Several same-named files exist and none is at the declared path. `path` is `None`.
    Ambiguous,
    /// Absolute path or escapes the catalog root. `path` is `None`.
    Rejected,
}

/// A file reference declared by a language definition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetRef {
    /// The attribute text exactly as written (after XML unescaping).
    pub declared: String,
    pub status: AssetStatus,
    /// Absolute path: the found file, or the expected location when `Missing`.
    pub path: Option<PathBuf>,
}

impl AssetRef {
    /// True when `path` names an existing file inside the catalog root.
    pub fn is_available(&self) -> bool {
        matches!(
            self.status,
            AssetStatus::Present | AssetStatus::FoundBySearch
        )
    }

    /// The existing file, if any.
    pub fn available_path(&self) -> Option<&Path> {
        if self.is_available() {
            self.path.as_deref()
        } else {
            None
        }
    }
}

/// A compiler (ABI) entry. Only the asset reference is read; cspec semantics are not
/// interpreted by this crate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompilerDefinition {
    pub id: String,
    pub name: String,
    pub spec: AssetRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalName {
    pub tool: String,
    pub name: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TruncatedSpace {
    pub space: String,
    pub size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct LanguageVersion {
    pub major: u32,
    pub minor: u32,
}

impl std::fmt::Display for LanguageVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

/// One `<language>` entry from an `.ldefs` file.
///
/// `source.status == Present` only means the `.slaspec` file exists. It is not evidence
/// that it compiles or that its semantics are supported.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LanguageDefinition {
    /// Language ID, e.g. `x86:LE:64:default`.
    pub id: String,
    pub processor: String,
    /// Data endianness (`endian`).
    pub endian: Endianness,
    /// Instruction endianness (`instructionEndian`, defaults to `endian`).
    pub instruction_endian: Endianness,
    /// Address size in bits (`size`).
    pub size: u32,
    pub variant: String,
    pub version: LanguageVersion,
    pub description: String,
    pub deprecated: bool,
    /// Ghidra only shows hidden languages in development mode.
    pub hidden: bool,
    /// The `slafile` attribute as written (a compiled-output name, e.g. `x86-64.sla`).
    pub sla_file: String,
    /// The `.slaspec` source the `slafile` maps to.
    pub source: AssetRef,
    pub processor_spec: AssetRef,
    pub manual_index: Option<AssetRef>,
    /// In declaration order; the first is Ghidra's default compiler.
    pub compilers: Vec<CompilerDefinition>,
    pub external_names: Vec<ExternalName>,
    pub truncated_spaces: Vec<TruncatedSpace>,
    /// The `.ldefs` file and line that declared this language.
    pub ldefs_path: PathBuf,
    pub line: u32,
}

impl LanguageDefinition {
    pub fn default_compiler(&self) -> Option<&CompilerDefinition> {
        self.compilers.first()
    }

    pub fn compiler(&self, id: &str) -> Option<&CompilerDefinition> {
        self.compilers.iter().find(|c| c.id == id)
    }

    /// External names registered for `tool` (e.g. `"gnu"`, `"IDA-PRO"`).
    pub fn external_names_for<'a>(&'a self, tool: &'a str) -> impl Iterator<Item = &'a str> + 'a {
        self.external_names
            .iter()
            .filter(move |n| n.tool == tool)
            .map(|n| n.name.as_str())
    }

    /// Read this language's `.pspec` with default [`Limits`].
    pub fn load_processor_spec(&self) -> Result<ProcessorSpec, Error> {
        self.load_processor_spec_with(&Limits::default())
    }

    pub fn load_processor_spec_with(&self, limits: &Limits) -> Result<ProcessorSpec, Error> {
        let path = self
            .processor_spec
            .available_path()
            .ok_or_else(|| Error::AssetUnavailable {
                language_id: self.id.clone(),
                asset: AssetKind::ProcessorSpec,
                declared: self.processor_spec.declared.clone(),
                status: self.processor_spec.status,
            })?;
        ProcessorSpec::from_path_with(path, limits)
    }
}

/// All language definitions discovered under a root directory.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Catalog {
    /// In discovery order (sorted `.ldefs` paths, then document order).
    pub languages: Vec<LanguageDefinition>,
    pub diagnostics: Vec<Diagnostic>,
    /// The `.ldefs` files that were read (including ones that failed to parse).
    pub ldefs_files: Vec<PathBuf>,
    root: PathBuf,
}

impl Catalog {
    /// Discover every `.ldefs` below `root` with default options.
    pub fn discover(root: &Path) -> Result<Catalog, Error> {
        Self::discover_with(root, &DiscoveryOptions::default())
    }

    pub fn discover_with(root: &Path, options: &DiscoveryOptions) -> Result<Catalog, Error> {
        let root = std::path::absolute(root).map_err(|e| Error::InvalidRoot {
            path: root.to_path_buf(),
            reason: e.to_string(),
        })?;
        match std::fs::metadata(&root) {
            Ok(meta) if meta.is_dir() => {}
            Ok(_) => {
                return Err(Error::InvalidRoot {
                    path: root,
                    reason: "not a directory".into(),
                });
            }
            Err(e) => {
                return Err(Error::InvalidRoot {
                    path: root,
                    reason: e.to_string(),
                });
            }
        }
        let mut catalog = Catalog {
            root: root.clone(),
            ..Catalog::default()
        };
        let index = paths::walk(&root, options, &mut catalog.diagnostics);
        let mut seen: HashMap<String, (PathBuf, u32)> = HashMap::new();
        for rel in &index.ldefs {
            let path = index.absolute(rel);
            catalog.ldefs_files.push(path.clone());
            let doc = match xml::parse_file(&path, &options.limits) {
                Ok(doc) => doc,
                Err(e) => {
                    let (kind, line) = match &e {
                        Error::Xml { line, .. } => (DiagnosticKind::MalformedXml, Some(*line)),
                        Error::Limit { .. } => (DiagnosticKind::LimitExceeded, None),
                        _ => (DiagnosticKind::Io, None),
                    };
                    catalog.diagnostics.push(Diagnostic {
                        severity: Severity::Error,
                        kind,
                        path: Some(path.clone()),
                        line,
                        language_id: None,
                        message: format!("file skipped: {e}"),
                    });
                    continue;
                }
            };
            let mut ctx = FileCtx {
                index: &index,
                path: &path,
                base_dir: paths::rel_parent(rel),
                diagnostics: &mut catalog.diagnostics,
            };
            for language in ctx.read_ldefs(&doc) {
                if catalog.languages.len() >= options.limits.max_languages {
                    ctx.diag(
                        Severity::Error,
                        DiagnosticKind::LimitExceeded,
                        Some(language.line),
                        Some(&language.id),
                        format!(
                            "more than {} languages; remaining definitions ignored",
                            options.limits.max_languages
                        ),
                    );
                    break;
                }
                if let Some((first_path, first_line)) = seen.get(&language.id) {
                    ctx.diag(
                        Severity::Error,
                        DiagnosticKind::DuplicateLanguageId,
                        Some(language.line),
                        Some(&language.id),
                        format!(
                            "duplicate language ID; keeping the definition at {}:{}",
                            first_path.display(),
                            first_line
                        ),
                    );
                    continue;
                }
                seen.insert(language.id.clone(), (path.clone(), language.line));
                catalog.languages.push(language);
            }
        }
        Ok(catalog)
    }

    /// The directory that was searched.
    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn by_id(&self, id: &str) -> Option<&LanguageDefinition> {
        self.languages.iter().find(|l| l.id == id)
    }

    /// Languages for one processor family, in discovery order.
    pub fn by_processor<'a>(
        &'a self,
        processor: &'a str,
    ) -> impl Iterator<Item = &'a LanguageDefinition> + 'a {
        self.languages
            .iter()
            .filter(move |l| l.processor == processor)
    }

    /// Diagnostics attributed to one language ID.
    pub fn diagnostics_for<'a>(&'a self, id: &'a str) -> impl Iterator<Item = &'a Diagnostic> + 'a {
        self.diagnostics
            .iter()
            .filter(move |d| d.language_id.as_deref() == Some(id))
    }

    pub fn has_errors(&self) -> bool {
        self.diagnostics
            .iter()
            .any(|d| d.severity == Severity::Error)
    }
}

struct FileCtx<'a> {
    index: &'a FileIndex,
    path: &'a Path,
    base_dir: Vec<String>,
    diagnostics: &'a mut Vec<Diagnostic>,
}

const LANGUAGE_ATTRS: &[&str] = &[
    "hidden",
    "deprecated",
    "processor",
    "endian",
    "instructionEndian",
    "size",
    "variant",
    "version",
    "slafile",
    "processorspec",
    "manualindexfile",
    "id",
];

impl FileCtx<'_> {
    fn diag(
        &mut self,
        severity: Severity,
        kind: DiagnosticKind,
        line: Option<u32>,
        language_id: Option<&str>,
        message: String,
    ) {
        self.diagnostics.push(Diagnostic {
            severity,
            kind,
            path: Some(self.path.to_path_buf()),
            line,
            language_id: language_id.map(str::to_owned),
            message,
        });
    }

    fn read_ldefs(&mut self, doc: &Element) -> Vec<LanguageDefinition> {
        let mut out = Vec::new();
        if doc.name != "language_definitions" {
            self.diag(
                Severity::Error,
                DiagnosticKind::MalformedXml,
                Some(doc.line),
                None,
                format!(
                    "root element is <{}>, expected <language_definitions>",
                    doc.name
                ),
            );
            return out;
        }
        for (key, _) in &doc.attrs {
            self.diag(
                Severity::Warning,
                DiagnosticKind::UnknownAttribute,
                Some(doc.line),
                None,
                format!("ignored attribute `{key}` on <language_definitions>"),
            );
        }
        for child in &doc.children {
            if child.name == "language" {
                if let Some(language) = self.read_language(child) {
                    out.push(language);
                }
            } else {
                self.diag(
                    Severity::Warning,
                    DiagnosticKind::UnknownElement,
                    Some(child.line),
                    None,
                    format!("ignored element <{}> in <language_definitions>", child.name),
                );
            }
        }
        out
    }

    fn require<'e>(&mut self, el: &'e Element, attr: &str, id: Option<&str>) -> Option<&'e str> {
        let value = el.attr(attr);
        if value.is_none() {
            self.diag(
                Severity::Error,
                DiagnosticKind::MissingAttribute,
                Some(el.line),
                id,
                format!("<{}> is missing required attribute `{attr}`", el.name),
            );
        }
        value
    }

    fn bool_attr(&mut self, el: &Element, attr: &str, id: &str) -> bool {
        let Some(text) = el.attr(attr) else {
            return false;
        };
        xml::decode_java_bool(text).unwrap_or_else(|| {
            self.diag(
                Severity::Warning,
                DiagnosticKind::InvalidAttribute,
                Some(el.line),
                Some(id),
                format!("`{attr}=\"{text}\"` is not a boolean; treated as false"),
            );
            false
        })
    }

    fn endian(&mut self, el: &Element, attr: &str, text: &str, id: &str) -> Option<Endianness> {
        match text.to_ascii_lowercase().as_str() {
            "little" => Some(Endianness::Little),
            "big" => Some(Endianness::Big),
            _ => {
                self.diag(
                    Severity::Error,
                    DiagnosticKind::InvalidAttribute,
                    Some(el.line),
                    Some(id),
                    format!("`{attr}=\"{text}\"` must be `little` or `big`; language skipped"),
                );
                None
            }
        }
    }

    fn read_language(&mut self, el: &Element) -> Option<LanguageDefinition> {
        let id = self.require(el, "id", None)?.to_owned();
        let idr = Some(id.as_str());
        let processor = self.require(el, "processor", idr);
        let endian_text = self.require(el, "endian", idr);
        let size_text = self.require(el, "size", idr);
        let variant = self.require(el, "variant", idr);
        let version_text = self.require(el, "version", idr);
        let sla_file = self.require(el, "slafile", idr);
        let pspec = self.require(el, "processorspec", idr);
        let (
            Some(processor),
            Some(endian_text),
            Some(size_text),
            Some(variant),
            Some(version_text),
            Some(sla_file),
            Some(pspec),
        ) = (
            processor,
            endian_text,
            size_text,
            variant,
            version_text,
            sla_file,
            pspec,
        )
        else {
            return None;
        };
        for (key, _) in &el.attrs {
            if !LANGUAGE_ATTRS.contains(&key.as_str()) {
                self.diag(
                    Severity::Warning,
                    DiagnosticKind::UnknownAttribute,
                    Some(el.line),
                    idr,
                    format!("ignored attribute `{key}` on <language>"),
                );
            }
        }

        let endian = self.endian(el, "endian", endian_text, &id)?;
        let instruction_endian = match el.attr("instructionEndian") {
            Some(text) => self.endian(el, "instructionEndian", text, &id)?,
            None => endian,
        };
        let size = match xml::decode_java_int(size_text).and_then(|v| u32::try_from(v).ok()) {
            Some(size) if size > 0 => size,
            _ => {
                self.diag(
                    Severity::Error,
                    DiagnosticKind::InvalidAttribute,
                    Some(el.line),
                    idr,
                    format!("`size=\"{size_text}\"` is not a positive integer; language skipped"),
                );
                return None;
            }
        };
        let Some(version) = parse_version(version_text) else {
            self.diag(
                Severity::Error,
                DiagnosticKind::InvalidAttribute,
                Some(el.line),
                idr,
                format!("`version=\"{version_text}\"` must be <major>[.<minor>]; language skipped"),
            );
            return None;
        };
        let deprecated = self.bool_attr(el, "deprecated", &id);
        let hidden = self.bool_attr(el, "hidden", &id);

        // slafile names compiled output; the source is the sibling `.slaspec`.
        let base = sla_file.strip_suffix(".sla").unwrap_or(sla_file);
        let source = self.asset(
            &format!("{base}.slaspec"),
            AssetKind::SleighSource,
            el.line,
            &id,
        );
        let processor_spec = self.asset(pspec, AssetKind::ProcessorSpec, el.line, &id);
        let manual_index = el
            .attr("manualindexfile")
            .map(|m| self.asset(m, AssetKind::ManualIndex, el.line, &id));

        let mut description = None;
        let mut compilers: Vec<CompilerDefinition> = Vec::new();
        let mut external_names = Vec::new();
        let mut truncated_spaces: Vec<TruncatedSpace> = Vec::new();
        for child in &el.children {
            match child.name.as_str() {
                "description" => {
                    if description.is_some() {
                        self.diag(
                            Severity::Warning,
                            DiagnosticKind::DuplicateEntry,
                            Some(child.line),
                            idr,
                            "more than one <description>; using the first".into(),
                        );
                    } else {
                        description = Some(child.text.trim().to_owned());
                    }
                }
                "compiler" => {
                    let (Some(cid), Some(name), Some(spec)) = (
                        self.require(child, "id", idr),
                        self.require(child, "name", idr),
                        self.require(child, "spec", idr),
                    ) else {
                        continue;
                    };
                    self.warn_unknown_attrs(child, &["id", "name", "spec"], &id);
                    if compilers.iter().any(|c| c.id == cid) {
                        self.diag(
                            Severity::Warning,
                            DiagnosticKind::DuplicateCompilerId,
                            Some(child.line),
                            idr,
                            format!("duplicate compiler id `{cid}`; keeping the first"),
                        );
                        continue;
                    }
                    let spec = self.asset(spec, AssetKind::CompilerSpec, child.line, &id);
                    compilers.push(CompilerDefinition {
                        id: cid.to_owned(),
                        name: name.to_owned(),
                        spec,
                    });
                }
                "external_name" => {
                    self.warn_unknown_attrs(child, &["tool", "name"], &id);
                    // Ghidra drops entries with missing or empty tool/name silently.
                    if let (Some(tool), Some(name)) = (child.attr("tool"), child.attr("name"))
                        && !tool.is_empty()
                        && !name.is_empty()
                    {
                        external_names.push(ExternalName {
                            tool: tool.to_owned(),
                            name: name.to_owned(),
                        });
                    }
                }
                "truncate_space" => {
                    let (Some(space), Some(size_text)) = (
                        self.require(child, "space", idr),
                        self.require(child, "size", idr),
                    ) else {
                        continue;
                    };
                    let Some(size) =
                        xml::decode_java_int(size_text).and_then(|v| u32::try_from(v).ok())
                    else {
                        self.diag(
                            Severity::Error,
                            DiagnosticKind::InvalidAttribute,
                            Some(child.line),
                            idr,
                            format!("truncate_space size `{size_text}` is invalid; entry ignored"),
                        );
                        continue;
                    };
                    if truncated_spaces.iter().any(|t| t.space == space) {
                        self.diag(
                            Severity::Error,
                            DiagnosticKind::DuplicateEntry,
                            Some(child.line),
                            idr,
                            format!("truncated space `{space}` already specified; entry ignored"),
                        );
                        continue;
                    }
                    truncated_spaces.push(TruncatedSpace {
                        space: space.to_owned(),
                        size,
                    });
                }
                other => self.diag(
                    Severity::Warning,
                    DiagnosticKind::UnknownElement,
                    Some(child.line),
                    idr,
                    format!("ignored element <{other}> in <language>"),
                ),
            }
        }
        let description = description.unwrap_or_else(|| {
            self.diag(
                Severity::Warning,
                DiagnosticKind::MissingAttribute,
                Some(el.line),
                idr,
                "<language> has no <description>".into(),
            );
            String::new()
        });
        if compilers.is_empty() {
            self.diag(
                Severity::Warning,
                DiagnosticKind::MissingAttribute,
                Some(el.line),
                idr,
                "<language> declares no <compiler>".into(),
            );
        }

        Some(LanguageDefinition {
            id,
            processor: processor.to_owned(),
            endian,
            instruction_endian,
            size,
            variant: variant.to_owned(),
            version,
            description,
            deprecated,
            hidden,
            sla_file: sla_file.to_owned(),
            source,
            processor_spec,
            manual_index,
            compilers,
            external_names,
            truncated_spaces,
            ldefs_path: self.path.to_path_buf(),
            line: el.line,
        })
    }

    fn warn_unknown_attrs(&mut self, el: &Element, known: &[&str], id: &str) {
        for (key, _) in &el.attrs {
            if !known.contains(&key.as_str()) {
                self.diag(
                    Severity::Warning,
                    DiagnosticKind::UnknownAttribute,
                    Some(el.line),
                    Some(id),
                    format!("ignored attribute `{key}` on <{}>", el.name),
                );
            }
        }
    }

    fn asset(&mut self, declared: &str, kind: AssetKind, line: u32, id: &str) -> AssetRef {
        let (status, path) = match self.index.resolve(&self.base_dir, declared) {
            Resolution::Present(rel) => (AssetStatus::Present, Some(self.index.absolute(&rel))),
            Resolution::FoundBySearch(rel) => {
                let path = self.index.absolute(&rel);
                self.diag(
                    Severity::Info,
                    DiagnosticKind::AssetFoundBySearch(kind),
                    Some(line),
                    Some(id),
                    format!(
                        "{kind} `{declared}` is not at its declared path; using {}",
                        path.display()
                    ),
                );
                (AssetStatus::FoundBySearch, Some(path))
            }
            Resolution::Missing(rel) => {
                let path = self.index.absolute(&rel);
                self.diag(
                    Severity::Warning,
                    DiagnosticKind::MissingAsset(kind),
                    Some(line),
                    Some(id),
                    format!(
                        "{kind} `{declared}` not found (expected {})",
                        path.display()
                    ),
                );
                (AssetStatus::Missing, Some(path))
            }
            Resolution::Ambiguous(candidates) => {
                self.diag(
                    Severity::Error,
                    DiagnosticKind::AmbiguousAsset(kind),
                    Some(line),
                    Some(id),
                    format!(
                        "{kind} `{declared}` is not at its declared path and matches {} files: {}",
                        candidates.len(),
                        candidates.join(", ")
                    ),
                );
                (AssetStatus::Ambiguous, None)
            }
            Resolution::Rejected(reason) => {
                self.diag(
                    Severity::Error,
                    DiagnosticKind::RejectedAssetPath(kind),
                    Some(line),
                    Some(id),
                    format!("{kind} path rejected: {reason}"),
                );
                (AssetStatus::Rejected, None)
            }
        };
        AssetRef {
            declared: declared.to_owned(),
            status,
            path,
        }
    }
}

/// Ghidra's `<major>[.<minor>]` with `SpecXmlUtils.decodeInt` pieces.
fn parse_version(text: &str) -> Option<LanguageVersion> {
    let mut pieces = text.split('.');
    let major = pieces.next().and_then(xml::decode_java_int)?;
    let minor = match pieces.next() {
        Some(p) => xml::decode_java_int(p)?,
        None => 0,
    };
    Some(LanguageVersion {
        major: u32::try_from(major).ok()?,
        minor: u32::try_from(minor).ok()?,
    })
}
