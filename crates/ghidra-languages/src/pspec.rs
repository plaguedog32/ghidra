//! `.pspec` processor specification: program counter, properties, and the
//! `<context_data>` defaults. Context-register fields (`context_set`) and tracked
//! register values (`tracked_set`) are kept in separate collections and resolved by
//! separate queries.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::xml::{self, Element};
use crate::{Diagnostic, DiagnosticKind, Error, Limits, Severity};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Property {
    pub key: String,
    pub value: String,
}

/// One `<set name=".." val=".."/>` entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetValue {
    /// Context field name (`context_set`) or register name (`tracked_set`).
    pub name: String,
    pub value: u128,
    /// The `val` attribute as written.
    pub raw: String,
    pub description: Option<String>,
}

/// An optionally ranged block of values for one address space.
///
/// `first`/`last` are inclusive offsets. A missing bound is open (Ghidra uses 0 and the
/// space maximum). When both are absent the block covers the whole space.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetBlock {
    pub space: String,
    pub first: Option<u64>,
    pub last: Option<u64>,
    /// In document order.
    pub values: Vec<SetValue>,
    pub line: u32,
}

impl SetBlock {
    /// True when the block declares a `first` and/or `last` bound.
    pub fn is_ranged(&self) -> bool {
        self.first.is_some() || self.last.is_some()
    }

    pub fn contains(&self, space: &str, offset: u64) -> bool {
        self.space == space
            && self.first.is_none_or(|f| offset >= f)
            && self.last.is_none_or(|l| offset <= l)
    }
}

/// `<context_set>`: defaults for SLEIGH context-register fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContextSet(pub SetBlock);

/// `<tracked_set>`: assumed values of ordinary registers. Not decode context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackedSet(pub SetBlock);

impl std::ops::Deref for ContextSet {
    type Target = SetBlock;
    fn deref(&self) -> &SetBlock {
        &self.0
    }
}

impl std::ops::Deref for TrackedSet {
    type Target = SetBlock;
    fn deref(&self) -> &SetBlock {
        &self.0
    }
}

/// Which block supplied a resolved value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ValueOrigin {
    /// An unranged block covering the whole space.
    SpaceWide { block: usize },
    /// A ranged block.
    Ranged {
        block: usize,
        first: Option<u64>,
        last: Option<u64>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResolvedValue {
    pub name: String,
    pub value: u128,
    pub origin: ValueOrigin,
}

/// Parsed processor spec.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessorSpec {
    pub path: Option<PathBuf>,
    /// `<programcounter register=".."/>`.
    pub program_counter: Option<String>,
    /// In document order; duplicates are kept (see [`ProcessorSpec::property`]).
    pub properties: Vec<Property>,
    pub context_sets: Vec<ContextSet>,
    pub tracked_sets: Vec<TrackedSet>,
    /// Schema elements present in the file that this crate does not interpret
    /// (e.g. `register_data`, `default_symbols`), in first-seen order.
    pub unmodeled_elements: Vec<String>,
    pub diagnostics: Vec<Diagnostic>,
}

/// Top-level `processor_spec` children defined by `processor_spec.rxg` that are not
/// modeled here.
const UNMODELED: &[&str] = &[
    "data_space",
    "inferptrbounds",
    "segmented_address",
    "segmentop",
    "volatile",
    "incidentalcopy",
    "jumpassist",
    "register_data",
    "default_symbols",
    "default_memory_blocks",
];

impl ProcessorSpec {
    pub fn from_path(path: &Path) -> Result<ProcessorSpec, Error> {
        Self::from_path_with(path, &Limits::default())
    }

    pub fn from_path_with(path: &Path, limits: &Limits) -> Result<ProcessorSpec, Error> {
        let doc = xml::parse_file(path, limits)?;
        Self::from_element(&doc, Some(path))
    }

    /// Parse spec text. `path` is only used for diagnostics.
    pub fn parse_str(
        text: &str,
        path: Option<&Path>,
        limits: &Limits,
    ) -> Result<ProcessorSpec, Error> {
        let label = path.map(Path::to_path_buf).unwrap_or_default();
        if text.len() as u64 > limits.max_file_bytes {
            return Err(Error::Limit {
                path: label,
                message: format!(
                    "text is {} bytes, limit is {}",
                    text.len(),
                    limits.max_file_bytes
                ),
            });
        }
        let doc = xml::parse_document(text, limits).map_err(|e| {
            if e.limit {
                Error::Limit {
                    path: label.clone(),
                    message: format!("line {}: {}", e.line, e.message),
                }
            } else {
                Error::Xml {
                    path: label.clone(),
                    line: e.line,
                    message: e.message,
                }
            }
        })?;
        Self::from_element(&doc, path)
    }

    fn from_element(doc: &Element, path: Option<&Path>) -> Result<ProcessorSpec, Error> {
        if doc.name != "processor_spec" {
            return Err(Error::Schema {
                path: path.map(Path::to_path_buf).unwrap_or_default(),
                line: doc.line,
                message: format!("root element is <{}>, expected <processor_spec>", doc.name),
            });
        }
        let mut spec = ProcessorSpec {
            path: path.map(Path::to_path_buf),
            program_counter: None,
            properties: Vec::new(),
            context_sets: Vec::new(),
            tracked_sets: Vec::new(),
            unmodeled_elements: Vec::new(),
            diagnostics: Vec::new(),
        };
        for child in &doc.children {
            match child.name.as_str() {
                "properties" => spec.read_properties(child),
                "programcounter" => {
                    spec.unknown_attrs(child, &["register"]);
                    match child.attr("register") {
                        Some(reg) => {
                            if let Some(old) = &spec.program_counter {
                                let msg = format!("program counter `{old}` replaced by `{reg}`");
                                spec.diag(
                                    Severity::Warning,
                                    DiagnosticKind::DuplicateEntry,
                                    child.line,
                                    msg,
                                );
                            }
                            spec.program_counter = Some(reg.to_owned());
                        }
                        None => spec.diag(
                            Severity::Error,
                            DiagnosticKind::MissingAttribute,
                            child.line,
                            "<programcounter> has no `register`".into(),
                        ),
                    }
                }
                "context_data" => spec.read_context_data(child),
                name if UNMODELED.contains(&name) => {
                    if !spec.unmodeled_elements.iter().any(|n| n == name) {
                        spec.unmodeled_elements.push(name.to_owned());
                    }
                }
                other => {
                    let msg = format!("ignored element <{other}> in <processor_spec>");
                    spec.diag(
                        Severity::Warning,
                        DiagnosticKind::UnknownElement,
                        child.line,
                        msg,
                    );
                }
            }
        }
        Ok(spec)
    }

    fn diag(&mut self, severity: Severity, kind: DiagnosticKind, line: u32, message: String) {
        self.diagnostics.push(Diagnostic {
            severity,
            kind,
            path: self.path.clone(),
            line: Some(line),
            language_id: None,
            message,
        });
    }

    fn unknown_attrs(&mut self, el: &Element, known: &[&str]) {
        for (key, _) in &el.attrs {
            if !known.contains(&key.as_str()) {
                let msg = format!("ignored attribute `{key}` on <{}>", el.name);
                self.diag(
                    Severity::Warning,
                    DiagnosticKind::UnknownAttribute,
                    el.line,
                    msg,
                );
            }
        }
    }

    fn read_properties(&mut self, el: &Element) {
        for prop in &el.children {
            if prop.name != "property" {
                let msg = format!("ignored element <{}> in <properties>", prop.name);
                self.diag(
                    Severity::Warning,
                    DiagnosticKind::UnknownElement,
                    prop.line,
                    msg,
                );
                continue;
            }
            self.unknown_attrs(prop, &["key", "value"]);
            let (Some(key), Some(value)) = (prop.attr("key"), prop.attr("value")) else {
                let msg = "<property> needs `key` and `value`; ignored".into();
                self.diag(
                    Severity::Error,
                    DiagnosticKind::MissingAttribute,
                    prop.line,
                    msg,
                );
                continue;
            };
            if self.properties.iter().any(|p| p.key == key) {
                let msg = format!("property `{key}` repeated; the last value wins");
                self.diag(
                    Severity::Warning,
                    DiagnosticKind::DuplicateEntry,
                    prop.line,
                    msg,
                );
            }
            self.properties.push(Property {
                key: key.to_owned(),
                value: value.to_owned(),
            });
        }
    }

    fn read_context_data(&mut self, el: &Element) {
        for block in &el.children {
            let is_context = match block.name.as_str() {
                "context_set" => true,
                "tracked_set" => false,
                other => {
                    let msg = format!(
                        "unsupported <{other}> in <context_data> (only context_set and tracked_set are defined); ignored"
                    );
                    self.diag(
                        Severity::Error,
                        DiagnosticKind::UnsupportedForm,
                        block.line,
                        msg,
                    );
                    continue;
                }
            };
            if let Some(parsed) = self.read_block(block) {
                if is_context {
                    self.context_sets.push(ContextSet(parsed));
                } else {
                    self.tracked_sets.push(TrackedSet(parsed));
                }
            }
        }
    }

    fn read_block(&mut self, el: &Element) -> Option<SetBlock> {
        self.unknown_attrs(el, &["space", "first", "last"]);
        let Some(space) = el.attr("space") else {
            let msg = format!("<{}> has no `space`; block ignored", el.name);
            self.diag(
                Severity::Error,
                DiagnosticKind::MissingAttribute,
                el.line,
                msg,
            );
            return None;
        };
        let mut bound = |attr: &str| -> Result<Option<u64>, ()> {
            match el.attr(attr) {
                None => Ok(None),
                Some(text) => match xml::decode_java_unsigned(text) {
                    Some(v) => Ok(Some(v)),
                    None => {
                        let msg = format!(
                            "<{}> `{attr}=\"{text}\"` is not an address offset; block ignored",
                            el.name
                        );
                        self.diag(
                            Severity::Error,
                            DiagnosticKind::InvalidAttribute,
                            el.line,
                            msg,
                        );
                        Err(())
                    }
                },
            }
        };
        let first = bound("first").ok()?;
        let last = bound("last").ok()?;
        if first.is_some() != last.is_some() {
            let msg = format!(
                "<{}> gives only one of `first`/`last`; the other bound is open",
                el.name
            );
            self.diag(
                Severity::Warning,
                DiagnosticKind::UnsupportedForm,
                el.line,
                msg,
            );
        }
        if let (Some(f), Some(l)) = (first, last)
            && f > l
        {
            let msg = format!(
                "<{}> range first {f:#x} > last {l:#x}; block ignored",
                el.name
            );
            self.diag(
                Severity::Error,
                DiagnosticKind::InvalidAttribute,
                el.line,
                msg,
            );
            return None;
        }
        let mut values = Vec::new();
        for set in &el.children {
            if set.name != "set" {
                let msg = format!("unsupported <{}> in <{}>; ignored", set.name, el.name);
                self.diag(
                    Severity::Error,
                    DiagnosticKind::UnsupportedForm,
                    set.line,
                    msg,
                );
                continue;
            }
            self.unknown_attrs(set, &["name", "val", "description"]);
            let (Some(name), Some(raw)) = (set.attr("name"), set.attr("val")) else {
                let msg = "<set> needs `name` and `val`; ignored".into();
                self.diag(
                    Severity::Error,
                    DiagnosticKind::MissingAttribute,
                    set.line,
                    msg,
                );
                continue;
            };
            let value = match decode_set_value(raw) {
                SetValueParse::Value(v) => v,
                SetValueParse::Negative => {
                    let msg = format!(
                        "<set name=\"{name}\"> negative value `{raw}` is unsupported; ignored"
                    );
                    self.diag(
                        Severity::Error,
                        DiagnosticKind::UnsupportedForm,
                        set.line,
                        msg,
                    );
                    continue;
                }
                SetValueParse::TooWide => {
                    let msg =
                        format!("<set name=\"{name}\"> value `{raw}` exceeds 128 bits; ignored");
                    self.diag(
                        Severity::Error,
                        DiagnosticKind::UnsupportedForm,
                        set.line,
                        msg,
                    );
                    continue;
                }
                SetValueParse::Invalid => {
                    // Ghidra substitutes zero for unparseable values.
                    let msg = format!(
                        "<set name=\"{name}\"> value `{raw}` is not a number; using 0 like Ghidra"
                    );
                    self.diag(
                        Severity::Warning,
                        DiagnosticKind::InvalidAttribute,
                        set.line,
                        msg,
                    );
                    0
                }
            };
            values.push(SetValue {
                name: name.to_owned(),
                value,
                raw: raw.to_owned(),
                description: set.attr("description").map(str::to_owned),
            });
        }
        if values.is_empty() {
            let msg = format!("<{}> contains no <set> entries", el.name);
            self.diag(
                Severity::Warning,
                DiagnosticKind::UnsupportedForm,
                el.line,
                msg,
            );
        }
        Some(SetBlock {
            space: space.to_owned(),
            first,
            last,
            values,
            line: el.line,
        })
    }

    /// Value of property `key`; when repeated, the last one (Ghidra map semantics).
    pub fn property(&self, key: &str) -> Option<&str> {
        self.properties
            .iter()
            .rev()
            .find(|p| p.key == key)
            .map(|p| p.value.as_str())
    }

    /// Address-space names referenced by context or tracked blocks, first-seen order.
    pub fn referenced_spaces(&self) -> Vec<&str> {
        let mut out: Vec<&str> = Vec::new();
        let blocks = self
            .context_sets
            .iter()
            .map(|c| &c.0)
            .chain(self.tracked_sets.iter().map(|t| &t.0));
        for block in blocks {
            if !out.contains(&block.space.as_str()) {
                out.push(&block.space);
            }
        }
        out
    }

    /// Context-field defaults that apply to all of `space`: only unranged
    /// `context_set` blocks. Ranged blocks are never folded in.
    pub fn context_globals(&self, space: &str) -> Vec<ResolvedValue> {
        resolve(self.context_sets.iter().map(|c| &c.0), |b| {
            !b.is_ranged() && b.space == space
        })
    }

    /// Context-field defaults in effect at `space:offset`: every `context_set` block
    /// covering the address, applied in document order (later blocks override earlier
    /// ones per field, as Ghidra's `applyContextSettings` does).
    pub fn context_at(&self, space: &str, offset: u64) -> Vec<ResolvedValue> {
        resolve(self.context_sets.iter().map(|c| &c.0), |b| {
            b.contains(space, offset)
        })
    }

    /// Tracked register values that apply to all of `space` (unranged `tracked_set`).
    pub fn tracked_globals(&self, space: &str) -> Vec<ResolvedValue> {
        resolve(self.tracked_sets.iter().map(|t| &t.0), |b| {
            !b.is_ranged() && b.space == space
        })
    }

    /// Tracked register values in effect at `space:offset`.
    pub fn tracked_at(&self, space: &str, offset: u64) -> Vec<ResolvedValue> {
        resolve(self.tracked_sets.iter().map(|t| &t.0), |b| {
            b.contains(space, offset)
        })
    }
}

fn resolve<'a>(
    blocks: impl Iterator<Item = &'a SetBlock>,
    applies: impl Fn(&SetBlock) -> bool,
) -> Vec<ResolvedValue> {
    let mut out: Vec<ResolvedValue> = Vec::new();
    for (index, block) in blocks.enumerate() {
        if !applies(block) {
            continue;
        }
        let origin = if block.is_ranged() {
            ValueOrigin::Ranged {
                block: index,
                first: block.first,
                last: block.last,
            }
        } else {
            ValueOrigin::SpaceWide { block: index }
        };
        for set in &block.values {
            let resolved = ResolvedValue {
                name: set.name.clone(),
                value: set.value,
                origin,
            };
            match out.iter_mut().find(|r| r.name == set.name) {
                Some(existing) => *existing = resolved,
                None => out.push(resolved),
            }
        }
    }
    out
}

enum SetValueParse {
    Value(u128),
    Negative,
    TooWide,
    Invalid,
}

/// `SleighLanguage.read`: `0x`/`0X` prefix is hex, anything else is decimal
/// (leading zeros stay decimal here, unlike `SpecXmlUtils`).
fn decode_set_value(raw: &str) -> SetValueParse {
    let (digits, radix) = match raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
        Some(hex) => (hex, 16),
        None => (raw, 10),
    };
    if radix == 10 && digits.starts_with('-') {
        let rest = &digits[1..];
        return if !rest.is_empty() && rest.bytes().all(|b| b.is_ascii_digit()) {
            SetValueParse::Negative
        } else {
            SetValueParse::Invalid
        };
    }
    let digits = digits.strip_prefix('+').unwrap_or(digits);
    if digits.is_empty() || !digits.chars().all(|c| c.is_digit(radix)) {
        return SetValueParse::Invalid;
    }
    match u128::from_str_radix(digits, radix) {
        Ok(v) => SetValueParse::Value(v),
        Err(_) => SetValueParse::TooWide,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn set_value_decoding_matches_sleigh_language() {
        assert!(matches!(
            decode_set_value("0x3e"),
            SetValueParse::Value(0x3e)
        ));
        assert!(matches!(decode_set_value("0X10"), SetValueParse::Value(16)));
        // Leading zero stays decimal in SleighLanguage.read.
        assert!(matches!(decode_set_value("010"), SetValueParse::Value(10)));
        assert!(matches!(decode_set_value("-1"), SetValueParse::Negative));
        assert!(matches!(decode_set_value("abc"), SetValueParse::Invalid));
        assert!(matches!(decode_set_value(""), SetValueParse::Invalid));
        assert!(matches!(
            decode_set_value("0x1ffffffffffffffffffffffffffffffff"),
            SetValueParse::TooWide
        ));
    }
}
