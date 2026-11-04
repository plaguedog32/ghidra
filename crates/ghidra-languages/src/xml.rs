//! Small bounded XML tree built on quick-xml.
//!
//! DTDs are rejected outright, so no entity can be declared or expanded. Only the five
//! predefined entities and numeric character references are resolved.

use std::fs;
use std::io::Read;
use std::path::Path;

use quick_xml::events::{BytesStart, Event};
use quick_xml::{Reader, XmlVersion};
use serde::{Deserialize, Serialize};

use crate::Error;

/// Resource bounds for discovery, XML parsing and compiler-spec reading.
///
/// Missing fields deserialize to their [`Default`] values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Limits {
    /// Largest XML file read, in bytes.
    pub max_file_bytes: u64,
    /// Deepest element nesting accepted.
    pub max_depth: usize,
    /// Most elements in one document.
    pub max_elements: usize,
    /// Most attributes on one element.
    pub max_attributes: usize,
    /// Longest attribute value or accumulated element text, in bytes.
    pub max_text_bytes: usize,
    /// Most directory entries visited while walking the catalog root.
    pub max_walk_entries: usize,
    /// Deepest directory level visited below the catalog root.
    pub max_walk_depth: usize,
    /// Most `.ldefs` files read.
    pub max_ldefs_files: usize,
    /// Most language definitions accepted across the catalog.
    pub max_languages: usize,
    /// Most diagnostics one `.cspec` may produce. One more stops the parse with
    /// [`Error::Limit`]; a spec is never returned with diagnostics missing.
    pub max_cspec_diagnostics: usize,
    /// Most diagnostic bytes one `.cspec` may produce, counting each diagnostic's message
    /// and path. Exceeding it stops the parse with [`Error::Limit`].
    pub max_cspec_diagnostic_bytes: usize,
    /// Most semantic work units one `.cspec` may use: one per element the compiler-spec
    /// reader visits, one per `sizes` list item and one per pair of `<group>` entries
    /// compared. Exceeding it stops the parse with [`Error::Limit`].
    pub max_cspec_work: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_file_bytes: 8 * 1024 * 1024,
            max_depth: 64,
            max_elements: 250_000,
            max_attributes: 64,
            max_text_bytes: 1024 * 1024,
            max_walk_entries: 2_000_000,
            max_walk_depth: 48,
            max_ldefs_files: 4096,
            max_languages: 20_000,
            max_cspec_diagnostics: 10_000,
            max_cspec_diagnostic_bytes: 2 * 1024 * 1024,
            max_cspec_work: 16_000_000,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct Element {
    pub name: String,
    pub attrs: Vec<(String, String)>,
    pub children: Vec<Element>,
    pub text: String,
    pub line: u32,
}

impl Element {
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug)]
pub(crate) struct XmlError {
    pub line: u32,
    pub message: String,
    pub limit: bool,
}

/// Read a regular, non-symlink file no larger than `limits.max_file_bytes`.
pub(crate) fn read_bounded(path: &Path, limits: &Limits) -> Result<String, Error> {
    let io = |source| Error::Io {
        path: path.to_path_buf(),
        source,
    };
    let meta = fs::symlink_metadata(path).map_err(io)?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(Error::Schema {
            path: path.to_path_buf(),
            line: 0,
            message: "not a regular file (symlinks are not followed)".into(),
        });
    }
    if meta.len() > limits.max_file_bytes {
        return Err(Error::Limit {
            path: path.to_path_buf(),
            message: format!(
                "file is {} bytes, limit is {}",
                meta.len(),
                limits.max_file_bytes
            ),
        });
    }
    let mut bytes = Vec::new();
    fs::File::open(path)
        .map_err(io)?
        .take(limits.max_file_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > limits.max_file_bytes {
        return Err(Error::Limit {
            path: path.to_path_buf(),
            message: format!("file grew beyond {} bytes", limits.max_file_bytes),
        });
    }
    let text = String::from_utf8(bytes).map_err(|e| Error::Xml {
        path: path.to_path_buf(),
        line: 0,
        message: format!("not valid UTF-8: {e}"),
    })?;
    Ok(text
        .strip_prefix('\u{feff}')
        .map(str::to_owned)
        .unwrap_or(text))
}

pub(crate) fn parse_file(path: &Path, limits: &Limits) -> Result<Element, Error> {
    let text = read_bounded(path, limits)?;
    parse_text(&text, path, limits)
}

/// Parse in-memory spec text under the same limits as a file. `label` names the source
/// in errors.
pub(crate) fn parse_text(text: &str, label: &Path, limits: &Limits) -> Result<Element, Error> {
    if text.len() as u64 > limits.max_file_bytes {
        return Err(Error::Limit {
            path: label.to_path_buf(),
            message: format!(
                "text is {} bytes, limit is {}",
                text.len(),
                limits.max_file_bytes
            ),
        });
    }
    parse_document(text, limits).map_err(|e| {
        if e.limit {
            Error::Limit {
                path: label.to_path_buf(),
                message: format!("line {}: {}", e.line, e.message),
            }
        } else {
            Error::Xml {
                path: label.to_path_buf(),
                line: e.line,
                message: e.message,
            }
        }
    })
}

struct LineCounter<'a> {
    src: &'a str,
    offset: usize,
    line: u32,
}

impl LineCounter<'_> {
    fn at(&mut self, offset: usize) -> u32 {
        let offset = offset.min(self.src.len());
        if offset >= self.offset {
            let added = self.src.as_bytes()[self.offset..offset]
                .iter()
                .filter(|&&b| b == b'\n')
                .count();
            self.line = self.line.saturating_add(added as u32);
        } else {
            self.line = 1 + self.src.as_bytes()[..offset]
                .iter()
                .filter(|&&b| b == b'\n')
                .count() as u32;
        }
        self.offset = offset;
        self.line
    }
}

pub(crate) fn parse_document(src: &str, limits: &Limits) -> Result<Element, XmlError> {
    let mut reader = Reader::from_str(src);
    {
        let config = reader.config_mut();
        config.trim_text(false);
        config.check_end_names = true;
        config.expand_empty_elements = false;
        config.allow_unmatched_ends = false;
    }
    let mut lines = LineCounter {
        src,
        offset: 0,
        line: 1,
    };
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    let mut elements = 0usize;

    let fail = |line: u32, message: String| XmlError {
        line,
        message,
        limit: false,
    };
    let over = |line: u32, message: String| XmlError {
        line,
        message,
        limit: true,
    };

    loop {
        let start = reader.buffer_position() as usize;
        let event = match reader.read_event() {
            Ok(event) => event,
            Err(e) => {
                let line = lines.at(reader.error_position() as usize);
                return Err(fail(line, e.to_string()));
            }
        };
        let line = lines.at(start);
        match event {
            Event::Start(ref e) | Event::Empty(ref e) => {
                let empty = matches!(event, Event::Empty(_));
                elements += 1;
                if elements > limits.max_elements {
                    return Err(over(
                        line,
                        format!("more than {} elements", limits.max_elements),
                    ));
                }
                if stack.is_empty() && root.is_some() {
                    return Err(fail(line, "more than one root element".into()));
                }
                let element = open_element(e, line, limits)?;
                if empty {
                    close(element, &mut stack, &mut root);
                } else {
                    stack.push(element);
                    if stack.len() > limits.max_depth {
                        return Err(over(
                            line,
                            format!("nesting deeper than {}", limits.max_depth),
                        ));
                    }
                }
            }
            Event::End(_) => {
                let element = stack
                    .pop()
                    .ok_or_else(|| fail(line, "unmatched end tag".into()))?;
                close(element, &mut stack, &mut root);
            }
            Event::Text(t) => {
                let text = t
                    .xml10_content()
                    .map_err(|e| fail(line, format!("bad text: {e}")))?;
                push_text(&mut stack, &text, line, limits)?;
            }
            Event::CData(c) => {
                let text = c
                    .decode()
                    .map_err(|e| fail(line, format!("bad CDATA: {e}")))?;
                push_text(&mut stack, &text, line, limits)?;
            }
            Event::GeneralRef(r) => {
                let resolved = if r.is_char_ref() {
                    match r.resolve_char_ref() {
                        Ok(Some(ch)) => ch.to_string(),
                        Ok(None) => unreachable!("is_char_ref checked"),
                        Err(e) => return Err(fail(line, format!("bad character reference: {e}"))),
                    }
                } else {
                    let name = r
                        .decode()
                        .map_err(|e| fail(line, format!("bad entity reference: {e}")))?;
                    match quick_xml::escape::resolve_predefined_entity(&name) {
                        Some(s) => s.to_string(),
                        None => {
                            return Err(fail(
                                line,
                                format!(
                                    "undeclared entity `&{name};` (DTD entities are not supported)"
                                ),
                            ));
                        }
                    }
                };
                push_text(&mut stack, &resolved, line, limits)?;
            }
            Event::Decl(d) => {
                if let Some(enc) = d.encoding() {
                    let enc = enc.map_err(|e| fail(line, format!("bad XML declaration: {e}")))?;
                    let enc = String::from_utf8_lossy(&enc).to_ascii_lowercase();
                    if enc != "utf-8" && enc != "utf8" && enc != "us-ascii" {
                        return Err(fail(
                            line,
                            format!("unsupported encoding `{enc}` (only UTF-8 is accepted)"),
                        ));
                    }
                }
            }
            Event::DocType(_) => {
                return Err(fail(
                    line,
                    "DOCTYPE/DTD declarations are not supported".into(),
                ));
            }
            Event::Comment(_) | Event::PI(_) => {}
            Event::Eof => break,
        }
    }
    if let Some(open) = stack.last() {
        return Err(fail(
            lines.at(src.len()),
            format!(
                "unclosed element <{}> opened at line {}",
                open.name, open.line
            ),
        ));
    }
    root.ok_or_else(|| fail(lines.at(src.len()), "document has no root element".into()))
}

fn push_text(
    stack: &mut [Element],
    text: &str,
    line: u32,
    limits: &Limits,
) -> Result<(), XmlError> {
    match stack.last_mut() {
        Some(top) => {
            if top.text.len() + text.len() > limits.max_text_bytes {
                return Err(XmlError {
                    line,
                    message: format!(
                        "text of <{}> exceeds {} bytes",
                        top.name, limits.max_text_bytes
                    ),
                    limit: true,
                });
            }
            top.text.push_str(text);
            Ok(())
        }
        None if text.trim().is_empty() => Ok(()),
        None => Err(XmlError {
            line,
            message: "text outside the root element".into(),
            limit: false,
        }),
    }
}

fn close(element: Element, stack: &mut [Element], root: &mut Option<Element>) {
    match stack.last_mut() {
        Some(parent) => parent.children.push(element),
        None => *root = Some(element),
    }
}

fn open_element(e: &BytesStart<'_>, line: u32, limits: &Limits) -> Result<Element, XmlError> {
    let fail = |message: String| XmlError {
        line,
        message,
        limit: false,
    };
    let name = std::str::from_utf8(e.name().as_ref())
        .map_err(|_| fail("element name is not UTF-8".into()))?
        .to_owned();
    let mut attrs = Vec::new();
    for attr in e.attributes().with_checks(true) {
        let attr = attr.map_err(|err| fail(format!("bad attribute on <{name}>: {err}")))?;
        if attrs.len() >= limits.max_attributes {
            return Err(XmlError {
                line,
                message: format!(
                    "<{name}> has more than {} attributes",
                    limits.max_attributes
                ),
                limit: true,
            });
        }
        let key = std::str::from_utf8(attr.key.as_ref())
            .map_err(|_| fail(format!("attribute name on <{name}> is not UTF-8")))?
            .to_owned();
        if attr.value.len() > limits.max_text_bytes {
            return Err(XmlError {
                line,
                message: format!(
                    "attribute `{key}` on <{name}> exceeds {} bytes",
                    limits.max_text_bytes
                ),
                limit: true,
            });
        }
        let value = attr
            .normalized_value(XmlVersion::Explicit1_0)
            .map_err(|err| {
                fail(format!(
                    "bad value for attribute `{key}` on <{name}>: {err}"
                ))
            })?
            .into_owned();
        attrs.push((key, value));
    }
    Ok(Element {
        name,
        attrs,
        children: Vec::new(),
        text: String::new(),
        line,
    })
}

/// Ghidra `SpecXmlUtils.decodeLong`/`decodeInt` number syntax: `0x` hex, leading `0`
/// octal, otherwise decimal (optionally signed).
pub(crate) fn decode_java_int(text: &str) -> Option<i64> {
    if text == "0" {
        return Some(0);
    }
    if let Some(hex) = text.strip_prefix("0x") {
        return i64::from_str_radix(hex, 16)
            .ok()
            .or_else(|| u64::from_str_radix(hex, 16).ok().map(|v| v as i64));
    }
    if let Some(oct) = text.strip_prefix('0') {
        return i64::from_str_radix(oct, 8).ok();
    }
    if text.starts_with('+') {
        return None;
    }
    text.parse::<i64>().ok()
}

/// Ghidra `SpecXmlUtils.decodeLong` restricted to unsigned values (address offsets).
pub(crate) fn decode_java_unsigned(text: &str) -> Option<u64> {
    if text == "0" {
        return Some(0);
    }
    if let Some(hex) = text.strip_prefix("0x") {
        return u64::from_str_radix(hex, 16).ok();
    }
    if let Some(oct) = text.strip_prefix('0') {
        return u64::from_str_radix(oct, 8).ok();
    }
    if text.starts_with('+') {
        return None;
    }
    text.parse::<u64>().ok()
}

/// Ghidra `SpecXmlUtils.decodeNullableBoolean`: first character y/t/1 is true, n/f/0 is
/// false. Returns `None` for anything else; the caller applies Ghidra's fallback (false
/// for `decodeBoolean(value)`, the given default for `decodeBoolean(value, default)`).
pub(crate) fn decode_java_bool(text: &str) -> Option<bool> {
    match text.as_bytes().first() {
        Some(b'y' | b't' | b'1') => Some(true),
        Some(b'n' | b'f' | b'0') => Some(false),
        _ => None,
    }
}
