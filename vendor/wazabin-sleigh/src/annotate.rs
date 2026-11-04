//! Section annotations read from specification comments.
//!
//! A SLEIGH specification says what an instruction *does*, never what group it
//! belongs to. Grouping is real information — a coverage report wants to say
//! "x87 is 40% done, AVX-512 is 2% done", and a specification split across
//! twenty include files already knows the answer — but there is nowhere in the
//! language to write it down.
//!
//! This module reads it from a comment convention instead, so a specification
//! carrying annotations still compiles unchanged with Ghidra's own `sleigh`:
//!
//! ```text
//! #@family x87
//! ```
//!
//! A marker line applies to every constructor defined after it **in the same
//! physical file**, until the next marker with the same key in that file. A
//! file with one marker at the top annotates itself wholesale; a file that
//! covers several groups marks each section. Constructors before any marker,
//! and files with none, are simply unannotated.
//!
//! Nothing here is x86-specific, and `family` is not a privileged key: the key
//! is a parameter, so a specification can carry `#@family`, `#@extension`,
//! `#@since`, or whatever else a consumer wants to bucket by.
//!
//! ```no_run
//! use sleigh::{Compiler, SourceDb, annotate};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut sources = SourceDb::new();
//! let root = sources.add_file_from_path("x86-64.slaspec")?;
//! let spec = Compiler::new(&mut sources).compile(root)?;
//!
//! let families = annotate::annotate(&spec, &sources, "family");
//! assert_eq!(families.get("instruction", 0), Some("base"));
//! # Ok(())
//! # }
//! ```

use std::collections::HashMap;

use crate::{
    runtime::CompiledSpec,
    source::{FileId, SourceDb},
};

/// The annotation carried by each constructor, keyed by `(table, index)`.
///
/// The key pair is the same one the decoder reports through
/// [`ConstructorMatch`](crate::ConstructorMatch), so a consumer that records
/// which constructors it reached can look each one up directly.
#[derive(Debug, Clone, Default)]
pub struct Annotations {
    tables: HashMap<Box<str>, HashMap<usize, Box<str>>>,
}

impl Annotations {
    /// The annotation on one constructor, or `None` if it has none.
    pub fn get(&self, table: &str, index: usize) -> Option<&str> {
        self.tables
            .get(table)?
            .get(&index)
            .map(|value| value.as_ref())
    }

    /// Every annotated constructor, as `(table, index, value)`.
    ///
    /// The order is unspecified.
    pub fn iter(&self) -> impl Iterator<Item = (&str, usize, &str)> {
        self.tables.iter().flat_map(|(table, indices)| {
            indices
                .iter()
                .map(move |(index, value)| (table.as_ref(), *index, value.as_ref()))
        })
    }

    /// How many constructors carry an annotation.
    pub fn len(&self) -> usize {
        self.tables.values().map(HashMap::len).sum()
    }

    /// Whether no constructor carries an annotation.
    pub fn is_empty(&self) -> bool {
        self.tables.values().all(HashMap::is_empty)
    }
}

/// One `#@key value` marker and where it starts applying.
struct Marker {
    /// Byte offset of the marker line within its file.
    start: usize,
    value: Box<str>,
}

/// Reads `#@<key>` markers out of `sources` and attaches them to `spec`'s
/// constructors.
///
/// Constructors defined in a file with no marker, or before its first marker,
/// are left unannotated rather than guessed at.
pub fn annotate(spec: &CompiledSpec, sources: &SourceDb, key: &str) -> Annotations {
    let markers = collect_markers(sources, key);
    if markers.is_empty() {
        return Annotations::default();
    }

    let mut tables: HashMap<Box<str>, HashMap<usize, Box<str>>> = HashMap::new();
    for tree in spec.inner().trees.iter() {
        for (index, constructor) in tree.constructors.iter().enumerate() {
            let file = FileId::from_index(constructor.src.file as usize);
            let Some(value) = lookup(&markers, file, constructor.src.start as usize) else {
                continue;
            };
            tables
                .entry(tree.name.clone())
                .or_default()
                .insert(index, value.into());
        }
    }

    Annotations { tables }
}

/// Scans every file for `#@<key> <value>` comment lines.
fn collect_markers(sources: &SourceDb, key: &str) -> HashMap<FileId, Vec<Marker>> {
    let mut markers: HashMap<FileId, Vec<Marker>> = HashMap::new();
    for (file, _path, text) in sources.files() {
        let mut offset = 0;
        for line in text.split_inclusive('\n') {
            if let Some(value) = parse_marker(line, key) {
                markers.entry(file).or_default().push(Marker {
                    start: offset,
                    value: value.into(),
                });
            }
            offset += line.len();
        }
    }
    markers
}

/// Extracts the value of a `#@<key> <value>` line, if that is what `line` is.
fn parse_marker<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.trim_start().strip_prefix("#@")?;
    let rest = rest.strip_prefix(key)?;
    // `#@familytree` is not a `family` marker.
    if !rest.starts_with([' ', '\t']) {
        return None;
    }
    let value = rest.trim();
    (!value.is_empty()).then_some(value)
}

/// The value of the last marker at or before `offset` in `file`.
fn lookup(markers: &HashMap<FileId, Vec<Marker>>, file: FileId, offset: usize) -> Option<&str> {
    let file_markers = markers.get(&file)?;
    let index = file_markers.partition_point(|marker| marker.start <= offset);
    index
        .checked_sub(1)
        .map(|index| file_markers[index].value.as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_marker_line() {
        assert_eq!(parse_marker("#@family x87\n", "family"), Some("x87"));
        assert_eq!(parse_marker("  \t#@family  x87 \n", "family"), Some("x87"));
        assert_eq!(parse_marker("#@extension avx512\n", "family"), None);
        assert_eq!(parse_marker("#@familytree x87\n", "family"), None);
        assert_eq!(parse_marker("#@family\n", "family"), None);
        assert_eq!(parse_marker("# @family x87\n", "family"), None);
        assert_eq!(parse_marker(":NOP is op=0 { }\n", "family"), None);
    }

    #[test]
    fn a_marker_applies_from_its_own_line_onwards() {
        let mut sources = SourceDb::new();
        let file = sources.add_file("markers.sinc", "");
        let markers = HashMap::from([(
            file,
            vec![
                Marker {
                    start: 10,
                    value: "base".into(),
                },
                Marker {
                    start: 40,
                    value: "x87".into(),
                },
            ],
        )]);
        assert_eq!(lookup(&markers, file, 0), None);
        assert_eq!(lookup(&markers, file, 10), Some("base"));
        assert_eq!(lookup(&markers, file, 39), Some("base"));
        assert_eq!(lookup(&markers, file, 40), Some("x87"));
        assert_eq!(lookup(&markers, file, 4000), Some("x87"));
    }

    #[test]
    fn annotates_constructors_by_section() {
        let mut sources = SourceDb::new();
        let root = sources.add_file(
            "tiny.slaspec",
            "define endian=little;
             define space ram type=ram_space size=4 default;
             define space register type=register_space size=4;
             define register offset=0 size=4 [ r0 ];
             define token instr(8) op=(0,7);
             #@family base
             :nop is op=0 { }
             :halt is op=1 { }
             #@family float
             :fnop is op=2 { }",
        );
        let spec = crate::Compiler::new(&mut sources)
            .compile(root)
            .expect("tiny spec compiles");

        let families = annotate(&spec, &sources, "family");
        assert_eq!(families.len(), 3);
        assert_eq!(families.get("instruction", 0), Some("base"));
        assert_eq!(families.get("instruction", 1), Some("base"));
        assert_eq!(families.get("instruction", 2), Some("float"));
    }

    #[test]
    fn an_unmarked_specification_annotates_nothing() {
        let mut sources = SourceDb::new();
        let root = sources.add_file(
            "tiny.slaspec",
            "define endian=little;
             define space ram type=ram_space size=4 default;
             define space register type=register_space size=4;
             define register offset=0 size=4 [ r0 ];
             define token instr(8) op=(0,7);
             :nop is op=0 { }",
        );
        let spec = crate::Compiler::new(&mut sources)
            .compile(root)
            .expect("tiny spec compiles");

        assert!(annotate(&spec, &sources, "family").is_empty());
    }
}
