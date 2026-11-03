//! Bounded catalog walk and asset path resolution confined to the catalog root.

use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

use crate::{Diagnostic, DiagnosticKind, Limits, Severity};

/// Directory names never descended into.
const SKIPPED_DIRS: &[&str] = &[
    ".git",
    ".gradle",
    ".idea",
    ".vscode",
    "target",
    "build",
    "bin",
    "node_modules",
];

/// File extensions recorded in the index (lower case).
const INDEXED_EXTENSIONS: &[&str] = &["ldefs", "slaspec", "sla", "pspec", "cspec", "idx"];

/// Options controlling [`crate::Catalog::discover_with`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct DiscoveryOptions {
    pub limits: Limits,
    /// Also read `.ldefs` below `src/test*` directories (test fixtures such as the
    /// emulator's `mock.ldefs`). Off by default, matching a Ghidra distribution.
    pub include_test_resources: bool,
}

/// Files found under the root, keyed by `/`-joined root-relative path.
#[derive(Debug, Default)]
pub(crate) struct FileIndex {
    pub root: PathBuf,
    files: HashSet<String>,
    by_name: HashMap<String, Vec<String>>,
    pub ldefs: Vec<String>,
}

pub(crate) enum Resolution {
    /// Exactly at the declared location.
    Present(String),
    /// Found elsewhere by unique file name (Ghidra's fallback search).
    FoundBySearch(String),
    /// Not found; carries the expected root-relative location.
    Missing(String),
    Ambiguous(Vec<String>),
    Rejected(String),
}

impl FileIndex {
    pub fn absolute(&self, rel: &str) -> PathBuf {
        let mut path = self.root.clone();
        path.extend(rel.split('/'));
        path
    }

    /// Resolve `declared` relative to the directory `base_dir` (root-relative components).
    pub fn resolve(&self, base_dir: &[String], declared: &str) -> Resolution {
        let parts = match normalize(base_dir, declared) {
            Ok(parts) => parts,
            Err(reason) => return Resolution::Rejected(reason),
        };
        let rel = parts.join("/");
        if self.files.contains(&rel) {
            return Resolution::Present(rel);
        }
        let Some(name) = parts.last() else {
            return Resolution::Rejected("empty path".into());
        };
        let candidates = self.by_name.get(name).cloned().unwrap_or_default();
        match candidates.len() {
            0 => Resolution::Missing(rel),
            1 => Resolution::FoundBySearch(candidates[0].clone()),
            _ => {
                // Prefer candidates whose path ends with the declared relative path.
                let suffix: Vec<&str> = declared
                    .split(['/', '\\'])
                    .filter(|p| !p.is_empty() && *p != "." && *p != "..")
                    .collect();
                let suffix = suffix.join("/");
                let matching: Vec<String> = candidates
                    .iter()
                    .filter(|c| *c == &suffix || c.ends_with(&format!("/{suffix}")))
                    .cloned()
                    .collect();
                if matching.len() == 1 {
                    Resolution::FoundBySearch(matching[0].clone())
                } else {
                    Resolution::Ambiguous(candidates)
                }
            }
        }
    }
}

/// Lexically join `declared` onto `base_dir`, rejecting absolute paths and root escapes.
pub(crate) fn normalize(base_dir: &[String], declared: &str) -> Result<Vec<String>, String> {
    if declared.is_empty() {
        return Err("empty path".into());
    }
    if declared.contains('\0') {
        return Err("path contains NUL".into());
    }
    if declared.starts_with('/')
        || declared.starts_with('\\')
        || declared.contains(':')
        || Path::new(declared).is_absolute()
    {
        return Err(format!(
            "absolute or drive-qualified path `{declared}` is not allowed"
        ));
    }
    let mut parts: Vec<String> = base_dir.to_vec();
    for piece in declared.split(['/', '\\']) {
        match piece {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(format!("path `{declared}` escapes the catalog root"));
                }
            }
            other => parts.push(other.to_owned()),
        }
    }
    if parts.is_empty() {
        return Err(format!("path `{declared}` names the catalog root"));
    }
    Ok(parts)
}

fn is_test_dir(parent: &[String], name: &str) -> bool {
    parent.last().is_some_and(|p| p == "src") && name.starts_with("test")
}

pub(crate) fn walk(
    root: &Path,
    options: &DiscoveryOptions,
    diagnostics: &mut Vec<Diagnostic>,
) -> FileIndex {
    let limits = &options.limits;
    let mut index = FileIndex {
        root: root.to_path_buf(),
        ..FileIndex::default()
    };
    let mut entries = 0usize;
    let mut stack: Vec<(PathBuf, Vec<String>, bool)> =
        vec![(root.to_path_buf(), Vec::new(), false)];
    let mut ldefs_limit_reported = false;

    while let Some((dir, rel, in_test)) = stack.pop() {
        let read = match fs::read_dir(&dir) {
            Ok(read) => read,
            Err(e) => {
                diagnostics.push(Diagnostic {
                    severity: Severity::Warning,
                    kind: DiagnosticKind::Io,
                    path: Some(dir.clone()),
                    line: None,
                    language_id: None,
                    message: format!("cannot read directory: {e}"),
                });
                continue;
            }
        };
        let mut children: Vec<(String, fs::FileType, PathBuf)> = Vec::new();
        for entry in read {
            entries += 1;
            if entries > limits.max_walk_entries {
                diagnostics.push(Diagnostic {
                    severity: Severity::Error,
                    kind: DiagnosticKind::LimitExceeded,
                    path: Some(root.to_path_buf()),
                    line: None,
                    language_id: None,
                    message: format!(
                        "catalog walk stopped after {} directory entries; catalog is incomplete",
                        limits.max_walk_entries
                    ),
                });
                index.ldefs.sort();
                return index;
            }
            let Ok(entry) = entry else { continue };
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let Some(name) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            children.push((name, file_type, entry.path()));
        }
        children.sort_by(|a, b| a.0.cmp(&b.0));
        let mut subdirs = Vec::new();
        for (name, file_type, path) in children {
            if file_type.is_symlink() {
                diagnostics.push(Diagnostic {
                    severity: Severity::Info,
                    kind: DiagnosticKind::SymlinkSkipped,
                    path: Some(path),
                    line: None,
                    language_id: None,
                    message: "symbolic link or junction not followed".into(),
                });
                continue;
            }
            if file_type.is_dir() {
                if SKIPPED_DIRS.contains(&name.as_str()) {
                    continue;
                }
                if rel.len() + 1 > limits.max_walk_depth {
                    diagnostics.push(Diagnostic {
                        severity: Severity::Warning,
                        kind: DiagnosticKind::LimitExceeded,
                        path: Some(path),
                        line: None,
                        language_id: None,
                        message: format!(
                            "directory deeper than {} levels not searched",
                            limits.max_walk_depth
                        ),
                    });
                    continue;
                }
                let test = in_test || is_test_dir(&rel, &name);
                let mut child_rel = rel.clone();
                child_rel.push(name);
                subdirs.push((path, child_rel, test));
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let Some(ext) = Path::new(&name)
                .extension()
                .and_then(|e| e.to_str())
                .map(str::to_ascii_lowercase)
            else {
                continue;
            };
            if !INDEXED_EXTENSIONS.contains(&ext.as_str()) {
                continue;
            }
            let mut file_rel = rel.clone();
            file_rel.push(name.clone());
            let key = file_rel.join("/");
            if ext == "ldefs" && (!in_test || options.include_test_resources) {
                if index.ldefs.len() >= limits.max_ldefs_files {
                    if !ldefs_limit_reported {
                        ldefs_limit_reported = true;
                        diagnostics.push(Diagnostic {
                            severity: Severity::Error,
                            kind: DiagnosticKind::LimitExceeded,
                            path: Some(path),
                            line: None,
                            language_id: None,
                            message: format!(
                                "more than {} .ldefs files; remaining files ignored",
                                limits.max_ldefs_files
                            ),
                        });
                    }
                } else {
                    index.ldefs.push(key.clone());
                }
            }
            index.by_name.entry(name).or_default().push(key.clone());
            index.files.insert(key);
        }
        // Reverse so the stack pops in sorted order.
        stack.extend(subdirs.into_iter().rev());
    }
    index.ldefs.sort();
    for list in index.by_name.values_mut() {
        list.sort();
    }
    index
}

pub(crate) fn rel_parent(rel: &str) -> Vec<String> {
    let mut parts: Vec<String> = rel.split('/').map(str::to_owned).collect();
    parts.pop();
    parts
}
