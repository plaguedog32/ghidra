//! Portable, self-contained native projects. This is not Ghidra's `.gpr` format.
//!
//! Versions 1 and 2 share this layout, with all integers little-endian:
//! - 8-byte magic `GHRS\r\n\x1a\n`;
//! - `u32` version, `u32` metadata length, `u64` image length;
//! - 32-byte SHA-256 of the image, then 32-byte SHA-256 of the metadata;
//! - UTF-8 JSON metadata, followed by the unchanged original image bytes.
//!
//! File lengths and limits are checked before allocating variable-length input.
//! Checksums detect corruption, not malicious modification or authorship. Saving
//! writes a sibling temporary file and atomically replaces the destination only
//! after validation, serialization, and flushing succeed.
//! Version 2 adds optional processor identity/context metadata. Version 1 is
//! migrated on load; saving always writes version 2.

mod processor;
pub use processor::*;

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::path::Path;
use std::sync::Arc;

use ghidra_core::{BinaryImage, MAX_FILE_SIZE};
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

const MAGIC: &[u8; 8] = b"GHRS\r\n\x1a\n";
const VERSION: u32 = 2;
const HEADER_SIZE: usize = 88;
pub const MAX_METADATA_SIZE: usize = 4 * 1024 * 1024;
pub const MAX_ANNOTATIONS: usize = 10_000;
pub const MAX_NAME_BYTES: usize = 1024;
pub const MAX_LABEL_BYTES: usize = 256;
pub const MAX_COMMENT_BYTES: usize = 65_536;

/// A project owns the original binary; saving never depends on its source path.
#[derive(Debug)]
pub struct Project {
    pub metadata: ProjectMetadata,
    pub image: Arc<BinaryImage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectMetadata {
    pub name: String,
    #[serde(deserialize_with = "deserialize_annotations")]
    pub annotations: BTreeMap<u64, Annotation>,
    pub last_address: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub processor: Option<ProcessorConfiguration>,
}

/// Keep the old schema strict: a v2 field must not be interpreted under a v1
/// header, and existing v1 files migrate without inventing a language choice.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataV1 {
    name: String,
    #[serde(deserialize_with = "deserialize_annotations")]
    annotations: BTreeMap<u64, Annotation>,
    last_address: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Annotation {
    pub label: String,
    pub comment: String,
    pub bookmarked: bool,
}

#[derive(Debug, Error)]
pub enum ProjectError {
    #[error("project I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("invalid project: {0}")]
    InvalidFormat(&'static str),
    #[error("unsupported project version {0}; supported versions are 1 and 2")]
    UnsupportedVersion(u32),
    #[error("project metadata exceeds the 4 MiB limit")]
    MetadataTooLarge,
    #[error("embedded binary exceeds the 128 MiB limit")]
    ImageTooLarge,
    #[error("project checksum does not match the {0}")]
    ChecksumMismatch(&'static str),
    #[error("invalid project metadata: {0}")]
    InvalidMetadata(String),
    #[error("project metadata JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid embedded binary: {0}")]
    Image(#[from] ghidra_core::Error),
}

impl Project {
    /// Creates an unsaved project. Metadata is validated by `save`, not truncated.
    pub fn new(name: String, image: Arc<BinaryImage>) -> Self {
        Self {
            metadata: ProjectMetadata {
                name,
                annotations: BTreeMap::new(),
                last_address: None,
                processor: None,
            },
            image,
        }
    }

    pub fn load(path: &Path) -> Result<Self, ProjectError> {
        let mut file = File::open(path)?;
        let file_info = file.metadata()?;
        if !file_info.is_file() {
            return Err(ProjectError::InvalidFormat("a regular file is required"));
        }
        let max_size = (HEADER_SIZE + MAX_METADATA_SIZE + MAX_FILE_SIZE) as u64;
        if file_info.len() < HEADER_SIZE as u64 || file_info.len() > max_size {
            return Err(ProjectError::InvalidFormat("file length is out of bounds"));
        }
        let mut header = [0_u8; HEADER_SIZE];
        file.read_exact(&mut header)?;
        if &header[..8] != MAGIC {
            return Err(ProjectError::InvalidFormat(
                "signature is not a .ghrs project",
            ));
        }
        let version = u32::from_le_bytes(header[8..12].try_into().unwrap());
        if !matches!(version, 1 | VERSION) {
            return Err(ProjectError::UnsupportedVersion(version));
        }
        let metadata_len = u32::from_le_bytes(header[12..16].try_into().unwrap()) as usize;
        let image_len = u64::from_le_bytes(header[16..24].try_into().unwrap());
        if metadata_len > MAX_METADATA_SIZE {
            return Err(ProjectError::MetadataTooLarge);
        }
        if image_len > MAX_FILE_SIZE as u64 {
            return Err(ProjectError::ImageTooLarge);
        }
        let expected_size = (HEADER_SIZE as u64)
            .checked_add(metadata_len as u64)
            .and_then(|size| size.checked_add(image_len))
            .ok_or(ProjectError::InvalidFormat("length arithmetic overflow"))?;
        if expected_size != file_info.len() {
            return Err(ProjectError::InvalidFormat(
                "truncated or trailing project data",
            ));
        }
        let mut metadata_bytes = vec![0; metadata_len];
        let mut image_bytes = vec![0; image_len as usize];
        file.read_exact(&mut metadata_bytes)?;
        file.read_exact(&mut image_bytes)?;
        if file.read(&mut [0_u8; 1])? != 0 {
            return Err(ProjectError::InvalidFormat("trailing project data"));
        }
        if Sha256::digest(&image_bytes).as_slice() != &header[24..56] {
            return Err(ProjectError::ChecksumMismatch("embedded binary"));
        }
        if Sha256::digest(&metadata_bytes).as_slice() != &header[56..88] {
            return Err(ProjectError::ChecksumMismatch("metadata"));
        }
        let metadata = match version {
            1 => {
                let old: MetadataV1 = serde_json::from_slice(&metadata_bytes)?;
                ProjectMetadata {
                    name: old.name,
                    annotations: old.annotations,
                    last_address: old.last_address,
                    processor: None,
                }
            }
            _ => serde_json::from_slice(&metadata_bytes)?,
        };
        let image = Arc::new(BinaryImage::parse(image_bytes)?);
        validate_metadata(&metadata, &image)?;
        Ok(Self { metadata, image })
    }

    pub fn save(&self, path: &Path) -> Result<(), ProjectError> {
        let image_bytes = self.image.bytes();
        if image_bytes.len() > MAX_FILE_SIZE {
            return Err(ProjectError::ImageTooLarge);
        }
        // BinaryImage's public inspection fields can be edited by a caller with
        // exclusive Arc ownership. Validate addresses against the bytes that will
        // actually be persisted, rather than trusting those mutable summaries.
        let embedded_image = BinaryImage::parse(image_bytes.to_vec())?;
        validate_metadata(&self.metadata, &embedded_image)?;
        let mut metadata_writer = BoundedMetadata::default();
        if let Err(error) = serde_json::to_writer(&mut metadata_writer, &self.metadata) {
            return if metadata_writer.limit_reached {
                Err(ProjectError::MetadataTooLarge)
            } else {
                Err(ProjectError::Json(error))
            };
        }
        let metadata_bytes = metadata_writer.bytes;
        let mut header = [0_u8; HEADER_SIZE];
        header[..8].copy_from_slice(MAGIC);
        header[8..12].copy_from_slice(&VERSION.to_le_bytes());
        header[12..16].copy_from_slice(&(metadata_bytes.len() as u32).to_le_bytes());
        header[16..24].copy_from_slice(&(image_bytes.len() as u64).to_le_bytes());
        header[24..56].copy_from_slice(&Sha256::digest(image_bytes));
        header[56..88].copy_from_slice(&Sha256::digest(&metadata_bytes));

        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let mut temporary = tempfile::Builder::new()
            .prefix(".ghrs-")
            .suffix(".tmp")
            .tempfile_in(parent)?;
        temporary.write_all(&header)?;
        temporary.write_all(&metadata_bytes)?;
        temporary.write_all(image_bytes)?;
        temporary.flush()?;
        temporary.as_file().sync_all()?;
        temporary
            .persist(path)
            .map_err(|error| ProjectError::Io(error.error))?;
        Ok(())
    }
}

fn validate_metadata(metadata: &ProjectMetadata, image: &BinaryImage) -> Result<(), ProjectError> {
    let invalid = |message: &str| ProjectError::InvalidMetadata(message.to_owned());
    if metadata.name.len() > MAX_NAME_BYTES {
        return Err(invalid("name exceeds 1024 UTF-8 bytes"));
    }
    if metadata.annotations.len() > MAX_ANNOTATIONS {
        return Err(invalid("more than 10000 annotations"));
    }
    if let Some(processor) = &metadata.processor {
        processor.validate()?;
    }
    let mapped = |address: u64| {
        image.sections.iter().any(|section| {
            section.address <= address
                && section
                    .address
                    .checked_add(section.size)
                    .is_some_and(|end| address < end)
        })
    };
    if metadata
        .last_address
        .is_some_and(|address| !mapped(address))
    {
        return Err(invalid("last address is not mapped in the embedded binary"));
    }
    for (address, annotation) in &metadata.annotations {
        if !mapped(*address) {
            return Err(invalid(
                "annotation address is not mapped in the embedded binary",
            ));
        }
        if annotation.label.len() > MAX_LABEL_BYTES {
            return Err(invalid("annotation label exceeds 256 UTF-8 bytes"));
        }
        if annotation.comment.len() > MAX_COMMENT_BYTES {
            return Err(invalid("annotation comment exceeds 65536 UTF-8 bytes"));
        }
    }
    Ok(())
}

fn deserialize_annotations<'de, D>(deserializer: D) -> Result<BTreeMap<u64, Annotation>, D::Error>
where
    D: Deserializer<'de>,
{
    struct AnnotationVisitor;
    impl<'de> Visitor<'de> for AnnotationVisitor {
        type Value = BTreeMap<u64, Annotation>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("a map of unique mapped addresses to annotations")
        }

        fn visit_map<M>(self, mut access: M) -> Result<Self::Value, M::Error>
        where
            M: MapAccess<'de>,
        {
            if access
                .size_hint()
                .is_some_and(|size| size > MAX_ANNOTATIONS)
            {
                return Err(de::Error::custom("more than 10000 annotations"));
            }
            let mut annotations = BTreeMap::new();
            while let Some((address, annotation)) = access.next_entry::<u64, Annotation>()? {
                if annotations.len() == MAX_ANNOTATIONS {
                    return Err(de::Error::custom("more than 10000 annotations"));
                }
                if annotations.insert(address, annotation).is_some() {
                    return Err(de::Error::custom("duplicate annotation address"));
                }
            }
            Ok(annotations)
        }
    }
    deserializer.deserialize_map(AnnotationVisitor)
}

#[derive(Default)]
struct BoundedMetadata {
    bytes: Vec<u8>,
    limit_reached: bool,
}

impl Write for BoundedMetadata {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.bytes.len().saturating_add(buffer.len()) > MAX_METADATA_SIZE {
            self.limit_reached = true;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "metadata limit exceeded",
            ));
        }
        self.bytes.extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
