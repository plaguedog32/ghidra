use super::*;
use std::fs;

mod processor;

fn put16(data: &mut [u8], offset: usize, value: u16) {
    data[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn put32(data: &mut [u8], offset: usize, value: u32) {
    data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn put64(data: &mut [u8], offset: usize, value: u64) {
    data[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

/// Generated PE32+ with .text backed by eight bytes and an unbacked virtual tail.
fn pe_fixture() -> Vec<u8> {
    let mut data = vec![0; 1024];
    data[..2].copy_from_slice(b"MZ");
    put32(&mut data, 0x3c, 0x80);
    data[0x80..0x84].copy_from_slice(b"PE\0\0");
    put16(&mut data, 0x84, 0x8664);
    put16(&mut data, 0x86, 1);
    put16(&mut data, 0x94, 0xf0);
    put16(&mut data, 0x96, 0x22);
    put16(&mut data, 0x98, 0x20b);
    put32(&mut data, 0xa8, 0x1000);
    put64(&mut data, 0xb0, 0x140000000);
    put32(&mut data, 0xb8, 0x1000);
    put32(&mut data, 0xbc, 0x200);
    put32(&mut data, 0xd0, 0x2000);
    put32(&mut data, 0xd4, 0x200);
    put16(&mut data, 0xdc, 3);
    put32(&mut data, 0x104, 16);
    data[0x188..0x18d].copy_from_slice(b".text");
    put32(&mut data, 0x190, 0x1000);
    put32(&mut data, 0x194, 0x1000);
    put32(&mut data, 0x198, 8);
    put32(&mut data, 0x19c, 0x200);
    put32(&mut data, 0x1ac, 0x60000020);
    data[0x200..0x208].copy_from_slice(&[0x55, 0x48, 0x89, 0xe5, 0x31, 0xc0, 0x5d, 0xc3]);
    data
}

fn project() -> Project {
    let image = Arc::new(BinaryImage::parse(pe_fixture()).unwrap());
    let address = image.entry;
    let mut project = Project::new("Portable analysis α".into(), image);
    project.metadata.last_address = Some(address);
    project.metadata.annotations.insert(
        address,
        Annotation {
            label: "entry".into(),
            comment: "A comment with UTF-8: λ and a newline\nSecond line".into(),
            bookmarked: true,
        },
    );
    project
}

fn assert_same_project(expected: &Project, actual: &Project) {
    assert_eq!(expected.image.bytes(), actual.image.bytes());
    assert_eq!(expected.image.entry, actual.image.entry);
    assert_eq!(
        serde_json::to_value(&expected.metadata).unwrap(),
        serde_json::to_value(&actual.metadata).unwrap()
    );
}

fn encode_raw(metadata: &[u8], image: &[u8]) -> Vec<u8> {
    let mut bytes = vec![0; HEADER_SIZE];
    bytes[..8].copy_from_slice(MAGIC);
    put32(&mut bytes, 8, VERSION);
    put32(&mut bytes, 12, metadata.len() as u32);
    put64(&mut bytes, 16, image.len() as u64);
    bytes[24..56].copy_from_slice(&Sha256::digest(image));
    bytes[56..88].copy_from_slice(&Sha256::digest(metadata));
    bytes.extend_from_slice(metadata);
    bytes.extend_from_slice(image);
    bytes
}

#[test]
fn portable_round_trip_preserves_binary_annotations_and_virtual_addresses() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("analysis.ghrs");
    let source = directory.path().join("source.exe");
    fs::write(&source, pe_fixture()).unwrap();
    let mut expected = project();
    // The virtual tail is mapped even though it has no corresponding disk bytes.
    expected
        .metadata
        .annotations
        .insert(expected.image.entry + 0x800, Annotation::default());
    expected.save(&path).unwrap();
    fs::write(&source, b"external source was changed").unwrap();
    fs::remove_file(source).unwrap();
    let actual = Project::load(&path).unwrap();
    assert_same_project(&expected, &actual);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn repeated_save_atomically_replaces_existing_project() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("analysis.ghrs");
    let mut expected = project();
    expected.save(&path).unwrap();
    expected.metadata.name = "Updated project".into();
    expected.metadata.annotations.clear();
    expected.save(&path).unwrap();
    assert_same_project(&expected, &Project::load(&path).unwrap());
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn failed_validation_preserves_existing_destination() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("analysis.ghrs");
    let mut project = project();
    project.save(&path).unwrap();
    let original = fs::read(&path).unwrap();
    project.metadata.name = "x".repeat(MAX_NAME_BYTES + 1);
    assert!(matches!(
        project.save(&path),
        Err(ProjectError::InvalidMetadata(_))
    ));
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn bounded_serialization_preserves_existing_destination() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("analysis.ghrs");
    let mut project = project();
    project.save(&path).unwrap();
    let original = fs::read(&path).unwrap();
    // Legal per-annotation sizes can still exceed the total metadata budget.
    for offset in 0..70 {
        project.metadata.annotations.insert(
            project.image.entry + offset,
            Annotation {
                comment: "x".repeat(MAX_COMMENT_BYTES),
                ..Annotation::default()
            },
        );
    }
    assert!(matches!(
        project.save(&path),
        Err(ProjectError::MetadataTooLarge)
    ));
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn failed_persist_cleans_temporary_and_leaves_destination_intact() {
    let directory = tempfile::tempdir().unwrap();
    let destination = directory.path().join("existing-directory.ghrs");
    fs::create_dir(&destination).unwrap();
    let marker = destination.join("keep.txt");
    fs::write(&marker, "existing data").unwrap();
    assert!(project().save(&destination).is_err());
    assert_eq!(fs::read_to_string(marker).unwrap(), "existing data");
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
}

#[test]
fn checksums_reject_image_and_metadata_corruption() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("analysis.ghrs");
    project().save(&path).unwrap();
    let original = fs::read(&path).unwrap();
    let mut corrupt_image = original.clone();
    *corrupt_image.last_mut().unwrap() ^= 1;
    fs::write(&path, corrupt_image).unwrap();
    assert!(matches!(
        Project::load(&path),
        Err(ProjectError::ChecksumMismatch("embedded binary"))
    ));
    let mut corrupt_metadata = original;
    corrupt_metadata[HEADER_SIZE] ^= 1;
    fs::write(&path, corrupt_metadata).unwrap();
    assert!(matches!(
        Project::load(&path),
        Err(ProjectError::ChecksumMismatch("metadata"))
    ));
}

#[test]
fn invalid_header_lengths_version_truncation_and_trailing_data_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("analysis.ghrs");
    project().save(&path).unwrap();
    let original = fs::read(&path).unwrap();
    let mut unknown_version = original.clone();
    put32(&mut unknown_version, 8, VERSION + 1);
    fs::write(&path, unknown_version).unwrap();
    assert!(matches!(
        Project::load(&path),
        Err(ProjectError::UnsupportedVersion(3))
    ));
    let mut large_metadata = original.clone();
    put32(&mut large_metadata, 12, (MAX_METADATA_SIZE + 1) as u32);
    fs::write(&path, large_metadata).unwrap();
    assert!(matches!(
        Project::load(&path),
        Err(ProjectError::MetadataTooLarge)
    ));
    let mut large_image = original.clone();
    put64(&mut large_image, 16, u64::MAX);
    fs::write(&path, large_image).unwrap();
    assert!(matches!(
        Project::load(&path),
        Err(ProjectError::ImageTooLarge)
    ));
    for length in [0, 1, HEADER_SIZE - 1, HEADER_SIZE, original.len() - 1] {
        fs::write(&path, &original[..length]).unwrap();
        assert!(
            Project::load(&path).is_err(),
            "accepted truncated length {length}"
        );
    }
    let mut trailing = original.clone();
    trailing.push(0);
    fs::write(&path, trailing).unwrap();
    assert!(Project::load(&path).is_err());
    let mut signature = original;
    signature[0] ^= 1;
    fs::write(&path, signature).unwrap();
    assert!(Project::load(&path).is_err());
}

#[test]
fn invalid_metadata_addresses_and_string_limits_are_rejected() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("analysis.ghrs");
    let mut project = project();
    project.metadata.last_address = Some(u64::MAX);
    assert!(project.save(&path).is_err());
    project.metadata.last_address = None;
    project
        .metadata
        .annotations
        .insert(0, Annotation::default());
    assert!(project.save(&path).is_err());
    project.metadata.annotations.remove(&0);
    project
        .metadata
        .annotations
        .get_mut(&project.image.entry)
        .unwrap()
        .label = "λ".repeat(MAX_LABEL_BYTES / 2 + 1);
    assert!(project.save(&path).is_err());
    project
        .metadata
        .annotations
        .get_mut(&project.image.entry)
        .unwrap()
        .label
        .clear();
    project
        .metadata
        .annotations
        .get_mut(&project.image.entry)
        .unwrap()
        .comment = "x".repeat(MAX_COMMENT_BYTES + 1);
    assert!(project.save(&path).is_err());
    assert!(!path.exists());
}

#[test]
fn save_checks_embedded_sections_instead_of_mutable_image_summaries() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("analysis.ghrs");
    let mut project = project();
    Arc::get_mut(&mut project.image).unwrap().sections[0].size = 0x10000;
    project.metadata.last_address = Some(project.image.entry + 0x2000);
    assert!(matches!(
        project.save(&path),
        Err(ProjectError::InvalidMetadata(_))
    ));
    assert!(!path.exists());
}

#[test]
fn embedded_binary_must_parse_even_with_valid_checksums() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("analysis.ghrs");
    let metadata = br#"{"name":"invalid binary","annotations":{},"last_address":null}"#;
    fs::write(&path, encode_raw(metadata, b"not an executable")).unwrap();
    assert!(matches!(Project::load(&path), Err(ProjectError::Image(_))));
}

#[test]
fn metadata_schema_and_duplicate_addresses_are_rejected_on_load() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("analysis.ghrs");
    let image = pe_fixture();
    let address = project().image.entry;
    let annotation = r#"{"label":"entry","comment":"","bookmarked":false}"#;
    let duplicate = format!(
        r#"{{"name":"duplicate","annotations":{{"{address}":{annotation},"{address}":{annotation}}},"last_address":null}}"#
    );
    for metadata in [
        duplicate,
        r#"{"name":"invalid","annotations":{},"last_address":1}"#.into(),
        r#"{"name":"unknown","annotations":{},"last_address":null,"extra":true}"#.into(),
        r#"{"name":"one","name":"two","annotations":{},"last_address":null}"#.into(),
        "[".into(),
    ] {
        fs::write(&path, encode_raw(metadata.as_bytes(), &image)).unwrap();
        assert!(Project::load(&path).is_err(), "accepted {metadata}");
    }
}

#[test]
fn annotation_count_is_bounded_on_save_and_deserialization() {
    let mut project = project();
    // Make the section large enough that count validation, not address validation, fails.
    Arc::get_mut(&mut project.image).unwrap().sections[0].size = 0x10000;
    for offset in 0..=MAX_ANNOTATIONS {
        project
            .metadata
            .annotations
            .insert(project.image.entry + offset as u64, Annotation::default());
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("analysis.ghrs");
    assert!(matches!(
        project.save(&path),
        Err(ProjectError::InvalidMetadata(_))
    ));
    let json = serde_json::to_vec(&project.metadata).unwrap();
    assert!(serde_json::from_slice::<ProjectMetadata>(&json).is_err());
}
