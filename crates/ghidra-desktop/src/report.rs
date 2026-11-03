use ghidra_core::{
    Analysis, BinaryImage,
    functions::{DiscoveryLimits, FunctionDiscovery},
    linkage::Linkage,
};
use ghidra_project::{Project, ProjectMetadata};
use std::{
    fs::File,
    io::{Read, Seek},
    path::{Path, PathBuf},
    sync::Arc,
};

pub const INSTRUCTION_LIMIT: usize = 20_000;
const MAX_FILE_SIZE: u64 = ghidra_core::MAX_FILE_SIZE as u64;

pub struct Loaded {
    pub name: String,
    pub image: Arc<BinaryImage>,
    pub analysis: Option<Analysis>,
    pub analysis_error: Option<String>,
    pub analysis_method: &'static str,
    pub functions: Arc<FunctionDiscovery>,
    pub linkage: Arc<Linkage>,
    pub metadata: ProjectMetadata,
    pub project_path: Option<PathBuf>,
}

pub fn load_path(path: &Path) -> Result<Loaded, String> {
    let mut file = File::open(path).map_err(|e| format!("Cannot open {}: {e}", path.display()))?;
    let mut magic = [0_u8; 8];
    let is_project = file.read_exact(&mut magic).is_ok() && &magic == b"GHRS\r\n\x1a\n";
    file.rewind().map_err(|e| e.to_string())?;
    if is_project
        || path
            .extension()
            .is_some_and(|ext| ext.eq_ignore_ascii_case("ghrs"))
    {
        let project = Project::load(path).map_err(|e| e.to_string())?;
        return load_image(
            path.display().to_string(),
            project.image,
            project.metadata,
            Some(path.to_path_buf()),
        );
    }
    if file.metadata().map_err(|e| e.to_string())?.len() > MAX_FILE_SIZE {
        return Err("File exceeds the 128 MiB import limit".into());
    }
    let mut data = Vec::new();
    file.take(MAX_FILE_SIZE + 1)
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    if data.len() as u64 > MAX_FILE_SIZE {
        return Err("File exceeds the 128 MiB import limit".into());
    }
    load_bytes(path.display().to_string(), data)
}

pub fn load_bytes(name: String, bytes: Vec<u8>) -> Result<Loaded, String> {
    let image = Arc::new(BinaryImage::parse(bytes).map_err(|e| e.to_string())?);
    let short_name: String = Path::new(&name)
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| name.clone())
        .chars()
        .take(240)
        .collect();
    let metadata = Project::new(short_name, image.clone()).metadata;
    load_image(name, image, metadata, None)
}

fn load_image(
    name: String,
    image: Arc<BinaryImage>,
    metadata: ProjectMetadata,
    project_path: Option<PathBuf>,
) -> Result<Loaded, String> {
    let is_code = |address: u64| {
        image.sections.iter().any(|s| {
            s.executable && address >= s.address && address - s.address < s.size.min(s.file_size)
        })
    };
    let address = metadata
        .last_address
        .filter(|a| is_code(*a))
        .or_else(|| is_code(image.entry).then_some(image.entry))
        .or_else(|| {
            image
                .sections
                .iter()
                .find(|s| s.executable && s.size.min(s.file_size) > 0)
                .map(|s| s.address)
        });
    let (analysis, analysis_error) = match address {
        Some(address) => match image.disassemble(address, INSTRUCTION_LIMIT) {
            Ok(analysis) => (Some(analysis), None),
            Err(e) => (None, Some(e.to_string())),
        },
        None => (
            None,
            Some("No file-backed executable section was found".into()),
        ),
    };
    let functions = Arc::new(
        image
            .discover_functions(DiscoveryLimits {
                max_functions: 2048,
                max_instructions: 50_000,
            })
            .unwrap_or_else(|e| FunctionDiscovery {
                warnings: vec![e.to_string()],
                ..Default::default()
            }),
    );
    let linkage = Arc::new(image.linkage().unwrap_or_else(|e| Linkage {
        warnings: vec![e.to_string()],
        ..Default::default()
    }));
    Ok(Loaded {
        name,
        image,
        analysis,
        analysis_error,
        analysis_method: "linear sweep",
        functions,
        linkage,
        metadata,
        project_path,
    })
}

pub fn json(loaded: &Loaded) -> Result<String, String> {
    serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": 2,
        "name": loaded.name,
        "format": loaded.image.format,
        "architecture": loaded.image.architecture,
        "bitness": loaded.image.bitness,
        "entry": loaded.image.entry,
        "image_base": loaded.image.image_base,
        "file_size": loaded.image.bytes().len(),
        "sections": loaded.image.sections,
        "symbols": loaded.image.symbols,
        "strings": loaded.image.strings,
        "warnings": loaded.image.warnings,
        "analysis": loaded.analysis,
        "analysis_error": loaded.analysis_error,
        "analysis_method": loaded.analysis_method,
        "instruction_limit": INSTRUCTION_LIMIT,
        "function_discovery": *loaded.functions,
        "linkage": *loaded.linkage,
        "project": loaded.metadata,
    }))
    .map_err(|e| e.to_string())
}
