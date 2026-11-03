use ghidra_core::{Analysis, BinaryImage};
use std::{fs::File, io::Read, path::Path, sync::Arc};

pub const INSTRUCTION_LIMIT: usize = 20_000;
const MAX_FILE_SIZE: u64 = 128 * 1024 * 1024;

pub struct Loaded {
    pub name: String,
    pub image: Arc<BinaryImage>,
    pub analysis: Option<Analysis>,
    pub analysis_error: Option<String>,
}

pub fn load_path(path: &Path) -> Result<Loaded, String> {
    let file = File::open(path).map_err(|e| format!("Cannot open {}: {e}", path.display()))?;
    if file.metadata().map_err(|e| e.to_string())?.len() > MAX_FILE_SIZE {
        return Err("File exceeds the 128 MiB limit for this milestone".into());
    }
    let mut data = Vec::new();
    file.take(MAX_FILE_SIZE + 1)
        .read_to_end(&mut data)
        .map_err(|e| e.to_string())?;
    if data.len() as u64 > MAX_FILE_SIZE {
        return Err("File exceeds the 128 MiB limit for this milestone".into());
    }
    load_bytes(path.display().to_string(), data)
}

pub fn load_bytes(name: String, bytes: Vec<u8>) -> Result<Loaded, String> {
    let image = Arc::new(BinaryImage::parse(bytes).map_err(|e| e.to_string())?);
    let address = image
        .sections
        .iter()
        .find(|s| s.executable && image.entry >= s.address && image.entry - s.address < s.file_size)
        .map(|_| image.entry)
        .or_else(|| {
            image
                .sections
                .iter()
                .find(|s| s.executable && s.file_size > 0)
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
    Ok(Loaded {
        name,
        image,
        analysis,
        analysis_error,
    })
}

pub fn json(loaded: &Loaded) -> Result<String, String> {
    serde_json::to_string_pretty(&serde_json::json!({
        "schema_version": 1,
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
        "analysis_method": "Bounded linear sweep in one executable section; not whole-program analysis",
        "instruction_limit": INSTRUCTION_LIMIT,
    })).map_err(|e| e.to_string())
}
