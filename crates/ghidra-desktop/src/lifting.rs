//! Persistent, coalescing source-lifting worker. Imported bytes are data only.
use ghidra_core::BinaryImage;
use ghidra_pcode::{AddressSpace, PcodeInstruction, SpaceId, SpaceKind, Varnode};
use ghidra_sleigh::SleighLanguage;
use std::{
    collections::BTreeMap,
    path::PathBuf,
    sync::{Arc, Mutex, mpsc},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LanguageConfig {
    pub source: PathBuf,
    pub context: BTreeMap<String, u64>,
    /// Explicit reload invalidates the compiled-source cache.
    pub revision: u64,
}

pub struct LiftRequest {
    pub id: u64,
    pub generation: u64,
    pub config: LanguageConfig,
    pub address: u64,
    pub bytes: Vec<u8>,
    pub defaults: BTreeMap<String, u64>,
}

pub struct LiftResponse {
    pub id: u64,
    pub generation: u64,
    pub address: u64,
    pub result: Result<LiftedView, String>,
}

pub struct LiftedView {
    pub instruction: PcodeInstruction,
    pub disassembly: String,
    pub next_address: u64,
    pub delay_slots: usize,
    pub rows: Vec<String>,
    pub json: String,
    pub cache_hit: bool,
}

pub struct LiftingWorker {
    latest: Arc<Mutex<Option<LiftRequest>>>,
    wake: mpsc::SyncSender<()>,
    results: mpsc::Receiver<LiftResponse>,
}

impl LiftingWorker {
    pub fn spawn() -> Self {
        let latest = Arc::new(Mutex::new(None::<LiftRequest>));
        let (wake, signal) = mpsc::sync_channel(1);
        let (send_result, results) = mpsc::sync_channel(1);
        let work = latest.clone();
        std::thread::spawn(move || {
            let mut compiler = CompilerCache::default();
            while signal.recv().is_ok() {
                let request = match work.lock() {
                    Ok(mut work) => work.take(),
                    Err(_) => break,
                };
                let Some(request) = request else {
                    continue;
                };
                let result = compiler.lift(&request);
                if send_result
                    .send(LiftResponse {
                        id: request.id,
                        generation: request.generation,
                        address: request.address,
                        result,
                    })
                    .is_err()
                {
                    break;
                }
            }
        });
        Self {
            latest,
            wake,
            results,
        }
    }

    /// A queued request is replaced by the newest selection, bounding both the
    /// pending bytes and compilation work when the user navigates quickly.
    pub fn request(&self, request: LiftRequest) -> Result<(), String> {
        if request.bytes.is_empty() || request.bytes.len() > ghidra_sleigh::MAX_DECODE_BYTES {
            return Err("Lift requires 1..4096 file-backed instruction bytes".into());
        }
        *self
            .latest
            .lock()
            .map_err(|_| "Lifting worker state is unavailable")? = Some(request);
        match self.wake.try_send(()) {
            Ok(()) | Err(mpsc::TrySendError::Full(())) => Ok(()),
            Err(mpsc::TrySendError::Disconnected(())) => Err("Lifting worker stopped".into()),
        }
    }

    pub fn try_recv(&self) -> Result<Option<LiftResponse>, String> {
        match self.results.try_recv() {
            Ok(result) => Ok(Some(result)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err("Lifting worker stopped".into()),
        }
    }
}

struct Compiled {
    config: LanguageConfig,
    generation: u64,
    language: SleighLanguage,
    names: BTreeMap<(SpaceId, u64, u32), String>,
}

#[derive(Default)]
struct CompilerCache {
    compiled: Option<Compiled>,
}

impl CompilerCache {
    fn lift(&mut self, request: &LiftRequest) -> Result<LiftedView, String> {
        let cache_hit = self
            .compiled
            .as_ref()
            .is_some_and(|cache| cache.config == request.config);
        if !cache_hit {
            let language =
                SleighLanguage::from_spec(&request.config.source, &request.config.context)
                    .map_err(|e| e.to_string())?;
            let mut names = BTreeMap::new();
            for register in language.registers().map_err(|e| e.to_string())? {
                names
                    .entry((register.space, register.offset, register.size))
                    .or_insert(register.name);
            }
            self.compiled = Some(Compiled {
                config: request.config.clone(),
                generation: request.generation,
                language,
                names,
            });
        }
        let cache = self.compiled.as_mut().expect("successful compilation");
        if cache.generation != request.generation {
            cache.language.reset_context();
            cache.generation = request.generation;
        }
        let decoded =
            cache
                .language
                .decode_with_defaults(request.address, &request.bytes, &request.defaults);
        let poisoned = matches!(decoded, Err(ghidra_sleigh::Error::DependencyPanic(_)));
        let result = decoded.map_err(|e| e.to_string()).and_then(|decoded| {
            let spaces = cache.language.spaces();
            let rows = decoded
                .instruction
                .ops
                .iter()
                .map(|op| {
                    let args = op
                        .inputs
                        .iter()
                        .map(|node| varnode_text(node, spaces, &cache.names))
                        .collect::<Vec<_>>()
                        .join(", ");
                    let output = op
                        .output
                        .map(|node| format!("{} = ", varnode_text(&node, spaces, &cache.names)))
                        .unwrap_or_default();
                    format!("{output}{}({args})", op.opcode.mnemonic())
                })
                .collect();
            #[derive(serde::Serialize)]
            struct Export<'a> {
                schema_version: u32,
                spaces: &'a [AddressSpace],
                code_space: SpaceId,
                userops: &'a [String],
                instruction: &'a PcodeInstruction,
            }
            let json = serde_json::to_string_pretty(&Export {
                schema_version: 1,
                spaces,
                code_space: cache.language.code_space(),
                userops: cache.language.userops(),
                instruction: &decoded.instruction,
            })
            .map_err(|e| e.to_string())?;
            Ok(LiftedView {
                instruction: decoded.instruction,
                disassembly: decoded.text,
                next_address: decoded.next_address,
                delay_slots: decoded.delay_slots.len(),
                rows,
                json,
                cache_hit,
            })
        });
        if poisoned {
            self.compiled = None;
        }
        result
    }
}

fn varnode_text(
    node: &Varnode,
    spaces: &[AddressSpace],
    names: &BTreeMap<(SpaceId, u64, u32), String>,
) -> String {
    if let Some(name) = names.get(&(node.space, node.offset, node.size)) {
        return format!("{name}:{}", node.size);
    }
    let space = spaces.iter().find(|s| s.id == node.space);
    if space.is_some_and(|s| s.kind == SpaceKind::Constant) {
        return format!("0x{:X}:{}", node.offset, node.size);
    }
    format!(
        "{}[0x{:X}]:{}",
        space.map(|s| s.name.as_str()).unwrap_or("unknown"),
        node.offset,
        node.size
    )
}

pub fn instruction_window(image: &BinaryImage, address: u64) -> Result<Vec<u8>, String> {
    let mut window = None;
    for section in image.sections.iter().filter(|s| s.executable) {
        let Some(delta) = address.checked_sub(section.address) else {
            continue;
        };
        let backed = section.size.min(section.file_size);
        if delta >= backed {
            continue;
        }
        let start = section
            .file_offset
            .checked_add(delta)
            .ok_or("File offset overflow")?;
        let count = (backed - delta).min(ghidra_sleigh::MAX_DECODE_BYTES as u64);
        let end = start.checked_add(count).ok_or("File range overflow")?;
        let bytes = image
            .bytes()
            .get(
                usize::try_from(start).map_err(|_| "File offset overflow")?
                    ..usize::try_from(end).map_err(|_| "File offset overflow")?,
            )
            .ok_or("Executable section extends beyond file bytes")?;
        if window.is_some() {
            return Err(format!(
                "Executable address {address:X} has overlapping section mappings"
            ));
        }
        window = Some(bytes.to_vec());
    }
    window.ok_or_else(|| format!("Address {address:X} is not in file-backed executable memory"))
}

#[cfg(test)]
mod tests;
