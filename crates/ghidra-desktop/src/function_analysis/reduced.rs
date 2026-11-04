//! Lazy simplification of a completed function analysis for the desktop's
//! reduced-expression view. A dedicated worker builds `PcodeSimplification`
//! from the view's existing constant facts (no SLEIGH compilation, lifting or
//! SSA work) and serializes the reduced document only when a copy is
//! requested. Like the function worker it runs one request and keeps at most
//! one replaceable queued request; each response is delivered through a
//! one-slot channel.
use std::sync::{Arc, Mutex, mpsc};

use ghidra_analysis::{
    ExpressionAddress, ExpressionDefinition, ExpressionKind, PcodeConstants, PcodeSimplification,
    TermKind,
};
use ghidra_ssa::{StatementId, ValueId};

use super::{FunctionView, MAX_DOCUMENT, RequestKey};

/// A reduced copy is the `--analyze-function --simplify` output without its
/// final newline, so it obeys the command's 64 MiB cap including the newline.
pub(crate) const EXPORT_LIMIT: usize = MAX_DOCUMENT;

const PANICKED: &str = "Simplification worker panicked; the base analysis is unchanged";
const STOPPED: &str = "Simplification worker stopped";
/// No executed operation contains the node.
const NO_OPERATION: u32 = u32::MAX;

/// One immutable simplification snapshot and the lists its virtual rows
/// need, collected once on the worker rather than per frame.
#[derive(Debug)]
pub(crate) struct ReducedView {
    pub simplification: PcodeSimplification,
    /// SSA values whose uses receive a literal or a propagated term rather
    /// than their own SSA identity, ascending.
    pub reduced_values: Vec<ValueId>,
    /// For every expression node, the position in `operations()` order of
    /// the first executed operation whose terms contain it.
    node_operations: Vec<u32>,
}

impl ReducedView {
    /// Simplifies the supplied facts with the shared command limits. The
    /// result keeps that exact allocation.
    pub(crate) fn new(constants: Arc<PcodeConstants>) -> Result<Self, String> {
        let simplification = crate::simplification_report::build(constants.clone())?;
        if !Arc::ptr_eq(simplification.constants(), &constants) {
            return Err("Simplification belongs to a different function snapshot".into());
        }
        let mut reduced_values = Vec::new();
        for id in 0..simplification.analysis().ssa().values().len() {
            let value = ValueId(id);
            let term = simplification
                .value_term(value)
                .and_then(|term| simplification.term(term))
                .map_err(|e| e.to_string())?;
            if !matches!(term.kind, TermKind::Leaf(leaf) if leaf == value) {
                reduced_values.push(value);
            }
        }
        let node_operations = node_operations(&simplification)?;
        Ok(Self {
            simplification,
            reduced_values,
            node_operations,
        })
    }

    /// The first executed operation (from `operations`, the expression
    /// operation statements in order) whose terms contain `node`.
    pub(crate) fn node_statement(
        &self,
        operations: &[StatementId],
        node: ghidra_analysis::ExpressionId,
    ) -> Option<StatementId> {
        let index = *self.node_operations.get(node.0)?;
        (index != NO_OPERATION)
            .then(|| operations.get(index as usize).copied())
            .flatten()
    }
}

/// Assigns every node to the first executed operation that reaches it from
/// its output, operands or defined memory state. Each node and child edge is
/// visited once; the snapshot's expression limits bound the traversal.
fn node_operations(s: &PcodeSimplification) -> Result<Vec<u32>, String> {
    let e = s.expressions();
    let mut owners = vec![NO_OPERATION; e.nodes().len()];
    let mut pending = Vec::new();
    for (index, operation) in e.operations().enumerate() {
        if !s
            .constants()
            .is_statement_executable(operation.statement)
            .map_err(|e| e.to_string())?
        {
            continue;
        }
        let index = u32::try_from(index)
            .ok()
            .filter(|&i| i != NO_OPERATION)
            .ok_or("Too many expression operations")?;
        pending.extend(operation.output);
        pending.extend(operation.operands.iter().filter_map(|o| o.expression()));
        if let Ok(renamed) = e.analysis().ssa().statement(operation.statement) {
            for value in renamed.defs() {
                if let Ok(ExpressionDefinition::Expression(root)) = e.definition(*value) {
                    pending.push(*root);
                }
            }
        }
        while let Some(node) = pending.pop() {
            let owner = owners
                .get_mut(node.0)
                .ok_or("Expression operation references an unknown node")?;
            if *owner != NO_OPERATION {
                continue;
            }
            *owner = index;
            let pointer = |address: &ExpressionAddress| match address {
                ExpressionAddress::Pointer { value, .. } => Some(*value),
                ExpressionAddress::ByteOffset(_) => None,
            };
            match &e.node(node).map_err(|e| e.to_string())?.kind {
                ExpressionKind::Constant(_) | ExpressionKind::SsaValue(_) => {}
                ExpressionKind::Join(pieces) => pending.extend(pieces.iter().map(|p| p.value)),
                ExpressionKind::Extract { value, .. } => pending.push(*value),
                ExpressionKind::Pure { inputs, .. } => pending.extend(inputs),
                ExpressionKind::ReadMemory { address, .. } => pending.extend(pointer(address)),
                ExpressionKind::WriteMemory { address, value, .. } => {
                    pending.extend(pointer(address));
                    pending.push(*value);
                }
            }
        }
    }
    Ok(owners)
}

/// Builds the reduced snapshot of a completed function view.
pub(crate) fn build(view: &FunctionView) -> Result<ReducedView, String> {
    let reduced = ReducedView::new(view.constants.clone())?;
    let s = &reduced.simplification;
    if !Arc::ptr_eq(s.expressions(), &view.expressions)
        || !Arc::ptr_eq(s.analysis(), &view.analysis)
    {
        return Err("Simplification belongs to a different function snapshot".into());
    }
    Ok(reduced)
}

/// The reduced analysis document: exactly the function command's
/// `--simplify` output without its final newline.
pub(crate) fn export(
    view: &FunctionView,
    reduced: &ReducedView,
    maximum: usize,
) -> Result<String, String> {
    let json = super::simplified_json(view, &reduced.simplification, maximum)?;
    String::from_utf8(json).map_err(|e| e.to_string())
}

pub(crate) enum ReducedTask {
    Build,
    /// Serialize this snapshot within `maximum` bytes.
    Export {
        snapshot: Arc<ReducedView>,
        maximum: usize,
    },
    /// Exercises the worker's panic recovery.
    #[cfg(test)]
    Panic,
}

pub(crate) struct ReducedRequest {
    pub id: u64,
    /// The function result `view` was accepted under.
    pub source: RequestKey,
    pub view: Arc<FunctionView>,
    pub task: ReducedTask,
}

pub(crate) enum ReducedOutcome {
    Built(Result<Arc<ReducedView>, String>),
    Exported {
        snapshot: Arc<ReducedView>,
        result: Result<String, String>,
    },
}

pub(crate) struct ReducedResponse {
    pub id: u64,
    pub source: RequestKey,
    pub outcome: ReducedOutcome,
}

fn run(view: &FunctionView, task: &ReducedTask) -> ReducedOutcome {
    match task {
        ReducedTask::Build => ReducedOutcome::Built(build(view).map(Arc::new)),
        ReducedTask::Export { snapshot, maximum } => ReducedOutcome::Exported {
            snapshot: snapshot.clone(),
            result: export(view, snapshot, *maximum),
        },
        #[cfg(test)]
        ReducedTask::Panic => panic!("requested worker panic"),
    }
}

pub(crate) struct ReducedWorker {
    latest: Arc<Mutex<Option<ReducedRequest>>>,
    wake: mpsc::SyncSender<()>,
    results: mpsc::Receiver<ReducedResponse>,
}

impl ReducedWorker {
    pub fn spawn() -> Self {
        let latest = Arc::new(Mutex::new(None::<ReducedRequest>));
        let (wake, signal) = mpsc::sync_channel(1);
        let (sender, results) = mpsc::sync_channel(1);
        let work = latest.clone();
        std::thread::spawn(move || {
            while signal.recv().is_ok() {
                let request = match work.lock() {
                    Ok(mut latest) => latest.take(),
                    Err(_) => break,
                };
                let Some(request) = request else {
                    continue;
                };
                // The snapshot is immutable and the worker keeps no state, so
                // a panic discards only this request.
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    run(&request.view, &request.task)
                }))
                .unwrap_or_else(|_| match &request.task {
                    ReducedTask::Export { snapshot, .. } => ReducedOutcome::Exported {
                        snapshot: snapshot.clone(),
                        result: Err(PANICKED.into()),
                    },
                    _ => ReducedOutcome::Built(Err(PANICKED.into())),
                });
                let response = ReducedResponse {
                    id: request.id,
                    source: request.source,
                    outcome,
                };
                drop(request);
                if sender.send(response).is_err() {
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

    /// Replaces any queued request; a running request finishes first.
    pub fn request(&self, request: ReducedRequest) -> Result<(), String> {
        *self.latest.lock().map_err(|_| STOPPED)? = Some(request);
        match self.wake.try_send(()) {
            Ok(()) | Err(mpsc::TrySendError::Full(())) => Ok(()),
            Err(mpsc::TrySendError::Disconnected(())) => Err(STOPPED.into()),
        }
    }

    /// Drops a queued request that has not started.
    pub fn cancel(&self) {
        if let Ok(mut latest) = self.latest.lock() {
            *latest = None;
        }
    }

    pub fn try_recv(&self) -> Result<Option<ReducedResponse>, String> {
        match self.results.try_recv() {
            Ok(response) => Ok(Some(response)),
            Err(mpsc::TryRecvError::Empty) => Ok(None),
            Err(mpsc::TryRecvError::Disconnected) => Err(STOPPED.into()),
        }
    }

    /// A worker whose thread has already exited.
    #[cfg(test)]
    pub fn stopped() -> Self {
        let (wake, _) = mpsc::sync_channel(1);
        let (_, results) = mpsc::sync_channel(1);
        Self {
            latest: Arc::new(Mutex::new(None)),
            wake,
            results,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn view() -> Arc<FunctionView> {
        let fixture = super::super::tests::fixture();
        Arc::new(super::super::tests::analyze(&fixture.request).unwrap())
    }

    fn wait(worker: &ReducedWorker, id: u64) -> ReducedResponse {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(response) = worker.try_recv().unwrap()
                && response.id == id
            {
                return response;
            }
            assert!(Instant::now() < deadline, "no response {id}");
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    #[test]
    fn snapshots_share_the_view_allocations_and_export_the_command_document() {
        let view = view();
        let reduced = build(&view).unwrap();
        let s = &reduced.simplification;
        assert!(Arc::ptr_eq(s.constants(), &view.constants));
        assert!(Arc::ptr_eq(s.expressions(), &view.expressions));
        assert!(Arc::ptr_eq(s.analysis(), &view.analysis));
        // `rax = zext(1)` is a literal for its uses.
        assert!(reduced.reduced_values.iter().any(|v| matches!(
            s.term(s.value_term(*v).unwrap()).unwrap().kind,
            TermKind::Literal(ref literal) if literal.to_u64() == Some(1)
        )));
        // Every reduced value is listed once, ascending; the rest are leaves.
        assert!(reduced.reduced_values.windows(2).all(|w| w[0] < w[1]));
        for id in 0..s.analysis().ssa().values().len() {
            let value = ValueId(id);
            let own = matches!(s.term(s.value_term(value).unwrap()).unwrap().kind,
                TermKind::Leaf(leaf) if leaf == value);
            assert_eq!(own, !reduced.reduced_values.contains(&value));
        }
        // The copy is the command's `--simplify` document.
        let exported = export(&view, &reduced, EXPORT_LIMIT).unwrap();
        let command = crate::simplification_report::build(view.constants.clone()).unwrap();
        assert_eq!(
            exported.as_bytes(),
            super::super::simplified_json(&view, &command, MAX_DOCUMENT).unwrap()
        );
        assert!(exported.starts_with(&view.json[..view.json.len() - 1]));
        let parsed: serde_json::Value = serde_json::from_str(&exported).unwrap();
        crate::simplification_report::tests::validate(
            &parsed["analysis"],
            &parsed["expressions"],
            &parsed["constants"],
            &parsed["simplification"],
        );
        // Exact cap, then one byte short.
        assert_eq!(export(&view, &reduced, exported.len()).unwrap(), exported);
        assert!(
            export(&view, &reduced, exported.len() - 1)
                .unwrap_err()
                .contains("64 MiB")
        );
        assert_eq!(EXPORT_LIMIT + 1, 64 * 1024 * 1024);
        // A snapshot of another analysis is rejected, even of the same bytes.
        let other = self::view();
        assert!(
            export(&other, &reduced, EXPORT_LIMIT)
                .unwrap_err()
                .contains("different function snapshot")
        );
    }

    #[test]
    fn node_owners_name_the_first_executed_operation_containing_each_node() {
        let view = view();
        let reduced = build(&view).unwrap();
        let e = view.expressions.as_ref();
        for operation in e.operations() {
            if let Some(output) = operation.output {
                let owner = reduced
                    .node_statement(&view.expression_operations, output)
                    .unwrap();
                // An output node is created by its own operation.
                assert_eq!(owner, operation.statement);
            }
        }
        assert!(
            reduced
                .node_statement(
                    &view.expression_operations,
                    ghidra_analysis::ExpressionId(usize::MAX)
                )
                .is_none()
        );
    }

    #[test]
    fn latest_request_wins_and_panics_and_stopped_workers_report_errors() {
        let view = view();
        let key = RequestKey {
            id: 1,
            generation: 2,
            revision: 3,
            entry: view.entry,
        };
        let worker = ReducedWorker::spawn();
        for id in 1..=20 {
            worker
                .request(ReducedRequest {
                    id,
                    source: key,
                    view: view.clone(),
                    task: ReducedTask::Build,
                })
                .unwrap();
        }
        let ReducedOutcome::Built(Ok(snapshot)) = wait(&worker, 20).outcome else {
            panic!("latest build failed");
        };
        assert!(Arc::ptr_eq(
            snapshot.simplification.constants(),
            &view.constants
        ));
        // A cancelled queued request never runs; the next one does.
        worker.cancel();
        worker
            .request(ReducedRequest {
                id: 21,
                source: key,
                view: view.clone(),
                task: ReducedTask::Panic,
            })
            .unwrap();
        let ReducedOutcome::Built(Err(error)) = wait(&worker, 21).outcome else {
            panic!("panic was not reported");
        };
        assert!(error.contains("panicked"), "{error}");
        // The worker survives its panic and still exports.
        worker
            .request(ReducedRequest {
                id: 22,
                source: key,
                view: view.clone(),
                task: ReducedTask::Export {
                    snapshot: snapshot.clone(),
                    maximum: 16,
                },
            })
            .unwrap();
        let ReducedOutcome::Exported {
            snapshot: same,
            result,
        } = wait(&worker, 22).outcome
        else {
            panic!("export missing");
        };
        assert!(Arc::ptr_eq(&same, &snapshot));
        assert!(result.unwrap_err().contains("64 MiB"));
        let stopped = ReducedWorker::stopped();
        assert!(stopped.try_recv().is_err());
        assert!(
            stopped
                .request(ReducedRequest {
                    id: 1,
                    source: key,
                    view,
                    task: ReducedTask::Build,
                })
                .is_err()
        );
    }

    #[test]
    #[ignore = "compiles the retained x86 source and simplifies a real WinHelloCPP function"]
    fn upstream_winhello_reduced_snapshot_and_copy_match_the_simplify_command() {
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let loaded = crate::report::load_path(
            &root.join("GhidraDocs/GhidraClass/ExerciseFiles/WinhelloCPP/WinHelloCPP.exe"),
        )
        .unwrap();
        let catalog = ghidra_languages::Catalog::discover(&root.join("Ghidra/Processors")).unwrap();
        let definition = catalog.by_id("x86:LE:32:default").unwrap().clone();
        let request = super::super::FunctionRequest {
            key: RequestKey {
                id: 1,
                generation: 1,
                revision: 1,
                entry: 0x401E46,
            },
            config: crate::lifting::LanguageConfig {
                source: definition.source.available_path().unwrap().to_path_buf(),
                definition: Some(definition),
                context: Default::default(),
                revision: 0,
            },
            image: loaded.image,
            functions: loaded.functions,
            havoc_unknown: true,
        };
        let view = Arc::new(super::super::Compiler::default().analyze(&request).unwrap());
        let started = std::time::Instant::now();
        let reduced = build(&view).unwrap();
        let built = started.elapsed();
        let s = &reduced.simplification;
        assert!(Arc::ptr_eq(s.constants(), &view.constants));
        let stats = s.stats();
        assert_eq!(
            reduced.reduced_values.len(),
            stats.literal_values + stats.propagated_values
        );
        let started = std::time::Instant::now();
        let copy = export(&view, &reduced, EXPORT_LIMIT).unwrap();
        let serialized = started.elapsed();
        let command = crate::simplification_report::build(view.constants.clone()).unwrap();
        assert_eq!(
            copy.as_bytes(),
            super::super::simplified_json(&view, &command, MAX_DOCUMENT).unwrap()
        );
        eprintln!(
            "WinHelloCPP 401E46 reduced view: {} terms, {} literal and {} propagated values, {} reduced values, {} faults, {} refused folds; build {built:?}, copy {} bytes in {serialized:?}",
            stats.terms,
            stats.literal_values,
            stats.propagated_values,
            reduced.reduced_values.len(),
            s.faults().len(),
            s.refused_folds().len(),
            copy.len()
        );
        // Optional byte evidence: the command writes this text and a newline.
        if let Some(path) = std::env::var_os("GHIDRA_RS_REDUCED_COPY_OUT") {
            std::fs::write(path, &copy).unwrap();
        }
    }
}
