# UI responsiveness and native MCP control

The Rust port must remain interactive while analysis and I/O run, and it must
let an LLM control every available application capability through native MCP.
Several copies of the application must advertise themselves and accept only
commands addressed to the intended instance and document.

These are required architecture and acceptance gates. The current desktop has
background workers but still has UI-thread work to migrate. It has no native
MCP server or instance discovery service yet. The full replacement goal has
resumed with the shared application/job boundary and native MCP integration
prioritized. The contract's requirements remain acceptance gates.

## Shared application operations

Extract a UI-independent application service, with typed commands, queries,
results and events. The desktop, CLI and MCP use the same operations and state
rules. Analysis libraries remain independent of GUI and transport types.
Proposed crate boundaries are `ghidra-app` for application/session/job ownership
and `ghidra-mcp` for protocol, discovery and transport adapters; neither crate
exists yet.

The service owns loaded documents, revisions, annotations, analysis jobs and
save/export transactions. The UI owns widgets and window presentation. A
document owner serializes short state transitions; CPU or I/O jobs run outside
that owner and return revision-checked results. Independent documents and
read-only jobs can progress concurrently. No global lock spans analysis or I/O.

Every available semantic UI action needs a typed operation and an MCP mapping.
This includes opening/closing/saving projects, processor settings, navigation,
search, analysis, annotations, types, patches, exports and job control. As the
port adds debugging, plugins or other subsystems, their operations join the
same surface. A command manifest must track UI, CLI and MCP coverage; a UI-only
exception needs an explicit reason and a follow-up gate.

GUI-specific operations, including window focus, selection, layout and view
inspection, use a bounded UI command mailbox. Completion means the UI applied
the command, not merely that the mailbox accepted it. Headless instances
advertise those operations as unavailable. Domain operations work without a
window or a native dialog. An MCP open/save call supplies paths and explicit
unsaved-change decisions instead of waiting for a file picker or hidden modal.

## UI thread ownership and work budgets

The UI thread handles input, window/platform integration, short command
submission and visible-row rendering from prepared views. It must not perform
binary parsing, discovery, lifting, graph/dataflow/type analysis, report
serialization, disk/network access or substantial object copying/destruction.
Native dialogs and clipboard APIs retain their platform thread ownership;
use asynchronous platform integration where supported and prepare payloads
off-thread. Their remaining main-thread cost must be measured explicitly.

CPU analysis uses a bounded worker pool. Blocking I/O, MCP transport and job
control have separate execution capacity so CPU saturation cannot prevent
input handling, cancellation, discovery or health queries. Thread-affine
SLEIGH/compiler state stays on its owning worker; do not force it across
threads with unsafe `Send`/`Sync` implementations.

Submission and completion paths must be nonblocking for the UI, including
under overload. Bound queued jobs, result bytes, retained snapshots and event
backlogs. Coalesce replaceable inspection requests, but never silently drop
mutations or exports. Reject overload with a typed busy outcome and retry
guidance. Reserve control capacity for cancel, close and shutdown requests.

Publish immutable snapshots and indexes prepared on workers. Installing a
result should exchange small handles. Arrange worker-owned retirement of
large objects: the last `Arc` drop can otherwise put graph/buffer destruction
back on the UI thread. Stale-result rejection and mailbox replacement need
the same retirement path. Do not hold a mailbox lock while disposing of a
large request. Virtualize lists and prepare filtered/search/reference indexes
outside the frame instead of scanning the whole model every repaint.

Record frame time by input, command dispatch, result installation, rendering
and disposal. An initial controlled-test target is p95 at or below 16.7 ms,
p99 at or below 33 ms, and no application-work stall over 100 ms while bounded
stress jobs run. Record hardware, build, font size and workload. Deterministic
tests must also prove that a deliberately blocked worker cannot block a UI
frame; averages alone do not establish separation. These are acceptance
targets, not current measured guarantees or promises about OS scheduling.

## Jobs and concurrent edits

Use a common job model with queued, running, cancel-requested and terminal
states, bounded progress, errors and result handles. UI and MCP observe the
same job. The execution key includes instance, document, input revision,
processor/policy settings and request identity. Discarding an obsolete result
does not mean its computation was cancelled.

Propagate cancellation and deadlines into long algorithm loops and I/O. When
a dependency cannot stop mid-call, report cancel-requested until it finishes,
retain its worker budget, and suppress obsolete publication. Never kill a
thread or block the UI joining it. Define shutdown admission, cancellation,
draining and persistence on a coordinator with observable completion.

Mutations carry an expected document revision and execute as ordered,
undoable transactions where supported. Concurrent UI/MCP edits return a
conflict instead of silently overwriting newer state. Save operates on a
specific snapshot; completion only clears the dirty flag for that revision.
Two instances opening the same project also need file ownership/content-change
checks, because an in-process revision cannot prevent cross-process overwrite.
Retries of mutations use scoped idempotency keys; reuse with different inputs
is an error. Domain errors remain distinct from protocol and admission errors.

## Native MCP surface

Ship a Rust MCP server as part of the application, backed by the shared
service. A Rust stdio connector may bridge a host to an already running
instance. No JVM, external scripting runtime, screen scraping or per-feature
UI automation is required. The connector must not silently launch another
desktop when the intended instance is absent.

Expose typed tools for commands and bounded queries, resources/templates for
versioned analysis views and large artifacts, and accurate capability and
schema discovery. Page lists, bound response sizes and provide resumable
application queries. Addresses, wide revisions and identifiers use lossless
string encodings rather than relying on JavaScript number precision. Resource
URIs and cursors bind the instance, document and snapshot revision; reject a
cursor against another snapshot. Client disconnects must not block a worker
or grow an unbounded notification queue.

Long analysis starts an application job and returns a handle. Job status,
result and cancellation remain callable while work runs. Application job
handles are not automatically protocol Tasks. Advertise the optional Tasks
extension only after its durable store, expiry, cancellation and recovery
semantics are implemented; an in-memory queue is insufficient. A disconnected
client can reconnect to its authorized job without submitting it again.

Pin supported MCP revisions and the Rust SDK/adapter version in the first
implementation. The current specification is `2026-07-28`: version and client
capabilities travel per request, `server/discover` describes the server, and
modern HTTP has no protocol session identity. Legacy `2025-11-25` support
requires a separately tested compatibility adapter; do not mix its handshake
or session rules into modern requests. See the official
[versioning specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/versioning)
and [server discovery](https://modelcontextprotocol.io/specification/2026-07-28/server/discover).
The [SDK evaluation](MCP_SDK_EVALUATION.md) records a Rust 1.88 candidate and
additional transport/admission limits required around the SDK.

Use standard stdio and Streamable HTTP framing, errors and cancellation for
each supported revision. In modern HTTP, request-stream closure cancels that
request; explicit application jobs have their own cancel operation. Optional
subscriptions and Tasks must be negotiated before use. Tool and resource
schemas describe only implemented behavior, including unavailable features.
The [transport](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports),
[tools](https://modelcontextprotocol.io/specification/2026-07-28/server/tools),
[resources](https://modelcontextprotocol.io/specification/2026-07-28/server/resources)
and [Tasks extension](https://tasks.extensions.modelcontextprotocol.io/)
define wire behavior; the job and instance model here is application policy.

## Discovering and targeting multiple instances

Each application run creates an unguessable `InstanceId` and binds its own
loopback MCP endpoint on an OS-assigned port. It publishes an owner-protected
local descriptor only after the endpoint and application service are ready.
No global fixed port, active-window heuristic or singleton application is
required. Multiple windows inside one instance have separate `WindowId`s;
every loaded document has its own `DocumentId`, even for the same binary.

A bounded per-user registry lets a stable stdio discovery connector find
instances without port scanning. Registration is atomic, with owner-checked
paths, protection against symlink/reparse-point substitution, leases and clean
shutdown removal. Crash/lease cleanup must not delete another live instance's
record. A lease, PID or listening port is only a hint: verify the endpoint's
authenticated instance identity before treating it as a live target. PID and
port reuse must never redirect a request after a restart.

Each discovery result includes instance ID, application/build/API versions,
endpoint/transport, start time, GUI/headless mode, readiness and capabilities.
Authorized detail queries expose window IDs and labels, document IDs,
project/binary identity, architecture, revision and dirty state. Names and
paths are descriptive, not routing identities; path disclosure is configurable.
Credentials are not included in public listings, tool results or logs.

Application tools such as `instances.list`, `instances.describe` and
`documents.list` are proposed MCP tool names, not new protocol RPC methods.
`server/discover` describes one reached server; discovering all local desktop
processes is the port's registry/connector responsibility. An external host
can configure this one stable connector and then choose its intended target.

Every targeted command carries `instance_id`; document operations also carry
`document_id`, and mutations carry `expected_revision`. A direct per-instance
endpoint validates the supplied instance ID too. A broker validates its
authenticated upstream identity before forwarding. No match, multiple name
matches, a dead target or an identity mismatch returns a clear error and the
available choices; it must never fall back to the first or newest instance.
Clients cannot change another client's target through shared selection state.
Transport sessions, request numbers and foreground windows are not identities.

## Access and visibility

Keep local registry and credentials restricted to the owning OS user. The
connector reads credentials through protected local storage and sends them
only to the verified endpoint; the LLM does not need bearer-token contents.
Bind HTTP to loopback, validate Host and Origin and authenticate callers. MCP's
[HTTP security requirements](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http#security--endpoint)
apply even to localhost. Remote access needs an explicit deployment mode with
the protocol's authorization/TLS requirements; it is not enabled by widening
the local listener address.

Authorized automation can use the application's full implemented command
surface. Enforce permissions, transaction rules and destructive-operation
policy in the shared service so every frontend behaves consistently. Expose
connected client/job activity and access revocation in the UI. Read-only and
write grants are distinguishable; tool annotations do not enforce permissions.
No operation should wait indefinitely for an unseen GUI confirmation.

## Existing boundaries to migrate

The source audit at `bf511063cb` found these concrete starting points. It
checked code placement and ownership, not measured stall durations.

| Current path | Required migration |
| --- | --- |
| [Import and navigation workers](../crates/ghidra-desktop/src/app.rs#L138), [function worker](../crates/ghidra-desktop/src/function_analysis.rs#L180), [reduced worker](../crates/ghidra-desktop/src/function_analysis/reduced.rs#L213) | Preserve off-thread construction and stale-result checks in the common job service. |
| [Report export](../crates/ghidra-desktop/src/app.rs#L308) | Move report construction, serialization and file writing off the UI thread. |
| [Function navigation](../crates/ghidra-desktop/src/app/views.rs#L64) | Prepare or share listings without deep UI-thread clones and replacement destruction. |
| [Function JSON copy](../crates/ghidra-desktop/src/app/dataflow.rs#L260) | Avoid a UI-thread clone of up to 64 MiB; measure the platform clipboard path. |
| [Worker submission](../crates/ghidra-desktop/src/function_analysis.rs#L225) | Replace UI-side blocking locks, add cancellation/shutdown and bound completion/disposal behavior. |
| [View replacement/invalidation](../crates/ghidra-desktop/src/app/dataflow.rs#L61) | Retire large successful, stale and discarded snapshots off-thread. |
| [Frame queries](../crates/ghidra-desktop/src/app.rs#L645), [catalog setup](../crates/ghidra-desktop/src/app/pcode/catalog.rs#L20) | Prepare filters/reference indexes and filesystem probes outside frames; retain virtual rendering. |

## Implementation order and acceptance gates

1. Extract the application/session API and common job coordinator. Migrate
   existing open/save/navigation/export paths, snapshot ownership and worker
   admission. Test commands without egui and pin revision/conflict behavior.
2. Add responsiveness instrumentation and stress tests, cooperative cancellation
   and shutdown. Saturate analysis and I/O while navigating, resizing, editing,
   replacing results, rejecting stale results and closing the application.
3. Add instance identity, protected discovery, native stdio connector and
   authenticated per-instance MCP endpoint. Launch at least three actual
   processes, including two viewing the same binary, and verify every route.
4. Expose current commands/resources/jobs and GUI view commands through MCP.
   Compare UI, CLI and MCP results on the same fixture and revision. Verify
   that no GUI dialog or visible window is needed for domain operations.
5. Extend the command manifest with every new feature. Run protocol compliance,
   responsiveness and multi-instance tests on Windows, Linux and macOS.

Required failure cases include request/result floods, slow consumers, worker
panic, unsupported protocol versions, denied clients, malformed discovery
records, symlink/reparse-point substitution, duplicate labels, simultaneous
startup, crash/restart with PID/port reuse, stale document IDs/revisions,
concurrent human/LLM edits and two instances saving the same project. Assert
bounded memory and admission latency, explicit outcomes, no cross-instance
reads or writes, and no worker-bound waits in UI callbacks.

These gates precede a claim of fully responsive UI or native multi-instance
MCP support. Passing existing analysis tests alone does not close them.
