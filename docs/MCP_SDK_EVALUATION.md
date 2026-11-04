# Native MCP SDK evaluation

`rmcp 3.8.0` is a viable SDK candidate for the native MCP implementation, with
additional admission, lifetime and transport bounds required by the
[application architecture](UI_AND_MCP_ARCHITECTURE.md). This evaluation uses
an isolated synthetic server; it does not add an application endpoint,
instance registry, authentication or control of the desktop.

## Package and build identity

The published package is Apache-2.0, declares Rust 1.88, and has checksum
`f8be15815186873ea063bf005011d16c356804973489e40c39116ae3a2878d1f`.
Its source records upstream commit
`cd88056ffdc97756fbd98e5a12bbeb41758f0ce8`. See the official
[package manifest](https://github.com/modelcontextprotocol/rust-sdk/blob/cd88056ffdc97756fbd98e5a12bbeb41758f0ce8/crates/rmcp/Cargo.toml)
and [SDK repository](https://github.com/modelcontextprotocol/rust-sdk).

An external test crate compiled on Windows with Rust 1.88.0 using the exact
published SDK version and a generated lockfile. Enabled SDK features were
`server`, `macros`, `transport-io` and `transport-streamable-http-server`, with
default features disabled. The probe used Tokio and Axum; no JVM, JavaScript
or Python runtime was part of the server. Python drove the raw-wire checks.
Production dependencies have not been added to the Ghidra workspace.

## Raw protocol checks

The raw client exercised modern `2026-07-28` requests and legacy `2025-11-25`
requests over both stdio and Streamable HTTP:

- Modern stdio worked without `initialize`; legacy stdio used its handshake.
- HTTP discovery and tool calls worked with per-request metadata. Modern
  replies created no protocol session. Legacy HTTP created a session after
  `initialize` and preserved legacy result shapes.
- Three separate synthetic server processes bound distinct ephemeral ports.
  Each checked an explicit instance argument before updating a test counter.
  Calls addressed to another instance were rejected without changing counters.
- Mismatched method/version headers were rejected. A consistent unsupported
  protocol version returned the explicit unsupported-version error.
- A second HTTP caller completed a query while another handler awaited a
  bounded delay. This checks transport concurrency, not CPU-heavy application
  work or desktop frame latency.
- All probe processes were stopped after each run.

The SDK's default HTTP configuration accepted a request carrying an untrusted
browser Origin. Repeating the checks with an exact loopback Host/port allowlist
and `enforce_origin_validation()` rejected that Origin, `Origin: null`, other
present Origins and the wrong Host port with HTTP 403. Native requests without
Origin continued to work. The production configuration must set this policy
explicitly and add authentication; loopback binding alone is insufficient.
See the pinned [HTTP configuration implementation](https://github.com/modelcontextprotocol/rust-sdk/blob/cd88056ffdc97756fbd98e5a12bbeb41758f0ce8/crates/rmcp/src/transport/streamable_http_server/tower.rs).

These checks cover selected protocol paths, not the complete MCP conformance
suite, resources, Tasks, platform support or actual application discovery.
The modern HTTP service factory runs per request. Capture a clone of the
instance's shared application handle; creating a new application service in
that factory would lose document/job state and change the instance identity.

## Bounds required around the SDK

A separate static audit identified the following integration requirements.
Numbers describe this pinned SDK, not application defaults to inherit blindly.

| SDK behavior | Required application or transport policy |
| --- | --- |
| Async read/write transport defaults to a 16 MiB input-line cap; standalone JSON codec defaults to no practical decoding cap. | Set the connector's line cap explicitly, bound malformed/oversized-input retries and avoid an unconfigured standalone codec. |
| HTTP defaults to a 4 MiB body cap, checked before copying each received data frame. | Configure payload limits plus aggregate connection/request admission and upload/header deadlines before body collection. |
| Peer/response/output channels are bounded, but the service drains into uncapped send task sets and spawns request handlers. | Bound active RPCs, queued output bytes, notification producers and slow consumers. A semaphore only inside a tool handler cannot bound all SDK state. |
| Stdio and SSE serializers have no result-size cap. | Page resources/results and impose serialized-output budgets before sending. Coalesce progress instead of emitting unlimited updates. |
| Legacy session/request maps have no count cap; a session worker can wait on a slow SSE send. | Bound legacy sessions/requests and forcibly terminate stalled streams; idle timeout alone is insufficient. |
| Modern request cancellation reaches a token; it does not abort detached handlers. | Connect that token to application admission/jobs and algorithm checkpoints. Explicit durable jobs retain their own cancellation operation. |
| Shutdown drains responses, then awaits transport close; a stalled writer can hold the writer lock beyond the drain timeout. | Apply write deadlines/forced connection closure, and keep runtime ownership, waits and disposal off the UI thread. Track actual shutdown completion. |
| Windows/macOS stdio uses Tokio's blocking stdio path. | Keep the stdio connector in its own process and test shutdown while input/output pipes are blocked on each platform. |
| The SDK TaskManager is an in-memory mutex-protected map without a task-count cap; some TTL choices retain tasks indefinitely. | Do not treat it as the contract's durable task store. Implement bounded persistence/recovery before advertising that extension. |

The relevant pinned sources are
[async transport and framing](https://github.com/modelcontextprotocol/rust-sdk/blob/cd88056ffdc97756fbd98e5a12bbeb41758f0ce8/crates/rmcp/src/transport/async_rw.rs),
[service scheduling and shutdown](https://github.com/modelcontextprotocol/rust-sdk/blob/cd88056ffdc97756fbd98e5a12bbeb41758f0ce8/crates/rmcp/src/service.rs),
[HTTP body/stream handling](https://github.com/modelcontextprotocol/rust-sdk/blob/cd88056ffdc97756fbd98e5a12bbeb41758f0ce8/crates/rmcp/src/transport/common/server_side_http.rs),
[legacy sessions](https://github.com/modelcontextprotocol/rust-sdk/blob/cd88056ffdc97756fbd98e5a12bbeb41758f0ce8/crates/rmcp/src/transport/streamable_http_server/session/local.rs),
[stdio ownership](https://github.com/modelcontextprotocol/rust-sdk/blob/cd88056ffdc97756fbd98e5a12bbeb41758f0ce8/crates/rmcp/src/transport/io.rs)
and [task storage](https://github.com/modelcontextprotocol/rust-sdk/blob/cd88056ffdc97756fbd98e5a12bbeb41758f0ce8/crates/rmcp/src/task_manager.rs).
Ordinary serde_json parsing retains its recursion protection; lower nesting
and key-count limits require an additional preflight/application policy.

## Next implementation gates

Use the shared application service's actual instance/document/revision types
and command semantics when connecting the transport. Keep protected registry
discovery, authentication, permissions and target validation independent of
MCP's legacy sessions. Run slow-reader/flood tests against the complete adapter,
including byte retention, RPC admission, cancellation and process shutdown.
Then run modern and legacy conformance suites and real multi-instance desktop
tests on Windows, Linux and macOS before claiming the requirement is met.

The reproducible development probe, lockfile and logs remain outside the
checkout in `ghidra-mcp-sdk-probe-x_60fnc8` under the Windows user TEMP directory.
`wire-default.json` and `wire-strict.json` record the raw-wire observations.
They are evaluation evidence, not application tests or a production server.
