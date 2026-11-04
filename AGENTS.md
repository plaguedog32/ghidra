# Native port architecture requirements

The user requires responsive UI execution and native MCP control of the full
application, including discovery and correct targeting of concurrent instances.
These are requirements for the Rust port, not optional integrations.

Read [the architecture contract](docs/UI_AND_MCP_ARCHITECTURE.md) before changing
native application orchestration, UI callbacks, background jobs, automation,
instance discovery or MCP transport code.

- Keep analysis, parsing, filesystem/network I/O, serialization and substantial
  allocation or reclamation off the UI thread. UI callbacks must not wait for
  workers, locks held by workers, or full queues.
- Put application operations behind typed commands and queries shared by the
  desktop, CLI and MCP. New application capabilities must have an explicit
  automation surface; do not bury its only implementation in a UI callback.
- Preserve thread ownership of GUI objects and compiler contexts. Publish
  bounded immutable views; identify results by document and revision.
- Make instance discovery and explicit target validation part of MCP from the
  start. Never route a command to the first available process or use PID, port,
  active window or transport session alone as application identity.
- Keep the contract's implementation status honest. Existing background workers
  do not establish full UI responsiveness, and CLI JSON is not an MCP server.
