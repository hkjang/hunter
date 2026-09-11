# PentAGI source retained by Hunter

Upstream: <https://github.com/vxcontrol/pentagi>, commit
`ea665308baaff015b226f308438a68d929d0f29b`.

`UPSTREAM.json` records the SHA-256 of every copied original file. The copied
backend packages and embedded templates are byte-identical to that commit.
`backend/pkg/providers/hunter_bridge.go` is the only Hunter-authored addition
inside the upstream Go module. Hunter integration lives in
`internal/pentagicore`; the upstream module is imported through a local Go
`replace` directive. Original tests and packages outside the dependency closure
of `pkg/providers` were not copied.

Retained behavior includes subtask generation and refinement, the original
multi-turn performer, delegated role agents, adviser/planner and reflector,
message-chain persistence and usage accounting, task reporting, and conversation
summarization. No generated replacement of those original algorithms is used.

Hunter supplies the authenticated streaming model provider and a
`FlowToolsExecutor`. Original role and barrier argument schemas come from
`pkg/tools/registry.go` and `pkg/tools/args.go`; underlying network/runtime
operations are limited to the seven documented Hunter tools. Upstream terminal,
file, browser, internet search, vector search and Graphiti implementations are
not registered or initialized. Compiling their transitive package dependencies
does not enable these runtimes.

Hunter does not initialize PentAGI's HTTP server, user authentication, provider
discovery/probing, Docker client, or telemetry clients. Upstream observability's
package initializer installs no-op clients. Its complete migrations are not
executed: `internal/pentagicore/schema.sql` supplies five compatibility tables
for the original sqlc queries in an isolated PostgreSQL schema, without pgvector
or pg_trgm. Engine initialization uses at most two additional SQL connections.

The adapter persists model message chains and token accounting in that schema.
Hunter passes redacted prompts and tool results; private chains may include
model reasoning required for continuation and are not exposed in user-facing
events. These core compatibility tables are not independently field-encrypted;
database access and backup protection remain necessary. Hunter's user-visible
events, service memory and vulnerability evidence use Hunter's encrypted stores.
No provider API key is put into a model message or core record.

A run may finish, fail, or pause at an original `ask` barrier. Hunter exposes a
new-run retry for paused/interrupted runs. Resuming an old private chain is not
implemented. A unique Hunter run ID cannot execute twice. A task's model-reported
success does not confirm a vulnerability or resolve a finding.

MIT copyright and permission notices are retained in `LICENSE`. `NOTICE` and
`EULA.md` are preserved verbatim as upstream notices; Hunter's dependency license
report distinguishes them from the licenses found in the actual pinned Go
modules. The upstream full product and its Docker-oriented deployment are not
represented as Hunter capabilities.
