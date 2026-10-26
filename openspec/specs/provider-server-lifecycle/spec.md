# provider-server-lifecycle Specification

## Purpose

Provide the local reference provider as an operator-controlled background
service, with safe start, stop, status, and foreground lifecycle operations.

## Requirements

### Requirement: Dedicated server command and runtime boundary
The provider SHALL expose local lifecycle operations through `auth-guide server
start`, `stop`, `status`, `restart`, and `foreground`. Reusable runtime and process
lifecycle code SHALL live in `src/auth_guide/server/`; the CLI command group
SHALL only adapt operator input to that boundary.

#### Scenario: A foreground provider is requested
- **WHEN** an operator invokes `auth-guide server foreground`
- **THEN** the CLI delegates provider runtime ownership to the server package

### Requirement: Bounded startup and restart readiness
The `server start` and `server restart` commands SHALL wait up to 30 seconds
for HTTPS readiness before reporting success. `server start` SHALL report a
secret-safe startup failure supplied by its detached child without waiting for
the deadline. On timeout they SHALL report failure without terminating a daemon
that may have completed startup.

#### Scenario: Startup readiness exceeds its deadline
- **WHEN** the daemon has not reported HTTPS readiness after 30 seconds
- **THEN** `server start` reports failure without terminating the daemon

#### Scenario: A detached child cannot start
- **WHEN** a detached server child encounters a prerequisite or startup failure
- **THEN** `server start` reports its safe failure through its private readiness
  channel rather than only reporting a generic timeout

### Requirement: Conventional PID-file lifecycle state
The server runtime SHALL record its PID as a decimal value in
`{configdir}/auth-guide.pid` in both background and foreground modes. It SHALL
record the effective listener address in sibling `{configdir}/auth-guide.meta.json`
metadata. The server runtime SHALL use a short-lived server-owned lifecycle
lock to coordinate examination, creation, replacement, and removal of that
pair. Before startup, while holding that lock, it SHALL reject a live existing
PID without changing metadata, and remove stale PID and orphan metadata files
before creating its own state. It SHALL exclusively create its PID file before
atomically writing generation-0 metadata. During normal shutdown it SHALL
remove metadata before the PID file, under the same lock. `stop` and `status`
SHALL only read the files and use ordinary process liveness checks; they SHALL
never create, remove, or repair them. Multiple named server instances are out
of scope for this change.

#### Scenario: Metadata records the active listener
- **WHEN** the server runtime records its lifecycle state
- **THEN** `{configdir}/auth-guide.meta.json` contains the effective `listen`
  address and a readiness `generation` counter

#### Scenario: Lifecycle state is created or removed
- **WHEN** the server runtime starts or shuts down
- **THEN** it exclusively creates the PID file before atomically writing
  metadata, and removes metadata before the PID file during shutdown

#### Scenario: A stale PID file is encountered
- **WHEN** the server runtime starts and the configured PID is no longer live
- **THEN** it removes stale PID and metadata files before recording its own
  lifecycle state

#### Scenario: A live provider is already running
- **WHEN** a foreground or background runtime starts while the PID file names a
  live process
- **THEN** startup is rejected without changing the PID file

#### Scenario: A concurrent start is attempted
- **WHEN** another server runtime attempts to start while lifecycle state is
  being created, replaced, or removed
- **THEN** another start is rejected without creating a second runtime

### Requirement: Graceful background shutdown
The `server stop` command SHALL send SIGTERM to the PID recorded in the
server-owned lifecycle file and wait up to 30 seconds for graceful shutdown. It
SHALL NOT send SIGKILL automatically. If the process remains live, it SHALL
report failure and retain the PID file.

#### Scenario: Graceful shutdown exceeds its deadline
- **WHEN** the background process remains live after 30 seconds
- **THEN** `server stop` reports failure without sending SIGKILL or deleting its
  PID file

### Requirement: In-process daemon restart
The daemon SHALL treat SIGHUP as a complete in-process rebuild of its HTTPS
server, account-store runtime, and TLS runtime while retaining its PID. The
`server restart` command SHALL send SIGHUP to the background daemon and wait
for it to become ready again. Before rebuilding, the daemon SHALL re-read its
selected TOML configuration. Original CLI arguments and inherited environment
values SHALL retain precedence over changed TOML values.
The `server restart` command SHALL read the current metadata generation before
signalling SIGHUP, then wait for a higher generation and HTTPS readiness.
If a SIGHUP arrives during initial startup, the daemon SHALL queue one rebuild
after its initial readiness transition. If a rebuild fails after teardown, the
daemon SHALL log the failure, perform normal lifecycle cleanup, and exit.
`server restart` SHALL reject a runtime whose metadata generation is 0.

#### Scenario: An operator restarts the provider
- **WHEN** an operator invokes `auth-guide server restart`
- **THEN** the daemon rebuilds its runtime under the same PID before the command
  reports readiness

#### Scenario: TOML configuration changes before restart
- **WHEN** an operator changes a TOML setting not overridden by daemon CLI or
  environment configuration, then invokes `server restart`
- **THEN** the rebuilt daemon uses the changed TOML setting

#### Scenario: A rebuild fails
- **WHEN** a SIGHUP-triggered rebuild fails after its existing runtime has been
  torn down
- **THEN** the daemon exits after normal lifecycle cleanup and `server restart`
  reports the failed restart

#### Scenario: A restart is requested while startup is incomplete
- **WHEN** `server restart` finds a live runtime with metadata generation 0
- **THEN** it rejects the request without signalling SIGHUP

### Requirement: Daemon-only persistent output
The detached daemon SHALL redirect standard output and error to `/dev/null`.
It SHALL use configured persistent handlers for diagnostics. Syslog SHALL be a
daemon-only handler and SHALL NOT be attached by ordinary CLI commands or
foreground service operation. The management server SHALL disable Uvicorn
access logging.

#### Scenario: A foreground provider is run with syslog configured
- **WHEN** an operator invokes `auth-guide server foreground` while syslog is
  configured
- **THEN** the foreground process logs to its console but does not attach syslog

#### Scenario: A request contains an account selector
- **WHEN** the management API receives a request with a query-string selector
- **THEN** the server does not write that request URI through Uvicorn access
  logging

### Requirement: Structured lifecycle status
The `server status` command SHALL write structured JSON to standard output. A
live PID SHALL yield `state` `running` with its PID and effective listener
address from metadata and exit 0. No PID file SHALL yield `state` `stopped` and
exit 3. A non-live recorded PID SHALL yield `state` `stale` with its PID and
exit 3. A live PID with metadata generation 0 SHALL yield `state` `starting`
with its PID and address. Status SHALL never mutate lifecycle state.

#### Scenario: A stale server state is queried
- **WHEN** `server status` finds a non-live PID in the lifecycle file
- **THEN** it emits `state` `stale`, exits 3, and leaves cleanup to server
  startup

#### Scenario: A server is still starting
- **WHEN** `server status` finds a live PID with metadata generation 0
- **THEN** it emits `state` `starting` without changing lifecycle state

### Requirement: Graceful foreground signals
The foreground server SHALL handle SIGINT and SIGTERM through the same graceful
shutdown sequence as background SIGTERM: stop accepting connections, close its
HTTPS server and account store, then remove its PID file.

#### Scenario: An operator interrupts foreground operation
- **WHEN** an operator sends Ctrl-C to `auth-guide server foreground`
- **THEN** the server performs graceful shutdown and removes its PID file

### Requirement: Explicit service prerequisites
The server runtime SHALL require existing CA, encrypted database, key, and
migration readiness before it starts serving. `server start` and `foreground`
SHALL NOT create or migrate any of those resources; a missing or unready
prerequisite SHALL fail startup without mutation.

#### Scenario: The account database is not initialised
- **WHEN** an operator starts the server before explicit provider setup
- **THEN** it reports the readiness failure without creating database state

### Requirement: Server-only listener configuration
The `--listen`/`-L` option SHALL apply only to `server start` and
`server foreground`, resolving through command line, environment, TOML, then
default precedence. `server stop`, `status`, and `restart` SHALL not accept a
listener override.

#### Scenario: A running server is restarted
- **WHEN** an operator invokes `auth-guide server restart`
- **THEN** the command has no listener option and signals the existing process

### Requirement: Provider service lifecycle
The provider CLI SHALL start the configured local provider as a background
service, stop it, report its status, restart it, and offer a foreground mode
for development or external supervision. Background startup SHALL use a
detached self-executing child rather than directly forking an active async
runtime. A successful start SHALL make the existing HTTPS management API
available using the configured TLS authority and account store.

#### Scenario: Provider starts in the background
- **WHEN** an operator starts a configured provider without foreground mode
- **THEN** the CLI returns after the provider is ready and the HTTPS management
  API accepts trusted connections

#### Scenario: Provider runs in the foreground
- **WHEN** an operator requests foreground mode
- **THEN** the provider remains attached to the operator terminal until stopped
