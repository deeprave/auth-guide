# Design

## Context

The existing provider has an asynchronous account-store runtime, local TLS
authority, and HTTPS server factory but no process owner. See proposal.md for
motivation and the provider-server-lifecycle delta for observable behaviour.

## Goals / Non-Goals

**Goals:**

- Run the existing provider runtime in foreground or a detached local process.
- Use a server-owned configuration-root PID file to coordinate one instance.
- Have CLI lifecycle commands use conventional PID-file liveness checks before
  signalling a running server.
- Keep the reusable provider runtime and process lifecycle in
  `src/auth_guide/server/`; keep the Click command group as a thin adapter.

**Non-Goals:**

- General service-manager integration, Windows support, remote deployment, or
  replacing external supervision such as launchd or systemd.
- Database, keyring, TLS, or management-API logic outside the existing library
  boundaries.

## Decisions

- Implement a POSIX local-process lifecycle. `start` launches a detached,
  self-executing server child rather than forking an active asynchronous
  process. The parent and child communicate readiness or a safe startup error
  over a private pipe, while the child owns its own event loop and all provider
  resources. The child redirects normal standard streams to `/dev/null`.
- Expose lifecycle commands as `auth-guide server start`, `stop`, `status`,
  `restart`, and `foreground`. Server-only `--listen` configuration belongs to
  `start` and `foreground`, not the global administration CLI options.
- Put runtime ownership, PID state, readiness, and shutdown behaviour in
  `src/auth_guide/server/`. The CLI package parses operator input, resolves
  command configuration, and calls that public asynchronous boundary; it does
  not own server lifecycle implementation details.
- Store a conventional decimal PID file at `{configdir}/auth-guide.pid` in both
  background and foreground modes, and the effective listener address in the
  sibling `{configdir}/auth-guide.meta.json`. A short-lived, server-owned
  lifecycle lock serialises every examination, creation, replacement, and
  removal of that pair. CLI commands only read lifecycle state and signal a
  live process; they never create, remove, or repair it. Multiple named
  instances are out of scope for this change.
- While holding the lifecycle lock, startup rejects a live recorded PID without
  changing metadata. It removes stale PID and orphan metadata, creates the new
  PID exclusively, then atomically writes metadata with generation 0. Normal
  shutdown removes metadata first and the PID last under the same lock. This
  ordering means a rejected start cannot overwrite a running server's metadata,
  and an exiting server cannot remove the lifecycle state of a replacement.
- No metadata version is needed for the additive JSON document. Metadata has a
  monotonically increasing `generation`, initially 0 while starting and
  advanced only after successful readiness. Restart reads the current
  generation, signals SIGHUP, and waits for a higher generation plus HTTPS
  readiness.
- `stop` sends SIGTERM and waits up to 30 seconds for ordinary TLS, server, and
  account-store shutdown. It never escalates to SIGKILL automatically; if the
  process remains live, it reports failure and retains the PID file.
- SIGHUP performs a complete in-process rebuild: close the HTTPS server,
  account store, and TLS runtime, recreate them, and resume serving under the
  same daemon PID. A HUP received while initial startup is still in progress
  queues exactly one rebuild after initial readiness. `server restart` refuses
  a `starting` runtime, sends SIGHUP to a ready daemon, and waits for readiness.
  If a rebuild fails after teardown, the daemon logs the failure, removes its
  lifecycle state through normal shutdown, and exits; `restart` reports that
  failure rather than treating the old generation as healthy.
- Background mode redirects detached standard output and error to `/dev/null`.
  It relies on configured persistent logging rather than a separate daemon-log
  file. Syslog is a daemon-only handler: ordinary CLI commands and `foreground`
  never attach it. Uvicorn access logging is disabled so account selectors in
  management-API query strings are not written to persistent logs.
- SIGHUP re-reads the selected TOML configuration before rebuilding the
  runtime. CLI arguments and the daemon's inherited environment retain their
  original higher-precedence values; restart applies TOML only where those
  sources did not already supply a setting.
- Parent `start` and client `restart` operations each wait up to 30 seconds for
  readiness. The start parent reports a child-provided safe failure immediately;
  a readiness timeout reports failure without tearing down a daemon that may
  already have completed startup.
- `server status` writes structured JSON. `running` exits 0 and includes the
  effective listener address from server-owned metadata; `stopped` and `stale`
  exit 3. Status never cleans PID state; the next runtime startup owns stale
  file cleanup.
- Foreground SIGINT and SIGTERM use the same graceful shutdown sequence as a
  daemon SIGTERM: stop accepting connections, close the HTTPS server and
  account store, then remove server-owned metadata and PID state under the
  lifecycle lock.
- `server start` and `foreground` are readiness-only operations. They do not
  create a CA, encryption key, database, or migration; missing or unready
  prerequisites fail startup without mutation.
- `--listen`/`-L` belongs only to `server start` and `foreground`, with the
  established CLI, environment, TOML, then default precedence. `stop`,
  `status`, and `restart` operate on an existing process and do not accept it.
- The child performs ordinary provider startup: resolve TLS state, start the
  account store, require migration readiness, create the management application,
  and serve HTTPS. It closes those owned components during normal shutdown.
- Startup failure removes only lifecycle state created by that invocation and
  returns a secret-safe error to the parent over its private readiness pipe.
  The parent imposes a bounded readiness wait, rather than reporting success
  immediately after launching the child.

## Risks / Trade-offs

- [Parent exit or crash while child starts] → the runtime owns its PID state and
  stale-state handling permits later recovery.
- [Stale PID file] → the next runtime start checks liveness and removes a
  non-live record before creating its own.
- [Overlapping starts or shutdown] → server-owned lifecycle locking and ordered
  PID/metadata replacement prevent one process overwriting or deleting another
  process's state.
- [Unexpected child output] → redirect detached standard streams to `/dev/null`;
  persistent diagnostics use configured daemon logging without credentials.
- [Windows differs from POSIX daemon conventions] → defer Windows process
  lifecycle to a separate change rather than simulate it unsafely.

## Migration Plan

No stored-data migration. Operators replace manual server invocation with the
CLI lifecycle commands; removing the feature leaves existing provider data and
TLS state intact.
