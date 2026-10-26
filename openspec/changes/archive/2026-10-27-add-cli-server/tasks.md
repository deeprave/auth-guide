# Tasks

## 1. Provider runtime ownership

- [x] 1.1 Build the asynchronous provider runtime in `src/auth_guide/server/` that owns TLS, account-store startup and shutdown, readiness checks without resource creation or migration, HTTPS serving, and single-instance PID/JSON-metadata creation and cleanup in both foreground and background modes; use a server-owned lifecycle lock and ordered metadata-then-PID removal; verify start-up failure closes every owned component
- [x] 1.2 Add `auth-guide server foreground` and server-only `--listen`/`-L` as thin CLI adapters for that runtime and verify trusted HTTPS management access plus clean SIGINT and SIGTERM shutdown

## 2. Background lifecycle

- [x] 2.1 Implement `auth-guide server start` as a POSIX detached self-executing child with a private readiness/error pipe, a 30-second deadline, exclusive pre-readiness PID creation, generation-0 starting metadata, `/dev/null` detached streams, daemon-only persistent logging, and server-owned configuration-root lifecycle state; verify the command returns only after HTTPS readiness or a safe child failure
- [x] 2.2 Implement `auth-guide server stop` and structured-JSON `status` as read-and-signal clients of the server-owned PID/metadata files, with liveness checks, effective-listener reporting, duplicate-start rejection by the runtime, SIGTERM-based graceful shutdown with a 30-second deadline, and safe stop
- [x] 2.3 Implement SIGHUP-driven in-process runtime rebuild and `auth-guide server restart`, re-reading TOML without overriding original CLI or environment settings; queue a HUP received during startup, fail cleanly on an unsuccessful rebuild, and use metadata readiness generations so the command waits for the completed rebuild with a stable PID

## 3. End-to-end validation

- [x] 3.1 Exercise start, status, duplicate start, stop, restart, stale PID recovery, lifecycle-state ordering, HUP during startup, failed rebuild, and foreground operation against a disposable provider configuration; verify no credentials or management-API access records appear in output or logs
