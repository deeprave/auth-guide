# Proposal

## Why

auth-guide is both the reference provider service and its operational command
interface. Operators need the CLI to start, stop, and inspect that local service
without manually managing a Uvicorn process.

## What Changes

- Add a server-owned local provider-service lifecycle using a detached
  self-executing child process and PID-file protocol, including in-process
  SIGHUP restart.
- Expose that lifecycle as `auth-guide server start`, `stop`, `status`,
  `restart`, and `foreground`, keeping server-only listener configuration out
  of unrelated administration commands.
- Start the service with its existing TLS, account-store, and configuration
  boundaries; have the server runtime own PID-file creation and cleanup.
- Provide status and foreground operation suitable for development and service
  supervision.
- Let the server runtime serialise lifecycle-file updates, prevent duplicate
  starts, and clean up stale PID files.
- Record the effective listener address in server-owned JSON metadata beside the
  conventional PID file. Multiple named instances are deferred to a later
  change.

## Capabilities

### New Capabilities
- `provider-server-lifecycle`: Local provider process start, stop, status, and
  safe PID-file ownership.

### Modified Capabilities
- None.

## Impact

Adds `src/auth_guide/server/` runtime and process-management code plus CLI
adapters and tests, and consumes existing local TLS,
encrypted-account-store, and management-API library boundaries. It does not
change management API routes or permit direct database access.
