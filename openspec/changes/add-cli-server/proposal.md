# Proposal

## Why

auth-guide is both the reference provider service and its operational command
interface. Operators need the CLI to start, stop, and inspect that local service
without manually managing a Uvicorn process.

## What Changes

- Add a CLI-owned local provider-service lifecycle using the normal background
  process and PID-file protocol.
- Start the service with its existing TLS, account-store, and configuration
  boundaries; stop only the process owned by the configured PID file.
- Provide status and foreground operation suitable for development and service
  supervision.
- Prevent duplicate starts, stale PID-file confusion, and accidental signalling
  of an unrelated process.

## Capabilities

### New Capabilities
- `provider-server-lifecycle`: Local provider process start, stop, status, and
  safe PID-file ownership.

### Modified Capabilities
- None.

## Impact

Adds CLI process-management code and tests, and consumes existing local TLS,
encrypted-account-store, and management-API library boundaries. It does not
change management API routes or permit direct database access.
