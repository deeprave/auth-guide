# Proposal

## Why

The current logging redaction hook is a pass-through formatter and only affects
provider-owned handlers. Dependency loggers can be enabled independently and
may disclose account selectors, outbound request URLs, or bound SQL values.

## What Changes

- Replace the inert formatter hook with an idempotent, process-wide
  `LogRecordFactory` redaction boundary that chains the pre-existing factory.
- Move HTTP request-target sanitisation into the shared redaction boundary so
  Uvicorn access records are protected before any handler can receive them.
- Add dependency-specific structural handling for Uvicorn access records,
  HTTPX outbound request records, and Tortoise database-client query records.
- Apply conservative text-level masking for recognised auth-guide credentials,
  bearer credentials, email addresses, UUIDs, and exception text.
- Remove the unused `redactor_file` configuration scaffold and the no-op
  formatter abstraction.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `provider-administration-cli`: replace the inert logging extension point
  with a process-wide dependency-safe redaction boundary.

## Impact

- Affects `auth_guide.cli.redaction`, logging setup, and Uvicorn access-log
  integration.
- Affects emitted diagnostics from HTTPX, HTTPcore, Tortoise/Tortoise-SQLCipher,
  keyring, and Uvicorn when those libraries log in the provider process.
- No HTTP API, account-storage, token, or configuration compatibility change is
  intended beyond removing the unused `redactor_file` scaffold.
