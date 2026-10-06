# Design

## Context

Secrets must be independent from encrypted storage. wybra-dev demonstrates the Linux Secret Service test environment.

## Goals / Non-Goals

**Goals:** a small reference-based interface, platform backends, and secret-safe failures.

**Non-Goals:** a general secret-management product or secret values in configuration.

## Decisions

- Use application namespace plus opaque reference; consumers name a reference, not a secret value.
- Ask `keyring` for the sensible backend for the current operating system: normally
  Keychain on macOS and Freedesktop Secret Service on Linux. Operators may choose
  a compatible non-default backend through normal keyring configuration; the
  provider documents that boundary but does not attempt to classify or police
  backend security.
- Expose an async provider interface while `keyring` operations run on one private,
  provider-owned worker thread. The worker serialises keyring calls through a
  private queue and is never exposed to consumers.
- Start the worker with the provider and stop it through one provider-owned,
  awaited shutdown-completion operation. Every concurrent closer awaits the
  same completion; cancellation of one closer does not abandon shutdown. The
  shutdown path stops accepting new operations, completes queued work, signals
  the worker to exit, and confirms its termination without busy waiting.
- Do not cache secret values. Operations carry a value only between the worker
  and their awaiting caller. Per-operation worker references are released before
  the worker waits for its next queue item.
- A caller awaits a provider-owned completion under `asyncio.shield`. Caller
  cancellation therefore does not cancel an already-dequeued keyring mutation:
  the mutation completes on a best-effort basis, and an orphaned failure is
  recorded only through secret-safe diagnostics.
- Preserve documented `keyring` operational exception types where possible.
  Provider-specific errors use exception chaining so the original cause remains
  available without including secret values in the provider error message.

## Risks / Trade-offs

- Headless Linux lacks a running keyring → provide documented test/deployment bootstrap, not a kernel-keyring fallback.
- `keyring` exposes synchronous APIs → contain them in the provider-owned
  worker rather than blocking the application event loop or using an
  application-wide executor.
