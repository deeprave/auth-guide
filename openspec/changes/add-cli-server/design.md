# Design

## Context

The existing provider has an asynchronous account-store runtime, local TLS
authority, and HTTPS server factory but no process owner. See proposal.md for
motivation and the provider-server-lifecycle delta for observable behaviour.

## Goals / Non-Goals

**Goals:**

- Run the existing provider runtime in foreground or a detached local process.
- Use a configuration-root PID file to coordinate one background instance.
- Prove process ownership before stopping it.

**Non-Goals:**

- General service-manager integration, Windows support, remote deployment, or
  replacing external supervision such as launchd or systemd.
- Database, keyring, TLS, or management-API logic outside the existing library
  boundaries.

## Decisions

- Implement a POSIX local-process lifecycle. `start` forks a child, detaches it
  from the terminal, waits for HTTPS readiness, then writes the PID file only
  after readiness succeeds. `foreground` owns no PID file. This matches the
  requested local daemon model while leaving service-manager operation possible.
- Store PID and a provider-specific process identity marker beneath the selected
  configuration root. `stop` and `status` verify the live PID and marker before
  acting; a stale record is removed without signalling. PID alone was rejected
  because operating-system reuse could target an unrelated process.
- The child performs ordinary provider startup: resolve TLS state, start the
  account store, require migration readiness, create the management application,
  and serve HTTPS. It closes those owned components during normal shutdown.
- Startup failure removes only the PID state created by that invocation and
  returns a secret-safe error to the parent. The parent imposes a bounded
  readiness wait, rather than reporting success immediately after fork.

## Risks / Trade-offs

- [Parent exit or crash while child starts] → child writes its own ready PID
  state only after readiness, and stale-state handling permits later recovery.
- [PID reuse] → require provider-specific process identity verification before
  signalling.
- [Unexpected child output] → redirect detached-process standard streams to
  controlled configuration-root logs with no credentials written by the CLI.
- [Windows differs from POSIX daemon conventions] → defer Windows process
  lifecycle to a separate change rather than simulate it unsafely.

## Migration Plan

No stored-data migration. Operators replace manual server invocation with the
CLI lifecycle commands; removing the feature leaves existing provider data and
TLS state intact.
