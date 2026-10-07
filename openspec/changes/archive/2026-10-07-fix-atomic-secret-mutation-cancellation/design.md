# Design

## Context

The worker currently observes a cancellation event separately from dequeue.
Because the event is set only after the awaiting task receives cancellation,
the worker can claim and run a queued mutation in between. See `proposal.md`
and the modified platform-secret-provider specification.

## Goals / Non-Goals

**Goals:**

- Make cancellation and worker claim one synchronised transition for mutations.
- Retain best-effort completion once a worker has claimed a mutation.
- Retain public behavioural coverage for a cancelled queued mutation and for
  best-effort completion of a claimed mutation.

**Non-Goals:**

- Change the public provider API or cancellation behaviour for secret reads.
- Interrupt an in-flight platform keyring call.
- Change existing diagnostics or shutdown semantics.

## Decisions

- Use a provider-private, lock-protected call state transition shared by the
  caller's cancellation path and the worker. This is the user-approved design
  for UT-432. At claim time the worker asks the caller's event loop to observe
  the awaiting task's cancellation request within that locked transition, so
  cancellation is visible before the task next runs its cancellation handler.
  A plain event is insufficient because checking and claiming are separate
  operations.
- A worker claim wins once it occurs; later caller cancellation retains the
  established best-effort semantics. Attempting to abort an operating-system
  keyring call is not reliable and is outside scope.
- Use a controlled worker-blocking test double with explicit release cleanup
  for public queued-cancellation behaviour. Do not add a scheduler-timing
  regression test for the narrow claim race.

## Risks / Trade-offs

- Synchronisation mistakes could incorrectly skip a claimed mutation → keep the
  state transition minimal and retain public behaviour coverage.
- The keyring call remains non-interruptible after claim → preserve and document
  the existing best-effort behaviour.

## Migration Plan

No migration is required. The behavioural correction applies to new operations
when the updated provider is deployed.
