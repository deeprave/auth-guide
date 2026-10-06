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
- Prove both outcomes with a deterministic behavioural test.

**Non-Goals:**

- Change the public provider API or cancellation behaviour for secret reads.
- Interrupt an in-flight platform keyring call.
- Change existing diagnostics or shutdown semantics.

## Decisions

- Use a provider-private, lock-protected call state transition shared by the
  caller's cancellation path and the worker. This is the user-approved design
  for UT-432. A plain event is insufficient because checking and claiming are
  separate operations.
- A worker claim wins once it occurs; later caller cancellation retains the
  established best-effort semantics. Attempting to abort an operating-system
  keyring call is not reliable and is outside scope.
- Use a controlled worker-blocking test double so cancellation is delivered
  immediately before worker claim without relying on scheduler timing.

## Risks / Trade-offs

- Synchronisation mistakes could incorrectly skip a claimed mutation → keep the
  state machine minimal and test both sides of the claim boundary.
- The keyring call remains non-interruptible after claim → preserve and document
  the existing best-effort behaviour.

## Migration Plan

No migration is required. The behavioural correction applies to new operations
when the updated provider is deployed.
