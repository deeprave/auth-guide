# Proposal

## Why

Cancelling a mutation that is still waiting in the private keyring-worker queue
can race worker dequeue and alter a secret after its caller has received
cancellation. The provider must reliably distinguish a pending mutation from
one the worker has already claimed.

## What Changes

- Atomically coordinate caller cancellation and the worker's dequeue transition
  for `store` and `delete` operations.
- Skip a cancelled mutation that remains pending.
- Preserve the existing best-effort behaviour for a mutation the worker has
  already dequeued.
- Add deterministic behavioural coverage of the cancellation/dequeue boundary.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `platform-secret-provider`: define the required cancellation behaviour for
  mutations awaiting the private keyring worker.

## Impact

Changes are limited to the platform-secret provider's call coordination and
its behavioural tests. No public API or dependency changes are required.
