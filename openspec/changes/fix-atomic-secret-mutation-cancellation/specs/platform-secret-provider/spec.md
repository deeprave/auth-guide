# Spec Delta

## MODIFIED Requirements

### Requirement: Secret rotation
The service SHALL support replacing a referenced secret without storing either
version in its database or ordinary configuration. It SHALL atomically decide
whether cancellation reaches a queued mutation before or after the private
keyring worker claims it.

#### Scenario: Secret reference is rotated
- **WHEN** an operator updates the platform entry and restarts the service
- **THEN** new key use resolves the replacement value

#### Scenario: Awaiting caller is cancelled during a mutation
- **WHEN** a caller is cancelled after the private keyring worker has claimed
  its mutation
- **THEN** the caller receives cancellation while the mutation completes on a
  best-effort basis without retaining the secret value

#### Scenario: Awaiting caller is cancelled before worker claim
- **WHEN** a caller cancels a queued mutation before the private keyring worker
  claims it
- **THEN** the mutation does not alter the platform secret store

#### Scenario: Orphaned mutation fails
- **WHEN** a caller is cancelled and its already-dequeued mutation subsequently
  fails
- **THEN** the provider emits only secret-safe diagnostics and remains usable
