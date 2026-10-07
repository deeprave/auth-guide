# Tasks

## 1. Deterministic cancellation boundary

- [x] 1.1 Add controlled public-provider coverage for cancelled queued store and delete mutations, asserting the keyring state remains unchanged
- [x] 1.2 Implement the lock-protected pending, claimed, and cancelled transition and verify the targeted regression test passes

## 2. Verification

- [x] 2.1 Run the complete provider test suite and project linting, type checking, security, build, and strict OpenSpec validation

## 3. Pull-request remediation

- [x] 3.1 Make the mutation lock annotation import-safe on supported Python versions without adding annotation-only test coverage
- [x] 3.2 Make a caller cancellation request visible to the worker's atomic claim and retain existing public behavioural coverage without adding a scheduler-timing test
- [x] 3.3 Replace timeout-based test-worker release with explicit release cleanup
