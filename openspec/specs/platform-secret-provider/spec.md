# Platform Secret Provider Specification

## Purpose

Provide provider-owned secret resolution through platform credential stores
without exposing secret values to configuration or diagnostics.

## Requirements

### Requirement: Asynchronous platform secret resolution
The service SHALL expose asynchronous resolution of application-namespaced
secret references through the current operating system's sensible `keyring`
default: normally macOS Keychain on macOS and Linux Freedesktop Secret Service
on Linux. Operators MAY configure a compatible non-default keyring backend. It
SHALL keep its serial keyring worker private to the provider and stop it during
provider shutdown.

#### Scenario: Referenced secret exists
- **WHEN** a configured reference resolves in the active platform store
- **THEN** the service receives its value without printing it

#### Scenario: Referenced secret is absent
- **WHEN** a configured reference cannot be resolved
- **THEN** startup fails with a secret-safe error

#### Scenario: Provider is shut down
- **WHEN** the provider shutdown completes
- **THEN** its private keyring worker has stopped and accepts no new operations

#### Scenario: Concurrent shutdown
- **WHEN** more than one caller closes the provider and one caller is cancelled
- **THEN** every non-cancelled closer awaits the same completed shutdown and the
  worker still exits

### Requirement: Secret-safe operational errors
The service SHALL distinguish an unresolved secret reference from documented
keyring operational failures. It SHALL preserve a provider-specific failure's
original keyring cause through exception chaining, and SHALL not include a
secret value in its own error message or diagnostics.

#### Scenario: Keyring is unavailable
- **WHEN** the selected keyring reports that it is unavailable
- **THEN** the caller can handle the documented keyring failure type and any
  provider-specific wrapper retains it as its cause

### Requirement: Secret rotation
The service SHALL support replacing a referenced secret without storing either
version in its database or ordinary configuration.

#### Scenario: Secret reference is rotated
- **WHEN** an operator updates the platform entry and restarts the service
- **THEN** new key use resolves the replacement value

#### Scenario: Awaiting caller is cancelled during a mutation
- **WHEN** a caller is cancelled while a keyring mutation is in progress
- **THEN** the caller receives cancellation while an already-dequeued mutation
  completes on a best-effort basis without retaining the secret value

#### Scenario: Orphaned mutation fails
- **WHEN** a caller is cancelled and its already-dequeued mutation subsequently
  fails
- **THEN** the provider emits only secret-safe diagnostics and remains usable
