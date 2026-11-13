# Spec Delta

## MODIFIED Requirements

### Requirement: Asynchronous platform secret resolution
The service SHALL expose asynchronous resolution of secret references scoped by
the selected provider namespace through the current operating system's sensible
`keyring` default: normally macOS Keychain on macOS and Linux Freedesktop Secret
Service on Linux. Operators MAY configure a compatible non-default keyring
backend. It SHALL keep its serial keyring worker private to the provider and
stop it during provider shutdown.

#### Scenario: Referenced secret exists
- **WHEN** a configured reference resolves in the active platform store
- **THEN** the service receives its value without printing it

#### Scenario: Referenced secret is absent
- **WHEN** a configured reference cannot be resolved
- **THEN** startup fails with a secret-safe error

#### Scenario: Initial secret is created concurrently
- **WHEN** callers concurrently explicitly create an absent secret
- **THEN** exactly one creation succeeds and the other reports that the reference exists

#### Scenario: Provider is shut down
- **WHEN** the provider shutdown completes
- **THEN** its private keyring worker has stopped and accepts no new operations

#### Scenario: Concurrent shutdown
- **WHEN** more than one caller closes the provider and one caller is cancelled
- **THEN** every non-cancelled closer awaits the same completed shutdown and the
  worker still exits

#### Scenario: Distinct namespaces use distinct credential entries
- **WHEN** two providers resolve the same secret reference under distinct
  namespaces
- **THEN** each provider reads and mutates only its own platform credential entry
