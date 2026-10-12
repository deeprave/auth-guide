# Spec Delta

## Purpose

Provide the local reference provider as an operator-controlled background
service, with safe start, stop, status, and foreground lifecycle operations.

## ADDED Requirements

### Requirement: Provider service lifecycle

The provider CLI SHALL start the configured local provider as a background
service, stop it, report its status, and offer a foreground mode for development
or external supervision. A successful start SHALL make the existing HTTPS
management API available using the configured TLS authority and account store.

#### Scenario: Provider starts in the background
- **WHEN** an operator starts a configured provider without foreground mode
- **THEN** the CLI returns after the provider is ready and the HTTPS management
  API accepts trusted connections

#### Scenario: Provider runs in the foreground
- **WHEN** an operator requests foreground mode
- **THEN** the provider remains attached to the operator terminal until stopped

### Requirement: Safe process ownership

The CLI SHALL record a successfully started background provider in a
configuration-root PID file. It SHALL reject a second start while that process
is alive, remove a stale PID file without signalling its recorded PID, and stop
only a process whose recorded identity is verified as the configured provider.

#### Scenario: A duplicate start is attempted
- **WHEN** a PID file identifies a live configured provider
- **THEN** the CLI reports that provider is already running without starting a
  second process

#### Scenario: A stale PID file is found
- **WHEN** the PID file does not identify a live configured provider
- **THEN** the CLI removes the stale file and may start a new provider without
  signalling the recorded PID

#### Scenario: Stop encounters an unrelated process
- **WHEN** a PID file points to a live process that is not the configured provider
- **THEN** the CLI refuses to signal it and reports a safe ownership error
