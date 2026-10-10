# Spec Delta

## Purpose

Provide a secret-safe local administrator client that invokes the provider management API without direct database access.

## ADDED Requirements

### Requirement: Authenticated management client
The CLI SHALL bootstrap the first administrator and perform account, password, and grant operations solely through the authenticated HTTPS management API.

#### Scenario: Administrator creates an account
- **WHEN** an authenticated CLI request creates an account
- **THEN** the provider management API performs the mutation

#### Scenario: Database access is unavailable
- **WHEN** the CLI runs without a database path or driver
- **THEN** its supported management operations remain API based

### Requirement: Explicit orphan-key bootstrap recovery
The CLI SHALL expose `--remove-orphan-key` only with its first-administrator
setup command. It SHALL send the provider's explicit orphan-key recovery
request and SHALL not inspect, delete, or overwrite database files or platform
keyring entries itself. It SHALL NOT expose a generic `--force` option or a
database-reset operation.

#### Scenario: An operator acknowledges an orphaned key
- **WHEN** an operator invokes setup with `--remove-orphan-key`
- **THEN** the CLI requests provider-owned key-only recovery and reports the
  provider result without exposing key material

### Requirement: Secret-safe interaction
The CLI SHALL acquire passwords and tokens through a prompt or controlled input channel and SHALL not accept or normally emit them in ordinary arguments or output.

#### Scenario: Password is set
- **WHEN** an administrator supplies a password through the controlled channel
- **THEN** normal command output does not contain that password
