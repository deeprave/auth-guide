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

### Requirement: Secret-safe interaction
The CLI SHALL acquire passwords and tokens through a prompt or controlled input channel and SHALL not accept or normally emit them in ordinary arguments or output.

#### Scenario: Password is set
- **WHEN** an administrator supplies a password through the controlled channel
- **THEN** normal command output does not contain that password
