# Encrypted Account Store Specification

## Purpose

Persist auth-guide accounts and recognised grants in its encrypted local
database with explicit database and migration lifecycle controls.

## Requirements

### Requirement: Account persistence
The store SHALL create, list, update, and permanently remove complete account records.

#### Scenario: An account is removed
- **WHEN** an administrator removes an account
- **THEN** its record and grants are permanently deleted without retention

### Requirement: Account identity and validation
An account SHALL have an immutable UUID4 identifier, unique syntax-valid email, validated recognised-grant set, UTC creation timestamp, and optional UTC expiry and full name. The store SHALL preserve local-part spelling, lowercase the domain, enforce case-insensitive uniqueness, reject an identifier over 254 octets, and validate email, expiry, and grants before persistence.

#### Scenario: An invalid account is saved
- **WHEN** an account has an invalid email, expiry, or recognised-grant set
- **THEN** the store rejects it without persistence

### Requirement: Expired account availability
Expired accounts SHALL be unavailable for authentication and authorisation but returned by explicit administrative queries.

#### Scenario: An account expires
- **WHEN** its expiry is at or before the current UTC time
- **THEN** ordinary queries omit it and authentication fails, while an explicit
  administrative query returns it


### Requirement: Explicit database lifecycle
The store SHALL use `auth-guide.sqlite3` under the provider configuration root.
It SHALL create a database only through explicit initialisation, reject an
existing database or key, and never create a replacement key at ordinary
startup. Migrations SHALL be an explicit administrative operation. Missing or
pending migrations SHALL be a fatal non-mutating readiness result with a plan
available to the administration CLI.

#### Scenario: A migration is pending
- **WHEN** readiness checks a database with unapplied migrations
- **THEN** it reports the pending state without modifying the database

### Requirement: Maintenance-extension boundary
tortoise-sqlcipher snapshot and key-rotation extensions SHALL NOT be exposed or
used by this reference provider or its administration CLI.

#### Scenario: Provider maintenance is requested
- **WHEN** an operator uses the reference provider or its administration CLI
- **THEN** backup, restore, and database-key rotation are not offered
