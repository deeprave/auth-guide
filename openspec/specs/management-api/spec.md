# Management API Specification

## Purpose

Expose the reference provider's sole administrative control plane through a
versioned HTTPS API rather than direct database access.

## Requirements

### Requirement: HTTPS-only management surface
The provider SHALL expose setup, account, self-service, password, token, and
Guide-validation operations only over HTTPS at `POST /v1/setup`,
`/v1/accounts`, `/v1/accounts/me`, `/v1/tokens`, and `POST /v1/authenticate`.

#### Scenario: Cleartext access is attempted
- **WHEN** management traffic is sent without HTTPS
- **THEN** no management operation is available

### Requirement: One-time initial setup
The provider SHALL permit unauthenticated CLI-led setup only while database and
named key are absent. It SHALL create the database and key, apply migrations,
create the first administrator from a validated email, issue its initial token,
and return generated password and token exactly once. A failure SHALL remove
only state it created; pre-existing state is a non-mutating error.

#### Scenario: Initial setup succeeds
- **WHEN** setup state is absent and the CLI submits a valid email
- **THEN** the provider creates the first administrator and returns once-only
  credentials

### Requirement: Explicit orphan-key recovery
The optional `remove_orphan_key` setup argument SHALL remove only the named key
when the database is absent and the key exists, then proceed through setup. It
SHALL be disabled by default, reveal no key material, and never delete or
overwrite a database.

#### Scenario: Recovery encounters a database
- **WHEN** orphan-key recovery is requested while a database exists
- **THEN** the provider rejects the request without modifying database or key
