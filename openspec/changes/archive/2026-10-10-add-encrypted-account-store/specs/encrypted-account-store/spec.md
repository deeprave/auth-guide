# Spec Delta

## Purpose

Persist the core accounts and global grants of auth-guide, the reference
auth-provider and example OIDC provider API for mcp-guide, in the selected
encrypted storage backend without retaining plaintext credentials or bearer
tokens.

## ADDED Requirements

### Requirement: Account and grant persistence
The store SHALL create, list, permanently remove, and update accounts with one
global user or admin grant, where admin satisfies user as a derived
authorisation rule. An account-facing identifier SHALL be an email address with
valid email syntax. The store SHALL not treat syntax validation as proof of
mailbox ownership. Each account SHALL have an immutable UUID4 primary key that
serves as its stable OIDC subject; the email address SHALL be unique but may be
updated. The store SHALL preserve the supplied local-part spelling, normalise
the domain to lowercase, enforce case-insensitive email uniqueness, and reject
a normalised identifier longer than 254 octets. Each account SHALL retain a
UTC creation timestamp, optional UTC expiry timestamp, and optional full name.
An absent expiry SHALL mean the account is active. An account whose expiry is
at or before the current UTC time SHALL be inactive for authentication and
authorisation while remaining available to administrative reads. Clearing an
expiry SHALL reactivate the account. The optional full name SHALL be ordinary
administrator-managed profile data and SHALL have no implied protocol meaning.
The account persistence surface SHALL expose complete `AccountRecord` ORM
records rather than a reduced account value object. Account creation and model
save operations SHALL validate and normalise the email identifier, expiry, and
grant before persistence. Default account ORM queries SHALL return active
accounts only. Administrative callers SHALL explicitly request inactive
accounts when required.

#### Scenario: Account receives an email identifier
- **WHEN** an administrator creates an account with a syntactically valid email address
- **THEN** the store accepts it as the account-facing identifier

#### Scenario: Invalid email identifier is supplied
- **WHEN** an administrator creates or updates an account with an invalid email address
- **THEN** the store rejects the operation without persisting the account change

#### Scenario: Account email is updated
- **WHEN** an administrator updates an account with a different valid email address
- **THEN** the account retains its existing UUID4 primary key and OIDC subject

#### Scenario: Equivalent email is supplied
- **WHEN** an administrator creates or updates an account with an email address
  equivalent to another account identifier under case-insensitive comparison
- **THEN** the store rejects the operation without creating duplicate accounts

#### Scenario: Account receives admin access
- **WHEN** an administrator grants admin access
- **THEN** the account has effective admin and user access

#### Scenario: Account metadata is recorded
- **WHEN** an administrator creates an account with an optional full name and expiry
- **THEN** the store returns those values and records the UTC creation timestamp

#### Scenario: Account is expired
- **WHEN** an account's expiry is at or before the current UTC time
- **THEN** authentication and grant lookup fail, ordinary account queries omit
  it, and an explicit administrative query retains the account

#### Scenario: Account is reactivated
- **WHEN** an administrator clears an account expiry
- **THEN** the account resumes authentication and authorisation according to its grant

#### Scenario: Account is removed
- **WHEN** an administrator removes an account
- **THEN** subsequent authentication and grant lookup fail for that account

#### Scenario: Account removal is inspected
- **WHEN** an administrator removes an account
- **THEN** the account record and its persisted grant are deleted without a
  retention record

### Requirement: Credential protection
The store SHALL persist only Argon2id password verifiers and SHALL not persist
plaintext passwords or issued bearer tokens. Argon2id verifiers SHALL use fixed
parameters of 64 MiB memory, three iterations, parallelism four, a 16-byte
salt, and a 32-byte hash. The store SHALL NOT automatically rehash a verifier;
any future password-policy change requires an explicit password reset. Missing,
inactive, and passwordless accounts SHALL use the same unknown-password
verification path before authentication fails.

#### Scenario: Database is inspected
- **WHEN** stored account data is examined through the supported test interface
- **THEN** it contains no plaintext password or bearer value

### Requirement: Storage lifecycle
The store SHALL use `auth-guide.sqlite3` beneath the provider configuration root. The
deploying user SHALL generate, review, and commit Tortoise native migrations
from the supplied models. The store SHALL create a database only through an
explicit initialisation operation, which SHALL reject an existing database or
database-key reference. Ordinary startup SHALL resolve an existing key and
SHALL fail when it is absent; it SHALL NOT create a replacement. The store
SHALL apply migrations through an explicit administrative operation and SHALL
NOT apply migrations automatically at service startup. A pending migration
SHALL be a fatal readiness failure without database mutation.

#### Scenario: Migration is pending
- **WHEN** a provider starts with unapplied native migrations
- **THEN** it reports that migration is required without modifying the database

#### Scenario: Migration readiness is checked
- **WHEN** a provider checks whether a present account database has unapplied
  native migrations
- **THEN** the account-store API reports the pending state without writing a
  plan to standard output and makes the display-ready plan available to an
  administration CLI that explicitly requests it

#### Scenario: Migration has not been supplied
- **WHEN** a deploying user has not generated and committed a native migration
- **THEN** the provider reports that migration is required without modifying the database

#### Scenario: Existing database key is absent
- **WHEN** an existing account database has no corresponding platform secret
- **THEN** startup fails with a secret-safe error and does not create a replacement key

### Requirement: Maintenance-extension scope
tortoise-sqlcipher may provide encrypted-database snapshot and key-rotation
extensions. They SHALL NOT be exposed through this reference provider's
service, used by its account-store workflow, or offered through its future
administration CLI. Their availability does not make them a critical part of
this implementation, and bugs or enhancement requests concerning them are out
of scope for auth-guide.

#### Scenario: Reference provider does not expose maintenance extensions
- **WHEN** an operator uses the reference provider service or its future
  administration CLI
- **THEN** backup, restore, and database-key rotation are not offered or
  invoked by that provider workflow
