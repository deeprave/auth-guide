# Account Credentials Specification

## Purpose

Protect account passwords with fixed Argon2id verifiers and define their
management lifecycle.

## Requirements

### Requirement: Password verifier protection
The provider SHALL persist only Argon2id password verifiers, never plaintext
passwords or bearer values. Verifiers SHALL use 64 MiB memory, three
iterations, parallelism four, a 16-byte salt, and a 32-byte hash. It SHALL not
automatically rehash. Missing, inactive, and passwordless accounts SHALL use
the same unknown-password verification path.

#### Scenario: Credential storage is inspected
- **WHEN** stored account data is examined through the supported test interface
- **THEN** it contains neither plaintext passwords nor bearer values

### Requirement: Password replacement policy
Account creation, self-service replacement, and administrator reset SHALL
require at least 12 password characters without maximum or composition rule. A
failed initial verifier operation SHALL leave no account record.
`must_change_password` SHALL default false, be set for bootstrap and resets,
and clear after successful self-service replacement.

#### Scenario: A user replaces a password
- **WHEN** an active account replaces its own password
- **THEN** the verifier is stored and `must_change_password` is cleared
