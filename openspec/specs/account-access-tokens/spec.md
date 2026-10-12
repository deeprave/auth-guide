# Account Access Tokens Specification

## Purpose

Issue, delegate, list, label, and revoke opaque account-bound bearer tokens.

## Requirements

### Requirement: Opaque non-expiring tokens
The provider SHALL issue `agt_`-prefixed opaque 256-bit bearers, persist only a
SHA-256 verifier and non-secret metadata, and return the raw value only on
creation. Tokens SHALL not expire and remain valid until revoked or their owner
becomes inactive.

#### Scenario: A token is issued
- **WHEN** the provider creates an access token
- **THEN** it persists no raw bearer and returns it exactly once

#### Scenario: A token owner becomes inactive
- **WHEN** a token's owning account becomes inactive
- **THEN** the provider rejects the token without mutation

### Requirement: Token lifecycle
Accounts MAY hold multiple labelled tokens. Labels are required and are the only
mutable property; scopes, verifiers, and raw values are immutable. Revocation
SHALL permanently delete a token. Replacement is create-then-revoke and SHALL
not be atomic. Listings SHALL return all visible non-secret metadata.

#### Scenario: A token is revoked
- **WHEN** its owner or an authorised manager revokes it
- **THEN** the provider permanently deletes its record

### Requirement: Constrained token issuance
Active accounts SHALL issue their own token; callers with `tokens:manage` SHALL
issue for another active account. Requested scopes SHALL be a subset of both
the presenting token's scopes and the receiving account's current grants.
An explicit account selector, including one identifying the presenting account,
SHALL require `tokens:manage` before the provider resolves it.

#### Scenario: A broader token is requested
- **WHEN** an issuer requests an unavailable scope
- **THEN** the provider rejects the request without creating a token

#### Scenario: An unauthorised explicit selector is supplied
- **WHEN** a caller without `tokens:manage` supplies an account UUID or email
  selector for token listing or issuance
- **THEN** the provider rejects the request without resolving that selector
