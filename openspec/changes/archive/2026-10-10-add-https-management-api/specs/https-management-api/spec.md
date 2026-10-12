# Spec Delta

## Purpose

Expose the provider's only administrative control plane through authenticated HTTPS rather than direct database access.

End-user registration, password login, and self-service token acquisition are
outside this change. Until a later accounts-screen/login change supplies them,
an account manager creates an account and issues its initial token through the
management API.

## ADDED Requirements

### Requirement: HTTPS-only management operations
The provider SHALL expose first-admin bootstrap, account operations, password
reset, and grant operations only over HTTPS. It SHALL expose `POST /v1/setup`,
`/v1/accounts` CRUD routes, `/v1/accounts/me` self-service routes,
`/v1/tokens` lifecycle routes, and `POST /v1/authenticate` for Guide bearer
validation.

#### Scenario: Authenticated administrator mutates an account
- **WHEN** an authorised management request is received over trusted HTTPS
- **THEN** the provider applies the requested permitted mutation

#### Scenario: Cleartext request is attempted
- **WHEN** management traffic is sent without HTTPS
- **THEN** no management operation is available

### Requirement: CLI-led initial setup
The provider SHALL permit the administration CLI to call an unauthenticated
HTTPS setup route only while both the encrypted database and its named
platform-secret key are absent. The route SHALL delegate database/key creation
and native migration execution to account-store lifecycle APIs; generate the
first administrator from a validated administrator email and initial access
token; and return the raw password and token exactly once. The route SHALL
compensate a failed setup by removing only
database and key material created by that attempt. Pre-existing database or key
state SHALL be a non-mutating error.

#### Scenario: Initial setup succeeds
- **WHEN** the encrypted database and named key are absent and the CLI submits
  a valid setup request containing an administrator email over HTTPS
- **THEN** the provider creates the encrypted database and key, applies
  migrations, creates one active account with `guide:admin`, `accounts:read`,
  `accounts:manage`, and `tokens:manage`, and an initial access token scoped to
  `accounts:read`, `accounts:manage`, and `tokens:manage`; it creates a
  12-character printable-ASCII initial password, sets
  `must_change_password`, and returns the raw password and token exactly once

#### Scenario: Setup is attempted with pre-existing state
- **WHEN** the encrypted database or named key already exists
- **THEN** the provider rejects the setup request without changing storage

#### Scenario: Setup fails after creating state
- **WHEN** setup fails after it creates the encrypted database or named key
- **THEN** the provider removes only the database and key created by that setup
  attempt and returns no password or token

### Requirement: Explicit orphan-key setup recovery
The provider SHALL support an explicit `remove_orphan_key` setup query argument that removes the
named database key only when the encrypted database is absent and that key is
present. The request SHALL be disabled by default, SHALL never delete or
overwrite a database, and SHALL fail without changing state when a database is
present or the key is absent. It SHALL return no key value.

#### Scenario: An orphaned key is explicitly removed
- **WHEN** a setup request explicitly requests orphan-key removal, the database
  is absent, and the named database key is present
- **THEN** the provider removes only that key and proceeds through ordinary
  first-admin setup

#### Scenario: Recovery is requested for a database-bearing state
- **WHEN** a setup-recovery request is made while an encrypted database exists
- **THEN** the provider rejects it without deleting or overwriting the database
  or key

#### Scenario: Recovery is requested without an orphaned key
- **WHEN** a setup-recovery request is made while the named key is absent
- **THEN** the provider rejects it without creating a database or key

### Requirement: Provider-owned authorisation
The provider SHALL authenticate callers using an account-bound bearer token.
Account creation, deletion, and grant assignment SHALL require an active
account holding the `accounts:manage` grant.
Account creation, self-service password replacement, and administrator password
reset SHALL require a password of at least 12 characters, without a maximum
length or composition rule. Account creation SHALL leave no account record when
generating or persisting that password fails.
An active account may use self-service routes to update only its own full name
or email, replace only its own password, or close only its own account by making
it inactive, and may read only its own record. A caller holding `accounts:read`
may read or list every account without requiring `accounts:manage`. The future
Guide auth-provider SHALL forward the bearer from the MCP request's
`Authorization` header to this provider for validation. The provider SHALL not
expose database credentials or direct database operations to clients.

An account holding `accounts:manage` may reset another account's password and
reactivate an inactive account, but may not edit another account's profile. An
account manager replaces the complete grant set in a normal account update; the
provider SHALL NOT expose granular add/remove grant operations.

#### Scenario: An unauthorised privileged mutation is attempted
- **WHEN** a caller lacking administrator authority attempts account creation,
  deletion, or grant assignment
- **THEN** the provider rejects the request without mutating storage

#### Scenario: Account creation has no partial password state
- **WHEN** an account manager creates an account with a non-empty initial
  password and generating or persisting its verifier fails
- **THEN** the provider persists no account record and returns the failure

#### Scenario: A user updates its own profile
- **WHEN** an active authenticated account updates its own full name or email
- **THEN** the provider updates only that account and applies normal email
  validation and uniqueness checks

#### Scenario: A self-service email update cannot enumerate accounts
- **WHEN** an active authenticated account supplies an invalid or already-used
  email identifier through its self-service update
- **THEN** the provider returns the same generic client error for either case

#### Scenario: A user closes its account
- **WHEN** an active authenticated account closes its own account
- **THEN** the provider makes that account inactive

#### Scenario: An administrator resets a password
- **WHEN** an active account holding `accounts:manage` resets another account's
  password
- **THEN** the provider replaces that password and sets `must_change_password`

#### Scenario: An administrator reactivates an account
- **WHEN** an active account holding `accounts:manage` reactivates an inactive
  account
- **THEN** the provider clears that account's expiry

#### Scenario: An administrator replaces a grant set
- **WHEN** an active account holding `accounts:manage` updates another account's
  grants
- **THEN** the provider replaces the complete validated grant set

#### Scenario: A user reads its own account
- **WHEN** an active authenticated account requests its own record
- **THEN** the provider returns that account record

#### Scenario: An account reader lists accounts
- **WHEN** a caller holding `accounts:read` lists accounts
- **THEN** the provider returns account records regardless of their ownership

### Requirement: Extensible account grants and token scopes
The provider SHALL assign every account an explicit set of recognised grants and
bind every account access token to a subset of its owner's grants. A valid active
token establishes Guide's user level without a `guide:user` grant. The
`guide:admin` grant is exclusively returned to Guide for its administrator
level; `accounts:manage` is necessary for privileged account operations. A
token without a route's required capability SHALL NOT authorise that route. The
provider SHALL reject unknown grants and scopes. It SHALL store each account's
grants and each token's scopes as a validated JSON array on the respective
record; it SHALL NOT use a separate grant relation.

#### Scenario: A grant set is persisted
- **WHEN** the provider creates or replaces an account's grants
- **THEN** it persists the complete validated grant set on that account record

#### Scenario: A token lacks a required capability
- **WHEN** an active account presents a valid token without the capability
  required by a route
- **THEN** the provider rejects the request without mutating storage

#### Scenario: A new grant is introduced
- **WHEN** the provider introduces a grant after an account or token was issued
- **THEN** neither the existing account nor token receives it automatically

#### Scenario: A token has no explicit scopes
- **WHEN** an active account presents a valid access token with an empty scope
  set to Guide
- **THEN** the provider authenticates it at Guide's user level, and returns
  `guide:admin` only if the account holds that grant

### Requirement: Non-expiring account access tokens
The provider SHALL issue account access tokens without an expiry time. A token SHALL
remain valid until it is explicitly revoked or replaced, unless its owning
account becomes inactive. Management routes additionally apply their designated
account-management grant requirement.

#### Scenario: A token owner becomes inactive
- **WHEN** a token's owning account is inactive
- **THEN** the provider rejects the token without mutating storage

### Requirement: Opaque account-token storage
The provider SHALL issue account access tokens as opaque 256-bit random bearer
values prefixed with `agt_`. It SHALL persist only a SHA-256 verifier and token
metadata, and SHALL return the raw token only when it is created or replaced.

#### Scenario: A token is issued
- **WHEN** the provider creates an account access token
- **THEN** it persists no raw bearer value and returns the raw value exactly once

### Requirement: Multiple token lifecycle
The provider SHALL allow an account to hold multiple access tokens, each with a
required label. Initial setup SHALL label its initial token `admin`; later token
creation SHALL accept a caller-supplied label. The provider SHALL permanently
delete a token record on revocation. Replacement SHALL be an operator workflow
of creating a new token and later revoking the old token; the provider SHALL NOT
replace a token atomically. A token label is its only mutable field; its scopes,
raw bearer value, and stored verifier SHALL remain immutable after creation.

#### Scenario: An operator replaces a token
- **WHEN** an operator creates a new token and then revokes an old token
- **THEN** the new token remains valid and the old token no longer authenticates

#### Scenario: Tokens are listed
- **WHEN** a caller lists visible account access tokens
- **THEN** the provider returns all non-secret token metadata and returns neither
  raw bearer values nor stored verifiers

#### Scenario: A user relabels a token
- **WHEN** a caller updates the label of a token it owns
- **THEN** the provider changes only that label and preserves the token's
  credential material and scopes

#### Scenario: A user lists tokens without token-management authority
- **WHEN** a caller without `tokens:manage` lists account access tokens
- **THEN** the provider returns only tokens owned by that caller

#### Scenario: A token manager lists another account's tokens
- **WHEN** a caller holding `tokens:manage` lists tokens for another account
- **THEN** the provider returns the other account's non-secret token metadata

#### Scenario: A user revokes its own token
- **WHEN** a caller revokes a token it owns
- **THEN** the provider permanently deletes that token record

#### Scenario: A token manager revokes another account's token
- **WHEN** a caller holding `tokens:manage` revokes a token owned by another
  account
- **THEN** the provider permanently deletes that token record

### Requirement: Account access-token issuance
The provider SHALL allow an active authenticated account to issue an access token
for itself. A caller holding `tokens:manage` SHALL be permitted to issue an
access token for another active account; this delegated issuance SHALL NOT
require `guide:admin` or `accounts:manage`. Every issued token's scope
set SHALL be a subset of both the presenting token's scope set and the receiving
account's grants.

#### Scenario: A user issues its own token
- **WHEN** an active authenticated user requests an access token for itself
- **THEN** the provider creates a token owned by that user

#### Scenario: A delegated token is issued
- **WHEN** an active caller holding `tokens:manage` requests a token for another
  active account
- **THEN** the provider creates a token owned by the requested account

#### Scenario: An issuer requests a broader token
- **WHEN** a caller requests scopes not held by its presenting token
- **THEN** the provider rejects the request without creating a token

#### Scenario: An issuer requests a capability not granted to the recipient
- **WHEN** a caller requests a scope which the receiving account does not hold
- **THEN** the provider rejects the request without creating a token

### Requirement: Guide token authentication
The provider SHALL authorise a valid account access token for future Guide
authentication while its owning account remains active. Successful
authentication SHALL establish Guide's authenticated-user level without a
`guide:user` grant or dedicated token scope. Its successful response SHALL
contain only Guide-recognised bare scope names: it SHALL return `admin` when
the account holds `guide:admin`, and SHALL omit `user` because successful
authentication implies it. It SHALL NOT return provider-management grants to
Guide.

#### Scenario: A token is presented to Guide
- **WHEN** an active account presents a valid account access token with
  no dedicated Guide scope
- **THEN** the provider returns an empty scope set and Guide authorises the token
  at its authenticated-user level

#### Scenario: An administrator token is presented to Guide
- **WHEN** an active account holding `guide:admin` presents a valid account
  access token
- **THEN** the provider returns the bare `admin` scope and Guide authorises the
  token at its administrator level

### Requirement: Mandatory password change state
The provider SHALL persist an account-level `must_change_password` flag. It
SHALL set the flag for the bootstrap administrator and clear it when that
account's password is successfully changed. The field SHALL default to `false`.
This API SHALL preserve the state; a later password-login/accounts-screen change
SHALL enforce it before issuing access tokens.

#### Scenario: The bootstrap password is replaced
- **WHEN** the initial administrator successfully changes its password
- **THEN** the provider clears `must_change_password`
