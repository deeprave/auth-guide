# Spec Delta

## MODIFIED Requirements

### Requirement: HTTPS-only management surface
The provider SHALL expose setup, account, self-service, password, token, and
Guide-validation operations only over HTTPS at `POST /v1/setup`,
`/v1/accounts`, `/v1/accounts/me`, `/v1/tokens`, and `POST /v1/authenticate`.
Every operation targeting an account other than the authenticated caller SHALL
accept exactly one selector: immutable account UUID or validated account email.
The provider SHALL authorise the requested operation before resolving and
mutating another account selector. Token listing and issuance SHALL require
`tokens:manage` before resolving any explicit UUID or email selector, including
one that identifies the authenticated caller.
Existing UUID-targeted paths SHALL remain supported. Email-targeted account
read, update, and deletion SHALL use the account collection's `email` query
parameter; password reset SHALL use the equivalent email selector convention.
Token creation and listing SHALL accept exactly one `account_id` or
`account_email` selector.

#### Scenario: Cleartext access is attempted
- **WHEN** management traffic is sent without HTTPS
- **THEN** no management operation is available

#### Scenario: Email identifies a target account
- **WHEN** a management request supplies a valid email selector for another
  account
- **THEN** the provider resolves the same account that its validated email
  identity identifies

#### Scenario: Email identifies the authenticated account
- **WHEN** an authenticated caller supplies its own validated account email to
  the account-read endpoint
- **THEN** the provider returns that account without requiring `accounts:read`

#### Scenario: An existing UUID path is used
- **WHEN** a management request supplies an account UUID in an existing account
  path
- **THEN** it continues to target that account without an email query parameter

## ADDED Requirements

### Requirement: Actionable account-expiry validation
The provider SHALL reject an account-creation expiry timestamp that omits a
timezone with a 422 response identifying the timezone requirement.

#### Scenario: A naive account expiry is supplied
- **WHEN** account creation receives an ISO-8601 timestamp without a timezone
- **THEN** the provider responds with 422 and identifies the missing timezone
