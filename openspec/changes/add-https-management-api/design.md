# Design

## Context

The management API is the sole administration boundary after TLS and account storage exist.

## Goals / Non-Goals

**Goals:** HTTPS-only authenticated mutations and first-admin bootstrap.

**Non-Goals:** database administration protocols, client-managed authorisation,
or serving a browser front end. A later independently deployed single-page
application may consume this API for account self-service; auth-guide remains
the API and account authority, not the front-end host.

The `add-admin-cli` change will decide the command boundary and orchestration
for TLS initialisation, system-trust installation, database bootstrap, and
initial-account creation. This API change consumes the existing active server
TLS material and fails before serving HTTPS when that material is absent.

Uvicorn receives a preloaded `ssl.SSLContext` through its supported context
factory. Because CPython's server-certificate loader accepts file paths only,
the TLS authority exclusively creates owner-only runtime files in an owner-only
directory, sets each file to exactly `0600` before writing, loads the context,
then removes the files before Uvicorn starts serving.

This change does not provide end-user registration, password login, or a
self-service token-acquisition screen. Bootstrap returns the first management
token once; until the later accounts-screen/login change exists, an account
manager creates an account and issues its initial user token through this API.

## Decisions

- Bind the service to the configured local HTTPS endpoint; do not add cleartext fallback.
- Use FastAPI request handling, Pydantic API schemas, and a single Uvicorn ASGI
  process with the active local-CA certificate and key.
- Generate the OpenAPI contract from the typed FastAPI routes and verify it in
  contract tests. Disable public Swagger and ReDoc interfaces by default.
- Expose the versioned API surface as `POST /v1/setup`, `/v1/accounts` CRUD,
  `/v1/accounts/me` self-service operations, `/v1/tokens` lifecycle operations,
  and `POST /v1/authenticate` for Guide bearer validation. Token list/create
  without an account identifier applies to the caller; a caller with
  `tokens:manage` may select another account.
- Initial setup is a CLI operation using an unauthenticated one-time HTTPS
  setup route. It requires both the encrypted database and its named
  platform-secret key to be absent; delegates database/key creation and native
  migration execution to the account-store lifecycle APIs; accepts a validated
  administrator email; then creates the
  first administrator and its initial account access token. It returns the raw
  password and token exactly once. A failure removes only database/key material
  created by that setup attempt; pre-existing state is a non-mutating error.
- Orphan-key recovery is the `remove_orphan_key` setup query argument, disabled by default. The
  provider first confirms that its database is absent, then removes only the
  named database key before following the ordinary setup path. It is not a
  generic force or database-reset operation; every state containing a database
  remains a non-mutating error.
- Account access uses account-bound bearer tokens. The future Guide auth-provider
  forwards the bearer from the MCP request's `Authorization` header for
  validation. Any active account may use the
  self-service routes for its own name, email, password, and account closure.
  Privileged account creation, deletion, and grant assignment require an active
  account holding `accounts:manage`.
- Accounts own an explicit set of recognised grants and tokens delegate a subset
  of their owner's grants. A valid active token establishes Guide's
  authenticated-user level without a `guide:user` grant. The account-level
  `guide:admin` grant is returned to Guide when present and provides its
  administrator level. The Guide-facing response returns only its recognised
  bare scope name, `admin`; successful authentication implies `user` and does
  not return it explicitly. `guide:admin` is exclusively a Guide authorisation
  grant; `accounts:manage` authorises privileged account
  operations. Self-service and token lifecycle operations have their separately
  stated authority rules. Unknown grants and
  scopes fail closed. This allows future feature-specific gates without issuing
  unrestricted tokens by default.
- Account grants and token scopes are stored as validated JSON arrays on their
  respective records. The account's existing single-grant column is replaced by
  `grants`; a separate grant relation is unnecessary because this small complete
  set is always resolved with the account and is not independently queried.
- Each independently revocable account token is stored as a separate record
  with a UUID, account foreign key, required label, unique SHA-256 verifier,
  validated scope array, and UTC creation time. The raw bearer is never stored.
- The bootstrap administrator receives `guide:admin`, `accounts:read`,
  `accounts:manage`, and `tokens:manage`. Its initial access token delegates the
  latter three
  capabilities; no grant is a wildcard or receives future capabilities
  automatically.
- Account access tokens do not expire in this reference provider. They remain
  valid until explicit revocation or replacement, unless their owning account
  becomes inactive. Management routes separately require their designated
  account-management grants.
- Account access tokens are opaque 256-bit random bearer values with an `agt_`
  prefix. Only their SHA-256 verifiers and metadata are persisted; raw values
  are returned exactly once at creation or replacement.
- An account may hold multiple labelled access tokens. Revocation permanently
  deletes the token record. Replacement is create a new token, safely retain its
  raw value, then revoke the old token; the provider does not offer a risky
  atomic swap.
- Every token has a required label. Initial setup creates the initial token with
  the label `admin`; later creation accepts a caller-supplied label. A token's
  label is its only mutable field: scopes, raw bearer value, and verifier are
  immutable after creation.
- Token listings expose all non-secret metadata, including labels, owner,
  scopes, and lifecycle metadata. They never expose a raw bearer value or its
  stored verifier. A caller without `tokens:manage` sees only its own tokens; a
  caller with that scope may list tokens for any account.
- A caller may revoke its own tokens. A caller holding `tokens:manage` may
  revoke a token for any account.
- An active authenticated account may issue an access token for itself. A caller
  holding `tokens:manage` may issue an access token for another active account;
  delegated issuance does not require `guide:admin` or `accounts:manage`.
- Every issued token's scope set must be a subset of both the presenting token's
  scope set and the receiving account's grants, for self-issued and delegated
  tokens alike.
- A token used solely for Guide authentication may have an empty scope set. Its
  active owning account provides baseline Guide authentication; its
  `guide:admin` account grant, when present, provides Guide administrator
  access. Explicit scopes gate provider capabilities.
- Initial setup generates and returns a 12-character printable-ASCII
  password for the initial administrator and sets `must_change_password` on
  that account. A successful password change clears the flag. The field belongs
  to the existing account model and defaults to `false`. A later accounts-screen
  and password-login change will enforce the flag before issuing access tokens;
  this token-authenticated API preserves the state but has no password-login
  route itself.
- A user may update only its own full name or email (subject to the normal email
  validation and uniqueness constraint), replace only its own password, and
  close only its own account by making it inactive. It cannot create or delete
  account records, change grants, or update another account through
  self-service routes.
- Self-service email updates return one generic client error for malformed and
  already-used identifiers, so an ordinary bearer cannot enumerate accounts.
- An account holding `accounts:manage` may reset another account's password and
  reactivate an inactive account. It does not edit another account's profile.
- An account manager replaces an account's entire grant set in one normal account
  update rather than issuing granular add/remove grant operations.
- Account creation, self-service replacement, and administrator reset require
  at least 12 password characters, with no maximum length or composition rule.
  If an initial password verifier cannot be generated or persisted, the provider
  persists no account record rather than leaving a partially provisioned record.
- An active account may read only its own account record. A caller holding
  `accounts:read` may read or list every account; this read authority does not
  require `accounts:manage`.

## Risks / Trade-offs

- Setup misuse → require absent database/key preflight, ownership-aware cleanup,
  and race-focused integration tests.
