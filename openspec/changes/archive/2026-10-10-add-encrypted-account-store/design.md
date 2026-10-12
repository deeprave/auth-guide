# Design

## Context

auth-guide is the reference auth-provider: a working example OIDC provider and
provider API for mcp-guide. Its account store follows the persistence proof and
uses platform-resolved database keys.

## Goals / Non-Goals

**Goals:** core provider account/grant lifecycle, Argon2id verifier handling,
and the persistence foundation used by the provider API and OIDC issuer.

**Non-Goals:** choosing storage before the proof, persisting bearer tokens, or
exposing encrypted-database maintenance to the reference provider's service or
administration CLI.

## Decisions

- Use Tortoise native migrations only; do not introduce Aerich. The deploying
  user generates, reviews, and commits migrations from these models; auth-guide
  does not ship a generated migration.
- Use `AccountRecord` directly as the account persistence surface rather than a
  repository of field-specific setters. Account reads retain the entire ORM
  record. Its save path validates and normalises email, expiry, and grant data;
  callers making changes use normal Tortoise model operations.
- Make the default `AccountRecord` query manager active-only. Administrative
  callers explicitly use `AccountRecord.including_inactive()` when they need
  expired records.
- Create the platform-held database key and database only through the explicit
  `initialise` operation. It refuses an existing database or key. Ordinary
  startup resolves the existing key and fails safely when it is absent.
  Readiness does not open a missing database; it reports that migration is
  required instead.
- Test account behaviour without reproducing tortoise-sqlcipher's encrypted
  backend coverage.
- Store one global grant enum per account: `admin` implies `user` at authorisation time and is not duplicated in persistence.
- Use an email address as the account-facing identifier and validate its syntax on creation and update. Preserve its supplied local-part spelling, normalise its domain to lowercase, and enforce case-insensitive uniqueness. Mailbox-ownership verification is outside this reference provider's account-store scope.
- Use a UUID4 primary key as the immutable account identity and stable OIDC subject; keep the validated email address unique but mutable.
- Store a creation timestamp, optional UTC expiry timestamp, and optional full
  name for each account. An absent expiry means active; an expiry at or before
  the current UTC time denies authentication and authorisation while retaining
  the account for administration. Clearing an expiry reactivates the account.
  The future administration CLI may set or clear the optional full name; it has
  no implied OIDC, discovery, or other protocol semantics.
- Remove accounts by permanent deletion; this reference provider has no retention or soft-delete lifecycle.
- Store the encrypted database as `auth-guide.sqlite3` beneath the provider configuration root. Apply Tortoise native migrations through an explicit administrative operation, not automatically at service startup.
- Keep migration readiness silent. The account store exposes a display-ready
  pending-migration plan so the future administration CLI can render it only
  when requested; its migration operation can check pending work or apply it,
  and skips application when no migrations are pending.
- tortoise-sqlcipher offers key rotation and encrypted snapshots as optional
  backend extensions. They may be used by deployment-specific consumers but
  are neither exposed nor invoked by this reference provider; future bugs or
  enhancement requests concerning them are out of scope here.
- Use fixed Argon2id parameters: 64 MiB memory, three iterations, parallelism
  four, a 16-byte salt, and a 32-byte hash. Policy changes require an explicit
  password reset; this reference provider does not rehash on login. Inactive,
  passwordless, and missing accounts use the same unknown-verifier work before
  authentication fails.

## Risks / Trade-offs

- Storage proof may reject Tortoise → implement the recorded approved alternative, not a fallback invented during this change.
