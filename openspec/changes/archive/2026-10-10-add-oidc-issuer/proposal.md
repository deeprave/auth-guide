# Proposal

## Why

Guide needs standards-based discovery and signed, short-lived opaque-to-Guide
bearer tokens without receiving provider credentials, accounts, or databases.

## What Changes

- Add browser login, OIDC discovery, JWKS publication, signing-key rotation,
  and short-lived bearer issuance.
- Map provider grants to global user and admin scopes, with admin satisfying
  user.
- Add readiness and managed-process lifecycle contracts for a future Guide
  adapter.

## Capabilities

### New Capabilities
- `reference-oidc-issuer`: Local OIDC login, discovery, keys, and bearer issuance.

### Modified Capabilities
- None.

## Impact

Depends on encrypted accounts, platform secrets, and HTTPS. The Guide-side
adapter remains explicitly out of scope in mcp-guide.
