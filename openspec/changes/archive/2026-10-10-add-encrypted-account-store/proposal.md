# Proposal

## Why

auth-guide is the reference auth-provider: a working example OIDC provider and
provider API for mcp-guide. It needs durable accounts and global user/admin
grants, but its exact storage implementation must follow the SQLCipher
feasibility result rather than be guessed.

## What Changes

- Define account, lifecycle metadata, password-verifier, and global-grant
  persistence using the selected encrypted async storage approach.
- Add explicit migrations and account removal. The encrypted backend's optional
  maintenance extensions remain available but are not part of this reference
  provider's service or administration surface.
- Use Argon2id verifiers and never persist plaintext passwords or bearer tokens.

## Capabilities

### New Capabilities
- `encrypted-account-store`: Encrypted provider-owned account and grant persistence.

### Modified Capabilities
- None.

## Impact

Depends on the persistence proof and platform secret provider. It is core
provider functionality, supporting the management API and OIDC issuer rather
than an optional future-platform experiment.
