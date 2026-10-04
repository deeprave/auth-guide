# Proposal

## Why

The provider needs durable accounts and global user/admin grants, but its exact
storage implementation must follow the SQLCipher feasibility result rather than
be guessed now.

## What Changes

- Define account, password-verifier, and global-grant persistence using the
  selected encrypted async storage approach.
- Add migrations, backup/restore, removal, and rotation-safe lifecycle rules.
- Use Argon2id verifiers and never persist plaintext passwords or bearer tokens.

## Capabilities

### New Capabilities
- `encrypted-account-store`: Encrypted provider-owned account and grant persistence.

### Modified Capabilities
- None.

## Impact

Depends on the persistence proof and platform secret provider. It is the storage
foundation for management and issuer changes.
