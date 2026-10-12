# Proposal

## Why

Local operators need a safe administration interface, while the provider must
remain the sole authority over its database and management authorisation.

## What Changes

- Add an authenticated HTTPS management client for first-admin bootstrap,
  account lifecycle, password changes, and user/admin grants.
- Extend management operations to accept exactly one account selector: immutable
  account UUID or validated account email, resolved by the provider.
- Add a TOML configuration file for separate provider listen and CLI connection
  addresses, with explicit command-line and environment overrides.
- Add trace-capable structured logging with configurable Rich console, standard
  file, and optional syslog handlers.
- Expose `--remove-orphan-key` only for explicit bootstrap recovery; it asks the
  provider to remove an orphaned database key and is never a database reset.
- Use prompts or controlled input for secrets; reject secrets in ordinary CLI
  arguments and normal output.
- Never open, migrate, read, or write the provider database directly.

## Capabilities

### New Capabilities
- `provider-administration-cli`: Secret-safe authenticated client for provider management.

### Modified Capabilities
- `management-api`: Accept account UUID or email target selectors.

## Impact

Depends on the HTTPS management API and local CA trust setup. It contains no
database driver or persistence logic.
