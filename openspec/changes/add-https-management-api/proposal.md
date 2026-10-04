# Proposal

## Why

Administrators need account and grant management without opening the provider
database directly. The reference service must expose a TLS-protected control
plane with provider-owned authorisation and bootstrap validation.

## What Changes

- Add HTTPS-only authenticated management operations for bootstrap, account
  CRUD, password reset, and user/admin grant assignment.
- Reject cleartext transport and unauthorised mutations.
- Keep all database access inside the provider.

## Capabilities

### New Capabilities
- `https-management-api`: Authenticated HTTPS management control plane for provider accounts.

### Modified Capabilities
- None.

## Impact

Depends on the account store and local TLS authority. It supplies the sole
administrative interface later consumed by the CLI.
