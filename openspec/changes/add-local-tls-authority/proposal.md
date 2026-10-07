# Proposal

## Why

The local provider and Guide communicate over HTTPS only, but public ACME is
not appropriate for the localhost reference deployment. A private local CA is
needed to issue a trusted service certificate without exposing a public issuer.

## What Changes

- Create a provider-owned private CA with root private material in the platform
  secret provider.
- Install its public root in supported system trust stores through an explicit
  privileged administrator flow.
- Verify the issued chain through macOS's Security framework with an explicit
  per-evaluation root anchor during ordinary development tests. This does not
  mutate a keychain or affect the production trust-store selection.
- Issue, rotate, replace, and retire server certificates; baseline TLS is
  server-authenticated only, with mTLS deferred.
- Store public certificate lifecycle metadata in a provider-owned JSON document
  under the Guide-aligned auth configuration root. A future database migration
  is a separate decision and change.
- Default server identities to localhost and loopback addresses, with a
  command-line override accepting an explicit list.
- Reconcile the implementation with the approved review outcomes: asynchronous
  lifecycle boundaries, atomic and recoverable metadata publication,
  certificate-specific system-trust removal, and behaviour-focused tests.

## Capabilities

### New Capabilities
- `local-tls-authority`: Private local CA, trusted server certificates, and their lifecycle.

### Modified Capabilities
- None.

## Impact

Depends on platform secrets and establishes the HTTPS transport prerequisite for
the management API and OIDC issuer.
