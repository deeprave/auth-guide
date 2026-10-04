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
- Issue, rotate, replace, and retire server certificates; baseline TLS is
  server-authenticated only, with mTLS deferred.

## Capabilities

### New Capabilities
- `local-tls-authority`: Private local CA, trusted server certificates, and their lifecycle.

### Modified Capabilities
- None.

## Impact

Depends on platform secrets and establishes the HTTPS transport prerequisite for
the management API and OIDC issuer.
