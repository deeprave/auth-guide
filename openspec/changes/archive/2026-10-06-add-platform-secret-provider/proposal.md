# Proposal

## Why

Database, signing, and CA keys must not be stored in provider configuration or
the encrypted database they protect. The reference service needs one portable,
testable boundary for OS-protected secret material.

## What Changes

- Add an application-namespaced secret provider backed by macOS Keychain and
  Linux Freedesktop Secret Service.
- Define non-secret references, rotation, missing-secret, and secret-safe
  diagnostics behaviour.
- Provide platform integration tests, including the GNOME Keyring path used by
  wybra-dev.

## Capabilities

### New Capabilities
- `platform-secret-provider`: OS-keychain backed secret resolution for provider-owned keys.

### Modified Capabilities
- None.

## Impact

Introduces a runtime dependency selected during implementation and a service
boundary consumed by persistence, TLS, and issuer changes.
