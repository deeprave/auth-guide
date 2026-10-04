# Spec Delta

## Purpose

Provide provider-owned secret resolution through platform credential stores without exposing secret values to configuration or diagnostics.

## ADDED Requirements

### Requirement: Platform secret resolution
The service SHALL resolve application-namespaced secret references from macOS Keychain and Linux Freedesktop Secret Service.

#### Scenario: Referenced secret exists
- **WHEN** a configured reference resolves in the active platform store
- **THEN** the service receives its value without printing it

#### Scenario: Referenced secret is absent
- **WHEN** a configured reference cannot be resolved
- **THEN** startup fails with a secret-safe error

### Requirement: Secret rotation
The service SHALL support replacing a referenced secret without storing either version in its database or ordinary configuration.

#### Scenario: Secret reference is rotated
- **WHEN** an operator updates the platform entry and restarts the service
- **THEN** new key use resolves the replacement value
