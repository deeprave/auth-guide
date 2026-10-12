# Spec Delta

## Purpose

Offer a local standards-based issuer that authenticates provider accounts and supplies Guide with short-lived signed bearer tokens.

## ADDED Requirements

### Requirement: OIDC discovery and key publication
The provider SHALL publish issuer discovery, JWKS, and readiness endpoints over trusted HTTPS and SHALL support signing-key rotation.

#### Scenario: Guide discovers issuer keys
- **WHEN** a TLS-trusting client requests discovery and JWKS
- **THEN** it receives the active issuer metadata and verification keys

#### Scenario: Signing key rotates
- **WHEN** the issuer activates a new signing key
- **THEN** JWKS exposes verification material needed during the configured overlap period

### Requirement: Authenticated bearer issuance
The provider SHALL authenticate browser login and issue short-lived signed bearers carrying only the account's effective user or admin scope.

#### Scenario: User signs in successfully
- **WHEN** valid account credentials are submitted
- **THEN** the provider issues a short-lived bearer with the effective scope

#### Scenario: Invalid credentials are submitted
- **WHEN** authentication fails
- **THEN** no bearer is issued and the response does not disclose a password verifier
