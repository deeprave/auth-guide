# Spec Delta

## Purpose

Provide a private local certificate authority that makes the reference provider available only through trusted server-authenticated HTTPS.

## ADDED Requirements

### Requirement: Private CA and trusted root
The provider SHALL keep its CA private key in the platform secret provider and SHALL install only the CA public root certificate into supported system trust stores through an explicit privileged flow.

#### Scenario: Trust installation succeeds
- **WHEN** an authorised local administrator runs the platform trust installer
- **THEN** a system TLS client trusts a certificate issued by the local CA

#### Scenario: Private key inspection is attempted
- **WHEN** the local database and ordinary configuration are inspected
- **THEN** neither contains the CA private key

### Requirement: Server certificate lifecycle
The provider SHALL issue, activate, rotate, replace, and retire server certificates with recorded serial, validity, subject, and state metadata.

#### Scenario: Active certificate is replaced
- **WHEN** a replacement server certificate is activated
- **THEN** new HTTPS connections use it and the replaced certificate is retained only as lifecycle metadata

#### Scenario: Emergency revocation occurs
- **WHEN** CA key compromise is declared
- **THEN** the CA root is rotated, the old root is removed from trust, and a new server certificate is issued
