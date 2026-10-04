# Spec Delta

## Purpose

Expose the provider's only administrative control plane through authenticated HTTPS rather than direct database access.

## ADDED Requirements

### Requirement: HTTPS-only management operations
The provider SHALL expose first-admin bootstrap, account CRUD, password reset, and user/admin grant operations only over authenticated HTTPS.

#### Scenario: Authenticated administrator mutates an account
- **WHEN** an authorised management request is received over trusted HTTPS
- **THEN** the provider applies the requested permitted mutation

#### Scenario: Cleartext request is attempted
- **WHEN** management traffic is sent without HTTPS
- **THEN** no management operation is available

### Requirement: Provider-owned authorisation
The provider SHALL authenticate and authorise every management mutation and SHALL not expose database credentials or direct database operations to clients.

#### Scenario: Unauthorised mutation is attempted
- **WHEN** a caller lacks management authority
- **THEN** the provider rejects the request without mutating storage
