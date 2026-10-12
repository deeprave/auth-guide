# Guide Token Authentication Specification

## Purpose

Validate account bearers for the future Guide adapter and return only Guide
authorisation data.

## Requirements

### Requirement: Guide authentication decision
The provider SHALL authenticate a valid token for an active account at Guide's
user level without `guide:user` or a dedicated token scope. It SHALL return the
bare `admin` scope only when that account holds `guide:admin`, never provider
management grants.

#### Scenario: A user token is validated
- **WHEN** an active account without `guide:admin` presents a valid token
- **THEN** the provider returns an empty Guide scope set

#### Scenario: An administrator token is validated
- **WHEN** an active account with `guide:admin` presents a valid token
- **THEN** the provider returns the bare `admin` scope
