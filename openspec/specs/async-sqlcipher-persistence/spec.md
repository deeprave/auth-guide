# Async SQLCipher Persistence Specification

## Purpose

Ensure the reference provider's persistent account data is protected at rest.

## Requirements

### Requirement: Encrypted persistent database

The reference provider SHALL store persistent account data in an encrypted database.

#### Scenario: Account data is persisted

- **WHEN** the reference provider writes persistent account data
- **THEN** it is stored in the encrypted database
