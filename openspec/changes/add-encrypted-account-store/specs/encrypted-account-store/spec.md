# Spec Delta

## Purpose

Persist provider accounts and global grants in the selected encrypted storage backend without retaining plaintext credentials or bearer tokens.

## ADDED Requirements

### Requirement: Account and grant persistence
The store SHALL create, list, remove, and update accounts with global user or admin grants, where admin satisfies user.

#### Scenario: Account receives admin access
- **WHEN** an administrator grants admin access
- **THEN** the account has effective admin and user access

#### Scenario: Account is removed
- **WHEN** an administrator removes an account
- **THEN** subsequent authentication and grant lookup fail for that account

### Requirement: Credential protection
The store SHALL persist only Argon2id password verifiers and SHALL not persist plaintext passwords or issued bearer tokens.

#### Scenario: Database is inspected
- **WHEN** stored account data is examined through the supported test interface
- **THEN** it contains no plaintext password or bearer value
