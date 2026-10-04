# Spec Delta

## Purpose

Establish a supportable encrypted asynchronous SQLite persistence foundation before application data is modelled.

## ADDED Requirements

### Requirement: Persistence compatibility proof
The project SHALL prove a maintained asynchronous SQLCipher approach supports model creation, migration, transaction, and concurrent access workflows, or SHALL record why the preferred ORM is rejected and select a maintained driver-level alternative.

#### Scenario: Preferred ORM succeeds
- **WHEN** the proof harness performs its required database lifecycle
- **THEN** it records the supported driver, versions, and reproducible commands

#### Scenario: Preferred ORM is incompatible
- **WHEN** a required workflow cannot be supported
- **THEN** the harness records evidence and does not ship a custom ORM encryption backend

### Requirement: Encrypted file verification
The proof SHALL demonstrate that database, WAL, and journal content cannot be read as the application schema by ordinary SQLite without the configured key.

#### Scenario: Encrypted storage is inspected without a key
- **WHEN** ordinary SQLite opens the proof database or its sidecar files
- **THEN** it cannot read the application schema or records
