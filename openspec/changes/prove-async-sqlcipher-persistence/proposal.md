# Proposal

## Why

The provider requires encrypted SQLite storage, but Tortoise does not document
SQLCipher support. The project must establish a supportable asynchronous
persistence approach before an account schema or API depends on it.

## What Changes

- Prove Tortoise compatibility with a maintained SQLCipher-capable async driver.
- Exercise model creation, migrations, transactions, encrypted WAL/journal
  files, and ordinary-SQLite rejection.
- Document the supported choice or a driver-level async alternative; do not
  create a custom Tortoise encryption backend.

## Capabilities

### New Capabilities
- `async-sqlcipher-persistence`: Evidence-based selection of encrypted async SQLite persistence.

### Modified Capabilities
- None.

## Impact

Adds a disposable proof harness and dependency-selection record. It gates the
encrypted account-store change without defining application data storage.
