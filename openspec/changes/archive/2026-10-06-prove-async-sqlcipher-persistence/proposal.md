# Proposal

## Why

The provider requires encrypted persistence, but Tortoise does not document
SQLCipher support. The project must establish a supportable asynchronous
encryption strategy before the encrypted account store is committed to a
specific implementation.

## What Changes

- Prove Tortoise compatibility with a maintained SQLCipher-capable async driver.
- Exercise model creation, migrations, transactions, encrypted WAL/journal
  files, and ordinary-SQLite rejection.
- Evaluate direct SQLCipher support, other documented Tortoise-compatible
  encrypted storage options, and a maintainable encryption layer where needed.
- Document the supported choice without relying on an unmaintained ORM patch.

## Capabilities

### New Capabilities
- `async-sqlcipher-persistence`: Evidence-based selection of encrypted async SQLite persistence.

### Modified Capabilities
- None.

## Impact

Adds a disposable proof harness and encryption-strategy decision record. It
informs the encrypted account-store change without defining application data
storage or blocking independent provider work.
