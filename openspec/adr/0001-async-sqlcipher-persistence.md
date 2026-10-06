# ADR 0001: Async SQLCipher persistence proof

## Status

Accepted for the persistence compatibility proof. Production integration with
the platform secret provider remains a later account-store concern.

## Context

The reference provider requires an asynchronous encrypted SQLite store. Tortoise
ORM's standard SQLite backend uses `aiosqlite`, but that connector opens the
standard-library `sqlite3` driver and therefore cannot open a SQLCipher
database.

The proof must preserve Tortoise model, transaction, concurrent-access, and
native-migration behaviour without maintaining an ORM patch.

## Decision

Use the external `tortoise-sqlcipher` package as the dynamically loadable
Tortoise backend. It subclasses Tortoise's `SqliteClient` and uses an
`aiosqlite.Connection` around the `sqlcipher3` DB-API connector.

The connector receives a 32-byte key and executes SQLCipher's key pragma before
any database operation. SQLCipher DB-API integrity and operational errors are
translated to Tortoise's established exception types. The module name includes
`sqlite` so Tortoise's native migration executor selects its SQLite schema
editor.

Use Tortoise's native migration API. Do not add Aerich: Tortoise 1.x documents
it as a legacy alternative.

## Evidence

The proof passed with:

- `sqlcipher3` 0.6.3, `aiosqlite` 0.22.1, and Tortoise ORM 1.1.8.
- macOS on Python 3.13.13.
- Debian Trixie Linux arm64 on Python 3.13.5, using the repository Dockerfile.

The proof verifies encrypted model data and a live WAL contain neither schema
nor record plaintext; ordinary SQLite cannot query the database. It also
verifies a native initial migration, transaction rollback, concurrent ORM
writes, and SQLCipher rekey from an old ephemeral key to a replacement key.
The old key is rejected after rekey; the replacement key opens both the rekeyed
database and a SQLCipher-native encrypted backup containing the original record.

## Alternatives considered

The stock Tortoise SQLite backend was rejected because it always constructs an
`aiosqlite` connection using standard-library `sqlite3`, which cannot read the
SQLCipher database. No unmaintained Tortoise patch is used.

## Distribution and licence

`sqlcipher3` provides a self-contained wheel with statically linked SQLCipher.
The binding is zlib-licensed. SQLCipher Community Edition is BSD-style and
requires its copyright and licence notice in a user-accessible product notice,
alongside notices for the selected cryptographic provider.

## Consequences and follow-up

The future platform-secret-provider and encrypted-account-store changes must:

- obtain database keys from the platform secret provider rather than arguments,
  configuration, or the database;
- integrate the proven exclusive SQLCipher rekey, old-key replacement, and
  reopened-database verification procedure; and
- integrate the proven encrypted backup and restore procedure with the
  production recovery workflow.

The adapter implementation and proof suite are maintained in the separate
`tortoise-sqlcipher` project. This project consumes the package and specifies
only that persistent account data is stored in an encrypted database.
