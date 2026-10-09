# Tasks

## 1. Persistence model

- [x] 1.1 Implement the account and global-grant ORM model with UUID4 primary keys, lifecycle metadata, and unique, case-insensitive validated email identifiers using the storage approach approved by the persistence proof; verify account behaviour without testing tortoise-sqlcipher encryption internals
- [x] 1.2 Add fixed-parameter Argon2id password set and verification flows, including unknown-account timing protection; verify no plaintext password or bearer is persisted

## 2. Lifecycle

- [x] 2.1 Configure explicit application of user-generated, model-first Tortoise native migrations, permanent removal, and grant revocation. Do not expose or invoke tortoise-sqlcipher maintenance extensions from this reference provider
- [x] 2.2 Verify admin implies user and removed accounts cannot authenticate or retain grants
