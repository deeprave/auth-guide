# Tasks

## 1. Persistence model

- [ ] 1.1 Implement the account and global-grant repository using the storage approach approved by the persistence proof and verify encrypted integration tests
- [ ] 1.2 Add Argon2id password set and verification flows and verify no plaintext password or bearer is persisted

## 2. Lifecycle

- [ ] 2.1 Add migrations, removal, grant revocation, and backup/restore workflows and verify disposable end-to-end recovery tests
- [ ] 2.2 Verify admin implies user and removed accounts cannot authenticate or retain grants
