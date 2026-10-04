# Design

## Context

The store follows the persistence proof and uses platform-resolved database keys.

## Goals / Non-Goals

**Goals:** encrypted account/grant lifecycle and Argon2id verifier handling.

**Non-Goals:** choosing storage before the proof or persisting bearer tokens.

## Decisions

- Define repository interfaces above the selected implementation so API and issuer do not own database sessions.
- Require migrations and disposable encrypted-storage integration tests.

## Risks / Trade-offs

- Storage proof may reject Tortoise → implement the recorded approved alternative, not a fallback invented during this change.
