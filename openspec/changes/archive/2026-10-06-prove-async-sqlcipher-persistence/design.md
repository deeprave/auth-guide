# Design

## Context

The project has no chosen persistence encryption strategy. See proposal.md for motivation.

## Goals / Non-Goals

**Goals:** produce repeatable compatibility evidence and a single supported encryption recommendation for the account store.

**Non-Goals:** define production account tables or conceal an incompatibility with an unmaintained ORM patch.

## Decisions

- Test Tortoise first with a maintained SQLCipher-capable async driver; it is preferred but not assumed.
- If that path fails, evaluate other documented Tortoise-compatible encrypted storage and a maintainable encryption layer before selecting a driver-level async alternative.

## Decision record

The selected backend, alternatives, platform evidence, distribution and licence
obligations, and outstanding key-lifecycle work are recorded in
[ADR 0001](../../adr/0001-async-sqlcipher-persistence.md).

## Risks / Trade-offs

- Native SQLCipher packaging and alternative encryption layers differ by platform → test the supported macOS/Linux matrix and record licence implications.
- WAL leakage is missed by a happy-path test → inspect database and sidecar files with ordinary SQLite.
