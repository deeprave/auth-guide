# Design

## Context

The project has no chosen database dependency. See proposal.md for motivation.

## Goals / Non-Goals

**Goals:** produce repeatable compatibility evidence and a single supported recommendation.

**Non-Goals:** define production account tables or conceal an incompatibility with custom ORM internals.

## Decisions

- Test Tortoise first with a maintained SQLCipher-capable async driver; it is preferred but not assumed.
- Test a driver-level async alternative only if the proof fails; this is safer than inventing Tortoise support.

## Risks / Trade-offs

- Native SQLCipher packaging differs by platform → test the supported macOS/Linux matrix and record licence implications.
- WAL leakage is missed by a happy-path test → inspect database and sidecar files with ordinary SQLite.
