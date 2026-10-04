# Design

## Context

The management API is the sole administration boundary after TLS and account storage exist.

## Goals / Non-Goals

**Goals:** HTTPS-only authenticated mutations and first-admin bootstrap.

**Non-Goals:** database administration protocols or client-managed authorisation.

## Decisions

- Bind the service to the configured local HTTPS endpoint; do not add cleartext fallback.
- Keep bootstrap one-time and provider-validated.

## Risks / Trade-offs

- Bootstrap misuse → make bootstrap state atomic and cover races in integration tests.
