# Design

## Context

Guide consumes only issued bearers and public discovery material.

## Goals / Non-Goals

**Goals:** local login, signed short-lived tokens, discovery, JWKS, readiness, key rotation.

**Non-Goals:** a Guide adapter, browser redirects from MCP calls, or bearer persistence.

## Decisions

- Resolve signing keys through the secret provider and expose only public verification keys.
- Keep user/admin scope mapping provider-owned; admin includes user.

## Risks / Trade-offs

- Key rotation can invalidate active consumers → publish overlap keys and test both generations.
