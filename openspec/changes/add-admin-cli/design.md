# Design

## Context

The CLI is a management-API client and must not have database knowledge.

## Goals / Non-Goals

**Goals:** authenticated lifecycle operations and controlled secret input.

**Non-Goals:** direct persistence, bearer installation, or ordinary-argument secrets.

## Decisions

- Use the system-trusted local CA for HTTPS verification.
- Send passwords and operator tokens only through prompt or controlled standard-input mechanisms.
- `--remove-orphan-key` is the only setup-recovery flag. It delegates the
  database-absence check and key removal to the provider API; the CLI has no
  keyring or database access and offers neither a generic force flag nor reset.

## Risks / Trade-offs

- Shell history leaks arguments → reject secret-bearing arguments and test redaction.
