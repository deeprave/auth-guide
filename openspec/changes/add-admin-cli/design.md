# Design

## Context

The CLI is a management-API client and must not have database knowledge.

## Goals / Non-Goals

**Goals:** authenticated lifecycle operations and controlled secret input.

**Non-Goals:** direct persistence, bearer installation, or ordinary-argument secrets.

## Decisions

- Use the system-trusted local CA for HTTPS verification.
- Send passwords and operator tokens only through prompt or controlled standard-input mechanisms.

## Risks / Trade-offs

- Shell history leaks arguments → reject secret-bearing arguments and test redaction.
