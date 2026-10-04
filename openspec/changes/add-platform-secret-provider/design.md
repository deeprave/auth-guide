# Design

## Context

Secrets must be independent from encrypted storage. wybra-dev demonstrates the Linux Secret Service test environment.

## Goals / Non-Goals

**Goals:** a small reference-based interface, platform backends, and secret-safe failures.

**Non-Goals:** a general secret-management product or secret values in configuration.

## Decisions

- Use application namespace plus opaque reference; consumers name a reference, not a secret value.
- Use Keychain on macOS and Freedesktop Secret Service on Linux; test Linux through a real GNOME Keyring session.

## Risks / Trade-offs

- Headless Linux lacks a running keyring → provide documented test/deployment bootstrap, not a kernel-keyring fallback.
