# Design

## Context

The local provider requires HTTPS without a public ACME deployment. See proposal.md.

## Goals / Non-Goals

**Goals:** private CA, trusted root, lifecycle metadata, server-authenticated TLS.

**Non-Goals:** public ACME, arbitrary certificate issuance, or baseline mTLS.

## Decisions

- Store CA and leaf private keys by reference in the platform secret provider; store only public certificates and metadata elsewhere.
- Require an explicit privileged trust installer; silent system-trust modification is forbidden.
- Treat compromise as root rotation and trust removal; CRL/OCSP is not relied upon for local clients.

## Risks / Trade-offs

- Trust installation requires platform privileges → provide reversible uninstall and clear operator confirmation.
