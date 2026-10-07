# Design

## Context

The local provider requires HTTPS without a public ACME deployment. See proposal.md.

## Goals / Non-Goals

**Goals:** private CA, trusted root, lifecycle metadata, server-authenticated TLS.

**Non-Goals:** public ACME, arbitrary certificate issuance, or baseline mTLS.

## Decisions

- Store CA and leaf private keys by reference in the platform secret provider; store only public certificates and metadata elsewhere.
- Resolve the auth configuration root using Guide's XDG pattern: normally
  `~/.config/mcp-guide/auth`, or `XDG_CONFIG_HOME/mcp-guide/auth`, with
  an explicit library root overriding the complete auth root. The later
  administration CLI will expose that library argument as `--configdir`.
  Store public certificate lifecycle metadata in one provider-owned JSON
  document there. Do not plan a database migration until it is separately
  proposed and decided.
- Require an explicit privileged trust installer; silent system-trust modification is forbidden.
- Keep CA initialisation unprivileged so the provider configuration and
  platform-keyring entries belong to the invoking user. Restrict elevation to
  the narrowly scoped root-trust install or uninstall operation.
- Treat initialisation as a one-time safety boundary: it fails when public CA
  state already exists, and every other lifecycle operation fails until that
  state exists.
- Define the system integration behind a provider-owned trust-store protocol.
  `SystemTrustStore` is the platform-trust facade: it owns selection and the
  shared contract, while each supported platform has its own implementation
  module. The administration CLI will select a supported implementation
  automatically by default and may expose an explicit implementation override.
- Hand the active leaf to the future HTTPS server as a small
  `ServerTLSMaterial` value. Its certificate and private key remain only in
  process memory; the HTTPS server owns any temporary-file or SSL-context
  lifecycle required by its runtime.
- On macOS, install the public root in the System keychain. A custom keychain
  is not part of the baseline because ordinary Python TLS clients do not
  reliably consult it.
- Verify the issued localhost chain in ordinary macOS development tests through
  the Security framework with the temporary root supplied as a per-evaluation
  custom anchor. This exercises native certificate and hostname validation
  without changing Keychain state or requiring any authorisation prompt. It is
  not a production trust-store selection target.
- Treat compromise as root rotation and trust removal; CRL/OCSP is not relied upon for local clients.
- Rotate a compromised CA by installing the replacement root, publishing the
  replacement authority and leaf metadata, then removing the old root. If
  old-root removal fails, retain a public pending-removal record and make a
  later rotation invocation retry only that removal. If publication fails,
  remove the replacement root and replacement keyring secrets so the prior
  authority remains active.
- Issue for `localhost`, `127.0.0.1`, and `::1` by default. Accept an explicit
  command-line list to override those server identities.
- Defer standalone Amazon Corretto bundled-`cacerts` support. Do not mutate
  arbitrary JDK installations; a future change may define an explicit JVM
  trust-store configuration contract.
- The future Guide adapter SHALL use Python's `truststore` package for its
  outbound HTTPS client so it consumes the native system trust store. This
  server-only provider does not depend on that client package.
- The public CA and trust-store operations are asynchronous. Blocking
  filesystem and cryptographic work SHALL remain outside the event loop behind
  owned lifecycle-managed boundaries; `asyncio.to_thread` is not permitted.
  Use `anyio.Path` for filesystem operations. The authority owns a serial
  certificate-operations worker, with the same explicit `start`/`aclose`
  lifecycle pattern as `PlatformSecretProvider`, for the synchronous
  `cryptography` dependency.
- Public metadata publication is atomic and lifecycle mutations are serialised
  per configuration root within the provider process. Cross-process lifecycle
  coordination is deliberately out of scope: the reference service is the
  sole lifecycle owner, and its future administration client invokes it over
  the management API rather than opening the configuration root directly.
  Staged secrets and a pending old-authority removal
  retain enough durable state for idempotent recovery after failure or
  cancellation.
- Linux trust anchors use certificate-specific filenames so the old and
  replacement roots coexist while rotation completes. macOS constrains trust
  to SSL and removes the corresponding admin trust setting before removing the
  System Keychain certificate.
- The provider validates identity syntax and duplicates but does not restrict
  valid operator-selected identities or use X.509 NameConstraints. It validates
  the configured CA material and expected local trust-store state before a
  privileged trust mutation.

## Risks / Trade-offs

- Trust installation requires platform privileges → provide reversible uninstall and clear operator confirmation.
- The cryptography library has no native asynchronous API → its owned worker
  must shut down cleanly and never expose synchronous operations to callers.
