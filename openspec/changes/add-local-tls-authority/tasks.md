# Tasks

## 1. Authority and trust

- [x] 1.1 Create a one-time, unprivileged CA initialisation library entry point and leaf-key secret references with public JSON certificate metadata in the Guide-aligned auth configuration root; prevent lifecycle operations before initialisation or duplicate initialisation; verify private keys are absent from storage and configuration
- [x] 1.2 Define modular system-trust integration with automatic supported-platform selection and an override, then add explicit privileged macOS, Debian-family, and Red Hat-family root-trust install/uninstall flows and verify a system TLS client trusts the issued leaf
- [x] 1.3 Add a non-interactive macOS Security-framework test using a per-evaluation temporary root anchor and verify the issued localhost leaf without keychain mutation

## 2. Lifecycle

- [x] 2.1 Implement leaf issue, activation, rotation, retirement, and metadata audit and verify new HTTPS connections use the active leaf
- [x] 2.2 Implement emergency CA rotation and verify old-root removal prevents trust while the replacement chain succeeds

## 3. Review remediation

- [x] 3.1 Establish the approved owned asynchronous boundaries for certificate
  generation and metadata I/O without `asyncio.to_thread`; retain native async
  filesystem operations and a lifecycle-managed interface for any synchronous
  dependency.
- [x] 3.2 Make lifecycle updates atomic, serialised, cancellation-safe, and
  recoverable: preserve prior metadata, compensate staged secrets, and retain
  idempotent old-authority cleanup state until all trust and secret operations
  complete.
- [x] 3.3 Correct platform trust behaviour: certificate-specific Linux anchors;
  macOS SSL-only trust and full trust-setting removal; validated CA and expected
  trust-store state; and deterministic post-launch command completion.
- [x] 3.4 Resolve the configuration root by default, validate identity and leaf
  certificate semantics, and normalise malformed metadata and unsupported-host
  errors without restricting valid operator-selected identities.
- [x] 3.5 Move shared trust helpers behind an appropriate module boundary and
  replace implementation-coupled tests with native asynchronous,
  behaviour-focused coverage. Document the supported lifecycle and current
  Red Hat verification boundary without adding extra native platform tests.
