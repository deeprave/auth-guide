# Tasks

## 1. Secret boundary

- [x] 1.1 Define an async application-namespaced secret interface, private serial keyring-worker lifecycle, and secret-safe errors; verify values are absent from repr and diagnostics
- [x] 1.2 Implement macOS Keychain resolution through the provider worker and verify create, resolve, replace, missing-reference, shutdown, and cancelled-mutation cases

## 2. Linux integration

- [x] 2.1 Implement Freedesktop Secret Service resolution and verify it against a real GNOME Keyring session
- [x] 2.2 Run cross-platform secret rotation and no-leak integration tests

## 3. Review remediation

- [x] 3.1 Consume tortoise-sqlcipher from PyPI and make CI run the project's explicit validation commands without pre-commit
- [x] 3.2 Harden the provider worker lifecycle, cancellation completion, idle-reference release, and chained keyring errors
- [x] 3.3 Document the OS-default and user-override backend policy; add behavioural coverage for lifecycle, cancellation, errors, and cleanup
- [x] 3.4 Skip cancelled pending mutations and discard traceback-bearing orphaned mutation failures
