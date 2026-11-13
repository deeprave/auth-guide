# Tasks

## 1. Resolve global provider selections

- [x] 1.1 Extend CLI configuration resolution with immutable namespace and storage-root values, including `--namespace`, `AG_NAMESPACE`, `--configdir`, `AG_CONFIGDIR`, explicit configuration-file parent fallback, and the namespace-specific default configuration filename.
- [x] 1.2 Add the global CLI options and retain the resolved selections in the command context without changing help-only command behaviour or explicit `--config` / `AG_CONFIG` selection.

## 2. Scope provider-owned state

- [x] 2.1 Thread the resolved namespace and storage root through local bootstrap, account-store construction, certificate-authority commands, and platform-secret-provider construction.
- [x] 2.2 Extend server settings and runtime construction so namespace-specific lifecycle, certificate, account, and platform-secret state uses the resolved selections throughout startup and reload.
- [x] 2.3 Forward effective namespace and storage-root selections to detached server children, and use the same selections for server stop, status, and restart lifecycle lookups.

## 3. Document the breaking migration

- [x] 3.1 Add a changelog entry that identifies the manual renaming of legacy provider files to namespace-specific filenames as a breaking change.
