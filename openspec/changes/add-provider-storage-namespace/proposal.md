# Proposal

## Why

`auth-guide-ui` needs to run auto-guide integration tests without sharing any
credential, certificate, key, or database state with a live `auth-guide`
instance. The provider currently uses its fixed application identity for that
state, so an isolated invocation can interfere with a live local provider.

## What Changes

- Add a provider storage namespace that selects the persistent state associated
  with an `auth-guide` instance.
- Expose the namespace as a global `--namespace <value>` CLI option and the
  `AG_NAMESPACE` environment override; the CLI option takes precedence.
- Preserve `auth-guide` as the default platform-secret namespace.
- Apply the selected namespace consistently to credential-store entries,
  certificate authority state, private keys, and encrypted database details.
- **BREAKING** Rename persistent files to namespace-specific filenames. Do not
  discover legacy filenames; operators must rename existing files manually.
- Validate namespace values before using them to derive persistent-resource
  identities.

## Capabilities

### New Capabilities

- `provider-storage-namespace`: Resolve and validate a provider storage
  namespace, then consistently scope provider-owned persistent resources to it.

### Modified Capabilities

- `provider-administration-cli`: Add global namespace option and environment
  precedence to the administrator CLI.
- `encrypted-account-store`: Scope the encrypted database and its named key to
  the selected namespace while preserving the default location.
- `local-tls-authority`: Scope local CA metadata and private-key references to
  the selected namespace.
- `platform-secret-provider`: Scope platform credential-store references to the
  selected namespace.
- `provider-server-lifecycle`: Use the selected namespace when resolving the
  provider state needed by server lifecycle operations.

## Impact

The change affects CLI configuration resolution, provider bootstrap, encrypted
database and key references, local TLS authority state, platform credential
stores, and server lifecycle state. It adds no external dependency. A changelog
entry will identify the manual file-renaming migration as breaking.
