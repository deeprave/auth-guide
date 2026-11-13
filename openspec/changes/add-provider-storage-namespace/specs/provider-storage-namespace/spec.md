# Spec Delta

## Purpose

Let separate local provider instances select distinct credential and filesystem
state while retaining the existing single-instance defaults.

## ADDED Requirements

### Requirement: Provider namespace selection
The provider SHALL resolve its namespace from global `--namespace`, then
`AG_NAMESPACE`, then `auth-guide`. A selected namespace MUST contain at least
one ASCII letter, number, hyphen, or underscore, and SHALL contain only those
characters. An invalid selected value SHALL fail before the provider accesses
persistent state.

#### Scenario: Command-line namespace overrides the environment
- **WHEN** an operator supplies `--namespace test-provider` and
  `AG_NAMESPACE=environment-provider`
- **THEN** the provider uses `test-provider` as its namespace

#### Scenario: Empty explicit namespace is rejected
- **WHEN** an operator supplies `--namespace ""`
- **THEN** the provider rejects the value before accessing persistent state

#### Scenario: Default namespace preserves existing instances
- **WHEN** neither a command-line nor environment namespace is supplied
- **THEN** the provider uses `auth-guide` as its namespace

### Requirement: Provider storage-root and configuration selection
The provider SHALL resolve its storage root from `--configdir`, then
`AG_CONFIGDIR`, then the parent of an explicit `--config` or `AG_CONFIG` file,
then its existing default root. An explicit configuration file SHALL remain
selected when a storage-root override is supplied; otherwise the configuration
file SHALL be `{configdir}/{namespace}-config.toml`.

#### Scenario: Explicit storage root overrides a configuration file parent
- **WHEN** an operator supplies both `--config settings/custom.toml` and
  `--configdir state/test-provider`
- **THEN** the provider reads `settings/custom.toml` and uses
  `state/test-provider` as its storage root

#### Scenario: Storage root supplies the default configuration file
- **WHEN** an operator supplies `AG_CONFIGDIR=state/test-provider` without an
  explicit configuration file
- **THEN** the provider selects `state/test-provider/auth-guide-config.toml`

### Requirement: Namespace-specific persistent filenames
The provider SHALL use `{namespace}.lifecycle.lock`, `{namespace}.sqlite3`,
`{namespace}.pid`, `{namespace}.meta.json`,
`{namespace}-certificates.json`, and `{namespace}-config.toml` for its
namespace-scoped filesystem state under the selected storage root.

#### Scenario: A named instance creates provider state
- **WHEN** a provider uses namespace `test-provider`
- **THEN** its filesystem state uses the `test-provider` filename prefix or
  basename according to the resource type

### Requirement: Manual legacy filename migration
The provider SHALL not read or migrate legacy unprefixed `config.toml` or
`certificates.json` files. Operators SHALL manually rename existing persistent
files to their namespace-specific filenames before using this version.

#### Scenario: Only a legacy configuration file exists
- **WHEN** no explicit configuration file is selected and only `config.toml`
  exists in the selected storage root
- **THEN** the provider selects `{namespace}-config.toml` without reading the
  legacy file

### Requirement: Isolated persistent provider state
The provider SHALL scope its platform credential-store entries by the selected
namespace and its certificate metadata, encrypted database, and lifecycle
state by the selected storage root. State selected by different namespace or
storage-root values SHALL not be read, replaced, or removed by another
instance.

#### Scenario: Isolated integration-test instance is initialised
- **WHEN** an integration-test instance uses a distinct namespace and storage
  root from a live provider
- **THEN** its initialisation does not replace the live provider's credentials,
  certificates, keys, database, or lifecycle state
