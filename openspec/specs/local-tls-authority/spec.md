# Local TLS Authority Specification

## Purpose

Provide a private local certificate authority that makes the reference provider available only through trusted server-authenticated HTTPS.

## Requirements

### Requirement: Private CA and trusted root
The provider SHALL keep its CA private key in the platform secret provider and SHALL install only the CA public root certificate into supported system trust stores through an explicit privileged flow.

#### Scenario: Trust installation succeeds
- **WHEN** an authorised local administrator runs the platform trust installer
- **THEN** a system TLS client trusts a certificate issued by the local CA

#### Scenario: Private key inspection is attempted
- **WHEN** the local database and ordinary configuration are inspected
- **THEN** neither contains the CA private key

### Requirement: Local CA configuration and identity
The provider SHALL resolve its local CA state under
`XDG_CONFIG_HOME/mcp-guide/auth`, defaulting to `~/.config/mcp-guide/auth`,
and SHALL accept an explicit library configuration root as an override. The
future administration CLI SHALL expose that library argument as `--configdir`.
It SHALL retain public certificate lifecycle metadata in a provider-owned JSON
document there. It SHALL issue localhost and loopback server identities by
default and SHALL accept an explicit identity list as an override; the later
administration CLI will expose that capability as command-line arguments.
It SHALL reject invalid, wildcard, or duplicate identities, but SHALL not
impose a policy restriction on otherwise valid operator-selected identities.

#### Scenario: Default local identity is issued
- **WHEN** an operator initialises the local CA without an identity override
- **THEN** the active server certificate identifies localhost and its loopback
  addresses

#### Scenario: Configuration root is overridden
- **WHEN** a library caller supplies an explicit configuration root
- **THEN** public certificate metadata is written beneath that supplied root

#### Scenario: Initialisation is repeated
- **WHEN** an operator attempts CA initialisation after public CA state exists
- **THEN** the operation fails without replacing certificates or keyring secrets

#### Scenario: Lifecycle operation runs before initialisation
- **WHEN** an operator attempts a certificate lifecycle operation before CA state exists
- **THEN** the operation fails without creating or modifying certificate state

### Requirement: Modular system trust integration
The provider SHALL perform local system trust through a modular platform
integration protocol. It SHALL automatically select a supported platform
implementation by default and SHALL permit an explicit implementation override
through the future administration CLI. CA initialisation itself SHALL NOT
require elevation; only root-trust installation or removal may do so.
Linux trust anchors SHALL be unique to the supplied certificate so a
replacement and its predecessor can coexist during CA rotation. macOS SHALL
trust the root only for SSL and SHALL remove both that trust setting and the
System Keychain item during uninstallation. Before a privileged trust mutation,
the provider SHALL validate the configured CA material and the expected local
trust-store state.

#### Scenario: Trust installation requires elevation
- **WHEN** an operator installs the public root into the system trust store
- **THEN** only the platform trust operation runs with the privileges required by that platform

#### Scenario: Routine macOS native trust is evaluated without keychain mutation
- **WHEN** a developer runs the macOS Security-framework certificate test
- **THEN** it evaluates the issued localhost leaf against the temporary root as
  an explicit per-evaluation anchor without altering any keychain
- **AND THEN** the Security framework accepts the issued leaf for localhost

#### Scenario: A replacement root is installed on Linux
- **WHEN** emergency rotation installs a replacement before removing the old root
- **THEN** both anchors remain distinct until the old root is explicitly removed

#### Scenario: A privileged trust command is cancelled after launch
- **WHEN** its caller is cancelled after the command has started
- **THEN** the provider retains the certificate material and owns the command to
  deterministic completion before propagating cancellation

### Requirement: Server certificate lifecycle
The provider SHALL issue, activate, rotate, replace, and retire server certificates with recorded serial, validity, subject, and state metadata. It SHALL atomically publish lifecycle metadata, serialise mutations for one configuration root, and retain recoverable staging or pending-removal state until the associated secret and trust cleanup completes.

#### Scenario: Active certificate is replaced
- **WHEN** a replacement server certificate is activated
- **THEN** new HTTPS connections use it and the replaced certificate is retained only as lifecycle metadata

#### Scenario: Emergency revocation occurs
- **WHEN** CA key compromise is declared
- **THEN** the CA root is rotated, the old root is removed from trust, and a new server certificate is issued

#### Scenario: Old-root removal fails
- **WHEN** the replacement authority has been activated but removal of the old root fails
- **THEN** the provider records the old root as pending removal, reports the failure, and a later rotation invocation retries only old-root removal

#### Scenario: Metadata publication is interrupted
- **WHEN** a lifecycle update cannot finish publishing public metadata
- **THEN** the previous metadata remains readable and the provider retains or
  compensates staged secret references without losing recovery information

### Requirement: Asynchronous lifecycle operations
The provider SHALL expose asynchronous CA and trust-store operations without
performing blocking filesystem or cryptographic work on the event loop.
`asyncio.to_thread` SHALL NOT be used. Synchronous dependencies SHALL be
contained behind an owned lifecycle-managed asynchronous boundary.

#### Scenario: Lifecycle operation performs metadata I/O
- **WHEN** a caller initialises, rotates, or retrieves authority state
- **THEN** metadata I/O is performed through the provider's asynchronous
  boundary and does not block the caller's event loop
