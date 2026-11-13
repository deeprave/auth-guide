# Spec Delta

## MODIFIED Requirements

### Requirement: Local CA configuration and identity
The provider SHALL resolve its local CA state under the selected provider
storage root and use the selected provider namespace for its private-key
references. It SHALL accept an explicit library configuration root as an
override. The administration CLI SHALL expose that root through `--configdir`
and `AG_CONFIGDIR`. It SHALL retain public certificate lifecycle metadata in a
provider-owned `{namespace}-certificates.json` document under the selected
storage root.

#### Scenario: Default local identity is issued
- **WHEN** an operator initialises the local CA without an identity override
- **THEN** the active server certificate identifies localhost and its loopback
  addresses

#### Scenario: Configuration root is overridden
- **WHEN** a library caller supplies an explicit configuration root
- **THEN** public certificate metadata is written beneath that supplied root

#### Scenario: Certificate state is isolated
- **WHEN** a provider uses a distinct namespace and storage root from another
  provider
- **THEN** CA initialisation does not replace the other provider's metadata or
  private-key references
