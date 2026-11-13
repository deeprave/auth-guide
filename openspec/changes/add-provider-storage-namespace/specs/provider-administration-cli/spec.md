# Spec Delta

## MODIFIED Requirements

### Requirement: Separate listener and connection configuration
The CLI SHALL resolve the provider storage root through `--configdir`,
`AG_CONFIGDIR`, the parent of `--config` or `AG_CONFIG`, then the existing
default root. It SHALL resolve its configuration file through `--config`/`-C`,
`AG_CONFIG`, or `{configdir}/{namespace}-config.toml`, without changing an explicitly
selected file when the storage root is overridden. It SHALL resolve its
namespace through global `--namespace`, `AG_NAMESPACE`, then `auth-guide`.
It SHALL resolve listen and API connection addresses separately: `listen`
through `AG_LISTEN` or `--listen`/`-L` on `server start` and `server
foreground`, and `address` through `AG_ADDRESS` or `--address`/`-A`.
Precedence SHALL be command line, environment, configuration, then
`https://localhost:8443`.

#### Scenario: Container connection address differs from listener
- **WHEN** an operator configures a non-local connection address
- **THEN** CLI requests target it without changing the provider listener

#### Scenario: Global storage options select an isolated provider
- **WHEN** an operator supplies global `--namespace integration-test` and
  `--configdir .state/integration-test`
- **THEN** every command receives the selected namespace and storage root
