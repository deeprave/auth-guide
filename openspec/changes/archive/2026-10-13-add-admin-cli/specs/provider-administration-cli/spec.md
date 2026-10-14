# Spec Delta

## Purpose

Provide a secret-safe local administrator client that invokes the provider management API without direct database access.

## ADDED Requirements

### Requirement: Authenticated management client
The CLI SHALL bootstrap the first administrator and perform account, password, and grant operations solely through the authenticated HTTPS management API.

#### Scenario: Administrator creates an account
- **WHEN** an authenticated CLI request creates an account
- **THEN** the provider management API performs the mutation

#### Scenario: Database access is unavailable
- **WHEN** the CLI runs without a database path or driver
- **THEN** its supported management operations remain API based

### Requirement: Local command help
The CLI SHALL provide `--help` for its root command, every command group, and
every concrete subcommand. Help output SHALL describe that command's arguments,
options, and purpose without connecting to the provider or resolving operator
credentials.

#### Scenario: A nested command help page is requested
- **WHEN** an operator runs `auth-guide token create --help`
- **THEN** the CLI displays local help for token creation without an HTTPS
  request or token prompt

#### Scenario: Persistent logging is misconfigured
- **WHEN** an operator requests any command's local help while persistent logging
  configuration cannot be applied
- **THEN** the CLI displays the requested help without initialising persistent
  logging

### Requirement: Explicit orphan-key bootstrap recovery
The CLI SHALL expose `--remove-orphan-key` only with its first-administrator
setup command. It SHALL send the provider's explicit orphan-key recovery
request and SHALL not inspect, delete, or overwrite database files or platform
keyring entries itself. It SHALL NOT expose a generic `--force` option or a
database-reset operation.

#### Scenario: An operator acknowledges an orphaned key
- **WHEN** an operator invokes setup with `--remove-orphan-key`
- **THEN** the CLI requests provider-owned key-only recovery and reports the
  provider result without exposing key material

### Requirement: Explicit local-service preparation
The CLI SHALL expose separate CA initialisation and system-trust installation or
removal commands. Its first-administrator `init` command SHALL only call the
provider setup API, require a running provider, and fail without mutation when
provider setup has already completed.

#### Scenario: Setup is repeated
- **WHEN** an operator runs `init` after provider setup completed
- **THEN** the CLI reports the provider state error without replacing accounts,
  credentials, database state, or keys

### Requirement: Native system-trust HTTPS client
The CLI SHALL make management-API requests through the operating system's
native TLS trust store. A locally installed provider root certificate SHALL be
trusted without `SSL_CERT_FILE` or `SSL_CERT_DIR` overrides; the CLI SHALL
ignore those variables so they cannot replace native trust.

#### Scenario: Trusted local provider connection
- **WHEN** the local provider CA has been installed in the system trust store
- **AND** `SSL_CERT_FILE` or `SSL_CERT_DIR` is supplied by the caller
- **THEN** the CLI can connect to the provider through its HTTPS address

### Requirement: Secret-safe interaction
The CLI SHALL acquire passwords through a prompt or controlled input channel.
It SHALL read an operator bearer from `AUTH_GUIDE_TOKEN` or, only when a
valueless `--token` option is supplied, a hidden prompt. It SHALL not accept
secret values in ordinary arguments or normally emit them in output. Bootstrap
SHALL require an interactive terminal and display its generated credentials only
once.
Before prompting for a password, a password-changing command SHALL obtain its
required operator bearer and validate locally knowable input. It SHALL re-prompt
for a password shorter than the API minimum rather than submit it.

#### Scenario: Password is set
- **WHEN** an administrator supplies a password through the controlled channel
- **THEN** normal command output does not contain that password

### Requirement: Human account selectors
The CLI SHALL accept an account UUID or validated email wherever a command
targets an account. It SHALL send exactly one selector to the management API;
the provider SHALL authorise and resolve that selector according to the target
operation's access rules. The CLI SHALL trim surrounding selector whitespace and
send UUID selectors in canonical form.

#### Scenario: An email target is supplied
- **WHEN** an operator supplies a syntactically valid account email
- **THEN** the CLI sends it as an email selector and the provider targets that
  account without requiring the operator to discover its UUID

### Requirement: Explicit empty grant replacement
The CLI SHALL describe `grant set` as complete replacement. When no replacement
grants are supplied, it SHALL require `--clear` before sending the empty grant set.

#### Scenario: Every grant is cleared
- **WHEN** an operator runs `auth-guide grant set ACCOUNT --clear` with no grants
- **THEN** the CLI sends an explicit empty complete grant set

### Requirement: Separate listener and connection configuration
The CLI SHALL resolve a default configuration file at
`{configdir}/config.toml`, overridden by `AG_CONFIG` or `--config`/`-C`. It
SHALL resolve the provider HTTPS listen address independently from its API
connection address. `listen` is overridden by `AG_LISTEN` or `--listen`/`-L`;
`address` is overridden by `AG_ADDRESS` or `--address`/`-A`. For each setting,
precedence SHALL be command line, environment, configuration file, then the
`https://localhost:8443` default.

#### Scenario: Container connection address differs from listener
- **WHEN** an operator configures a non-local CLI connection address and leaves
  the listener at its default
- **THEN** CLI requests target the configured address without changing the
  provider listener

### Requirement: Explicit configuration-file creation
The CLI SHALL provide `config init` to create a commented, non-secret default
configuration file only when it is absent. It SHALL not overwrite an existing
file, and no other command SHALL implicitly create configuration. The root
help SHALL omit first-administrator `init` when an operator bearer is present.
It SHALL
provide `config path` to display the selected configuration path without
creating it. Once that file exists, `config --help` SHALL omit `init` while
retaining `path`.

#### Scenario: Existing configuration is initialised
- **WHEN** an operator runs `config init` for an existing configuration file
- **THEN** the CLI reports that it exists without changing it

#### Scenario: Configuration path is requested
- **WHEN** an operator runs `config path`
- **THEN** the CLI displays the selected configuration path without modifying it

#### Scenario: Bootstrap is explicitly attempted with an operator token
- **WHEN** an operator invokes `init` while `AUTH_GUIDE_TOKEN` or `--token`
  supplies a bearer token
- **THEN** the CLI fails locally before contacting the provider
- **AND** it states that initial setup cannot run while an operator token is
  configured

### Requirement: Configurable secret-safe logging
The provider SHALL expose Python's standard DEBUG, INFO, WARNING, ERROR, and
CRITICAL logging levels, plus TRACE below DEBUG. It SHALL accept WARN as an
alias for WARNING.
It SHALL report every non-secret operational status, warning, and failure
through the configured logger once command configuration is available. It SHALL
emit colourised Rich console logging with no timestamp or visible level name by
default at INFO, applying the severity colour directly to the message. Direct
standard output SHALL be reserved for structured command results, requested
diagnostic values, hidden prompts, and once-only bootstrap or token credentials.
Click usage output SHALL be reserved for command parsing, missing arguments,
and invalid option combinations. Its console threshold SHALL resolve independently through
`--log-console`, `AG_LOGCONSOLE`, `log_level_console`, then that default. TOML SHALL configure `console_log_format` and
`file_log_format`. File logging SHALL be disabled unless `log_file`,
`AG_LOGFILE`, or `--log-file`/`-l` supplies a path. Syslog SHALL be disabled
unless `log_syslog`, `AG_LOGSYSLOG`, or `--log-syslog`/`-S` enables it. An
explicit `log_level`, `AG_LOGLEVEL`, or `--log-level`/`-v` SHALL apply to every
enabled persistent handler; otherwise enabled file and syslog handlers use DEBUG. For
CLI-only operations, `AG_CLILOG=false` or `--no-cli-log`/`-N` SHALL suppress
file and syslog output. File and syslog handlers SHALL default to Guide's
timestamped formatter and route messages through a redaction extension point
before any configured textual formatter. This change's extension point SHALL
be an inert pass-through; passwords and raw issued tokens SHALL instead be
kept out of logging by the CLI input and output boundary. The generated
configuration scaffold SHALL include the `log_cli` Boolean and a commented,
currently inert `redactor_file` pointer reserved for a future declarative
redaction-rules file; this change SHALL not load custom redaction rules.

#### Scenario: CLI-only logging is suppressed
- **WHEN** an operator invokes a CLI-only operation with `--no-cli-log`
- **THEN** console logging remains available while file and syslog handlers are
  not created

#### Scenario: Console verbosity is raised independently
- **WHEN** an operator supplies `--log-console DEBUG`
- **THEN** DEBUG records are emitted to the console without changing the file
  or syslog threshold

#### Scenario: An operational command fails
- **WHEN** a configured CLI command encounters a provider, certificate,
  keyring, trust-store, or connection failure
- **THEN** it reports the non-secret failure through the configured Rich logger
- **AND** it exits without Click's usage banner

#### Scenario: Command syntax is invalid
- **WHEN** an operator omits a required argument or supplies an invalid option
  combination
- **THEN** the CLI uses Click's usage output to explain the syntax error

#### Scenario: Bootstrap returns credentials
- **WHEN** initial setup succeeds
- **THEN** its password and raw token are displayed once without any log record
  containing either value

#### Scenario: A future redactor file is reserved
- **WHEN** an operator inspects a configuration scaffold generated by `config init`
- **THEN** it documents the inert `redactor_file` setting without loading a
  custom redactor
