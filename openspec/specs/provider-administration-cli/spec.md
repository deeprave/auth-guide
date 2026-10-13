# Provider Administration CLI Specification

## Purpose

Provide a secret-safe local administrator client that initialises its local
provider once, then invokes the provider management API for management work.

## Requirements

### Requirement: Authenticated management client
The CLI SHALL perform account, password, and grant operations solely through
the authenticated HTTPS management API. Its explicit first-administrator
initialisation operation is the sole local persistence exception.

#### Scenario: Administrator creates an account
- **WHEN** an authenticated CLI request creates an account
- **THEN** the provider management API performs the mutation

#### Scenario: Database access is unavailable
- **WHEN** the CLI runs without a database path or driver
- **THEN** its supported management operations remain API based

### Requirement: Local command help
The CLI SHALL provide `--help` for its root command, every command group, and
every concrete subcommand without connecting to the provider or resolving
operator credentials.

#### Scenario: A nested command help page is requested
- **WHEN** an operator runs `auth-guide token create --help`
- **THEN** the CLI displays local help without an HTTPS request or token prompt

#### Scenario: Persistent logging is misconfigured
- **WHEN** an operator requests local help while persistent logging cannot start
- **THEN** the CLI displays the requested help without initialising it

### Requirement: Local first-administrator initialisation
The CLI SHALL expose `--remove-orphan-key` only with first-administrator setup.
It SHALL initialise the local provider only while its database and named key
are absent: create the database and key, apply migrations, create the first
administrator from a validated email, issue its initial token, and display the
generated password and token once through an interactive terminal. A failure
SHALL remove only state created by that invocation. `--remove-orphan-key` SHALL
remove only the named key when the database is absent and the key exists, then
continue initialisation. The CLI SHALL NOT expose a generic `--force` option or
a database-reset operation.

#### Scenario: An operator acknowledges an orphaned key
- **WHEN** an operator invokes setup with `--remove-orphan-key`
- **THEN** the CLI performs key-only recovery without exposing key material

### Requirement: Explicit local-service preparation
The CLI SHALL expose separate CA initialisation and system-trust installation or
removal commands. Its first-administrator `init` SHALL not require a running
provider and SHALL fail without mutation if setup has already completed.

#### Scenario: Setup is repeated
- **WHEN** an operator runs `init` after provider setup completed
- **THEN** the CLI reports the provider state error without replacing state

### Requirement: Native system-trust HTTPS client
The CLI SHALL make management-API requests through native system TLS trust. It
SHALL ignore `SSL_CERT_FILE` and `SSL_CERT_DIR` so they cannot replace that
trust.

#### Scenario: Trusted local provider connection
- **WHEN** the local provider CA is installed in system trust and those variables
  are supplied by the caller
- **THEN** the CLI can connect through its HTTPS address

### Requirement: Secret-safe interaction
The CLI SHALL acquire passwords through a prompt or controlled input channel.
It SHALL read an operator bearer from `AUTH_GUIDE_TOKEN` or a hidden `--token`
prompt, never accept secrets in ordinary arguments, and display bootstrap
credentials only once through an interactive terminal. Password-changing
commands SHALL obtain the bearer and validate locally knowable input before
prompting, and re-prompt a password shorter than the API minimum.

#### Scenario: Password is set
- **WHEN** an administrator supplies a password through the controlled channel
- **THEN** normal command output does not contain that password

### Requirement: Human account selectors
The CLI SHALL accept an account UUID or validated email wherever a command
targets an account. It SHALL send exactly one selector, trim surrounding
whitespace, and send UUID selectors canonically. The provider SHALL authorise
and resolve that selector according to the target operation's access rules.

#### Scenario: An email target is supplied
- **WHEN** an operator supplies a syntactically valid account email
- **THEN** the CLI sends it as an email selector

### Requirement: Explicit empty grant replacement
The CLI SHALL require `--clear` before sending an empty complete grant set.

#### Scenario: Every grant is cleared
- **WHEN** an operator runs `auth-guide grant set ACCOUNT --clear` with no grants
- **THEN** the CLI sends an explicit empty complete grant set

### Requirement: Separate listener and connection configuration
The CLI SHALL resolve `{configdir}/config.toml`, overridden by `AG_CONFIG` or
`--config`/`-C`. It SHALL resolve listen and API connection addresses separately:
`listen` through `AG_LISTEN` or `--listen`/`-L` on `server start` and `server
foreground`, and `address` through `AG_ADDRESS` or `--address`/`-A`.
Precedence SHALL be command line,
environment, configuration, then `https://localhost:8443`.

#### Scenario: Container connection address differs from listener
- **WHEN** an operator configures a non-local connection address
- **THEN** CLI requests target it without changing the provider listener

### Requirement: Explicit configuration-file creation
The CLI SHALL provide `config init` to create a commented non-secret file only
when absent, and `config path` to display its path without creating it. Root
help SHALL omit first-administrator `init` when an operator bearer is present;
after configuration exists, `config --help` SHALL omit `init` while retaining
`path`.

#### Scenario: Existing configuration is initialised
- **WHEN** an operator runs `config init` for an existing file
- **THEN** the CLI reports that it exists without changing it

### Requirement: Configurable secret-safe logging
The provider SHALL expose Python's standard DEBUG, INFO, WARNING, ERROR, and
CRITICAL levels plus TRACE, accepting WARN as an alias. Non-secret operational
status and failures SHALL use the configured logger; direct output is reserved
for structured data, prompts, and once-only credentials. Click usage output is
reserved for syntax errors. Console output SHALL be colourised Rich output at
INFO by default with no timestamp or visible level name, independently resolved
through `--log-console`, `AG_LOGCONSOLE`, and `log_level_console`. File and
syslog handlers SHALL be opt-in and suppressible for CLI-only commands. Their
level resolves through `--log-level`, `AG_LOGLEVEL`, and `log_level`, defaulting
to DEBUG. They SHALL use Guide's timestamped formatter and an inert redaction
extension point. The generated configuration SHALL include `log_cli` and an
inert `redactor_file` pointer; raw passwords and issued tokens SHALL never reach
any logger.

#### Scenario: Console verbosity is raised independently
- **WHEN** an operator supplies `--log-console DEBUG`
- **THEN** DEBUG records are emitted without changing persistent-handler levels

#### Scenario: An operational command fails
- **WHEN** a configured command encounters a provider or connection failure
- **THEN** it reports the non-secret failure through the configured logger

#### Scenario: Command syntax is invalid
- **WHEN** an operator supplies invalid command syntax
- **THEN** the CLI uses Click's usage output to explain it
