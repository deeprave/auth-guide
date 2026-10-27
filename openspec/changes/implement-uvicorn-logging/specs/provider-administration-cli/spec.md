# Spec Delta

## MODIFIED Requirements

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
any logger. The provider's HTTP server and access records SHALL use these
provider-managed logging policies rather than a framework-default configuration.

#### Scenario: Console verbosity is raised independently
- **WHEN** an operator supplies `--log-console DEBUG`
- **THEN** DEBUG records are emitted without changing persistent-handler levels

#### Scenario: An operational command fails
- **WHEN** a configured command encounters a provider or connection failure
- **THEN** it reports the non-secret failure through the configured logger

#### Scenario: Command syntax is invalid
- **WHEN** an operator supplies invalid command syntax
- **THEN** the CLI uses Click's usage output to explain it

#### Scenario: Provider server starts
- **WHEN** the provider HTTP server starts, stops, or reports an operational error
- **THEN** the record uses the provider's configured logging policy rather than a framework-default handler

## ADDED Requirements

### Requirement: Secret-safe HTTP access targets
The provider SHALL record HTTP access requests through its configured logging
policy. It SHALL preserve the request method, route shape, and query parameter
names, but SHALL not record raw query values. It SHALL structurally mask email
and UUID identifiers wherever they appear in an access target.

#### Scenario: Email selector is accessed
- **WHEN** an access request contains `email` or `account_email`
- **THEN** the log retains the parameter name and a structurally masked email value rather than the original email

#### Scenario: UUID selector is accessed
- **WHEN** an access request contains a UUID in its path or query value
- **THEN** the log retains only the identifier's first and last four characters and masks its intervening characters

#### Scenario: Unknown query value is accessed
- **WHEN** an access request contains a query parameter without an explicitly approved safe value format
- **THEN** the log retains the parameter name and replaces its value with `***`

### Requirement: Foreground HTTP access presentation
The foreground provider server SHALL present HTTP access records using a concise
console format separate from ordinary operational records. Detached provider
operation SHALL route access records only to configured persistent handlers.

#### Scenario: Foreground access request
- **WHEN** a request reaches a foreground provider server
- **THEN** the console shows the sanitised access record without the ordinary console timestamp or level columns

#### Scenario: Detached access request
- **WHEN** a request reaches a detached provider server
- **THEN** the sanitised access record is written only to configured persistent handlers

