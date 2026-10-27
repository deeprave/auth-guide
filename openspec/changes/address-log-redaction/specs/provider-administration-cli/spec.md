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
to DEBUG. The provider SHALL sanitise every standard-library logging record in
its process before handler selection or propagation, including records emitted
by dependencies with non-propagating handlers. The generated configuration
SHALL include `log_cli`; legacy `redactor_file` entries SHALL be ignored. Raw
passwords and issued tokens SHALL never reach any logger.

#### Scenario: Console verbosity is raised independently
- **WHEN** an operator supplies `--log-console DEBUG`
- **THEN** DEBUG records are emitted without changing persistent-handler levels

#### Scenario: An operational command fails
- **WHEN** a configured command encounters a provider or connection failure
- **THEN** it reports the non-secret failure through the configured logger

#### Scenario: Command syntax is invalid
- **WHEN** an operator supplies invalid command syntax
- **THEN** the CLI uses Click's usage output to explain it

#### Scenario: A dependency uses its own handler
- **WHEN** a dependency emits a standard logging record through a non-propagating handler
- **THEN** recognised sensitive values in that record are sanitised before its handler receives it

## ADDED Requirements

### Requirement: Structural dependency diagnostics
The provider SHALL retain diagnostic structure while sanitising known
dependency record formats. Uvicorn access records and HTTPX outbound-request
records SHALL retain method, route shape, status, and query names without raw
query values. Tortoise database-client records SHALL retain query structure
without raw bound values. Exception text emitted through standard logging SHALL
be sanitised before formatting.

#### Scenario: HTTPX reports an outbound management request
- **WHEN** HTTPX logs a management request whose URL contains account selectors
- **THEN** the emitted record retains the request method and URL shape but masks selector values

#### Scenario: Tortoise reports a parameterised query
- **WHEN** Tortoise logs a database query with bound account or credential values
- **THEN** the emitted record retains diagnostic query structure without those raw values

#### Scenario: A logged exception contains a recognised selector
- **WHEN** an exception message emitted through standard logging contains a recognised sensitive value
- **THEN** formatted exception output masks that value
