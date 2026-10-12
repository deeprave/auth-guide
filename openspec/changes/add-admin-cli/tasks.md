# Tasks

## 1. API client

- [x] 1.1 Implement local-CA-trusting authenticated API client commands for bootstrap, account lifecycle, grants, and tokens; accept UUID or email target selectors through the provider API and verify each mutation occurs through HTTPS
- [x] 1.2 Implement controlled password and token input, TTY-only once-only bootstrap credential display, and verify ordinary arguments, output, and logs contain no secret values
- [x] 1.3 Implement `--remove-orphan-key` only for initial setup, send the
  provider's key-only recovery request, and verify the CLI has no generic force
  or database-reset behaviour
- [x] 1.4 Implement TOML configuration and separate listener/connection address resolution with CLI, environment, configuration, and default precedence; verify container-oriented address overrides do not alter the listener
- [x] 1.5 Expose explicit CA initialisation and trust commands plus one-time first-administrator bootstrap; verify repeated setup does not mutate provider state
- [x] 1.6 Implement `config init` for an absent commented non-secret TOML scaffold and verify it never overwrites or implicitly creates configuration
- [x] 1.7 Add direct Rich logging support with a TRACE level, independently configurable console threshold (`--log-console`, `AG_LOGCONSOLE`, `log_level_console`), Guide-compatible redaction, configurable console/file formatters, optional file and syslog handlers, and CLI-only persistent-log suppression; include an inert, commented `redactor_file` configuration pointer reserved for future declarative rules; verify secrets never reach any handler
- [x] 1.8 Provide descriptive local `--help` at the root, command-group, and subcommand levels; verify it does not connect to the provider or resolve credentials
- [x] 1.9 Define and implement the CLI output boundary: use configured logging for non-secret operational messages, reserve direct output for data and one-time credentials, and retain Click usage rendering only for syntax errors

## 2. End-to-end validation

- [x] 2.1 Run the CLI against the disposable provider and verify it has no database driver, path, or direct persistence access
- [x] 2.2 Verify invalid trust, authentication, authorisation, and controlled-input failures are secret-safe and leave provider state unchanged
