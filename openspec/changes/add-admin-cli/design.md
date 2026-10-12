# Design

## Context

The CLI is a management-API client and must not have database knowledge.

## Goals / Non-Goals

**Goals:** authenticated lifecycle operations and controlled secret input.

**Non-Goals:** direct persistence, bearer installation, or ordinary-argument secrets.

## Decisions

- Use the system-trusted local CA for HTTPS verification.
- Send passwords and operator tokens only through prompt or controlled standard-input mechanisms.
- `--remove-orphan-key` is the only setup-recovery flag. It delegates the
  database-absence check and key removal to the provider API; the CLI has no
  keyring or database access and offers neither a generic force flag nor reset.
- Account-targeting commands detect UUID or email syntax. They send exactly one
  selector to the API; the provider resolves it with its existing email
  validation and uniqueness rules, so all callers receive identical behaviour.
  Existing UUID account paths remain stable; email-targeted read, update, and
  deletion use an `email` query parameter on the account collection, and the
  password-reset endpoint follows the same selector convention.
- `AUTH_GUIDE_TOKEN` is the non-interactive bearer source. A valueless
  `--token` option requests a hidden prompt; a missing source is an explicit
  command error. Bootstrap requires a TTY and displays its generated credentials
  once only.
- The default configuration file is `{configdir}/config.toml`. `AG_CONFIG` and
  `--config`/`-C` select a replacement file. `listen` selects the provider's
  HTTPS bind address through `AG_LISTEN` and `--listen`/`-L`; `address` selects
  the CLI HTTPS target through `AG_ADDRESS` and `--address`/`-A`. Each setting
  resolves independently in CLI, environment, config, then default order; both
  defaults are `https://localhost:8443`.
- Provide a provider-owned logger modelled on Guide: register TRACE below DEBUG,
  extend Rich logging to display it, and use a plain colourised console format
  without visible level names. Rich becomes a direct runtime dependency rather
  than an incidental transitive dependency. File output uses a conventional
  Guide-style timestamped format. `console_log_format` and `file_log_format`
  are configurable in TOML.
- Console logging defaults to INFO and resolves independently through
  `--log-console`, `AG_LOGCONSOLE`, `log_level_console`, then that default.
  File and syslog handlers are disabled unless
  `log_file`/`AG_LOGFILE`/`--log-file` or
  `log_syslog`/`AG_LOGSYSLOG`/`--log-syslog` enables them. An explicit
  `log_level`/`AG_LOGLEVEL`/`--log-level` applies to every enabled persistent handler;
  otherwise enabled persistent handlers default to DEBUG. `--no-cli-log`/`-N`
  or `AG_CLILOG=false` suppresses file and syslog handlers for CLI-only work.
- Generated bootstrap passwords and raw tokens bypass logging entirely and are
  the only direct secret-bearing terminal output.
- Use the configured logger for non-secret operational status, warnings, and
  failures once command configuration is available. Direct standard output is
  reserved for structured command results, requested diagnostic values such as
  `config path`, hidden prompts, and the one-time bootstrap or token
  credential. Click's native usage renderer is reserved for parsing failures,
  missing arguments, and invalid option combinations. The Rich console has no
  timestamp or level column; it applies severity colour to the message itself.
- File and syslog handlers use Guide's conventional default:
  `%(asctime)s - %(name)s - %(levelname)s - %(message)s` with
  `%Y-%m-%d %H:%M:%S` timestamps and optional structured extras. A
  provider-owned redactor is applied before every formatter, including custom
  textual layouts; it adopts Guide's current secret-redaction strategy.
- Reserve a non-secret `redactor_file` TOML setting in the generated
  configuration scaffold. It is a documented, currently inert pointer to a
  future declarative regex-replacement rules file; this change does not load
  custom rules or introduce callable/import-path configuration.
- Provide Click's standard `--help` at the root command, each command group,
  and every concrete subcommand. Help is local descriptive output and never
  attempts a provider connection or reads credentials.
- Click parses command-line input and builds the resolved command configuration
  synchronously. Each concrete command then enters one async implementation
  through `anyio.run`, passing that prepared configuration to the async HTTPS
  client. There is no callback layer or synchronous wrapper around individual
  client operations.

## Risks / Trade-offs

- Shell history leaks arguments → reject secret-bearing arguments and test redaction.
