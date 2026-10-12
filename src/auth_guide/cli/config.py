"""Synchronous command-line configuration resolution."""

import os
import tomllib
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from anyio import Path as AsyncPath

from auth_guide.config_paths import get_auth_config_dir

DEFAULT_ADDRESS = "https://localhost:8443"
DEFAULT_CONSOLE_LOG_FORMAT = "%(message)s"
DEFAULT_FILE_LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
CONFIGURATION_SCAFFOLD = """# auth-guide administration configuration
# listen = \"https://localhost:8443\"
# address = \"https://localhost:8443\"
# log_level_console = \"INFO\"
# console_log_format = \"%(message)s\"
# log_level = \"DEBUG\"
# log_file = \"\"
# log_syslog = false
# file_log_format = \"%(asctime)s - %(name)s - %(levelname)s - %(message)s\"
# redactor_file = \"\"  # Reserved for future declarative redaction rules.
"""


@dataclass(frozen=True, slots=True)
class CLIConfiguration:
    """Resolved non-secret administration CLI settings."""

    configuration_file: Path
    listen: str
    address: str
    log_level_console: str
    log_level: str
    log_file: str | None
    log_syslog: bool
    cli_log: bool
    console_log_format: str
    file_log_format: str


def resolve_configuration_path(
    configuration_file: Path | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> Path:
    """Resolve the explicit configuration file before loading any settings."""
    environment = os.environ if environ is None else environ
    return configuration_file or Path(environment.get("AG_CONFIG") or get_auth_config_dir() / "config.toml")


def resolve_configuration(
    configuration_file: Path,
    *,
    listen: str | None = None,
    address: str | None = None,
    log_level_console: str | None = None,
    log_level: str | None = None,
    log_file: str | None = None,
    log_syslog: bool | None = None,
    cli_log: bool | None = None,
    environ: Mapping[str, str] | None = None,
) -> CLIConfiguration:
    """Resolve settings from arguments, environment, TOML, then defaults."""
    environment = os.environ if environ is None else environ
    values = _read_configuration_file(configuration_file)
    return CLIConfiguration(
        configuration_file=configuration_file,
        listen=_resolve_string(listen, environment.get("AG_LISTEN"), values.get("listen"), DEFAULT_ADDRESS),
        address=_resolve_string(address, environment.get("AG_ADDRESS"), values.get("address"), DEFAULT_ADDRESS),
        log_level_console=_resolve_string(
            log_level_console,
            environment.get("AG_LOGCONSOLE"),
            values.get("log_level_console"),
            "INFO",
        ),
        log_level=_resolve_string(log_level, environment.get("AG_LOGLEVEL"), values.get("log_level"), "DEBUG"),
        log_file=_resolve_optional_string(log_file, environment.get("AG_LOGFILE"), values.get("log_file")),
        log_syslog=_resolve_boolean(log_syslog, environment.get("AG_LOGSYSLOG"), values.get("log_syslog"), False),
        cli_log=_resolve_boolean(cli_log, environment.get("AG_CLILOG"), values.get("log_cli"), True),
        console_log_format=_resolve_string(None, None, values.get("console_log_format"), DEFAULT_CONSOLE_LOG_FORMAT),
        file_log_format=_resolve_string(None, None, values.get("file_log_format"), DEFAULT_FILE_LOG_FORMAT),
    )


def _read_configuration_file(configuration_file: Path) -> dict[str, object]:
    """Read the optional non-secret TOML configuration document."""
    if not configuration_file.exists():
        return {}
    with configuration_file.open("rb") as stream:
        parsed = tomllib.load(stream)
    return dict(parsed)


def _resolve_string(
    command_line: str | None,
    environment: str | None,
    configuration: object | None,
    default: str,
) -> str:
    """Return the first configured string in the documented precedence order."""
    value = command_line or environment or configuration or default
    if not isinstance(value, str):
        raise ValueError("Configuration value must be a string")
    return value


def _resolve_optional_string(
    command_line: str | None,
    environment: str | None,
    configuration: object | None,
) -> str | None:
    """Return an optional configured string, treating an empty value as absent."""
    value = command_line or environment or configuration
    if value in (None, ""):
        return None
    if not isinstance(value, str):
        raise ValueError("Configuration value must be a string")
    return value


def _resolve_boolean(
    command_line: bool | None,
    environment: str | None,
    configuration: object | None,
    default: bool,
) -> bool:
    """Return a strict boolean using the documented precedence order."""
    if command_line is not None:
        return command_line
    if environment is not None:
        return _parse_boolean(environment)
    if configuration is None:
        return default
    if not isinstance(configuration, bool):
        raise ValueError("Configuration value must be true or false")
    return configuration


def _parse_boolean(value: str) -> bool:
    """Parse an environment boolean without accepting ambiguous values."""
    if value.lower() == "true":
        return True
    if value.lower() == "false":
        return False
    raise ValueError("Environment boolean must be true or false")


async def create_configuration_file(configuration_file: AsyncPath) -> None:
    """Create the documented non-secret configuration scaffold exactly once."""
    await configuration_file.parent.mkdir(parents=True, exist_ok=True)
    async with await configuration_file.open("x", encoding="utf-8") as stream:
        await stream.write(CONFIGURATION_SCAFFOLD)
