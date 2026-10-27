"""Logging configuration for the administration CLI."""

import logging
import logging.handlers
from dataclasses import dataclass
from ipaddress import ip_address
from typing import Any, cast
from urllib.parse import parse_qsl, quote, unquote, urlsplit, urlunsplit
from uuid import UUID

from rich.console import Console
from rich.logging import RichHandler
from rich.text import Text

from auth_guide.accounts.models import validate_account_email
from auth_guide.cli.config import CLIConfiguration
from auth_guide.cli.redaction import get_redaction_function

TRACE = 5
logging.addLevelName(TRACE, "TRACE")

_MANAGED_LOGGERS = ("auth_guide", "uvicorn", "uvicorn.error", "uvicorn.access", "uvicorn.asgi")
_ACCESS_EMAIL_PARAMETERS = {"email", "account_email"}
_ACCESS_UUID_PARAMETERS = {"account_id"}
_provider_handlers: set[logging.Handler] = set()
_provider_filters: set[logging.Filter] = set()


class LoggerWithTrace(logging.Logger):
    """Logger with Guide-compatible TRACE support."""

    def trace(self, message: object, *args: object, **kwargs: Any) -> None:
        """Log one message below DEBUG."""
        if self.isEnabledFor(TRACE):
            self._log(TRACE, message, args, **kwargs)


logging.setLoggerClass(LoggerWithTrace)


class RedactingFormatter(logging.Formatter):
    """Apply the reserved provider redactor before textual formatting."""

    def format(self, record: logging.LogRecord) -> str:
        """Format and then apply the current redaction policy."""
        return get_redaction_function()(super().format(record))


class ColouredRichHandler(RichHandler):
    """Render the console message in its level colour without metadata columns."""

    def render_message(self, record: logging.LogRecord, message: str) -> Text:
        """Apply Rich's configured level style to the rendered message."""
        message_text = cast(Text, super().render_message(record, message))
        message_text.stylize(f"logging.level.{record.levelname.lower()}")
        return message_text


class AccessLogFormatter(RedactingFormatter):
    """Render a concise, already-sanitised foreground HTTP access record."""

    def format(self, record: logging.LogRecord) -> str:
        """Format the sanitised Uvicorn request tuple without console metadata."""
        if not isinstance(record.args, tuple) or len(record.args) != 5:
            return "UNKNOWN <redacted-target> ?"
        _, method, target, _, status = record.args
        return f"• {get_redaction_function()(f'{method} {target} {status}')}"


class ForegroundServerFormatter(RedactingFormatter):
    """Prefix foreground server records without changing persistent log output."""

    def format(self, record: logging.LogRecord) -> str:
        """Render one provider or Uvicorn record with a concise leading bullet."""
        return f"• {super().format(record)}"


@dataclass(frozen=True)
class ProviderHandlers:
    """Name the provider-owned handler roles used for Uvicorn routing."""

    console: logging.Handler
    persistent: tuple[logging.Handler, ...]


@dataclass(frozen=True)
class UvicornLoggerState:
    """Retain the host's Uvicorn logger state while the provider owns it."""

    level: int
    propagate: bool


_uvicorn_logger_states: dict[str, UvicornLoggerState] = {}


class UvicornAccessFilter(logging.Filter):
    """Remove sensitive request-target values before access records are handled."""

    def filter(self, record: logging.LogRecord) -> bool:
        """Sanitise Uvicorn's positional access-record data in place."""
        if not isinstance(record.args, tuple) or len(record.args) != 5:
            record.msg = "%s"
            record.args = ("<redacted-access-record>",)
            return True

        client, method, target, version, status = record.args
        sanitised_target = sanitise_access_target(str(target))
        record.args = (_sanitise_client(str(client)), method, sanitised_target, version, status)
        return True


def get_logger(name: str) -> LoggerWithTrace:
    """Return a logger that provides the TRACE convenience method."""
    return cast(LoggerWithTrace, logging.getLogger(name))


def _level(level_name: str) -> int:
    """Convert the documented log-level spelling to logging's numeric level."""
    levels = {
        "TRACE": TRACE,
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "WARN": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL,
    }
    level = levels.get(level_name.upper())
    if level is None:
        raise ValueError("Log level must be TRACE, DEBUG, INFO, WARNING, ERROR, or CRITICAL")
    return level


def _formatter(layout: str) -> RedactingFormatter:
    """Create a redacting formatter with Guide's timestamp convention."""
    return RedactingFormatter(layout, datefmt="%Y-%m-%d %H:%M:%S")


def sanitise_access_target(target: str) -> str:
    """Keep useful request-target shape while masking sensitive selector values."""
    try:
        parsed = urlsplit(target)
        if parsed.scheme or parsed.netloc or parsed.fragment:
            return "<redacted-target>"
        path = "/".join(_mask_uuid_path_segment(segment) for segment in parsed.path.split("/"))
        query = _sanitise_query(parsed.query)
    except (TypeError, ValueError):
        return "<redacted-target>"
    return urlunsplit(("", "", path, query, ""))


def _mask_uuid_path_segment(segment: str) -> str:
    """Mask a UUID-shaped path segment without changing an ordinary route segment."""
    decoded_segment = unquote(segment)
    try:
        return _mask_uuid(str(UUID(decoded_segment)))
    except (TypeError, ValueError, AttributeError):
        return segment


def _sanitise_query(query: str) -> str:
    """Retain query names while replacing every value with a safe representation."""
    values = parse_qsl(query, keep_blank_values=True, strict_parsing=True)
    return "&".join(f"{quote(name, safe='')}={_sanitise_query_value(name, value)}" for name, value in values)


def _sanitise_query_value(name: str, value: str) -> str:
    """Use structural masking only for known selector forms."""
    if name in _ACCESS_EMAIL_PARAMETERS:
        return _mask_email(value)
    if name in _ACCESS_UUID_PARAMETERS:
        return _mask_uuid_value(value)
    try:
        UUID(value)
    except (TypeError, ValueError, AttributeError):
        return "***"
    return _mask_uuid(value)


def _mask_email(value: str) -> str:
    """Show the outer email characters without retaining its actual address."""
    try:
        valid_email = validate_account_email(value)
    except ValueError:
        return "[invalid]"
    local, separator, domain = valid_email.rpartition("@")
    domain_name, domain_separator, suffix = domain.rpartition(".")
    if not separator or not local or not domain_separator or not domain_name or not suffix:
        return "***"
    return f"{_mask_outer(local)}@{_mask_outer(domain_name)}.{suffix}"


def _mask_uuid_value(value: str) -> str:
    """Mask an API-compatible UUID value or identify it as invalid."""
    try:
        return _mask_uuid(str(UUID(value)))
    except (TypeError, ValueError, AttributeError):
        return "[invalid]"


def _mask_outer(value: str) -> str:
    """Retain only a value's first and final character around a fixed mask."""
    return f"{value[0]}***{value[-1]}" if len(value) > 1 else f"{value}***"


def _mask_uuid(value: str) -> str:
    """Retain only a UUID's first and final four source characters."""
    return f"{value[:4]}{'*' * (len(value) - 8)}{value[-4:]}"


def _sanitise_client(value: str) -> str:
    """Retain only a valid socket peer representation in access records."""
    host, separator, port = value.rpartition(":")
    try:
        if separator and host:
            ip_address(host)
            return f"{host}:{port}" if port.isdecimal() else "[invalid]"
        ip_address(value)
    except ValueError:
        return "[invalid]"
    return value


def _clear_managed_handlers() -> None:
    """Remove and close every handler installed by the provider logging boundary."""
    handlers: dict[int, logging.Handler] = {}
    for name in _MANAGED_LOGGERS:
        logger = logging.getLogger(name)
        for handler in logger.handlers[:]:
            if handler in _provider_handlers:
                logger.removeHandler(handler)
                handlers[id(handler)] = handler
        for log_filter in logger.filters[:]:
            if log_filter in _provider_filters:
                logger.removeFilter(log_filter)
    for name, state in _uvicorn_logger_states.items():
        logger = logging.getLogger(name)
        logger.setLevel(state.level)
        logger.propagate = state.propagate
    _uvicorn_logger_states.clear()
    for handler in handlers.values():
        handler.close()
        _provider_handlers.discard(handler)


def _uvicorn_logger(name: str) -> logging.Logger:
    """Return a Uvicorn logger after retaining the host configuration once."""
    logger = logging.getLogger(name)
    if name not in _uvicorn_logger_states:
        _uvicorn_logger_states[name] = UvicornLoggerState(level=logger.level, propagate=logger.propagate)
    return logger


def _add_provider_handler(logger: logging.Logger, handler: logging.Handler) -> None:
    """Attach one provider-owned handler for cleanup during later reconfiguration."""
    logger.addHandler(handler)
    _provider_handlers.add(handler)


def _add_provider_filter(logger: logging.Logger, log_filter: logging.Filter) -> None:
    """Attach one provider-owned filter without replacing host filters."""
    logger.addFilter(log_filter)
    _provider_filters.add(log_filter)


def _console_handler() -> ColouredRichHandler:
    """Create the metadata-free Rich console handler used by provider records."""
    return ColouredRichHandler(
        console=Console(stderr=True),
        show_time=False,
        show_level=False,
        show_path=False,
        rich_tracebacks=True,
    )


def ensure_uvicorn_access_policy() -> None:
    """Prevent a factory-created server from emitting unmanaged access records."""
    access_logger = _uvicorn_logger("uvicorn.access")
    access_logger.propagate = False
    if not any(isinstance(log_filter, UvicornAccessFilter) for log_filter in access_logger.filters):
        _add_provider_filter(access_logger, UvicornAccessFilter())


def _configure_uvicorn_logging(handlers: ProviderHandlers, *, foreground: bool) -> None:
    """Route Uvicorn records through the provider's managed handlers."""
    for name in ("uvicorn", "uvicorn.error", "uvicorn.asgi"):
        uvicorn_logger = _uvicorn_logger(name)
        uvicorn_logger.setLevel(TRACE)
        uvicorn_logger.propagate = False
        if foreground:
            _add_provider_handler(uvicorn_logger, handlers.console)
        for handler in handlers.persistent:
            _add_provider_handler(uvicorn_logger, handler)

    access_logger = _uvicorn_logger("uvicorn.access")
    access_logger.setLevel(TRACE)
    ensure_uvicorn_access_policy()
    if foreground:
        access_console = _console_handler()
        access_console.setLevel(handlers.console.level)
        access_console.setFormatter(AccessLogFormatter())
        _add_provider_handler(access_logger, access_console)
    for handler in handlers.persistent:
        _add_provider_handler(access_logger, handler)


def configure_safe_console_logging() -> LoggerWithTrace:
    """Configure safe console diagnostics before configuration is available."""
    logger = get_logger("auth_guide")
    logger.setLevel(TRACE)
    logger.propagate = False
    _clear_managed_handlers()

    console = _console_handler()
    console.setLevel(logging.INFO)
    console.setFormatter(_formatter("%(message)s"))
    _add_provider_handler(logger, console)
    return logger


def configure_logging(
    configuration: CLIConfiguration,
    *,
    cli_only: bool,
    foreground: bool = True,
) -> LoggerWithTrace:
    """Replace managed console and persistent handlers for one CLI invocation."""
    logger = configure_safe_console_logging()
    console = next(handler for handler in logger.handlers if isinstance(handler, ColouredRichHandler))
    if not cli_only and foreground:
        console.setFormatter(ForegroundServerFormatter(configuration.console_log_format))
    else:
        console.setFormatter(_formatter(configuration.console_log_format))

    console.setLevel(_level(configuration.log_level_console))

    if cli_only and not configuration.cli_log:
        return logger
    persistent_level = _level(configuration.log_level)
    if configuration.log_file is not None:
        file_handler = logging.FileHandler(configuration.log_file, encoding="utf-8")
        file_handler.setLevel(persistent_level)
        file_handler.setFormatter(_formatter(configuration.file_log_format))
        _add_provider_handler(logger, file_handler)
    if configuration.log_syslog:
        syslog_handler = logging.handlers.SysLogHandler(address=_syslog_address())
        syslog_handler.setLevel(persistent_level)
        syslog_handler.setFormatter(_formatter(configuration.file_log_format))
        _add_provider_handler(logger, syslog_handler)
    if not cli_only:
        handlers = ProviderHandlers(
            console=console,
            persistent=tuple(handler for handler in logger.handlers if handler is not console),
        )
        _configure_uvicorn_logging(handlers, foreground=foreground)
    return logger


def _syslog_address() -> str:
    """Select the conventional host syslog socket for supported Unix platforms."""
    import sys

    return "/var/run/syslog" if sys.platform == "darwin" else "/dev/log"
