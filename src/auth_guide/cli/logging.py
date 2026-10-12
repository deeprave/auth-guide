"""Logging configuration for the administration CLI."""

import logging
import logging.handlers
from typing import Any, cast

from rich.console import Console
from rich.logging import RichHandler
from rich.text import Text

from auth_guide.cli.config import CLIConfiguration
from auth_guide.cli.redaction import get_redaction_function

TRACE = 5
logging.addLevelName(TRACE, "TRACE")


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


def get_logger(name: str) -> LoggerWithTrace:
    """Return a logger that provides the TRACE convenience method."""
    return cast(LoggerWithTrace, logging.getLogger(name))


def _level(level_name: str) -> int:
    """Convert the documented log-level spelling to logging's numeric level."""
    levels = {
        "TRACE": TRACE,
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARN": logging.WARNING,
        "CRITICAL": logging.CRITICAL,
    }
    level = levels.get(level_name.upper())
    if level is None:
        raise ValueError("Log level must be TRACE, DEBUG, INFO, WARN, or CRITICAL")
    return level


def _formatter(layout: str) -> RedactingFormatter:
    """Create a redacting formatter with Guide's timestamp convention."""
    return RedactingFormatter(layout, datefmt="%Y-%m-%d %H:%M:%S")


def configure_safe_console_logging() -> LoggerWithTrace:
    """Configure safe console diagnostics before configuration is available."""
    logger = get_logger("auth_guide")
    logger.setLevel(TRACE)
    logger.propagate = False
    for handler in logger.handlers[:]:
        logger.removeHandler(handler)
        handler.close()

    console = ColouredRichHandler(
        console=Console(stderr=True),
        show_time=False,
        show_level=False,
        show_path=False,
        rich_tracebacks=True,
    )
    console.setLevel(logging.INFO)
    console.setFormatter(_formatter("%(message)s"))
    logger.addHandler(console)
    return logger


def configure_logging(configuration: CLIConfiguration, *, cli_only: bool) -> LoggerWithTrace:
    """Configure console and optional persistent handlers for one CLI invocation."""
    logger = configure_safe_console_logging()
    console = logger.handlers[0]
    console.setFormatter(_formatter(configuration.console_log_format))

    console.setLevel(_level(configuration.log_level_console))

    if cli_only and not configuration.cli_log:
        return logger
    persistent_level = _level(configuration.log_level)
    if configuration.log_file is not None:
        file_handler = logging.FileHandler(configuration.log_file, encoding="utf-8")
        file_handler.setLevel(persistent_level)
        file_handler.setFormatter(_formatter(configuration.file_log_format))
        logger.addHandler(file_handler)
    if configuration.log_syslog:
        syslog_handler = logging.handlers.SysLogHandler(address=_syslog_address())
        syslog_handler.setLevel(persistent_level)
        syslog_handler.setFormatter(_formatter(configuration.file_log_format))
        logger.addHandler(syslog_handler)
    return logger


def _syslog_address() -> str:
    """Select the conventional host syslog socket for supported Unix platforms."""
    import sys

    return "/var/run/syslog" if sys.platform == "darwin" else "/dev/log"
