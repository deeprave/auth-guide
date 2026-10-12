"""Reserved redaction integration point for CLI logging."""

from collections.abc import Callable


def get_redaction_function() -> Callable[[str], str]:
    """Return the current pass-through redactor.

    Declarative custom redaction rules are intentionally deferred.
    """
    return lambda message: message
