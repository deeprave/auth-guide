"""Shared provider-instance defaults."""

import os

DEFAULT_NAMESPACE = "auth-guide"
_WINDOWS_RESERVED_NAMES = frozenset(
    {"con", "prn", "aux", "nul"}
    | {f"com{number}" for number in range(1, 10)}
    | {f"lpt{number}" for number in range(1, 10)}
)


def validate_namespace(namespace: str) -> str:
    """Return a canonical namespace that can safely form provider filenames."""
    if not namespace or not all(
        character.isascii() and (character.isalnum() or character in "-_") for character in namespace
    ):
        raise ValueError("Provider namespace must use only ASCII letters, numbers, hyphens, and underscores")
    normalised = namespace.lower()
    if os.name == "nt" and normalised in _WINDOWS_RESERVED_NAMES:
        raise ValueError("Provider namespace must not be a Windows reserved device name")
    return normalised
