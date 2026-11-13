"""Shared provider-instance defaults."""

DEFAULT_NAMESPACE = "auth-guide"


def validate_namespace(namespace: str) -> None:
    """Reject namespace values that cannot safely form provider filenames."""
    if not namespace or not all(
        character.isascii() and (character.isalnum() or character in "-_") for character in namespace
    ):
        raise ValueError("Provider namespace must use only ASCII letters, numbers, hyphens, and underscores")
