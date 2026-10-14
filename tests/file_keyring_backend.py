"""A disposable keyring backend used only by detached-process integration tests."""

import json
import os
from pathlib import Path

from keyring.backend import KeyringBackend


class FileKeyring(KeyringBackend):
    """Share non-production test secrets between a parent and its child process."""

    priority = 1

    @property
    def _path(self) -> Path:
        """Return the explicitly isolated test keyring document."""
        return Path(os.environ["AUTH_GUIDE_TEST_KEYRING"])

    def get_password(self, service: str, username: str) -> str | None:
        """Read one opaque test secret."""
        return self._values().get(self._key(service, username))

    def set_password(self, service: str, username: str, password: str) -> None:
        """Persist one opaque test secret."""
        values = self._values()
        values[self._key(service, username)] = password
        self._write_values(values)

    def delete_password(self, service: str, username: str) -> None:
        """Delete one opaque test secret."""
        values = self._values()
        del values[self._key(service, username)]
        self._write_values(values)

    def _values(self) -> dict[str, str]:
        """Load the complete test-only keyring document."""
        try:
            contents = self._path.read_text(encoding="utf-8")
        except FileNotFoundError:
            return {}
        value = json.loads(contents)
        if not isinstance(value, dict) or not all(isinstance(item, str) for item in value.values()):
            raise ValueError("Test keyring data is invalid")
        return value

    def _write_values(self, values: dict[str, str]) -> None:
        """Write the isolated keyring with owner-only permissions."""
        self._path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(values, stream, sort_keys=True)

    @staticmethod
    def _key(service: str, username: str) -> str:
        """Separate service and secret references in the JSON document."""
        return f"{service}\x00{username}"
