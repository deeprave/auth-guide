"""Suite-wide isolation for provider configuration and platform integrations."""

import os
import tempfile
from pathlib import Path

import pytest

_session_directory: tempfile.TemporaryDirectory[str] | None = None
_configuration_root: Path | None = None


def pytest_addoption(parser: pytest.Parser) -> None:
    """Register the explicit switch for tests that mutate platform state."""
    parser.addoption(
        "--run-platform-integration",
        action="store_true",
        default=False,
        help="run integration tests that access the platform Keychain or trust store",
    )


def pytest_configure(config: pytest.Config) -> None:
    """Redirect provider configuration before test modules can import it."""
    global _configuration_root, _session_directory
    _session_directory = tempfile.TemporaryDirectory(prefix="auth-guide-tests-")
    _configuration_root = Path(_session_directory.name) / "xdg-config"
    _configuration_root.mkdir()

    for name in tuple(os.environ):
        if name.startswith("AG_") or name in {"AUTH_GUIDE_TOKEN", "SSL_CERT_FILE", "SSL_CERT_DIR"}:
            os.environ.pop(name)
    os.environ["XDG_CONFIG_HOME"] = str(_configuration_root)
    if os.name == "nt":
        os.environ["APPDATA"] = str(_configuration_root)
        os.environ["LOCALAPPDATA"] = str(_configuration_root)

    config.addinivalue_line(
        "markers",
        "platform_integration: accesses a real platform Keychain or trust store",
    )


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Keep stateful platform integration tests out of the ordinary suite."""
    if config.getoption("--run-platform-integration"):
        return
    skip = pytest.mark.skip(reason="requires --run-platform-integration")
    for item in items:
        if item.get_closest_marker("platform_integration") is not None:
            item.add_marker(skip)


@pytest.fixture(scope="session")
def isolated_configuration_root() -> Path:
    """Return the session-owned XDG configuration root used by every test."""
    if _configuration_root is None:
        raise RuntimeError("pytest configuration isolation was not initialised")
    return _configuration_root


def pytest_unconfigure(config: pytest.Config) -> None:
    """Remove the complete session-isolation directory after the suite."""
    global _configuration_root, _session_directory
    del config
    if _session_directory is not None:
        _session_directory.cleanup()
        _session_directory = None
    _configuration_root = None
