"""Behaviour tests for the provider configuration directory."""

from pathlib import Path

from pytest import MonkeyPatch

from auth_guide.config_paths import get_auth_config_dir


def test_get_auth_config_dir_uses_guide_xdg_layout(monkeypatch: MonkeyPatch, tmp_path: Path) -> None:
    """The default location shares Guide's XDG configuration root."""
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))

    assert get_auth_config_dir() == tmp_path / "xdg" / "mcp-guide" / "auth"


def test_get_auth_config_dir_accepts_an_explicit_root(tmp_path: Path) -> None:
    """An explicit configuration root takes precedence over environment defaults."""
    config_dir = tmp_path / "provider-config"

    assert get_auth_config_dir(config_dir) == config_dir
