"""Configuration path helpers for the reference provider."""

import os
from pathlib import Path


def get_auth_config_dir(config_dir: str | Path | None = None) -> Path:
    """Return the provider configuration root.

    An explicit directory is the complete provider root.  Otherwise the root
    is nested beneath Guide's configuration directory, using the host's XDG
    convention where it applies.
    """
    if config_dir is not None:
        return Path(config_dir)

    if os.name != "nt":
        xdg_config_home = os.environ.get("XDG_CONFIG_HOME")
        if xdg_config_home:
            return Path(xdg_config_home) / "mcp-guide" / "auth"
        return Path.home() / ".config" / "mcp-guide" / "auth"

    appdata = os.environ.get("APPDATA")
    if appdata:
        return Path(appdata) / "mcp-guide" / "auth"
    return Path.home() / "AppData" / "Roaming" / "mcp-guide" / "auth"
